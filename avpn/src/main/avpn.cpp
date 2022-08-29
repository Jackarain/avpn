//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#include "utils/async_connect.hpp"
#include "utils/url_view.hpp"
#include "utils/scoped_exit.hpp"
#include "utils/uawaitable.hpp"
#include "utils/misc.hpp"
#include "utils/fileop.hpp"

#include "avpn/version.hpp"
#include "avpn/endpoint_pair.hpp"
#include "avpn/fec_cache.hpp"
#include "avpn/vpn_tunnel.hpp"
#include "avpn/avpn.hpp"
#include "avpn/vpn_conntrack.hpp"
#include "avpn/protocol.hpp"

#include "socks/socks_enums.hpp"

#include <chrono>
#include <iomanip>


namespace avpn {
	using namespace std::chrono_literals;
	using net::ip::make_network_v4;

	vtun_device_type instantiate_vtun_device(
		[[maybe_unused]] int device_type,
		net::io_context& ioc)
	{
#if defined(AVPN_WINDOWS)
		if (device_type == 0)
			return vtun_device_type(tuntap_device(ioc));
#if defined(AVPN_USE_WINTUN)
		else
			return vtun_device_type(wintun_device(ioc));
#else
		return vtun_device_type(tuntap_device(ioc));
#endif
#else
		return vtun_device_type(tun_device(ioc));
#endif
	}

	avpn_service::avpn_service(
		io_context_pool& ios, const service_config& config)
		: m_ioc_pool(ios)
		, m_main_context(m_ioc_pool.main_io_context())
		, m_config(config)
		, m_client_id(gen_unique_string(32))
		, m_client_key(base64_encode(crypto_util::ecdh_keygen()))
		, m_tundev(instantiate_vtun_device(
			config.ifdev_ == "wintun" ? 1 : 0, m_main_context))
		, m_tick_timer(m_main_context)
		, m_tun_wait_timer(m_main_context)
		, m_subnet(make_network_v4(config.tunnel_params_.subnet_))
		, m_ip_assigner(m_subnet.hosts())
		, m_ip_iterator(++m_ip_assigner.begin())
	{
		init_ssl_context();
	}

	std::shared_ptr<avpn_service> avpn_service::make_avpn_service(
			io_context_pool& ioc_pool, avpn::service_config cfg)
	{
		return std::shared_ptr<avpn_service>(new avpn_service(ioc_pool, cfg));
	}

	avpn_service::~avpn_service()
	{
		// TODO: 退出时删除所有添加的路由.
		LOG_DBG << "avpn_service::~avpn_service()";
	}

	void avpn_service::remove_client(size_t id)
	{
		m_socks_clients.erase(id);
	}

	const socks::socks_server_option& avpn_service::option()
	{
		return m_config.socks_opt_;
	}

	void avpn_service::start()
	{
		m_abort = false;
		m_client_reset_flag = vpn_tcp_loop_exit;
		auto self = shared_from_this();

		// 开启定时器.
		net::co_spawn(m_main_context,
			[this, self]() -> net::awaitable<void>
			{
				co_await tick();
				co_return;
			}, net::detached);

		// 客户端启动客户端通信通道.
		if (m_config.identity_ == Identity::avpn_client)
		{
			m_conntrack = std::make_shared<vpn_conntrack>(m_main_context, self);
			run_as_client();
		}

		// 服务器则将启动服务器通信通道.
		if (m_config.identity_ == Identity::avpn_server)
			run_as_server();
	}

	void avpn_service::stop()
	{
		LOG_WARN << "avpn_service::stop";

		boost::system::error_code ignore_ec;
		m_abort = true;

		if (m_cancel_sig.slot().has_handler())
			m_cancel_sig.emit(net::cancellation_type::all);

		for (auto& a : m_tcp_acceptors)
			a.cancel(ignore_ec);

		for (auto& socket_ptr : m_udp_sockets)
		{
			if (!socket_ptr) continue;

			auto& udp_socket = *socket_ptr;
			udp_socket.sock_.close(ignore_ec);
		}

		// 根据client/server身份关闭相应隧道.
		if (m_identity == Identity::avpn_client)
		{
			auto tunnel = m_tunnel.lock();
			if (tunnel)
			{
				tunnel->close_tunnel();
				m_tunnel = {};
			}
		}

		if (m_identity == Identity::avpn_server)
		{
			auto& tab = m_clients.table();
			for (auto& c : tab)
			{
				auto client = c.tunnel_.lock();
				if (!client)
					continue;
				client->close_tunnel();
			}

			auto& clients = m_socks_clients;
			for (auto& c : clients)
			{
				auto client = c.second.lock();
				if (!client)
					continue;
				client->close();
			}
		}

		// TODO: 退出时删除路由.
		LOG_WARN << "avpn_service::stop, close tun dev and cancel timers";
		m_tundev.close();
		m_tick_timer.cancel(ignore_ec);
		m_tun_wait_timer.cancel(ignore_ec);
		m_subnet = {};
		m_upload_speed = 0;
		m_down_speed = 0;
		m_start_udp = 0;
	}

	int64_t avpn_service::upload_rate() const
	{
		return m_upload_speed;
	}

	int64_t avpn_service::download_rate() const
	{
		return m_down_speed;
	}

	std::vector<tcp::endpoint> avpn_service::server_endpoint() const
	{
		return m_server_tcp_endps;
	}

	std::string avpn_service::client_key() const
	{
		return m_client_key;
	}

	const avpn::service_config& avpn_service::config() const
	{
		return m_config;
	}

	void avpn_service::init_ssl_context()
	{
		m_ssl_ctx.set_options(
			boost::asio::ssl::context::default_workarounds
			| boost::asio::ssl::context::no_sslv2
			| boost::asio::ssl::context::single_dh_use);

		auto dir = std::filesystem::path(m_config.ssl_certificate_dir_);
		auto pwd = dir / "ssl_crt.pwd";

		if (std::filesystem::exists(pwd))
			m_ssl_ctx.set_password_callback(
				[this, &pwd]([[maybe_unused]] auto... args) {
					std::string password;
					fileop::read(pwd, password);
					return password;
				}
		);

		auto cert = dir / "ssl_crt.pem";
		auto key = dir / "ssl_key.pem";
		auto dh = dir / "ssl_dh.pem";

		if (std::filesystem::exists(cert))
			m_ssl_ctx.use_certificate_chain_file(cert.string());

		if (std::filesystem::exists(key))
			m_ssl_ctx.use_private_key_file(
				key.string(), boost::asio::ssl::context::pem);

		if (std::filesystem::exists(dh))
			m_ssl_ctx.use_tmp_dh_file(dh.string());
	}

	net::awaitable<void> avpn_service::start_tun_read_loop()
	{
		boost::system::error_code ec;
		LOG_DBG << "Enter tun read loop: " << std::this_thread::get_id();

		while (!m_abort)
		{
			vpn_packet pkt;

			auto payload = pkt.data() + avpn_payload_header_size;
			auto size = avpn_packet_size - avpn_payload_header_size;

			auto bytes = co_await m_tundev.async_read_some(
				net::buffer(payload, size), uawaitable[ec]);
			if (ec)
			{
				LOG_ERR << "start_tun_read_loop, read: " << ec.message();
				break;
			}

			// 重置 pkt 的 payload size.
			pkt.resize(bytes + avpn_payload_header_size);
			pkt.payload_size(bytes);

			// 解析ip相关的信息.
			auto endp = parser_endpoint(payload, bytes);

			// 解析不出来的ip包, 直接跳过...
			if (endp.empty())
				continue;

			// 保存数据包类型.
			pkt.type((vpn_packet_t)endp.type_);

			// 根据程序的身份, 准备透传.
			if (m_config.identity_ == Identity::avpn_server)
			{
				// 作为server时, 要根据目标虚拟ip寻找到对应的通信
				// 通道透传到tunnel.
				do_server_tun_read(std::move(pkt), std::move(endp));
				continue;
			}
			else if (m_config.identity_ == Identity::avpn_client)
			{
				if (m_routes.lookup(endp.dst_.address())
					== (acl_util::lpm_tag)0xa)
				{
					// TODO: 通过tun2socks模式转发.
					if (!m_conntrack)
						continue;

					auto& conntrack = *m_conntrack;
					conntrack.forward_ip(std::move(pkt), std::move(endp));
				}
				else
				{
					do_client_tun_read(std::move(pkt), std::move(endp));
				}

				continue;
			}
		}

		// 在重启tun设备时, 当前这个tun read loop退出时以唤醒新的
		// tun read loop开始读取.
		m_tun_wait_timer.cancel_one(ec);
		LOG_WARN << "Quit tun loop";

		co_return;
	}

	void avpn_service::do_tun_write(vpn_packet_ptr pkt)
	{
		auto self = shared_from_this();
		net::co_spawn(m_main_context,
		[this, self, pkt] () mutable->net::awaitable<void>
		{
			boost::system::error_code ec;
			co_await m_tundev.async_write_some(
				net::buffer(pkt->payload(),
					pkt->payload_size()), uawaitable[ec]);
			co_return;
		}, net::detached);
	}

	void avpn_service::do_server_tun_read(vpn_packet pkt, endpoint_pair endp)
	{
		// 根据对端的虚拟ip查找tunnel对象.
		uint32_t dst = endp.dst_.address().to_v4().to_uint();
		auto tunnel = lookup_tunnel(dst);
		if (!tunnel)
			return;

		// 创建packet指针再通过tun_forward传入协程.
		auto ptr = std::make_shared<vpn_packet>(std::move(pkt));
		auto executor = tunnel->get_executor();

		// 转发到对应的vp对象.
		net::co_spawn(executor,
			[tunnel, ptr, endp = std::move(endp)]()
			mutable -> net::awaitable<void>
			{
				co_await tunnel->tun_forward(ptr, std::move(endp));
				co_return;
			}, net::detached);
	}

	void avpn_service::do_client_tun_read(vpn_packet pkt, endpoint_pair endp)
	{
		// 获取tunnel对象指针.
		auto tunnel = m_tunnel.lock();
		if (!tunnel)
			return;

		// 创建packet指针再通过tun_forward传入协程.
		auto ptr = std::make_shared<vpn_packet>(std::move(pkt));
		auto self = shared_from_this();

		// 透传到tunnel.
		net::co_spawn(tunnel->get_executor(),
			[this, self, ptr, endp = std::move(endp)]()
			mutable->net::awaitable<void>
		{
			auto tunnel = m_tunnel.lock();
			if (!tunnel)
				co_return;
			co_await tunnel->tun_forward(ptr, std::move(endp));
			co_return;
		}, net::detached);
	}

	net::awaitable<void> avpn_service::start_udp_read_loop(int index)
	{
		udp::endpoint remote;
		boost::system::error_code ec;

		while (!m_abort)
		{
			auto socket_ptr = m_udp_sockets[index];
			auto& udp_socket = socket_ptr->sock_;

			vpn_packet pkt;

			auto bytes = co_await udp_socket.async_receive_from(
				net::buffer(pkt.data(), avpn_packet_size),
					remote, uawaitable[ec]);
			if (ec)
				continue;

			// 只有是client时, 才需要更新last see, 因为client一旦检
			// 测到超时, 则会重建udp socket对象重新向server建立通信.
			if (m_identity == Identity::avpn_client)
				socket_ptr->last_see_ = steady_clock::now();

			// 重置为实际接收的数据大小.
			pkt.resize(bytes);

			if (m_identity == Identity::avpn_server)
			{
				// 根据协议中的虚拟ip信息, 找到相应vpn连接进行相应数
				// 据处理.

				// 如果是认证请求, 则根据client的id, 先查询client连
				// 接池中是否已有相同id存在的请求, 如果有则直接使用池
				// 中vpn tunnel, 如果没有, 则创建新的 vpn tunnel,
				// 并加入到 vpn tunnel连接池中, 直到认证完成, 则能将
				// 其从连接池中移动到已经完成的连接列表.
				bool enc = false;
				uint8_t type = 0;
				uint32_t src_vaddr = 0;

				int ret = unwrap_common_header(pkt,
					enc, type, src_vaddr);
				if (!ret)
					continue;

				// client握手认证请求, 转入handshake处理流程.
				if (type == vpt_handshake)
				{
					auto self = shared_from_this();
					net::co_spawn(m_main_context,
						[this, self, remote, pkt = std::move(pkt), src_vaddr]
						() mutable ->net::awaitable<void>
						{
							co_await on_udp_handshake(
								remote, std::move(pkt), src_vaddr);
							co_return;
						}, net::detached);
					continue;
				}

				// 根据src寻找对应的client, 找到后转入相应client
				// 的处理流程中.
				auto tunnel = co_await net::co_spawn(m_main_context,
					async_lookup_tunnel(src_vaddr), net::use_awaitable);
				if (!tunnel)
				{
					net::ip::address_v4 src_addr(src_vaddr);
					LOG_WARN << "Not found client via loop: "
						<< src_addr.to_string();

					// 若不为同一网络段, 则有可能是错误的数据包, 忽略掉.
					if (!same_ipv4_network(m_subnet, src_vaddr))
						continue;

					// 没找到src对应的client, 则返回空handshake reply消息.
					auto response = make_handshake_reply(
						{}, 0, 0, 0, 0, false, 0, {});
					auto ptr = std::make_shared<vpn_packet>(
						std::move(response));
					co_await udp_write(ptr, remote);
					continue;
				}

				// 更新ipproto.
				tunnel->ipproto(Proto::avpn_udp);

				// 创建packet指针再通过tun_forward传入协程.
				auto ptr = std::make_shared<vpn_packet>(std::move(pkt));

				// 将UDP消息转发到对应的tunnel连接中处理.
				auto executor = tunnel->get_executor();
				net::co_spawn(executor,
					[tunnel, ptr, remote]()
					mutable -> net::awaitable<void>
					{
						co_await tunnel->udp_forward(ptr, remote);
						co_return;
					}, net::detached);

				continue;
			}

			if (m_identity == Identity::avpn_client)
			{
				bool enc = false;
				uint8_t type = 0;
				uint32_t src_vaddr = 0;

				int ret = unwrap_common_header(pkt,
					enc, type, src_vaddr);
				if (!ret)
					continue;

				// server握手认证请求回复, 转入handshake处理流程.
				if (type == vpt_handshake_reply)
				{
					auto self = shared_from_this();
					net::co_spawn(m_main_context,
						[this, self, remote, pkt = std::move(pkt)]
						() mutable -> net::awaitable<void>
						{
							co_await on_udp_handshake_reply(
								remote, std::move(pkt));
							co_return;
						}, net::detached);
					continue;
				}

				// client的tunnel还没建立好, 忽略所有非vpt_handshake_reply消息.
				auto tunnel = m_tunnel.lock();
				if (!tunnel)
					continue;

				// 转发到client连接, 让client对象处理相应的协议数据.
				auto ptr = std::make_shared<vpn_packet>(std::move(pkt));
				auto self = shared_from_this();

				// 将UDP消息转发到对应的vp连接中处理.
				net::co_spawn(m_main_context,
					[this, self, ptr, remote]()
					mutable -> net::awaitable<void>
					{
						auto tunnel = m_tunnel.lock();
						if (!tunnel)
							co_return;
						co_await tunnel->udp_forward(ptr, remote);
						co_return;
					}, net::detached);

				continue;
			}
		}

		co_return;
	}

	void avpn_service::do_udp_write(vpn_packet_ptr pkt, udp::endpoint endp)
	{
		auto self = shared_from_this();
		net::co_spawn(m_main_context,
			[this, self, pkt = std::move(pkt), endp = std::move(endp)]
			() -> net::awaitable<void>
			{
				co_await udp_write(pkt, std::move(endp));
				co_return;
			}, net::detached);
	}

	net::awaitable<void>
	avpn_service::udp_write(vpn_packet_ptr pkt, udp::endpoint remote)
	{
		auto usize = m_udp_sockets.size();
		static uint32_t index = 0;

		// TODO: 这里可以优化为选择一个活跃的udp socket 用于发送.
		auto socket_ptr = m_udp_sockets[index++ % usize];
		auto& udp_socket = socket_ptr->sock_;

		boost::system::error_code ec;
		// 调用udp socket发送数据.
		co_await udp_socket.async_send_to(
			net::buffer(pkt->data(), pkt->size()),
			remote, uawaitable[ec]);
		if (ec)
			LOG_WARN << "udp_write"
			<< ", send_to " << remote
			<< ", error: " << ec.message();

		co_return;
	}

	void avpn_service::run_as_client()
	{
		// 开始client之前, 清理重要控制部分的状态至最初.
		m_identity = Identity::avpn_client;
		m_abort = false;
		m_subnet = {};
		m_client_tcp_cnt = 0;
		auto self = shared_from_this();

		LOG_DBG << "Start run_as_client...";

		// 开始客户端协程.
		net::co_spawn(m_main_context,
			[this, self]() mutable -> net::awaitable<void>
			{
				co_await run_client();
				co_return;
			}, net::detached);
	}

	void avpn_service::run_as_server()
	{
		m_identity = Identity::avpn_server;
		m_abort = false;
		auto self = shared_from_this();

		LOG_DBG << "Start run_as_server...";
		net::co_spawn(m_main_context,
			[this, self]() -> net::awaitable<void>
			{
				co_await setup_tun(m_subnet);
				co_return;
			}, net::detached);

		// 初始化tcp连接.
		bool ret = init_acceptors();
		if (!ret)
			return;

		// 开始侦听tcp客户端连接消息.
		net::co_spawn(m_main_context,
			[this, self]() mutable -> net::awaitable<void>
			{
				int pool_size = static_cast<int>(m_ioc_pool.pool_size());
				for (int i = 0; i < pool_size; i++)
				{
					for (auto& a : m_tcp_acceptors)
					{
						// start_tcp_listen keep self.
						net::co_spawn(a.get_executor(),
							[this, self, &a] () mutable -> net::awaitable<void>
							{
								co_await start_tcp_listen(a);
								co_return;
							}, net::detached);
					}
				}
				co_return;
			}, net::detached);

		// 开始侦听udp客户端消息.
		net::co_spawn(m_main_context,
			[this, self]() mutable->net::awaitable<void>
			{
				co_await start_udp_server();
				co_return;
			}, net::detached);
	}

	net::awaitable<void> avpn_service::run_client()
	{
		// 筛选出udp协议的url.
		co_await make_endpoint("udp");

		auto self = shared_from_this();
		// 开始侦听udp客户端消息.
		net::co_spawn(m_main_context,
			[this, self]() mutable -> net::awaitable<void>
			{
				co_await start_udp_client();
				co_return;
			}, net::detached);

		net::co_spawn(
			m_main_context,
			[this, self]() mutable -> net::awaitable<void>
			{
				co_await start_tcp_client();
				co_return;
			},
			net::detached);

		co_return;
	}

	net::awaitable<void> avpn_service::tick()
	{
		boost::system::error_code ec;

		LOG_DBG << "Enter avpn_service::tick "
			<< std::this_thread::get_id();

		// 检查tunnel.
		auto check_tunnel = [&](time_point& now) mutable
		{
			auto& clients = m_clients.table();
			for (auto it = clients.begin();
				it != clients.end();)
			{
				auto& c = *it;
				auto tunnel = c.tunnel_.lock();
				if (!tunnel)
				{
					it = clients.erase(it);
					continue;
				}

				auto duration = now - tunnel->last_see();
				if (duration >= std::chrono::minutes(2))
				{
					LOG_WARN << "tunnel: " << tunnel.get() << " timeout";
					tunnel->close_tunnel();
					it = clients.erase(it);
					continue;
				}

				it++;
			}
		};

		// 检查client 是否能够重启.
		auto check_client_reset = [&]() mutable
		{
			if (m_client_reset_flag & vpn_restart)
			{
				// 重启过程中, 停止tcp重连逻辑.
				m_client_tcp_cnt = 0;

				// 输出重启flag, 以便诊断错误.
				LOG_DBG << "Client restart flag: " << m_client_reset_flag;

				auto result = m_client_reset_flag & vpn_restart_ready;
				auto busy = !!(m_client_reset_flag & vpn_restart_busy);

				// 如果已经可重启且还未开始重启.
				if (result == vpn_restart_ready && !busy)
				{
					m_client_reset_flag |= vpn_restart_busy;
					run_as_client();
				}
			}
		};

		// 检查client tcp连接是否超时需要重连.
		auto check_client_tcp = [&]() mutable
		{
			// 为0表示没有开始计数, 无需检查.
			if (m_client_tcp_cnt > 0)
			{
				LOG_DBG << "Tcp reconnect timer: " << m_client_tcp_cnt;
				if (++m_client_tcp_cnt > 10)
				{
					m_client_tcp_cnt = 0;
					auto self = shared_from_this();

					net::co_spawn(m_main_context,
						[this, self] () mutable -> net::awaitable<void>
						{
							co_await start_tcp_client();
							co_return;
						}, net::detached);
					LOG_DBG << "Tcp reconnect started...";
				}
			}
		};

		// 检查client udp是否超时.
		auto check_client_udp = [&]() mutable
		{
			auto tunnel = m_tunnel.lock();
			if (!tunnel)
				return;

			auto now = steady_clock::now();
			auto tmp_sockets = m_udp_sockets;
			for (size_t i = 0; i < tmp_sockets.size(); i++)
			{
				if (m_abort)
					break;

				auto socket_ptr = tmp_sockets[i];
				if (!socket_ptr)
					continue;

				auto duration = now - socket_ptr->last_see_;
				if (duration < std::chrono::seconds(60))
					continue;

				auto local_endp = socket_ptr->sock_.local_endpoint();
				auto protocol = local_endp.protocol();

				socket_ptr->sock_.close(ec);

				udp::socket new_usock(m_main_context,
					udp::endpoint(protocol, 0));
				auto new_endp = new_usock.local_endpoint(ec);
				if (ec)
				{
					LOG_ERR << "Renew udp socket: " << local_endp
						<< " -> " << new_endp
						<< ", ec: " << ec.message();
				}
				else
				{
					LOG_INFO << "Renew udp socket: " << local_endp
						<< " -> " << new_endp;
				}

				auto new_udp_socket = std::make_shared<udp_socket>(
					udp_socket{ now, std::move(new_usock) });

				m_udp_sockets[i] = new_udp_socket;
			}
		};

		while (!m_abort)
		{
			m_tick_timer.expires_from_now(std::chrono::seconds(1));
			co_await m_tick_timer.async_wait(uawaitable[ec]);
			if (ec)
			{
				LOG_ERR << "avpn_service::tick, ec: " << ec.message();
				break;
			}

			auto now = std::chrono::steady_clock::now();

			// 检查超时连接, 清除超时的连接.
			if (m_identity == Identity::avpn_server)
			{
				check_tunnel(now);

				int64_t urate = 0;
				int64_t drate = 0;

				auto& tab = m_clients.table();
				for (auto& c : tab)
				{
					auto client = c.tunnel_.lock();
					if (!client)
						continue;

					urate += client->upload_rate();
					drate += client->download_rate();
				}

				m_upload_speed = urate;
				m_down_speed = drate;
			}

			if (m_identity == Identity::avpn_client)
			{
				check_client_reset();

				if (!m_server_tcp_endps.empty())
					check_client_tcp();

				if (!m_server_udp_endps.empty())
					check_client_udp();

				auto tunnel = m_tunnel.lock();
				if (!tunnel)
					continue;

				m_upload_speed = tunnel->upload_rate();
				m_down_speed = tunnel->download_rate();
			}
		}

		LOG_WARN << "Quit avpn_service::tick "
			<< std::this_thread::get_id();
		co_return;
	}

	net::awaitable<void>
	avpn_service::setup_tun(const net::ip::network_v4 & net)
	{
		// 设置定时等待.
		m_tun_wait_timer.expires_from_now(std::chrono::seconds(1));

		// 先关闭设备.
		m_tundev.close();

		auto mask = net.netmask();
		auto addr = net.address();
		auto ipaddr = addr.to_string();

		uint32_t gw = (addr.to_uint() & mask.to_uint()) + 1;
		auto gateway = net::ip::make_address_v4(gw);

		LOG_DBG << "setup_tun ip: " << ipaddr
			<< ", mask: " << mask.to_string()
			<< ", gateway: " << gateway.to_string()
			<< ", tun: " << m_config.ifdev_;

		// 构造配置参数.
		avpn::dev_config dc = { ipaddr, mask.to_string(),
			gateway.to_string(), "", "", "", 0 };
		dc.dev_name_ = m_config.ifdev_;
		auto dev_list = m_tundev.take_device_list();
		std::string guid;
		for (auto& i : dev_list)
		{
			if (i.name_ == dc.dev_name_)
			{
				dc.guid_ = i.guid_;
				break;
			}
		}
#ifdef WIN32
		// 如果指定的tap设备有问题, 则默认选择第一个网卡.
		if (dc.guid_.empty() && !dev_list.empty())
		{
			LOG_INFO << "Not found tun: " << dc.dev_name_
				<< ", use default: " << dev_list[0].name_;
			dc.dev_name_ = dev_list[0].name_;
			dc.guid_ = dev_list[0].guid_;
		}
#endif // WIN32

		auto defgw = get_default_gateway();
		auto defgw_string = defgw->address().to_string();

		if (!m_tundev.open(dc))
		{
			LOG_ERR << "Open tun device: " << dc.dev_name_ << " fail!";
			co_return;
		}

		auto& params = m_config.tunnel_params_;

		// 根据server的推送信息配置网络.
		if (!params.ignore_push_ &&
			(m_push_params.passbyvpn_ &&
			m_config.identity_ == Identity::avpn_client))
		{
			auto vgateway = gateway.to_string();

			del_route("0.0.0.0/0 " + vgateway);

			if (set_default_route(ipaddr,
				vgateway,
				defgw_string,
				m_push_params.server_ip_))
				LOG_DBG << "Default gateway: "
					<< defgw_string << " change successfully!";
			else
				LOG_INFO << "Default gateway: "
					<< defgw_string << ", change faild!";
		}

		if (!params.ignore_push_)
		{
			for (auto& route : m_push_params.pushroutes_)
			{
				auto [ret, ok] = add_route(route);
				if (ok)
					LOG_DBG << "Add route: " << route
						<< " route added successfully!";
				else
					LOG_ERR << "Add route: " << route
						<< " route added fail, reason: "
						<< boost::trim_copy(ret);
			}
		}

		if (!params.ignore_push_ &&
			(m_push_params.pushdns_ != 0 &&
			m_config.identity_ == Identity::avpn_client))
		{
			auto dns = net::ip::address_v4(m_push_params.pushdns_).to_string();
			if (set_dns(dns, ipaddr))
				LOG_DBG << "Set dns: " << dns << " successfully";
		}

		// 等待1s后, 再开始循环读取tun设备.
		boost::system::error_code ec;
		co_await m_tun_wait_timer.async_wait(uawaitable[ec]);
		if (ec)
			LOG_INFO << "Tun read loop exited";
		else
			LOG_INFO << "Tun read loop starting";

		// 开始读取tun上的数据包.
		auto self = shared_from_this();
		net::co_spawn(m_main_context,
			[this, self]() mutable -> net::awaitable<void>
			{
				m_client_reset_flag &= ~vpn_tun_loop_exit;
				co_await start_tun_read_loop();
				m_client_reset_flag |= vpn_tun_loop_exit;

				co_return;
			}, net::detached);

		co_return;
	}

	ip_assign_type avpn_service::ip_assigner()
	{
		std::string ip_string;
		uint32_t ipaddr;

		const auto prefix = m_subnet.prefix_length();

		do {
			if (m_ip_iterator == m_ip_assigner.begin())
				m_ip_iterator++;
			if (m_ip_iterator == m_ip_assigner.end())
				m_ip_iterator = m_ip_assigner.begin();

			auto ip = *m_ip_iterator++;
			ipaddr = ip.to_uint();

			uint32_t tail = (ipaddr & ((1 << prefix) - 1)) % 256;
			if (tail == 255 || tail == 0)
			{
				continue;
			}
			else
			{
				ip_string = ip.to_string();
				break;
			}
		} while (true);

		ip_assign_type ret{ ip_string, ipaddr };

		return ret;
	}

	bool avpn_service::init_acceptors()
	{
		auto& tcp_listens = m_config.tcp_listens_;

		if (tcp_listens.empty())
		{
			LOG_ERR << "Tcp listen is empty!";
			return false;
		}

		boost::system::error_code ec;

		for (const auto& listen : tcp_listens)
		{
			tcp::endpoint endp;
			bool ipv6only = make_listen_endpoint(listen, endp, ec);
			if (ec)
			{
				LOG_ERR << "TCP server listen error: " << listen
					<< ", ec: " << ec.message();
				return false;
			}

			tcp::acceptor a{ m_ioc_pool.get_io_context() };

			a.open(endp.protocol(), ec);
			if (ec)
			{
				LOG_ERR << "TCP server open "
					<< "accept error: " << ec.message();
				return false;
			}

			a.set_option(net::socket_base::reuse_address(true), ec);
			if (ec)
			{
				LOG_ERR << "TCP server accept "
					<< "set option failed: " << ec.message();
				return false;
			}

			if (ipv6only)
			{
				a.set_option(net::ip::v6_only(true), ec);
				if (ec)
				{
					LOG_ERR << "TCP server accept "
						<< "set v6_only failed: " << ec.message();
					return false;
				}
			}

			a.bind(endp, ec);
			if (ec)
			{
				LOG_ERR << "TCP server bind failed: " << ec.message()
					<< ", address: " << endp.address().to_string()
					<< ", port: " << endp.port();
				return false;
			}

			a.listen(net::socket_base::max_listen_connections, ec);
			if (ec)
			{
				LOG_ERR << "TCP server listen failed: " << ec.message();
				return false;
			}

			m_tcp_acceptors.emplace_back(std::move(a));
		}

		return true;
	}

	net::awaitable<void> avpn_service::make_endpoint(std::string protocol)
	{
		boost::system::error_code ec;

		auto& upstreams = m_config.upstreams_;
		for (auto it = upstreams.begin(); !m_abort
			&& it != upstreams.end(); it++)
		{
			auto upstream = *it;
			urls::url_view parser;

			if (!parser.parse(upstream))
				continue;

			auto scheme = std::string(parser.scheme());
			boost::to_lower(scheme);

			if (scheme != protocol)
				continue;

			if (protocol == "udp")
			{
				udp::resolver resolver{ m_main_context };
				auto const results = co_await resolver.async_resolve(
					std::string(parser.host()),
					std::string(parser.port()),
					uawaitable[ec]);
				if (ec)
				{
					LOG_ERR << "make_endpoint"
						<< ", udp async_resolve: " << ec.message();
					continue;
				}

				m_server_udp_endps.clear();
				for (auto& endp : results)
					m_server_udp_endps.emplace_back(endp.endpoint());
			}
			else
			{
				tcp::resolver resolver{ m_main_context };
				auto const results = co_await resolver.async_resolve(
					std::string(parser.host()),
					std::string(parser.port()),
					uawaitable[ec]);
				if (ec)
				{
					LOG_ERR << "make_endpoint"
						<< ", tcp async_resolve: " << ec.message();
					continue;
				}

				m_server_tcp_endps.clear();
				for (auto& endp : results)
					m_server_tcp_endps.emplace_back(endp.endpoint());
			}
		}

		co_return;
	}

	net::awaitable<void> avpn_service::start_tcp_listen(tcp::acceptor& a)
	{
		boost::system::error_code error;
		[[maybe_unused]] auto self = shared_from_this();

		while (!m_abort)
		{
			tcp::socket socket(m_ioc_pool.get_io_context());
			co_await a.async_accept(socket, uawaitable[error]);
			if (error)
			{
				LOG_ERR << "start_tcp_listen"
					<< ", async_accept: " << error.message();

				if (error == net::error::operation_aborted ||
					error == net::error::bad_descriptor)
				{
					co_return;
				}

				if (!a.is_open())
					co_return;

				continue;
			}

			{
				net::socket_base::keep_alive option(true);
				socket.set_option(option, error);
			}

			{
				net::ip::tcp::no_delay option(true);
				socket.set_option(option);
			}

			static std::atomic_size_t id{ 1 };
			size_t connection_id = id++;

			LOG_DBG << "start_tcp_listen, incoming id: " << connection_id;

			// 等待读取事件.
			co_await socket.async_wait(
				tcp::socket::wait_read, uawaitable[error]);
			if (error)
			{
				LOG_WARN << "socket.async_wait error: " << error.message();
				continue;
			}

			// 检查协议.
			auto fd = socket.native_handle();
			uint8_t detect[5] = { 0 };

#if defined(WIN32) || defined(__APPLE__)
			auto ret = recv(fd, (char*)detect, sizeof(detect),
				MSG_PEEK);
#else
			auto ret = recv(fd, (void*)detect, sizeof(detect),
				MSG_PEEK | MSG_NOSIGNAL | MSG_DONTWAIT);
#endif
			if (ret <= 0)
			{
				LOG_WARN << "start_tcp_listen, peek message return: " << ret;
				continue;
			}

			// socks4/5 protocol.
			if (detect[0] == 0x05 || detect[0] == 0x04)
			{
				LOG_DBG << "socks protocol: " << detect[0]
					<< ", connection id: " << connection_id;

				socks_session_ptr new_session =
					std::make_shared<socks::socks_session>(
						instantiate_socks_stream(std::move(socket)),
						connection_id,
						self);

				m_socks_clients[connection_id] = new_session;
				new_session->start();

				continue;
			}
			else if (detect[0] == 0x16) // socks5 with ssl protocol.
			{
				LOG_DBG << "https protocol: " << detect[0]
					<< ", connection id: " << connection_id;

				// instantiate socks stream with ssl context.
				auto ssl_socks_stream = instantiate_socks_stream(
					std::move(socket), m_ssl_ctx);

				// get origin ssl stream type.
				ssl_stream& ssl_socket =
					boost::variant2::get<ssl_stream>(ssl_socks_stream);

				// do async handshake.
				co_await ssl_socket.async_handshake(
					net::ssl::stream_base::server, uawaitable[error]);
				if (error)
				{
					LOG_WARN << "ssl protocol handshake error: "
						<< error.message();
					continue;
				}

				// make socks session shared ptr.
				socks_session_ptr new_session =
					std::make_shared<socks::socks_session>(
						std::move(ssl_socks_stream),
						connection_id,
						self);

				// save and start.
				m_socks_clients[connection_id] = new_session;
				new_session->start();

				continue;
			}
			else if (detect[0] == 0x47 || detect[0] == 0x50) // http protocol.
			{
				LOG_DBG << "http protocol: " << detect[0]
					<< ", connection id: " << connection_id;

				// instantiate socks stream with socket.
				auto ssl_socks_stream = instantiate_socks_stream(
					std::move(socket));

				// make socks session shared ptr.
				socks_session_ptr new_session =
					std::make_shared<socks::socks_session>(
						std::move(ssl_socks_stream),
						connection_id,
						self);

				// save and start.
				m_socks_clients[connection_id] = new_session;
				new_session->start();

				continue;
			}

			// tun2socks protocol.
			if ((detect[0] & 0x3f) == vpt_tun2socks &&
				(detect[0] & 0x40) == 0)
			{
				// tun2socks protocol 协议处理.
				continue;
			}

			// 新连接, server先读取client的认证请求, 如果client未认
			// 证, 则会发出认证请求, 如果是已认证过只是断开重连, 发送
			// 认证重连消息server会根据重连信息中的src虚拟ip找到对应
			// 的client, 并使用这个client解密重连认证信息, 解密成功
			// 则将此tcp替换client中的原tcp连接, 解密失败, 则回复认
			// 证失败消息, 以快速触发client进行完整重新协商认证过程
			// (或者server端沉默, 等client直到超时重新协商通信key).
			net::co_spawn(m_main_context,
				[this, self, socket = std::move(socket), connection_id]
				() mutable -> net::awaitable<void>
				{
					co_await on_tcp_handshake(std::move(socket), connection_id);
					co_return;
				}, net::detached);
		}

		LOG_WARN << "start_tcp_listen exit ...";
		co_return;
	}

	net::awaitable<void> avpn_service::start_udp_server()
	{
		BOOST_ASSERT(m_identity == Identity::avpn_server);

		boost::system::error_code ec;

		auto& listens = m_config.udp_listens_;
		for (auto& listen : listens)
		{
			udp::endpoint endp;
			bool ipv6only = make_listen_endpoint(listen, endp, ec);
			if (ec)
			{
				LOG_ERR << "start_udp_server"
					<< ", make udp: " << listen
					<< ", ec: " << ec.message();
				continue;
			}

			udp::socket sock(m_main_context, endp.protocol());
			if (ipv6only)
			{
				sock.set_option(net::ip::v6_only(true), ec);
				if (ec)
				{
					LOG_ERR << "start_udp_server"
						<< ", make udp: " << listen
						<< ", setsockopt v6only: " << ec.message();
					continue;
				}
			}

			sock.bind(endp, ec);
			if (ec)
			{
				LOG_ERR << "start_udp_server"
					<< ", make udp: " << listen
					<< ", bind error: " << ec.message();
				continue;
			}

			auto sockptr = std::make_shared<udp_socket>(
				udp_socket{ steady_clock::now(), std::move(sock) });
			m_udp_sockets.emplace_back(std::move(sockptr));
		}

		auto tmp_sockets = m_udp_sockets;
		for (int fast = 0; fast < 8; fast++)
		{
			for (int n = 0; n < (int)tmp_sockets.size(); n++)
			{
				auto socket_ptr = tmp_sockets[n];
				auto local_endp = socket_ptr->sock_.local_endpoint();

				LOG_DBG << "start_udp_server"
					<< ", listen endpoint: ["
					<< local_endp.address().to_string()
					<< "]:"
					<< local_endp.port();

				net::co_spawn(m_ioc_pool.get_io_context(),
					start_udp_read_loop(n), net::detached);
			}
		}

		co_return;
	}

	net::awaitable<void> avpn_service::start_tcp_client()
	{
		auto self = shared_from_this();
		boost::system::error_code ec;

		// scoped_exit用于退出此函数时将自动重试tcp连接.
		scoped_exit se([&]() mutable
			{
				if (m_server_tcp_endps.empty())
					return;

				LOG_WARN << "Set tcp reconnect";
				m_client_tcp_cnt = 1;
			});

		tcp::socket stream(m_main_context);
		auto ret = co_await connect_server(stream);
		if (!ret)
			co_return;

		auto& params = m_config.tunnel_params_;

		crypto_util::keyexchange ke(m_client_key);
		auto pubkey = ke.StaticPublicKey();
		auto src_vaddr = m_subnet.address().to_uint();

		auto pkt = make_handshake(src_vaddr, m_client_id, pubkey,
			(uint8_t)params.data_shards_, (uint8_t)params.parity_shards_);

		// 发送handshake到server.
		co_await tcp_write_packet(stream, pkt, 0);

		// 就地等待server回复.
		auto bytes = co_await tcp_read_packet(stream, pkt, 0);
		if (bytes == -1)
			co_return;

		// 解析handshake_reply消息.
		std::string id;
		uint8_t ds;
		uint8_t ps;
		uint8_t prefix_length;

		auto& passbyvpn = m_push_params.passbyvpn_;
		auto& pushdns = m_push_params.pushdns_;
		auto& pushroutes = m_push_params.pushroutes_;
		auto remote = stream.remote_endpoint(ec);
		m_push_params.server_ip_ = remote.address().to_string();

		bytes = unwrap_handshake_reply(pkt, id, ds, ps,
			src_vaddr, prefix_length, passbyvpn, pushdns, pushroutes);

		auto tunnel = m_tunnel.lock();
		if (src_vaddr == 0)
		{
			LOG_WARN << "tcp handshake reply: '" << id
				<< "' detected server reboot!";

			// 如果tunnel对象为空, 则表示重启已经开始.
			if (!tunnel)
				co_return;

			if (m_client_reset_flag & vpn_restart)
				co_return;

			// 设置为vpn_restart, 表示重启过程开始.
			m_client_reset_flag |= vpn_restart;

			// 关闭已创建的隧道.
			tunnel->close_tunnel();
			stream.close(ec);

			// 取消重连.
			se.cancel();

			// 关闭tun设备.
			m_tundev.close();

			// 重置tunnel对象.
			m_tunnel = {};

			co_return;
		}
		if (bytes < 0)
		{
			LOG_WARN << "unwrap_handshake_reply detected invalid!";
			co_return;
		}

		// 判断client的tunnel对象是否创建, 如果已经创建, 则表示已经
		// 握手成功.
		if (!tunnel)
		{
			auto server_pubkey = base64_decode(m_config.passphrase_);

			// 创建tunnel对象, 在完成握手后, 进入tunnel的tcp loop中
			// 循环处理tcp消息.
			tunnel = vpn_tunnel::make(m_main_context,
				self, m_config, server_pubkey, m_client_key);
			m_tunnel = tunnel;

			if (!m_server_udp_endps.empty())
			{
				tunnel->remote_endpoint(m_server_udp_endps.front());
				tunnel->ipproto(Proto::avpn_udp);
			}

			LOG_DBG << "Handshake by tcp, make tunnel: " << tunnel.get()
				<< ", thread: " << std::this_thread::get_id()
				<< ", cid: " << m_client_id;
			LOG_DBG << "Negotiated shared key: "
				<< base64_encode(tunnel->shared_key());

			m_subnet = make_network(src_vaddr, (unsigned short)prefix_length);
			tunnel->vnet_addr(m_subnet);
			tunnel->client_id(m_client_id);

			co_await setup_tun(m_subnet);
		}

		LOG_DBG << "Tcp connected to "<< remote << " successfully!";

		// 成功握手, 重置标志清0.
		m_client_reset_flag &= ~vpn_restart;
		m_client_reset_flag &= ~vpn_restart_busy;

		// 成功连接, 取消重连.
		se.cancel();

		// 替换为新的tcp socket对象.
		tunnel->tcp_socket(std::move(stream), 0);

		// 设置ipproto.
		tunnel->ipproto(Proto::avpn_tcp);

		// 启动tunnel.
		tunnel->start_tunnel(ds, ps);

		// 开始tunnel的tcp读取消息循环.
		net::co_spawn(m_main_context,
			[this, self, tunnel]() mutable -> net::awaitable<void>
			{
				co_await start_tunnel_tcp(tunnel);
				co_return;
			}, net::detached);

		co_return;
	}

	net::awaitable<bool> avpn_service::connect_server(tcp::socket& stream)
	{
		auto executor = co_await net::this_coro::executor;
		boost::system::error_code ec;

		while (!(m_client_reset_flag & vpn_tcp_loop_exit) && !m_abort)
		{
			asio_timer t(executor);
			t.expires_from_now(std::chrono::milliseconds(16));
			co_await t.async_wait(uawaitable[ec]);
		}

		// make tcp endpoints.
		co_await make_endpoint("tcp");

		// start async connect to server.
		for (auto it = m_server_tcp_endps.begin();
			it != m_server_tcp_endps.end() && !m_abort; it++)
		{
			const auto& endp = *it;

			stream.close(ec);
			co_await stream.async_connect(endp,
				net::redirect_error(
					net::bind_cancellation_slot(
						m_cancel_sig.slot(), net::use_awaitable), ec));
			m_cancel_sig.slot().clear();
			if (m_abort)
			{
				LOG_ERR << "connect_server, async_connect abort";
				co_return false;
			}
			if (ec)
			{
				LOG_ERR << "connect_server, async_connect: " << ec.message();
				if (ec == boost::asio::error::operation_aborted)
					break;
				continue;
			}

			net::ip::tcp::no_delay option(true);
			stream.set_option(option, ec);
			if (!ec)
				co_return true;
		}

		co_return false;
	}

	net::awaitable<void> avpn_service::start_udp_client()
	{
		// 只有在第1次启动client时创建好所有udp socket对象.
		if (m_start_udp == 0)
		{
			m_start_udp = 1;
			co_await make_udp_client();
		}

		// 发起UDP握手请求.
		co_await start_udp_handshake();
		co_return;
	}

	net::awaitable<void> avpn_service::make_udp_client()
	{
		boost::system::error_code ec;

		// 关闭清除原来的udp socket.
		for (auto& socket_ptr : m_udp_sockets)
		{
			if (!socket_ptr)
				continue;
			if (!socket_ptr->sock_.is_open())
				continue;

			socket_ptr->sock_.close(ec);
		}

		m_udp_sockets.clear();

		// 创建udp socket, 使用随机端口, 创建4倍个数的udp socket用于
		// 与vpn服务端通信以提高收发效率.
		const static int max_client_udp_socket = 4;
		auto size = m_server_udp_endps.size() * max_client_udp_socket;
		for (size_t i = 0; i < size; i++)
		{
			auto& endp = m_server_udp_endps[i % m_server_udp_endps.size()];

			udp::socket sock(m_main_context,
				udp::endpoint(endp.protocol(), 0));

			[[maybe_unused]] auto local_endp = sock.local_endpoint(ec);
			if (ec)
			{
				LOG_ERR << "start_udp_client"
					<< ", udp open error: " << ec.message();
				continue;
			}

			auto address_string = local_endp.address().to_string();
			LOG_DBG << "start_udp_client"
				<< ", create udp socket: [" << address_string
				<< "]:" << local_endp.port();

			auto socket_ptr = std::make_shared<udp_socket>(
				udp_socket{ steady_clock::now(), std::move(sock) });
			m_udp_sockets.emplace_back(std::move(socket_ptr));
		}

		auto self = shared_from_this();
		auto tmp_sockets = m_udp_sockets;
		for (int fast = 0; fast < 8; fast++)
		{
			for (int n = 0; n < (int)tmp_sockets.size(); n++)
			{
				auto socket_ptr = tmp_sockets[n];
				net::co_spawn(m_ioc_pool.get_io_context(),
					[this, self, n]() mutable -> net::awaitable<void>
					{
						co_await start_udp_read_loop(n);
						co_return;
					}, net::detached);
			}
		}

		co_return;
	}

	net::awaitable<void> avpn_service::start_udp_handshake()
	{
		// 发起UDP握手请求.
		auto& params = m_config.tunnel_params_;
		auto src_vaddr = m_subnet.address().to_uint();

		crypto_util::keyexchange ke(m_client_key);
		auto pubkey = ke.StaticPublicKey();

		auto pkt = make_handshake(src_vaddr, m_client_id, pubkey,
			(uint8_t)params.data_shards_, (uint8_t)params.parity_shards_);

		auto ptr = std::make_shared<vpn_packet>(std::move(pkt));

		// 发送udp握手包.
		for (auto endp : m_server_udp_endps)
			do_udp_write(ptr, endp);

		co_return;
	}

	net::awaitable<void> avpn_service::on_tcp_handshake(
		tcp::socket stream, size_t id)
	{
		vpn_packet pkt;

		int ret = co_await tcp_read_packet(stream, pkt, id);
		if (ret == -1)
			co_return;

		auto& params = m_config.tunnel_params_;

		uint32_t src_vaddr = 0;
		std::string client_id;
		std::string pubkey;
		std::string additional;
		uint8_t ds;
		uint8_t ps;

		ret = unwrap_handshake(pkt,
			src_vaddr, client_id, pubkey,
			ds, ps);
		if (ret == -1)
			co_return;

		auto remote = stream.remote_endpoint();

		// client id长度必须等于32字节.
		if (client_id.size() != 32)
		{
			LOG_INFO << "invalid handshake message: " << client_id
				<< " from tcp: " << remote;
			co_return;
		}

		vpn_tunnel_ptr tunnel;
		if (src_vaddr != 0)
		{
			tunnel = lookup_tunnel(src_vaddr);
			if (!tunnel)
			{
				net::ip::address_v4 src_addr(src_vaddr);
				LOG_WARN << "Not found client via tcp: " << src_addr.to_string();

				// 找不到连接, 说明src已经过期, 回复认证失败.

				// 规定 src为0 则表示认证失败.
				// 规定client id原样返回.
				auto response = make_handshake_reply(
					client_id, 0, 0, 0, 0, false, 0, {});
				co_await tcp_write_packet(stream, response, id);
				co_return;
			}
		}
		else
		{
			// 连接认证请求, 查询是否存在client id, 如果存在, 则使用
			// 存在的请求, 并回复认证信息.
			tunnel = co_await async_make_tunnel(client_id, pubkey);
			BOOST_ASSERT(tunnel && "tunnel must be valid");
			if (!tunnel)
			{
				LOG_ERR << "async make tunnel fail!!!";
				co_return;
			}
		}

		// 获取tunnel的虚拟ip.
		auto vnetaddr = tunnel->vnet_addr();
		uint32_t vaddr = vnetaddr.address().to_uint();

		// 输出协商的加密密钥到日志.
		LOG_DBG << "Negotiated shared key via tcp: "
			<< base64_encode(tunnel->shared_key())
			<< ", ip: " << vaddr
			<< ", remote: " << remote;

		// 回复认证消息.
		auto response = make_handshake_reply(
			client_id,
			(uint8_t)params.data_shards_,
			(uint8_t)params.parity_shards_,
			vaddr,
			(uint8_t)m_subnet.prefix_length(),
			params.passbyvpn_,
			params.pushdns_,
			params.pushroutes_);
		co_await tcp_write_packet(stream, response, id);

		// 替换为新的tcp socket, 然后用新的tcp socket 用于tcp通信.
		tunnel->tcp_socket(std::move(stream), id);
		tunnel->ipproto(Proto::avpn_tcp);
		tunnel->start_tunnel(ds, ps);

		// 开始tunnel的tcp读取消息循环.
		net::co_spawn(m_main_context,
			[this, tunnel]() mutable -> net::awaitable<void>
			{
				co_await start_tunnel_tcp(tunnel);
				co_return;
			}, net::detached);

		co_return;
	}

	net::awaitable<void>
	avpn_service::on_udp_handshake(
		udp::endpoint remote, vpn_packet pkt, uint32_t src_vaddr)
	{
		uint8_t ds;
		uint8_t ps;
		std::string pubkey;
		std::string client_id;
		auto& params = m_config.tunnel_params_;

		// 解析client的认证消息.
		int ret = unwrap_handshake(pkt,
			src_vaddr, client_id, pubkey, ds, ps);
		if (ret == -1)
			co_return;

		// client id长度必须等于32字节.
		if (client_id.size() != 32)
		{
			LOG_INFO << "invalid handshake message: " << client_id
				<< " from: " << remote;
			co_return;
		}

		vpn_tunnel_ptr tunnel;
		if (src_vaddr != 0)
		{
			tunnel = lookup_tunnel(src_vaddr);
			if (!tunnel)
			{
				net::ip::address_v4 src_addr(src_vaddr);
				LOG_WARN << "Not found client via udp: "
					<< src_addr.to_string();

				// 找不到连接, 说明src已经过期, 回复认证失败.

				// 规定 src为0 则表示认证失败.
				// 规定client id原样返回.
				auto response = make_handshake_reply(
					client_id, 0, 0, 0, 0, false, 0, {});
				auto ptr = std::make_shared<vpn_packet>(std::move(response));
				co_await udp_write(ptr, remote);
				co_return;
			}
		}
		else
		{
			// 连接认证请求, 查询是否存在client id, 如果存在, 则使
			// 用存在的请求, 并回复认证信息.
			tunnel = co_await async_make_tunnel(client_id, pubkey);
			BOOST_ASSERT(tunnel && "tunnel must be valid");
		}

		// 获取tunnel的虚拟ip.
		auto vnetaddr = tunnel->vnet_addr();
		auto vaddr = vnetaddr.address().to_uint();

		// 输出协商的加密密钥到日志.
		LOG_DBG << "Negotiated shared key via udp: "
			<< base64_encode(tunnel->shared_key())
			<< ", ip: " << vaddr
			<< ", remote: " << remote;

		// 回复认证消息.
		auto response = make_handshake_reply(
			client_id,
			(uint8_t)params.data_shards_,
			(uint8_t)params.parity_shards_,
			vaddr,
			(uint8_t)m_subnet.prefix_length(),
			params.passbyvpn_,
			params.pushdns_,
			params.pushroutes_);
		auto ptr = std::make_shared<vpn_packet>(std::move(response));
		co_await udp_write(ptr, remote);

		// 更新tunnel的远端udp的endpoint.
		tunnel->remote_endpoint(remote);
		tunnel->ipproto(Proto::avpn_udp);
		tunnel->start_tunnel(ds, ps);

		co_return;
	}

	net::awaitable<void> avpn_service::on_udp_handshake_reply(
		udp::endpoint remote, vpn_packet pkt)
	{
		auto self = shared_from_this();

		// 解析handshake_reply消息.
		std::string id;
		uint8_t ds;
		uint8_t ps;
		uint32_t addr;
		uint8_t prefix_length;

		auto& passbyvpn = m_push_params.passbyvpn_;
		auto& pushdns = m_push_params.pushdns_;
		auto& pushroutes = m_push_params.pushroutes_;
		m_push_params.server_ip_ = remote.address().to_string();

		auto bytes = unwrap_handshake_reply(pkt, id, ds, ps,
			addr, prefix_length, passbyvpn, pushdns, pushroutes);
		if (bytes < 0)
		{
			LOG_WARN << "udp handshake reply detected invalid!";
			co_return;
		}

		vpn_tunnel_ptr tunnel = m_tunnel.lock();
		if (addr == 0)
		{
			LOG_WARN << "udp handshake reply: '" << id
				<< "' detected server reboot!";

			// 如果tunnel指针为空, 则表示重启已经开始, 在这个消息之
			// 前, tunnel指针已经被清了.
			if (!tunnel)
				co_return;

			if (m_client_reset_flag & vpn_restart)
				co_return;

			// 设置为vpn_restart, 表示重启过程开始.
			m_client_reset_flag |= vpn_restart;

			// 关闭已创建的隧道.
			tunnel->close_tunnel();

			// 关闭tun设备.
			m_tundev.close();

			// 重置tunnel对象.
			m_tunnel = {};

			co_return;
		}

		// 判断client的tunnel对象是否创建, 如果已经创建, 则表示已经握
		// 手成功, 如果未创建, 则创建tunnel对象.
		if (!tunnel)
		{
			auto server_pubkey = base64_decode(m_config.passphrase_);

			// 创建tunnel对象, 在完成握手后, 进入tunnel的tcp loop中循
			// 环处理tcp消息.
			tunnel = vpn_tunnel::make(m_main_context,
				self, m_config, server_pubkey, m_client_key);
			BOOST_ASSERT(tunnel);
			m_tunnel = tunnel;
			tunnel->remote_endpoint(remote);

			LOG_DBG << "Handshake by udp, make tunnel: " << tunnel.get()
				<< ", thread: " << std::this_thread::get_id()
				<< ", cid: " << m_client_id;

			LOG_DBG << "Negotiated shared key via udp: "
				<< base64_encode(tunnel->shared_key());

			m_subnet = make_network(addr, (unsigned short)prefix_length);
			tunnel->vnet_addr(m_subnet);
			tunnel->client_id(m_client_id);

			co_await setup_tun(m_subnet);
		}

		// 成功握手, 重置标志清0.
		m_client_reset_flag &= ~vpn_restart;
		m_client_reset_flag &= ~vpn_restart_busy;

		// 更新tunnel的远端udp的endpoint.
		tunnel->ipproto(Proto::avpn_udp);
		tunnel->remote_endpoint(remote);
		tunnel->start_tunnel(ds, ps);

		co_return;
	}

	net::awaitable<int> avpn_service::tcp_read_packet(
		tcp::socket& stream, vpn_packet& pkt, size_t id)
	{
		boost::system::error_code ec;
		int start_len_tag = -1;

		// 先读取4个字节的头.
		co_await net::async_read(stream,
			net::buffer((void*)&start_len_tag, 4),
				net::transfer_exactly(4), uawaitable[ec]);
		if (ec)
		{
			LOG_ERR << "tcp_read_packet, id: "
				<< id << ", read tag error: " << ec.message();
			co_return -1;
		}

		{
			start_len_tag = ntohl(start_len_tag);
			if ((uint32_t)start_len_tag > (uint32_t)avpn_static_mtu)
			{
				LOG_ERR << "tcp_read_packet, id: "
					<< id << ", verify size fail: " << start_len_tag;
				co_return -1;
			}
		}

		// 读取body本身.
		co_await net::async_read(stream,
			net::buffer(pkt.data(), start_len_tag),
				net::transfer_exactly(start_len_tag), uawaitable[ec]);
		if (ec)
		{
			LOG_ERR << "tcp_read_packet, id: "
				<< id << ", read body error: " << ec.message();
			co_return -1;
		}

		pkt.resize(start_len_tag);

		co_return start_len_tag;
	}

	net::awaitable<void>
	avpn_service::tcp_write_packet(tcp::socket& stream,
		vpn_packet& pkt, size_t id)
	{
		boost::system::error_code ec;
		uint32_t start_len_tag = htonl((uint32_t)pkt.size());

		co_await net::async_write(stream,
			net::buffer(&start_len_tag, 4), uawaitable[ec]);
		if (ec)
		{
			LOG_ERR << "tcp_write_packet, id: " << id
				<< " async_write tag error: " << ec.message();
			co_return;
		}

		co_await net::async_write(stream,
			net::buffer(pkt.data(), pkt.size()), uawaitable[ec]);
		if (ec)
		{
			LOG_ERR << "tcp_write_packet, id: " << id
				<< " async_write body error: " << ec.message();
			co_return;
		}

		co_return;
	}

	vpn_tunnel_ptr avpn_service::lookup_tunnel(uint32_t vaddr)
	{
		vpn_tunnel_ptr vp;

		auto vc = m_clients.lookup_by_addr(vaddr);
		return vc.tunnel_.lock();
	}

	vpn_tunnel_ptr avpn_service::lookup_tunnel(std::string id)
	{
		auto vc = m_clients.lookup_by_id(id);
		return vc.tunnel_.lock();
	}

	net::awaitable<vpn_tunnel_ptr>
	avpn_service::async_lookup_tunnel(uint32_t vaddr)
	{
		co_return lookup_tunnel(vaddr);
	}

	net::awaitable<vpn_tunnel_ptr>
	avpn_service::async_lookup_tunnel(std::string id)
	{
		co_return lookup_tunnel(id);
	}

	net::awaitable<avpn::vpn_tunnel_ptr>
	avpn_service::async_make_tunnel(std::string id, std::string pubkey)
	{
		// 查找存在的tunnel.
		auto tunnel = lookup_tunnel(id);
		if (tunnel)
			co_return tunnel;

		// 分配一个虚拟ip.
		auto [ip_string, vaddr] = ip_assigner();

		// 创建tunnel.
		tunnel = make_tunnel(vaddr, id, pubkey);

		// 输出创建tunnel相关日志.
		LOG_DBG << "make tunnel: " << tunnel.get()
			<< ", thread: " << std::this_thread::get_id()
			<< ", cid: " << id
			<< ", assign: " << ip_string;

		co_return tunnel;
	}

	vpn_tunnel_ptr avpn_service::make_tunnel(
		uint32_t vaddr, std::string id, std::string pubkey)
	{
		auto self = shared_from_this();

		auto& ioc = m_ioc_pool.get_io_context();
		auto tunnel = vpn_tunnel::make(ioc, self, m_config,
			pubkey, m_config.passphrase_);

		auto ipaddr = net::ip::address_v4(vaddr);
		auto vnetaddr = net::ip::make_network_v4(
			ipaddr, m_subnet.prefix_length());

		// 设置tunnel的vnet addr.
		tunnel->vnet_addr(vnetaddr);
		// 设置tunnel的client id.
		tunnel->client_id(id);

		vpn_client vc;

		vc.id_ = id;
		vc.vnet_addr_ = vaddr;
		vc.tunnel_ = tunnel;

		m_clients.make(vc);

		return tunnel;
	}

	net::awaitable<void> avpn_service::start_tunnel_tcp(vpn_tunnel_ptr tunnel)
	{
		auto self = shared_from_this();

		auto executor = tunnel->get_executor();
		net::co_spawn(executor,
			[this, self, tunnel]() mutable -> net::awaitable<void>
			{
				m_client_reset_flag &= ~vpn_tcp_loop_exit;
				co_await tunnel->tcp_loop();
				m_client_reset_flag |= vpn_tcp_loop_exit;
				co_return;
			}, net::detached);

		co_return;
	}

	void avpn_service::reset_tcp_cnt(int cnt)
	{
		LOG_WARN << "Reset tcp reconnect";
		m_client_tcp_cnt = cnt;
	}

}

