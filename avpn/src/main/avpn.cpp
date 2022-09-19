//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#include "utils/async_connect.hpp"
#include "utils/url_view.hpp"
#include "utils/scoped_exit.hpp"
#include "utils/asio_util.hpp"
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

#include <boost/stacktrace.hpp>



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
		, m_client_key(
			config.private_key_.empty()
			? base64_encode(crypto_util::ecdh_keygen())
			: config.private_key_)
		, m_tundev(instantiate_vtun_device(
			config.ifdev_ == "wintun" ? 1 : 0, m_main_context))
		, m_tick_timer(m_main_context)
		, m_tun_wait_timer(m_main_context)
		, m_subnet(make_network_v4(config.tunnel_params_.subnet_))
		, m_ip_assigner(m_subnet.hosts())
		, m_ip_iterator(++m_ip_assigner.begin())
	{
		m_main_thread_id = std::this_thread::get_id();
		net::post(m_main_context, [this]() mutable
			{
				auto id = std::this_thread::get_id();
				// BOOST_ASSERT(m_main_thread_id == id);
				m_main_thread_id = id;
			});
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

	void avpn_service::remove_socks_client(size_t id)
	{
		m_socks_clients.erase(id);
	}

	const socks::socks_server_option& avpn_service::option()
	{
		return m_config.socks_opt_;
	}

	void avpn_service::start()
	{
		LOG_DBG << "avpn_service::start, main thread id: "
			<< std::this_thread::get_id();

		m_abort = false;
		m_client_state = vst_starting;
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

		{
			std::lock_guard lock(m_udp_sockets);
			for (auto& socket_ptr : m_udp_sockets)
			{
				if (!socket_ptr) continue;

				auto& udp_socket = *socket_ptr;
				udp_socket.sock_.close(ignore_ec);
			}
			m_udp_sockets.clear();
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

	void avpn_service::remove_tunnel(uint32_t vaddr)
	{
		if (std::this_thread::get_id() == m_main_thread_id)
		{
			m_clients.remove(vaddr);
			return;
		}

		auto self = shared_from_this();
		net::post(m_main_context,
			[this, self, vaddr]() mutable
			{
				m_clients.remove(vaddr);
			});
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
				[&pwd]([[maybe_unused]] auto... args) {
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
				do_client_tun_read(std::move(pkt), std::move(endp));
				continue;
			}
		}

		// 在重启tun设备时, 当前这个tun read loop退出时以唤醒新的
		// tun read loop开始读取.
		m_tun_wait_timer.cancel_one(ec);
		LOG_WARN << "Quit start_tun_read_loop"
			<< ", this: " << this
			<< ", thread: " << std::this_thread::get_id();

		co_return;
	}

	void avpn_service::do_tun_write(vpn_packet pkt)
	{
		auto self = shared_from_this();
		net::post(m_main_context,
			[this, self, pkt = std::move(pkt)]() mutable
			{
				auto ptr = std::make_shared<vpn_packet>(std::move(pkt));
				m_tundev.async_write_some(
					net::buffer(ptr->payload(),
						ptr->payload_size()), [ptr](auto, auto) {});
			});
	}

	void avpn_service::do_server_tun_read(vpn_packet pkt, endpoint_pair endp)
	{
		// 根据对端的虚拟ip查找tunnel对象.
		uint32_t dst = endp.dst_.address().to_v4().to_uint();
		auto tunnel = lookup_tunnel(dst);
		if (!tunnel)
			return;

		// 提交到tunnel的队列进行处理.
		tunnel->tun_submit(vpn_tun_packet(
			std::move(pkt), std::move(endp)));
	}

	void avpn_service::do_client_tun_read(vpn_packet pkt, endpoint_pair endp)
	{
		// 获取tunnel对象指针.
		auto tunnel = m_tunnel.lock();
		if (!tunnel)
			return;

		// 提交到tunnel的队列进行处理.
		tunnel->tun_submit(vpn_tun_packet(
			std::move(pkt), std::move(endp)));
	}

	net::awaitable<void> avpn_service::start_udp_read_loop(int index)
	{
		boost::system::error_code ec;
		udp::endpoint remote;

		auto socket_ptr = pick_random_usock(index);
		auto thread_id = std::this_thread::get_id();

		while (!m_abort)
		{
			if (!socket_ptr)
			{
				socket_ptr = pick_random_usock(index);
				continue;
			}

			auto& udp_socket = socket_ptr->sock_;

			vpn_packet pkt;

			auto bytes = co_await udp_socket.async_receive_from(
				net::buffer(pkt.data(), avpn_packet_size),
					remote, uawaitable[ec]);
			if (ec)
			{
				socket_ptr = pick_random_usock(index);
				continue;
			}

			// 只有是client时, 才需要更新last see, 因为client一旦检
			// 测到超时, 则会重建udp socket对象重新向server建立通信.
			if (m_identity == Identity::avpn_client)
				socket_ptr->last_see_ = steady_clock::now();

			// 重置为实际接收的数据大小.
			pkt.resize(bytes);

			if (m_identity == Identity::avpn_server)
			{
				auto self = shared_from_this();

				if (thread_id == m_main_thread_id)
				{
					server_dispatch_udp(std::move(pkt), std::move(remote));
					continue;
				}

				net::post(m_main_context, [this, self,
					pkt = std::move(pkt),
					remote = std::move(remote)]() mutable
				{
					server_dispatch_udp(std::move(pkt), std::move(remote));
				});

				continue;
			}

			if (m_identity == Identity::avpn_client)
			{
				auto self = shared_from_this();

				if (thread_id == m_main_thread_id)
				{
					client_dispatch_udp(std::move(pkt), std::move(remote));
					continue;
				}

				net::post(m_main_context, [this, self,
					pkt = std::move(pkt),
					remote = std::move(remote)]() mutable
				{
					client_dispatch_udp(std::move(pkt), std::move(remote));
				});

				continue;
			}
		}

		LOG_WARN << "Quit avpn_service::start_udp_read_loop"
			<< ", this: " << this
			<< ", thread: " << std::this_thread::get_id();

		co_return;
	}

	void avpn_service::do_udp_write(vpn_packet pkt, udp::endpoint remote)
	{
		// 选择一个可用的udp socket准备用于数据发送.
		auto socket_ptr = pick_random_usock();
		if (!socket_ptr)
			return;

 		auto& udp_socket = socket_ptr->sock_;
		// udp_socket.send_to(net::buffer(pkt.data(), pkt.size()), remote);

#if 1
		auto ptr = pkt.release();

		// 直接发送, 仅在回调时释放packet.
		udp_socket.async_send_to(
			net::buffer(ptr, pkt.size()),
			remote,
			[ptr, remote](boost::system::error_code ec, std::size_t) mutable
			{
				if (ptr)
					std::free(ptr);

				if (ec)
				{
					LOG_WARN << "udp_write"
						<< ", send_to " << remote
						<< ", error: " << ec.message();
				}
			});
#endif
	}

	void avpn_service::run_as_client()
	{
		// 开始client之前, 清理重要控制部分的状态至最初.
		m_identity = Identity::avpn_client;
		m_abort = false;
		m_subnet = {};
		m_client_state = vst_starting;
		m_tcp_reconnect_cnt = 0;
		auto self = shared_from_this();

		LOG_DBG << "Start run_as_client"
			<< ", thread: " << std::this_thread::get_id()
			<< ", this: " << this;

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
		auto self = shared_from_this();

		// 筛选出udp协议的url.
		co_await make_endpoint("udp");

		// 开始侦听udp客户端消息.
		net::co_spawn(m_main_context,
			[this, self]() mutable -> net::awaitable<void>
			{
				co_await start_udp_client();
				co_return;
			}, net::detached);

		// 开始进行tcp客户端连接.
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

		// 检查所有tunnel是否超时, 超时2分钟则关闭并释放.
		auto check_all_tunnel = [&](time_point& now) mutable
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
				if (duration < std::chrono::minutes(2))
				{
					it++;
					continue;
				}

				LOG_WARN << "Detect tunnel: "
					<< tunnel.get() << " timeout";
				tunnel->close_tunnel();

				it = clients.erase(it);
			}
		};

		// 检查 client 是否需要重启.
		auto check_client_restart = [&]() mutable
		{
			if (!(m_client_state & vst_restart))
				return;

			// 重启过程中, 停止tcp重连逻辑.
			m_tcp_reconnect_cnt = 0;

			// 输出重启flag, 以便诊断错误.
			LOG_DBG << "Client restart state: " << m_client_state;

			// 重启 client, 完全重新握手协商.
			run_as_client();
		};

		// 检查client tcp连接是否超时需要重连.
		auto check_client_tcp_reconnect = [&]() mutable
		{
			// 小于等于0表示没有开始计数, 无需检查.
			if (m_tcp_reconnect_cnt <= 0)
				return;

			LOG_DBG << "Tcp reconnect timer: " << m_tcp_reconnect_cnt;

			// tcp重连倒计时, 10s 等待时间重连.
			if (++m_tcp_reconnect_cnt <= 10)
				return;

			m_tcp_reconnect_cnt = 0;
			auto self = shared_from_this();

			LOG_DBG << "Tcp reconnect started...";
			net::co_spawn(m_main_context,
				[this, self] () mutable -> net::awaitable<void>
				{
					co_await start_tcp_client();
					co_return;
				}, net::detached);
		};

		// 检查client udp是否超时需要重建.
		auto check_client_udp_renew = [&]() mutable
		{
			auto tunnel = m_tunnel.lock();
			if (!tunnel)
				return;

			auto now = steady_clock::now();

			std::lock_guard lock(m_udp_sockets);
			for (size_t i = 0; i < m_udp_sockets.size(); i++)
			{
				if (m_abort)
					break;

				auto socket_ptr = m_udp_sockets[i];
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

		// 计算上下行总带宽.
		auto compute_bandwidth = [&]() mutable
		{
			// 计算上下行总带宽.
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
				check_all_tunnel(now);
				compute_bandwidth();
			}

			if (m_identity == Identity::avpn_client)
			{
				check_client_restart();

				if (!m_server_tcp_endps.empty())
					check_client_tcp_reconnect();

				if (!m_server_udp_endps.empty())
					check_client_udp_renew();

				auto tunnel = m_tunnel.lock();
				if (!tunnel)
					continue;

				m_upload_speed = tunnel->upload_rate();
				m_down_speed = tunnel->download_rate();
			}
		}

		LOG_WARN << "Quit avpn_service::tick"
			<< ", this: " << this
			<< ", thread: " << std::this_thread::get_id();
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
				co_await start_tun_read_loop();
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

		LOG_WARN << "Quit avpn_service::start_tcp_listen"
			<< ", this: " << this
			<< ", thread: " << std::this_thread::get_id();
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

			std::lock_guard lock(m_udp_sockets);
			m_udp_sockets.emplace_back(std::move(sockptr));
		}

		auto self = shared_from_this();
		for (int fast = 0; fast < 8; fast++)
		{
			std::vector<udp_socket_ptr> sockets;
			{
				std::lock_guard lock(m_udp_sockets);
				sockets = m_udp_sockets;
			}

			for (int n = 0; n < (int)sockets.size(); n++)
			{
				auto socket_ptr = sockets[n];
				auto local_endp = socket_ptr->sock_.local_endpoint();

				LOG_DBG << "start_udp_server"
					<< ", listen endpoint: ["
					<< local_endp.address().to_string()
					<< "]:"
					<< local_endp.port();

				net::co_spawn(m_main_context,// m_ioc_pool.get_io_context(),
					[this, self, n]() mutable -> net::awaitable<void> {
						co_await start_udp_read_loop(n);
						co_return;
					}, net::detached);
			}
		}

		co_return;
	}

	void avpn_service::server_dispatch_udp(vpn_packet pkt, udp::endpoint remote)
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
			return;

		// client握手认证请求, 转入handshake处理流程.
		if (type == vpt_handshake)
		{
			auto self = shared_from_this();

			net::co_spawn(m_main_context,
				[this, self,
				src_vaddr,
				remote,
				pkt = std::move(pkt)]
			() mutable->net::awaitable<void>
			{
				co_await on_udp_handshake(
					remote,
					std::move(pkt),
					src_vaddr);
				co_return;
			}, net::detached);

			return;
		}

		// 根据src寻找对应的client, 找到后转入相应client
		// 的处理流程中.
		auto tunnel = lookup_tunnel(src_vaddr);
		if (!tunnel)
		{
			net::ip::address_v4 src_addr(src_vaddr);
			LOG_WARN << "Not found client via loop: "
				<< src_addr.to_string();

			// 若不为同一网络段, 则有可能是错误的数据包, 忽略掉.
			if (!same_ipv4_network(m_subnet, src_vaddr))
				return;

			// 没找到src对应的client, 则返回空handshake reply消息.
			do_udp_write(make_handshake_reply(
				{}, 0, 0, 0, 0, false, 0, {}), remote);

			return;
		}

		// 更新ipproto.
		tunnel->ipproto(Proto::avpn_udp);

		// 将UDP消息转发到对应的tunnel连接中处理.
		tunnel->net_submit(std::move(pkt), { remote });
	}

	void avpn_service::client_dispatch_udp(vpn_packet pkt, udp::endpoint remote)
	{
		bool enc = false;
		uint8_t type = 0;
		uint32_t src_vaddr = 0;

		int ret = unwrap_common_header(pkt,
			enc, type, src_vaddr);
		if (!ret)
			return;

		// server握手认证请求回复, 转入handshake处理流程.
		if (type == vpt_handshake_reply)
		{
			auto self = shared_from_this();

			net::co_spawn(m_main_context,
				[this, self,
				remote,
				pkt = std::move(pkt)]
			() mutable->net::awaitable<void>
			{
				co_await on_udp_handshake_reply(
					remote,
					std::move(pkt));
				co_return;
			}, net::detached);

			return;
		}

		// client的tunnel还没建立好, 忽略所有非vpt_handshake_reply消息.
		auto tunnel = m_tunnel.lock();
		if (!tunnel)
			return;

		// 转发到client连接, 让client对象处理相应的协议数据.
		tunnel->net_submit(std::move(pkt), { remote });
	}

	net::awaitable<void> avpn_service::start_tcp_client()
	{
		auto self = shared_from_this();
		boost::system::error_code ec;

		m_client_state |= vst_tcping;

		// scoped_exit用于提前退出此函数时, 将在tick中自动重试tcp连接.
		scoped_exit se([&]() mutable
			{
				if (m_server_tcp_endps.empty())
					return;

				LOG_WARN << "Set tcp reconnect";
				m_tcp_reconnect_cnt = 1;
			});

		tcp::socket stream(m_main_context);
		auto ret = co_await connect_tcp_server(stream);
		if (!ret)
			co_return;

		auto& params = m_config.tunnel_params_;

		// 连接成功后, 使用密钥的公钥构造握手消息.
		crypto_util::keyexchange ke(m_client_key);
		auto pubkey = ke.StaticPublicKey();
		auto src_vaddr = m_subnet.address().to_uint();

		auto pkt = make_handshake(src_vaddr,
			m_client_id,
			pubkey,
			(uint8_t)params.data_shards_,
			(uint8_t)params.parity_shards_);

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

		bytes = unwrap_handshake_reply(pkt,
			id,
			ds,
			ps,
			src_vaddr,
			prefix_length,
			passbyvpn,
			pushdns,
			pushroutes);

		auto tunnel = m_tunnel.lock();
		if (src_vaddr == 0)
		{
			LOG_WARN << "tcp handshake reply: '" << id
				<< "' detected server reboot!";

			// 如果tunnel对象为空, 则表示重启已经开始.
			if (!tunnel)
				co_return;

			// 如果已经开始重启client, 则表示已经接收到这个消息.
			// 忽略重复的消息直接退出.
			if (m_client_state & vst_restart)
				co_return;

			// 服务器重启了, 重启client完整的进行重新协商过程.
			// vst_restart状态由tick中统一逻辑处理.
			m_client_state = vst_restart;

			// 关闭已创建的隧道.
			tunnel->close_tunnel();

			// 关闭已经连接的socket.
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
			LOG_WARN << "unwrap_handshake_reply detected invalid!!!";
			co_return;
		}

		// 判断client的tunnel对象是否创建, 如果已经创建, 则表示已经
		// 握手成功.
		if (!tunnel)
		{
			auto server_pubkey = base64_decode(m_config.public_key_);

			// 创建tunnel对象, 在完成握手后, 进入tunnel的tcp loop中
			// 循环处理tcp消息.
			m_tunnel = tunnel = vpn_tunnel::make(
				m_main_context,
				self,
				m_config,
				server_pubkey,
				m_client_key);

			if (!m_server_udp_endps.empty())
			{
				tunnel->remote_endpoint(m_server_udp_endps.front());
				tunnel->ipproto(Proto::avpn_udp);
			}

			LOG_DBG << "Handshake by tcp"
				<< ", make tunnel: " << tunnel.get()
				<< ", thread: " << std::this_thread::get_id()
				<< ", cid: " << m_client_id;

			LOG_DBG << "Shared key: "
				<< base64_encode(tunnel->shared_key());

			m_subnet = make_network(src_vaddr, (unsigned short)prefix_length);
			tunnel->vnet_addr(m_subnet);
			tunnel->client_id(m_client_id);

			// 进行tun设备配置.
			co_await setup_tun(m_subnet);
		}

		LOG_DBG << "Tcp connected to "<< remote << " successfully!";

		// 成功握手, 去掉一些标志状态.
		m_client_state &= ~vst_restart;
		m_client_state &= ~vst_tcped;
		m_client_state &= ~vst_tcping;

		// 设置为运行中的状态.
		m_client_state |= vst_running;

		// 成功连接, 取消重连.
		se.cancel();

		// 替换为新的tcp socket对象.
		tunnel->rebind_tcp_socket(std::move(stream));

		// 设置ipproto.
		tunnel->ipproto(Proto::avpn_tcp);

		// 启动tunnel.
		tunnel->start_tunnel(ds, ps);
		// 启动tcp loop.
		tunnel->start_tcp_loop();

		co_return;
	}

	net::awaitable<bool> avpn_service::connect_tcp_server(tcp::socket& stream)
	{
		auto executor = co_await net::this_coro::executor;
		boost::system::error_code ec;

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
		if (m_udp_sockets.empty())
			co_await make_udp_client();

		// 发起UDP握手请求.
		co_await start_udp_handshake();
		co_return;
	}

	net::awaitable<void> avpn_service::make_udp_client()
	{
		boost::system::error_code ec;

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
				LOG_ERR << "make_udp_client"
					<< ", udp open error: " << ec.message();
				continue;
			}

			auto socket_ptr = std::make_shared<udp_socket>(
				udp_socket{ steady_clock::now(), std::move(sock) });

			std::lock_guard lock(m_udp_sockets);
			m_udp_sockets.emplace_back(std::move(socket_ptr));
		}

		auto self = shared_from_this();
		// for (int fast = 0; fast < 8; fast++)
		{
			int num_socket;

			{
				std::lock_guard lock(m_udp_sockets);
				num_socket = (int)m_udp_sockets.size();
			}

			for (int n = 0; n < (int)num_socket; n++)
			{
				{
					std::lock_guard lock(m_udp_sockets);

					auto socket_ptr = m_udp_sockets[n];
					auto local_endp = socket_ptr->sock_.local_endpoint();

					LOG_DBG << "start_udp_client"
						<< ", local endpoint: ["
						<< local_endp.address().to_string()
						<< "]:"
						<< local_endp.port();
				}

				net::co_spawn(m_main_context, //m_ioc_pool.get_io_context(),
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

		// 发送udp握手包.
		for (auto endp : m_server_udp_endps)
			do_udp_write(dup_vpn_packet(pkt), endp);

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
		LOG_DBG << "Shared key via tcp: "
			<< base64_encode(tunnel->shared_key())
			<< ", ip: " << vaddr
			<< ", remote: " << remote
			<< ", socket id: " << id
			<< ", tunnel: " << tunnel.get();

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
		tunnel->rebind_tcp_socket(std::move(stream));
		tunnel->ipproto(Proto::avpn_tcp);
		tunnel->start_tunnel(ds, ps);
		tunnel->start_tcp_loop();

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
				do_udp_write(make_handshake_reply(
					client_id, 0, 0, 0, 0, false, 0, {}), remote);

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
		LOG_DBG << "Shared key via udp: "
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
		do_udp_write(std::move(response), remote);

		// 更新tunnel的远端udp的endpoint.
		tunnel->remote_endpoint(remote);
		tunnel->ipproto(Proto::avpn_udp);
		tunnel->start_tunnel(ds, ps);
		tunnel->start_tcp_loop();

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

		auto bytes = unwrap_handshake_reply(pkt,
			id,
			ds,
			ps,
			addr,
			prefix_length,
			passbyvpn,
			pushdns,
			pushroutes);
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

			// 如果tunnel对象为空, 则表示重启已经开始.
			if (!tunnel)
				co_return;

			// 如果已经开始重启client, 则表示已经接收到这个消息.
			// 忽略重复的消息直接退出.
			if (m_client_state & vst_restart)
				co_return;

			// 服务器重启了, 重启client完整的进行重新协商过程.
			// vst_restart状态由tick中统一逻辑处理.
			m_client_state = vst_restart;

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
			auto server_pubkey = base64_decode(m_config.public_key_);

			// 创建tunnel对象, 在完成握手后, 进入tunnel的tcp loop中循
			// 环处理tcp消息.
			m_tunnel = tunnel = vpn_tunnel::make(m_main_context,
				self,
				m_config,
				server_pubkey,
				m_client_key);
			BOOST_ASSERT(tunnel);

			// 更新为对方的endpoint.
			tunnel->remote_endpoint(remote);

			LOG_DBG << "Handshake by udp"
				<< ", make tunnel: " << tunnel.get()
				<< ", thread: " << std::this_thread::get_id()
				<< ", cid: " << m_client_id;

			LOG_DBG << "Shared key via udp: "
				<< base64_encode(tunnel->shared_key());

			m_subnet = make_network(addr, (unsigned short)prefix_length);
			tunnel->vnet_addr(m_subnet);
			tunnel->client_id(m_client_id);

			// 进行tun设备配置.
			co_await setup_tun(m_subnet);
		}

		// 成功握手, 去掉一些标志状态.
		m_client_state &= ~vst_restart;
		m_client_state &= ~vst_tcped;
		m_client_state &= ~vst_tcping;

		// 设置为运行中的状态.
		m_client_state |= vst_running;

		// 更新tunnel的远端udp的endpoint.
		tunnel->ipproto(Proto::avpn_udp);
		tunnel->remote_endpoint(remote);
		tunnel->start_tunnel(ds, ps);
		tunnel->start_tcp_loop();

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
			if ((uint32_t)start_len_tag > (uint32_t)avpn_packet_size)
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
		auto vc = m_clients.lookup_by_addr(vaddr);
		return vc.tunnel_.lock();
	}

	vpn_tunnel_ptr avpn_service::lookup_tunnel(std::string id)
	{
		auto vc = m_clients.lookup_by_id(id);
		return vc.tunnel_.lock();
	}

	net::awaitable<avpn::vpn_tunnel_ptr>
	avpn_service::async_make_tunnel(std::string id, std::string pubkey)
	{
		// 查找存在的tunnel.
		auto tunnel = lookup_tunnel(id);
		if (tunnel)
			co_return tunnel;

		// TODO: 根据client的pubkey, 查找m_staic_ipp表, 然后分配
		// 一个固定虚拟ip.
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
			pubkey, m_config.private_key_);

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

	void avpn_service::tcp_reconnect(int cnt)
	{
		if (m_identity != Identity::avpn_client)
		{
			BOOST_ASSERT(false && "identity != client");
			return;
		}

		if (cnt > 0)
		{
			m_client_state &= ~vst_tcping;
			m_client_state |= vst_tcped;
		}

		std::ostringstream oss;
		oss << boost::stacktrace::stacktrace();
		LOG_DBG << "Callstack:\n" << oss.str();

		LOG_WARN << "Tcp reconnect: " << cnt;
		m_tcp_reconnect_cnt = cnt;
	}

	avpn_service::udp_socket_ptr
	avpn_service::pick_random_usock(int index/* = -1*/)
	{
		if (m_abort)
			return {};

		std::lock_guard lock(m_udp_sockets);
		static uint32_t static_index = 0;

		auto num_sockets = m_udp_sockets.size();
		if (num_sockets == 0)
		{
			BOOST_ASSERT(false && "m_udp_sockets is empty!");
			return {};
		}

		// TODO: 这里可以优化为选择一个活跃的udp socket 用于发送.
		if (index == -1)
			index = static_index++ % num_sockets;

		if (index < 0 || index >= static_cast<int>(num_sockets))
		{
			BOOST_ASSERT(false && "index out of range!");
			return {};
		}

		auto socket_ptr = m_udp_sockets[index];
		if (!socket_ptr)
		{
			BOOST_ASSERT(false && "socket_ptr == nullptr");
			return {};
		}

		return socket_ptr;
	}

}

