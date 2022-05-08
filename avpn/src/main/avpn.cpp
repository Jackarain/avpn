//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#include "utils/async_connect.hpp"
#include "utils/url_parser.hpp"
#include "utils/scoped_exit.hpp"
#include "utils/uawaitable.hpp"
#include "utils/misc.hpp"

#include "avpn/version.hpp"
#include "avpn/endpoint_pair.hpp"
#include "avpn/fec_cache.hpp"
#include "avpn/vpn_tunnel.hpp"
#include "avpn/avpn.hpp"
#include "avpn/protocol.hpp"

#include <chrono>
#include <iomanip>


namespace avpn {
	using namespace std::chrono_literals;
	using net::ip::make_network_v4;

	avpn_service::avpn_service(
		io_context_pool& ios, const service_config& config)
		: m_ioc_pool(ios)
		, m_main_context(m_ioc_pool.main_io_context())
		, m_config(config)
		, m_client_id(gen_unique_string(32))
		, m_tundev(m_main_context)
		, m_tick_timer(m_main_context)
		, m_subnet(make_network_v4(config.tunnel_params_.subnet_))
		, m_ip_assigner(m_subnet.hosts())
		, m_ip_iterator(++m_ip_assigner.begin())
	{}

	std::shared_ptr<avpn_service> avpn_service::make_avpn_service(
			io_context_pool& ioc_pool, avpn::service_config cfg)
	{
		return std::shared_ptr<avpn_service>(new avpn_service(ioc_pool, cfg));
	}

	avpn_service::~avpn_service()
	{
		// TODO: 退出时删除所有添加的路由.

		// 删除所有avpn临时文件.
		using namespace std::filesystem;
		auto tmpdir = temp_directory_path() / "avpn";

		std::error_code ignore_ec;
		remove_all(tmpdir, ignore_ec);

		LOG_DBG << "avpn_service::~avpn_service()";
	}

	void avpn_service::start()
	{
		m_abort = false;

		// 开启定时器.
		net::co_spawn(m_tick_timer.get_executor(),
			tick(), net::detached);

		// 客户端启动客户端通信通道.
		if (m_config.identity_ == Identity::avpn_client)
			run_as_client();

		// 服务器则将启动服务器通信通道.
		if (m_config.identity_ == Identity::avpn_server)
			run_as_server();
	}

	void avpn_service::stop()
	{
		boost::system::error_code ignore_ec;
		m_abort = true;

		// TODO: 退出时删除路由.
		LOG_DBG << "avpn_service stop tuntap.";
		m_tundev.close();
		m_tick_timer.cancel(ignore_ec);
		m_vnet = {};
		m_upload_stat = {};
		m_down_stat = {};

		LOG_DBG << "avpn_service.stop()";
	}

	int64_t avpn_service::upload_rate() const
	{
		return m_upload_stat.rate_;
	}

	int64_t avpn_service::download_rate() const
	{
		return m_down_stat.rate_;
	}

	net::awaitable<void> avpn_service::start_tun_read_loop()
	{
		boost::system::error_code ec;

		while (!m_abort)
		{
			vpn_packet pkt;

			auto content = pkt.data();
			auto bytes = co_await m_tundev.async_read_some(
				net::buffer(content, 1450), uawaitable[ec]);
			if (ec)
			{
				LOG_ERR << "start_tun_read_loop, read: " << ec.message();
				break;
			}

			// resize content.
			pkt.resize(bytes);

			// 解析ip相关的信息.
			auto endp = avpn::lookup_endpoint_pair(content, bytes);

			// 解析不出来的ip包, 直接跳过...
			if (endp.empty())
				continue;

			// 保存数据包类型.
			pkt.type((vpn_packet_type)endp.type_);

			// 根据程序的身份, 准备透传.
			if (m_config.identity_ == Identity::avpn_server)
			{
				// 作为server时, 要根据目标虚拟ip寻找到对应的通信
				// 通道透传到tunnel.
				co_spawn(m_main_context,
					do_server_tun_read(std::move(pkt), std::move(endp)),
						net::detached);
				continue;
			}
			else if (m_config.identity_ == Identity::avpn_client)
			{
				// TODO: 作为client时, 未连接状态, 丢弃所有packet.

				// 统计上传数据量用于计算上传速率.
				m_upload_stat.bytes_ += (int64_t)bytes;
				auto index = m_down_stat.speeder_count_ % speed_entries;
				m_upload_stat.speeder_[index] = m_upload_stat.bytes_;

				// 透传到tunnel.
			}
		}

		LOG_WARN << "start_tun_read_loop quit...";
		co_return;
	}

	void avpn_service::do_tun_write(std::string&& message)
	{
		net::co_spawn(m_main_context.get_executor(),
		[this, message = std::move(message)]() mutable->net::awaitable<void>
		{
			boost::system::error_code ec;
			co_await m_tundev.async_write_some(
				net::buffer(message), uawaitable[ec]);

			// 统计发送数据量用于计算发送速率.
			m_down_stat.bytes_ += (int64_t)message.size();
			auto index = m_down_stat.speeder_count_ % speed_entries;
			m_down_stat.speeder_[index] = m_down_stat.bytes_;
		}, net::detached);
	}

	net::awaitable<void>
	avpn_service::do_server_tun_read(vpn_packet pkt, endpoint_pair endp)
	{
		uint32_t dst = endp.dst_.address().to_v4().to_uint();
		auto vp = co_await lookup_tunnel(dst);
		if (!vp)
		{
			LOG_WARN << "lost connection: " << endp;
			co_return;
		}
	}

	net::awaitable<void> avpn_service::start_udp_read_loop(int index)
	{
		udp::endpoint remote;
		boost::system::error_code ec;

		while (!m_abort)
		{
			auto ptr = m_udp_sockets[index];
			auto& usock = ptr->sock_;

			vpn_packet pkt;

			auto bytes = co_await usock.async_receive_from(
				net::buffer(pkt.data(), 1450), remote, uawaitable[ec]);
			if (ec)
				continue;

			// 只有是client时, 才需要更新last see.
			// 因为client一旦检测到超时, 则会重建
			// udp socket对象重新向server建立通信.
			if (m_identity == Identity::avpn_client)
				ptr->last_see_ = steady_clock::now();

			// 重置为实际接收的数据大小.
			pkt.resize(bytes);

			vpn_tunnel_ptr vp;
			if (m_identity == Identity::avpn_server)
			{
				// 根据协议中的虚拟ip信息, 找到相应vpn连接
				// 进行相应数据处理.

				// 如果是认证请求, 则根据client的id, 先查
				// 询client连接池中是否已有相同id存在的请
				// 求, 如果有则直接使用池中vpn tunnel, 如
				// 果没有, 则创建新的vpn tunnel, 并加入到
				// vpn tunnel连接池中, 直到认证完成, 则能
				// 将其从连接池中移动到已经完成的连接列表.
				bool enc = false;
				bool has_src = false;
				uint8_t type = 0;
				uint32_t src = 0;

				int ret = unwrap_common_header(pkt,
					enc, has_src, type, src);
				if (!ret)
					continue;

				// client认证请求.
				if (type == vpt_auth_request)
				{
					co_await start_udp_auth(remote, pkt, src);
					continue;
				}

				// 根据src寻找对应的client.
				vp = co_await net::co_spawn(m_main_context,
					lookup_tunnel(src), net::use_awaitable);
				if (!vp)
					continue;

				// TODO: 将UDP消息转发到vp连接中处理.

				continue;
			}

			if (m_identity == Identity::avpn_client)
			{
				// 转发到client连接, 让client对象处理相应
				// 的协议数据.

				continue;
			}
		}

		co_return;
	}

	net::awaitable<void>
	avpn_service::do_udp_write(vpn_packet pkt, udp::endpoint remote)
	{
		auto usize = m_udp_sockets.size();
		static uint32_t index = 0;
		auto ptr = m_udp_sockets[index++ % usize];
		boost::system::error_code ec;

		auto& usock = ptr->sock_;

		co_await usock.async_send_to(
			net::buffer(pkt.data(), pkt.size()),
			remote, uawaitable[ec]);
		if (ec)
			LOG_WARN << "do_udp_write"
			<< ", send_to " << remote
			<< ", error: " << ec.message();

		co_return;
	}

	void avpn_service::run_as_client()
	{
		m_identity = Identity::avpn_client;
		m_abort = false;
	}

	void avpn_service::run_as_server()
	{
		m_identity = Identity::avpn_server;
		m_abort = false;

		LOG_DBG << "Start run_as_server...";
		setup_tun(m_subnet);

		// 初始化tcp连接.
		bool ret = init_tcp_acceptors();
		if (!ret)
			return;

		// 开始侦听tcp客户端连接消息.
		net::co_spawn(m_main_context,
			[this]() mutable -> net::awaitable<void>
			{
				int pool_size = static_cast<int>(m_ioc_pool.pool_size());
				for (int i = 0; i < pool_size; i++)
				{
					for (auto& a : m_tcp_acceptors)
					{
						net::co_spawn(a.get_executor(),
							start_tcp_listen(a), net::detached);
					}
				}
				co_return;
			}, net::detached);

		// 开始侦听udp客户端消息.
		net::co_spawn(m_main_context,
			[this]() mutable->net::awaitable<void>
			{
				co_await start_udp_server();
				co_return;
			}, net::detached);

		// 开始读取tun上的数据包.
		boost::asio::co_spawn(m_main_context,
			start_tun_read_loop(), boost::asio::detached);
	}

	net::awaitable<void> avpn_service::tick()
	{
		boost::system::error_code ec;

		auto compute_speed = [&](speed_stat& stat,
			steady_clock::time_point& now) mutable
		{
			auto& speeder_time = stat.speeder_time_;

			int nowindex = stat.speeder_count_ % speed_entries;
			speeder_time[nowindex] = now;

			auto speeder_count = stat.speeder_count_ + 1;
			if (speeder_count > 0)
			{
				int checkindex = speeder_count >= speed_entries
					? speeder_count % speed_entries : 0;

				auto& speeder = stat.speeder_;

				auto deltams = now - speeder_time[checkindex];
				auto amount = speeder[nowindex] - speeder[checkindex];

				if (amount < 0)
					amount = 0;

				auto ms = std::chrono::duration_cast<
					std::chrono::milliseconds>(deltams);
				if (ms.count() <= 0)
					ms = std::chrono::milliseconds(1);

				stat.rate_ = int64_t((double)amount /
					((double)ms.count() / 1000.0f));
			}

			stat.speeder_count_ = speeder_count;
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

			compute_speed(m_down_stat, now);
			compute_speed(m_upload_stat, now);
		}

		LOG_WARN << "avpn_service::tick() quit...";
		co_return;
	}

	void avpn_service::setup_tun(const net::ip::network_v4& net)
	{
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
			LOG_ERR << "open tun device: " << dc.dev_name_ << " fail!";
			return;
		}

		m_vnet = net;
	}

	net::awaitable<avpn_service::ip_assign_type>
	avpn_service::ip_assigner()
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

		co_return ret;
	}

	bool avpn_service::init_tcp_acceptors()
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

	net::awaitable<void> avpn_service::start_tcp_listen(tcp::acceptor& a)
	{
		boost::system::error_code error;

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

			auto executor = socket.get_executor();

			// 新连接, server先读取client的认证请求, 如果client未认证, 则
			// 会发出认证请求, 如果是已认证过只是断开重连, 发送认证重连消息
			// server会根据重连信息中的src虚拟ip找到对应的client, 并使用这
			// 个client解密重连认证信息, 解密成功则将此tcp替换client中的原
			// tcp连接, 解密失败, 则回复认证失败消息, 以快速触发client进行
			// 完整重新协商认证过程(或者server端沉默, 等client直到超时重新
			// 协商通信key).

			net::co_spawn(executor,
				start_tcp_auth(std::move(socket), connection_id),
					net::detached);
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
			LOG_DBG << "start_udp_server, udp listen: " << listen;

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
				auto usock_ptr = tmp_sockets[n];
				auto local_endp = usock_ptr->sock_.local_endpoint();

				LOG_DBG << "start_udp_server"
					<< ", listen endpoint: ["
					<< local_endp.address().to_string()
					<< "]:"
					<< local_endp.port();

				net::co_spawn(m_ioc_pool.get_io_context(),
					start_udp_read_loop(n), boost::asio::detached);
			}
		}

		co_return;
	}

	net::awaitable<void> avpn_service::start_tcp_auth(
		tcp::socket stream, size_t id)
	{
		vpn_packet pkt;

		int ret = co_await tcp_read_packet(stream, pkt, id);
		if (ret == -1)
			co_return;

		uint32_t src = 0;
		std::string client_id;
		std::string pubkey;
		std::string additional;

		ret = unwrap_auth_request(pkt,
			src, client_id, pubkey, additional);
		if (ret == -1)
			co_return;

		vpn_tunnel_ptr vp;

		if (src != 0)
		{
			// 使用main线程查询, 以避免加锁.
			vp = co_await net::co_spawn(m_main_context,
				lookup_tunnel(src), net::use_awaitable);
			if (!vp)
			{
				// 找不到连接, 说明src已经过期, 回复认证失败.
				auto response = make_auth_response(
					0, client_id, additional);
				co_await tcp_write_packet(stream, response, id);
				co_return;
			}

			// 找到连接, 回复成功消息带回已分配的地址.
			// 然后将原来tunnel中的tcp socket替换, 启
			// 再动vpn的tcp读取循环.
			auto response = make_auth_response(
				src, client_id, additional);
			co_await tcp_write_packet(stream, response, id);

			vp->tcp_socket() = std::move(stream);

			// 启动tunnel的tcp读取循环.
			vp->start_tcp_loop();
			co_return;
		}

		// 连接认证请求, 查询是否存在client id, 如果存在, 则使用存在的
		// 请求, 并回复认证信息.
		auto incoming = co_await net::co_spawn(m_main_context,
			lookup_incoming(client_id), net::use_awaitable);
		vp = incoming.client_.lock();
		if (!vp)
		{
			vp = co_await net::co_spawn(m_main_context,
				make_incoming(client_id, pubkey), net::use_awaitable);
		}

		// 分配一个虚拟ip.
		auto [ip_string, vaddr] = co_await co_spawn(
			m_main_context, ip_assigner(), net::use_awaitable);

		auto ipaddr = net::ip::address_v4(vaddr);
		auto vnetaddr = net::ip::make_network_v4(
			ipaddr, m_subnet.prefix_length());

		// 配置到vp对象中.
		vp->vnet_addr(vnetaddr);

		// 回复认证消息.
		auto response = make_auth_response(vaddr, client_id);
		co_await tcp_write_packet(stream, response, id);

		// 开始vp的tcp读取消息循环.
		vp->start_tcp_loop();
		co_return;
	}

	net::awaitable<void>
	avpn_service::start_udp_auth(
		udp::endpoint remote, vpn_packet& pkt, uint32_t src)
	{
		std::string pubkey;
		std::string client_id;
		std::string additional;

		// 解析client的认证消息.
		int ret = unwrap_auth_request(pkt,
			src, client_id, pubkey, additional);
		if (ret == -1)
			co_return;

		vpn_tunnel_ptr vp;

		if (src != 0)
		{
			// 使用main线程查询, 以避免加锁.
			vp = co_await net::co_spawn(m_main_context,
				lookup_tunnel(src), net::use_awaitable);
			if (!vp)
			{
				// 找不到连接, 说明src已经过期, 回复认证失败.
				auto response = make_auth_response(
					0, client_id, additional);
				co_await do_udp_write(std::move(response), remote);
				co_return;
			}

			// 找到连接, 回复成功消息带回已分配的地址.
			// 然后将原来tunnel中的udp remote替换.
			auto response = make_auth_response(
				src, client_id, additional);
			co_await do_udp_write(std::move(response), remote);

			// 更新远端udp的endpoint.
			vp->remote_endpoint(remote);
			co_return;
		}

		// 连接认证请求, 查询是否存在client id, 如果存在, 则使用存在的
		// 请求, 并回复认证信息.
		auto incoming = co_await net::co_spawn(m_main_context,
			lookup_incoming(client_id), net::use_awaitable);
		vp = incoming.client_.lock();
		if (!vp)
		{
			vp = co_await net::co_spawn(m_main_context,
				make_incoming(client_id, pubkey), net::use_awaitable);
		}

		// 分配一个虚拟ip.
		auto [ip_string, vaddr] = co_await co_spawn(
			m_main_context, ip_assigner(), net::use_awaitable);

		auto ipaddr = net::ip::address_v4(vaddr);
		auto vnetaddr = net::ip::make_network_v4(
			ipaddr, m_subnet.prefix_length());

		// 配置到vp对象中.
		vp->vnet_addr(vnetaddr);

		// 回复认证消息.
		auto response = make_auth_response(vaddr, client_id);
		co_await do_udp_write(std::move(response), remote);

		// 更新vp的远端udp的endpoint.
		vp->remote_endpoint(remote);
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
			if ((uint32_t)start_len_tag > (uint32_t)static_mtu)
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

	net::awaitable<vpn_tunnel_ptr>
	avpn_service::lookup_tunnel(uint32_t vaddr)
	{
		vpn_tunnel_ptr vp;

		auto it = m_tunnels.find(vaddr);
		if (it == m_tunnels.end())
			co_return vp;

		co_return it->second;
	}

	net::awaitable<avpn_service::client_incoming>
	avpn_service::lookup_incoming(std::string id)
	{
		client_incoming ci;

		auto it = m_incomings.find(id);
		if (it == m_incomings.end())
			co_return ci;

		co_return it->second;
	}

	net::awaitable<vpn_tunnel_ptr>
	avpn_service::make_incoming(std::string id, std::string pubkey)
	{
		client_incoming incoming;
		auto self = shared_from_this();
		auto& ioc = m_ioc_pool.get_io_context();

		vpn_tunnel_ptr vp = vpn_tunnel::make_tunnel(
			ioc, self, m_config, pubkey, m_config.passphrase_);

		incoming.last_see_ = steady_clock::now();
		incoming.client_ = vp;

		m_incomings[id] = incoming;

		co_return vp;
	}

}

