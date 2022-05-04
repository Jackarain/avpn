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
		auto avpn_tmp_dir = std::filesystem::temp_directory_path() / "avpn";
		std::error_code ignore_ec;
		std::filesystem::remove_all(avpn_tmp_dir, ignore_ec);

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
		vpn_packet msg;

		while (!m_abort)
		{
			auto content = msg.data();

			auto bytes = co_await m_tundev.async_read_some(
				net::buffer(content, 1450), uawaitable[ec]);
			if (ec)
			{
				LOG_ERR << "start_tun_read_loop, read: " << ec.message();
				break;
			}

			// resize content.
			msg.resize(bytes);

			// 解析ip相关的信息.
			auto endp = avpn::lookup_endpoint_pair(content, bytes);

			// 解析不出来的ip包, 直接跳过...
			if (endp.empty())
				continue;

			// 保存数据包类型.
			msg.type((vpn_packet_type)endp.type_);

			// 根据程序的身份, 准备透传.
			if (m_config.identity_ == Identity::avpn_server)
			{
				// TODO: 作为server时, 要根据目标虚拟ip寻找到对应的通信通道.
				// 透传到tunnel.
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

	void avpn_service::do_udp_write(std::string&& msg, udp::endpoint&& remote)
	{
		static uint32_t index = 0;

		auto usize = m_udp_sockets.size();
		auto ptr = m_udp_sockets[index++ % usize];

		net::co_spawn(m_ioc_pool.get_io_context(),
			[&, ptr = ptr, msg = std::move(msg), remote = std::move(remote)]
			() mutable -> net::awaitable<void>
			{
				boost::system::error_code ec;
				auto& usock = ptr->sock_;

				co_await usock.async_send_to(
					net::buffer(msg), remote, uawaitable[ec]);
				if (ec)
					LOG_WARN << "do_udp_write"
					<< ", send_to " << remote
					<< ", error: " << ec.message();

				co_return;

			}, net::detached);
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

		bool ret = init_tcp_acceptors();
		if (!ret)
			return;

		net::co_spawn(m_main_context.get_executor(),
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

	std::tuple<std::string, uint32_t> avpn_service::ip_assigner()
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

		return { ip_string, ipaddr };
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
				LOG_ERR << "TCP server, async_accept: " << error.message();

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

			// net::co_spawn(executor,
			//	start_tcp_connection(connection_id, std::move(socket)), net::detached);
		}

		LOG_WARN << "start_tcp_listen exit ...";
		co_return;
	}

}

