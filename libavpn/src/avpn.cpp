#include "libavpn/avpn.hpp"
#include "libavpn/avpn_session.hpp"
#include "libavpn/avpn_tun.hpp"
#include "libavpn/avpn_protocol.hpp"
#include "libavpn/use_awaitable.hpp"
#include "libavpn/logging.hpp"
#include "libavpn/vpn_controller.hpp"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/ip/address_v4.hpp>
#include <boost/asio/ip/address_v6.hpp>

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <string_view>
#include <thread>

#if defined(__linux__)
#	include <sys/socket.h>
#endif

namespace libavpn {

	// 每个 UDP socket 并发接收协程数, 参考 avpn 的 global_op_concurrency.
	// 单 io_context 单线程调度, 多协程并发异步接收, 在数据包处理
	// (解密/FEC) 期间保持接收不中断, 提升高 PPS 下的吞吐.
	const std::size_t udp_receive_concurrency = std::clamp<std::size_t>(
		std::thread::hardware_concurrency(), 2, 16);

	// 解析 IPv6 内网子网字符串, 默认 fd00::/64.
	// 低 32 位作为虚拟地址主机位, 因此前缀必须 <= 96.
	static void parse_v6_subnet(const std::string& text,
		net::ip::address_v6& net, uint8_t& prefix)
	{
		net = net::ip::make_address_v6("fd00::");
		prefix = 64;
		if (text.empty())
			return;

		boost::system::error_code ec;
		auto slash = text.find('/');
		auto host = slash == std::string::npos ?
			text : text.substr(0, slash);
		auto v6 = net::ip::make_address_v6(host, ec);
		if (ec)
			return;
		net = v6;
		if (slash != std::string::npos)
		{
			try
			{
				prefix = static_cast<uint8_t>(
					std::stoi(text.substr(slash + 1)));
			}
			catch (...)
			{
				prefix = 64;
			}
		}
		if (prefix > 96)
			prefix = 96;
	}


	//////////////////////////////////////////////////////////////////////////
	// DDoS 缓解措施.
	//
	// 在不引入 2-RTT Cookie 的情况下:
	//   1. 单个源 IP 地址的握手尝试频率限制 (默认每 5 秒 1 次).
	//   2. 握手失败达到阈值后, 源 IP 进入短暂拒绝请求状态.
	class avpn_service::ddos_guard
	{
	public:
		ddos_guard(int interval_s = 5, int max_fails = 5, int block_s = 60)
			: m_interval_s(std::max(1, interval_s))
			, m_max_fails(std::max(1, max_fails))
			, m_block_s(std::max(1, block_s))
		{}

		// 是否允许该 IP 发起握手.
		bool allow_handshake(const net::ip::address& ip)
		{
			auto key = ip.to_string();
			auto now = now_ms();
			auto& e = m_entries[key];

			// 是否处于封锁状态.
			if (now < e.block_until_ms)
				return false;

			// 握手频率限制.
			if (e.last_handshake_ms != 0 &&
				now - e.last_handshake_ms <
					static_cast<uint64_t>(m_interval_s) * 1000)
				return false;

			e.last_handshake_ms = now;
			return true;
		}

		// 握手失败.
		void report_failure(const net::ip::address& ip)
		{
			auto key = ip.to_string();
			auto now = now_ms();
			auto& e = m_entries[key];

			e.fails++;
			if (e.fails >= m_max_fails)
			{
				e.block_until_ms = now +
					static_cast<uint64_t>(m_block_s) * 1000;
				e.fails = 0;
				XLOG_WARN << "DDoS: block " << key
					<< " for " << m_block_s << "s";
			}
		}

		// 握手成功.
		void report_success(const net::ip::address& ip)
		{
			auto key = ip.to_string();
			auto& e = m_entries[key];
			e.fails = 0;
			e.block_until_ms = 0;
		}

	private:
		static uint64_t now_ms()
		{
			return static_cast<uint64_t>(
				std::chrono::duration_cast<std::chrono::milliseconds>(
					std::chrono::system_clock::now().time_since_epoch()).count());
		}

		struct entry
		{
			uint64_t last_handshake_ms{ 0 };
			int fails{ 0 };
			uint64_t block_until_ms{ 0 };
		};

		std::map<std::string, entry> m_entries;
		int m_interval_s;
		int m_max_fails;
		int m_block_s;
	};

	//////////////////////////////////////////////////////////////////////////

	avpn_service::avpn_service(io_context_pool& ioc_pool, const service_config& config)
		: m_ioc_pool(ioc_pool)
		, m_main_context(ioc_pool.main_io_context())
		, m_config(config)
		, m_bandwidth_timer(m_main_context)
		, m_bypass_timer(m_main_context)
		, m_netmon_timer(m_main_context)
		, m_ddos(std::make_unique<ddos_guard>(5, 5, 60))
	{
		// 解析子网配置.
		boost::system::error_code ec;
		m_subnet = net::ip::make_network_v4(
			config.subnet_.empty() ? "10.8.0.0/16" : config.subnet_, ec);
		if (ec)
			m_subnet = net::ip::make_network_v4("10.8.0.0/16", ec);

		// 客户端地址分配区间: 从网络地址 +1 开始, 到广播地址 -1.
		m_next_vaddr = m_subnet.address().to_uint() + 1;
		m_vaddr_end = m_subnet.broadcast().to_uint();
		if (m_next_vaddr >= m_vaddr_end)
			m_next_vaddr = m_subnet.address().to_uint();
	}

	std::shared_ptr<avpn_service>
	avpn_service::create_service(io_context_pool& ioc_pool, const service_config& config)
	{
		return std::shared_ptr<avpn_service>(new avpn_service(ioc_pool, config));
	}

	avpn_service::~avpn_service()
	{
		XLOG_DBG << "avpn_service::~avpn_service()";
	}

	uint32_t avpn_service::alloc_vaddr()
	{
		for (int i = 0; i < 10000; i++)
		{
			uint32_t v = m_next_vaddr;
			m_next_vaddr++;
			if (m_next_vaddr >= m_vaddr_end)
				m_next_vaddr = m_subnet.address().to_uint() + 1;

			if (v >= m_vaddr_end || v <= m_subnet.address().to_uint())
				continue;

			if (m_allocated_addrs.insert(v).second)
				return v;
		}
		return 0;
	}

	void avpn_service::free_vaddr(uint32_t vaddr)
	{
		if (vaddr != 0)
			m_allocated_addrs.erase(vaddr);
	}

	std::shared_ptr<avpn_session> avpn_service::find_session(uint32_t vaddr) const
	{
		for (auto& [key, session] : m_sessions)
		{
			if (session && session->established() && session->vaddr() == vaddr)
				return session;
		}
		return {};
	}

	void avpn_service::on_session_close(
		const std::shared_ptr<avpn_session>& session)
	{
		// 从 endpoint 索引移除.
		for (auto it = m_sessions.begin(); it != m_sessions.end(); ++it)
		{
			if (it->second == session)
			{
				m_sessions.erase(it);
				break;
			}
		}

		// 从公钥索引移除.
		auto pub = session->peer_public_key();
		if (!pub.empty())
		{
			auto it = m_sessions_by_pubkey.find(pub);
			if (it != m_sessions_by_pubkey.end() && it->second == session)
				m_sessions_by_pubkey.erase(it);
		}

		free_vaddr(session->vaddr());
	}

	void avpn_service::write_to_tun(std::vector<uint8_t> ip_packet)
	{
		if (!m_tundev || ip_packet.empty())
			return;

#if defined(__APPLE__)
		// macOS utun 要求每个数据包前置 4 字节地址族头部
		// (AF_INET=2 / AF_INET6=30, 大端), 否则包无法正确送达.
		uint8_t version = (ip_packet[0] >> 4) & 0x0f;
		uint32_t family = (version == 6) ? AF_INET6 : AF_INET;
		std::vector<uint8_t> framed;
		framed.reserve(4 + ip_packet.size());
		framed.push_back(static_cast<uint8_t>((family >> 24) & 0xff));
		framed.push_back(static_cast<uint8_t>((family >> 16) & 0xff));
		framed.push_back(static_cast<uint8_t>((family >> 8) & 0xff));
		framed.push_back(static_cast<uint8_t>(family & 0xff));
		framed.insert(framed.end(), ip_packet.begin(), ip_packet.end());
		ip_packet.swap(framed);
#endif

		auto buf = std::make_shared<std::vector<uint8_t>>(std::move(ip_packet));
		boost::system::error_code ignore_ec;
		m_tundev->async_write_some(net::buffer(*buf),
			[buf](const boost::system::error_code&, std::size_t) {});
	}

	void avpn_service::route_tun_packet(std::vector<uint8_t> ip_packet)
	{
		if (ip_packet.size() < 20)
			return;

		// 解析目标 IP.
		uint32_t dst = 0;
		uint8_t version = (ip_packet[0] >> 4) & 0x0f;
		if (version == 4)
		{
			if (ip_packet.size() < 20)
				return;
			std::memcpy(&dst, ip_packet.data() + 16, 4);
			dst = ntohl(dst);
		}
		else if (version == 6)
		{
			if (ip_packet.size() < 40)
				return;

			// client 模式: 全部转发给唯一会话.
			if (m_tunnel)
			{
				m_tunnel->tun_submit(std::move(ip_packet));
				return;
			}

			// gateway 模式: IPv6 内网 (fd00::/64) 目标地址低 32 位即虚拟地址.
			uint32_t dst = 0;
			std::memcpy(&dst, ip_packet.data() + 24 + 12, 4);
			dst = ntohl(dst);

			auto session = find_session(dst);
			if (session)
			{
				session->tun_submit(std::move(ip_packet));
				return;
			}

			net::ip::address_v6::bytes_type bytes{};
			std::memcpy(bytes.data(), ip_packet.data() + 24, 16);
			XLOG_DBG << "Drop tun packet, no route to: "
				<< net::ip::address_v6(bytes).to_string();
			return;
		}
		else
		{
			return;
		}

		// client 模式: 全部转发给唯一会话.
		if (m_tunnel)
		{
			m_tunnel->tun_submit(std::move(ip_packet));
			return;
		}

		// gateway 模式: 根据目标虚拟地址路由到对应会话.
		auto session = find_session(dst);
		if (session)
		{
			session->tun_submit(std::move(ip_packet));
			return;
		}

		// 目标为 gateway 自身, 或未找到会话, 丢弃.
		XLOG_DBG << "Drop tun packet, no route to: "
			<< net::ip::address_v4(dst).to_string();
	}

	net::awaitable<void> avpn_service::tun_read_loop()
	{
		while (!m_abort)
		{
			std::vector<uint8_t> buf(avpn_max_mtu);
			boost::system::error_code ec;
			std::size_t n = co_await m_tundev->async_read_some(
				net::buffer(buf), net_awaitable[ec]);
			if (ec || m_abort)
				break;

#if defined(__APPLE__)
			// macOS utun 每个数据包前置 4 字节地址族头部, 剥离后
			// 才是原始 IP 数据包.
			if (n < 4)
				continue;
			std::memmove(buf.data(), buf.data() + 4, n - 4);
			n -= 4;
#endif

			buf.resize(n);
			route_tun_packet(std::move(buf));
		}

		co_return;
	}

	bool avpn_service::start_tun_io_task()
	{
		if (!m_tundev)
			return false;

		auto self = shared_from_this();
		net::co_spawn(m_main_context,
			[this, self]() -> net::awaitable<void>
			{
				co_await tun_read_loop();
				co_return;
			}, net::detached);

		return true;
	}

	//////////////////////////////////////////////////////////////////////////
	// gateway 模式

	void avpn_service::on_gateway_udp_packet(
		const std::shared_ptr<net::ip::udp::socket>& socket,
		const net::ip::udp::endpoint& remote, std::vector<uint8_t> data)
	{
		if (m_abort)
			return;

		std::string_view sv(reinterpret_cast<const char*>(data.data()),
			data.size());
		auto key = endpoint_to_string(remote);

		// 已存在的会话.
		auto it = m_sessions.find(key);
		if (it != m_sessions.end())
		{
			it->second->on_udp_packet(remote, sv);
			return;
		}

		// 网络迁移: 对端物理网络变化 (如 wifi -> 移动网络) 导致源 endpoint
		// 变化, 用已建立会话的接收密钥尝试解密识别, 命中后更新对端地址.
		for (auto& [pub, session] : m_sessions_by_pubkey)
		{
			if (!session || !session->established() || session->aborted())
				continue;
			if (session->transport() != transport_type::udp)
				continue;
			if (!session->try_decrypt_udp(sv))
				continue;

			// 命中: 迁移会话对端 endpoint.
			auto old_key = endpoint_to_string(session->remote_udp());
			session->update_remote_udp(remote);
			if (old_key != key)
			{
				m_sessions.erase(old_key);
				m_sessions[key] = session;
			}
			XLOG_INFO << "Session endpoint migrated: " << old_key
				<< " -> " << key;
			session->on_udp_packet(remote, sv);
			return;
		}

		// 新来源: 可能是握手包. 先做 DDoS 检查.
		if (!m_ddos->allow_handshake(remote.address()))
			return;

		// 创建临时会话尝试握手.
		auto session = avpn_session::create(m_main_context, m_config,
			session_role::responder);

		session->set_udp_send_handler(
			[socket](const net::ip::udp::endpoint& ep,
				std::vector<uint8_t> wire)
			{
				socket->async_send_to(net::buffer(wire), ep, net::detached);
			});

		session->set_ip_packet_handler(
			[self = shared_from_this()](std::vector<uint8_t> pkt)
			{
				self->write_to_tun(std::move(pkt));
			});

		session->set_vaddr_allocator(
			[self = shared_from_this()]() -> std::pair<uint32_t, uint8_t>
			{
				return std::make_pair(self->alloc_vaddr(),
					static_cast<uint8_t>(self->m_subnet.prefix_length()));
			});

		session->set_close_handler(
			[self = shared_from_this()](const std::shared_ptr<avpn_session>& s)
			{
				self->on_session_close(s);
			});

		bool consumed = session->on_udp_packet(remote, sv);

		if (consumed && session->established())
		{
			// 握手成功, 登记会话.
			m_sessions[key] = session;
			auto peer_pub = session->peer_public_key();
			if (!peer_pub.empty())
			{
				// 同公钥旧会话 (客户端重启/更换端口后重新握手) 先关闭.
				auto old_it = m_sessions_by_pubkey.find(peer_pub);
				if (old_it != m_sessions_by_pubkey.end() &&
					old_it->second && old_it->second != session)
				{
					XLOG_INFO << "Replacing old session for peer, vaddr: "
						<< net::ip::address_v4(old_it->second->vaddr()).to_string();
					old_it->second->close();
				}
				m_sessions_by_pubkey[peer_pub] = session;
			}
			m_ddos->report_success(remote.address());
			XLOG_INFO << "New session from: " << key
				<< ", vaddr: " << net::ip::address_v4(session->vaddr()).to_string();
		}
		else if (!consumed)
		{
			// 非握手包, 记录失败.
			m_ddos->report_failure(remote.address());
		}
	}

	net::awaitable<void> avpn_service::udp_receive_loop(
		std::shared_ptr<net::ip::udp::socket> socket)
	{
		auto self = shared_from_this();

		while (!m_abort)
		{
			std::vector<uint8_t> buf(avpn_max_packet_size);
			net::ip::udp::endpoint remote;
			boost::system::error_code ec;
			std::size_t n = co_await socket->async_receive_from(
				net::buffer(buf), remote, net_awaitable[ec]);
			if (ec || m_abort)
				break;

			buf.resize(n);
			on_gateway_udp_packet(socket, remote, std::move(buf));
		}

		co_return;
	}

	net::awaitable<void> avpn_service::on_gateway_tcp_connection(
		net::ip::tcp::socket stream)
	{
		auto self = shared_from_this();

		boost::system::error_code nd_ec;
		stream.set_option(net::ip::tcp::no_delay(true), nd_ec);

		// 创建会话, 处理 TCP 控制连接 (握手 + 数据).
		auto session = avpn_session::create(m_main_context, m_config,
			session_role::responder);

		auto remote = stream.remote_endpoint();
		auto key = remote.address().to_string() + ":" + std::to_string(remote.port());

		session->set_ip_packet_handler(
			[self](std::vector<uint8_t> pkt)
			{
				self->write_to_tun(std::move(pkt));
			});

		session->set_vaddr_allocator(
			[self]() -> std::pair<uint32_t, uint8_t>
			{
				return std::make_pair(self->alloc_vaddr(),
					static_cast<uint8_t>(self->m_subnet.prefix_length()));
			});

		session->set_close_handler(
			[self = shared_from_this()](const std::shared_ptr<avpn_session>& s)
			{
				self->on_session_close(s);
			});

		// 登记会话 (TCP 控制连接 key 使用客户端地址:端口).
		m_sessions[key] = session;

		co_await session->run_responder_tcp(std::move(stream));
		co_return;
	}

	net::awaitable<void> avpn_service::tcp_accept_loop(
		std::shared_ptr<net::ip::tcp::acceptor> acceptor)
	{
		auto self = shared_from_this();

		while (!m_abort)
		{
			boost::system::error_code ec;
			tcp::socket stream(m_main_context);
			co_await acceptor->async_accept(stream, net_awaitable[ec]);
			if (ec || m_abort)
				break;

			net::co_spawn(m_main_context,
				[this, self, stream = std::move(stream)]() mutable
					-> net::awaitable<void>
				{
					co_await on_gateway_tcp_connection(std::move(stream));
					co_return;
				}, net::detached);
		}

		co_return;
	}

	bool avpn_service::run_as_gateway()
	{
		// 打开 tun 设备.
		if (m_config.ifdev_.size() || m_config.ptun_fd_ >= 0 ||
			m_config.utun_fd_ >= 0)
		{
			m_tundev = std::make_unique<tun_device>(m_main_context);
			if (!m_tundev->open(m_config))
				XLOG_ERR << "open tun device failed";

			// 配置 gateway 自身地址.
			if (m_config.mtu_size_ <= 0)
				m_config.mtu_size_ = 1450;
			m_tundev->configure(m_subnet.address().to_uint(),
				static_cast<uint8_t>(m_subnet.prefix_length()),
				m_config.mtu_size_);
			// 配置 IPv6 内网地址 (<v6_subnet> + ffff:ffff).
			net::ip::address_v6 v6_net;
			uint8_t v6_prefix = 64;
			parse_v6_subnet(m_config.v6_subnet_, v6_net, v6_prefix);
			m_tundev->configure_v6(v6_net, v6_prefix, 0xffffffffu);

			start_tun_io_task();
		}

		// UDP 监听.
		for (auto& addr : m_config.udp_listens_)
		{
			net::ip::udp::endpoint ep;
			if (!parse_endpoint(addr, ep))
			{
				XLOG_ERR << "Invalid udp listen address: " << addr;
				continue;
			}

			auto socket = std::make_shared<net::ip::udp::socket>(m_main_context);
			boost::system::error_code ec;
			socket->open(ep.protocol(), ec);
			if (ec)
			{
				XLOG_ERR << "udp open failed: " << ec.message();
				continue;
			}
			socket->set_option(net::socket_base::reuse_address(true), ec);
			socket->bind(ep, ec);
			if (ec)
			{
				XLOG_ERR << "udp bind " << addr << " failed: " << ec.message();
				continue;
			}

			m_udp_sockets.push_back(socket);
			XLOG_INFO << "UDP listening on: " << addr;

			auto self = shared_from_this();
			for (std::size_t i = 0; i < udp_receive_concurrency; i++)
			{
				net::co_spawn(m_main_context,
					[this, self, socket]() -> net::awaitable<void>
					{
						co_await udp_receive_loop(socket);
						co_return;
					}, net::detached);
			}
		}

		// TCP 监听.
		for (auto& addr : m_config.tcp_listens_)
		{
			net::ip::tcp::endpoint ep;
			if (!parse_endpoint(addr, ep))
			{
				XLOG_ERR << "Invalid tcp listen address: " << addr;
				continue;
			}

			auto acceptor = std::make_shared<net::ip::tcp::acceptor>(m_main_context);
			boost::system::error_code ec;
			acceptor->open(ep.protocol(), ec);
			if (ec)
			{
				XLOG_ERR << "tcp open failed: " << ec.message();
				continue;
			}
			acceptor->set_option(net::socket_base::reuse_address(true), ec);
			acceptor->bind(ep, ec);
			if (ec)
			{
				XLOG_ERR << "tcp bind " << addr << " failed: " << ec.message();
				continue;
			}
			acceptor->listen(net::socket_base::max_listen_connections, ec);
			if (ec)
			{
				XLOG_ERR << "tcp listen " << addr << " failed: " << ec.message();
				continue;
			}

			m_tcp_acceptors.push_back(acceptor);
			XLOG_INFO << "TCP listening on: " << addr;

			auto self = shared_from_this();
			net::co_spawn(m_main_context,
				[this, self, acceptor]() -> net::awaitable<void>
				{
					co_await tcp_accept_loop(acceptor);
					co_return;
				}, net::detached);
		}

		// 带宽统计报告.
		auto self = shared_from_this();
		net::co_spawn(m_main_context,
			[this, self]() -> net::awaitable<void>
			{
				co_await bandwidth_report_loop();
				co_return;
			}, net::detached);

		return true;
	}

	//////////////////////////////////////////////////////////////////////////
	// client 模式

	net::awaitable<void> avpn_service::client_udp_receive_loop(
		std::shared_ptr<net::ip::udp::socket> socket)
	{
		auto self = shared_from_this();

		while (!m_abort)
		{
			std::vector<uint8_t> buf(avpn_max_packet_size);
			net::ip::udp::endpoint remote;
			boost::system::error_code ec;
			std::size_t n = co_await socket->async_receive_from(
				net::buffer(buf), remote, net_awaitable[ec]);
			if (ec || m_abort)
				break;

			buf.resize(n);
			if (m_tunnel)
			{
				m_tunnel->on_udp_packet(remote, std::string_view(
					reinterpret_cast<const char*>(buf.data()), buf.size()));
			}
		}

		co_return;
	}

	net::ip::address avpn_service::local_source_address(
		const net::ip::udp::endpoint& server)
	{
		// 用一个临时 UDP socket connect 到服务器, 内核会按当前路由表
		// 选出将使用的本地源地址, 不发送任何数据.
		boost::system::error_code ec;
		net::ip::udp::socket probe(m_main_context);
		probe.open(net::ip::udp::v4(), ec);
		if (ec)
			return {};
		probe.connect(server, ec);
		if (!ec)
		{
			auto ep = probe.local_endpoint(ec);
			if (!ec)
			{
				net::ip::address addr = ep.address();
				probe.close(ec);
				return addr;
			}
		}
		probe.close(ec);
		return {};
	}

	void avpn_service::renew_client_udp()
	{
		if (m_abort)
			return;

		// 关闭旧 socket 并取消挂起的接收操作 (旧接收循环随之退出).
		auto old = m_client_udp;
		boost::system::error_code ec;
		if (old)
		{
			old->cancel(ec);
			old->close(ec);
		}

		auto socket = std::make_shared<net::ip::udp::socket>(m_main_context);
		socket->open(net::ip::udp::v4(), ec);
		if (ec)
		{
			XLOG_ERR << "udp open failed on network switch: " << ec.message();
			m_client_udp = old;
			return;
		}

		// 尽量复用旧本地端口, 减小服务端迁移代价.
		if (old)
		{
			boost::system::error_code lec;
			auto old_local = old->local_endpoint(lec);
			if (!lec && old_local.port() != 0)
			{
				socket->set_option(net::socket_base::reuse_address(true), lec);
				socket->bind(net::ip::udp::endpoint(net::ip::udp::v4(),
					old_local.port()), lec);
				if (lec)
					XLOG_WARN << "rebind port " << old_local.port()
						<< " failed: " << lec.message();
			}
		}

		m_client_udp = socket;

		// 重建接收循环.
		auto self = shared_from_this();
		for (std::size_t i = 0; i < udp_receive_concurrency; i++)
		{
			net::co_spawn(m_main_context,
				[this, self, socket]() -> net::awaitable<void>
				{
					co_await client_udp_receive_loop(socket);
					co_return;
				}, net::detached);
		}

		// 立即发送保活, 让服务端尽快迁移会话 endpoint.
		if (m_tunnel)
			m_tunnel->notify_network_changed();

		boost::system::error_code lec;
		auto local = socket->local_endpoint(lec);
		if (!lec)
		{
			XLOG_INFO << "Client udp socket renewed, local: "
				<< local.address().to_string() << ":" << local.port();
		}
	}

	net::awaitable<void> avpn_service::client_network_monitor()
	{
		auto self = shared_from_this();
		net::ip::address last_addr;

		while (!m_abort && m_client_udp)
		{
			boost::system::error_code ec;
			m_netmon_timer.expires_after(std::chrono::seconds(2));
			co_await m_netmon_timer.async_wait(net_awaitable[ec]);
			if (m_abort || !m_client_udp)
				break;

			auto addr = local_source_address(m_nexthop_udp);
			if (addr.is_unspecified())
				continue;

			if (last_addr.is_unspecified())
			{
				// 首次观测到有效地址, 建立基线.
				last_addr = addr;
				continue;
			}

			if (addr != last_addr)
			{
				XLOG_INFO << "Network switch detected: "
					<< last_addr.to_string() << " -> " << addr.to_string();
				renew_client_udp();
				last_addr = addr;
			}
		}

		co_return;
	}

	net::awaitable<void> avpn_service::bandwidth_report_loop()
	{
		auto self = shared_from_this();

		while (!m_abort)
		{
			boost::system::error_code ec;
			m_bandwidth_timer.expires_after(std::chrono::seconds(10));
			co_await m_bandwidth_timer.async_wait(net_awaitable[ec]);
			if (m_abort)
				break;

			if (m_tunnel && m_tunnel->established())
			{
				XLOG_INFO << "Tunnel bandwidth vaddr: "
					<< net::ip::address_v4(m_tunnel->vaddr()).to_string()
					<< " up=" << m_tunnel->upload_rate() << "B/s"
					<< " down=" << m_tunnel->download_rate() << "B/s"
					<< " total_up=" << m_tunnel->upload_bytes() << "B"
					<< " total_down=" << m_tunnel->download_bytes() << "B";
			}

			for (auto& [key, session] : m_sessions)
			{
				if (!session || !session->established())
					continue;
				XLOG_INFO << "Session bandwidth vaddr: "
					<< net::ip::address_v4(session->vaddr()).to_string()
					<< " up=" << session->upload_rate() << "B/s"
					<< " down=" << session->download_rate() << "B/s"
					<< " total_up=" << session->upload_bytes() << "B"
					<< " total_down=" << session->download_bytes() << "B";
			}
		}

		co_return;
	}

	net::awaitable<void> avpn_service::client_tcp_connect()
	{
		auto self = shared_from_this();

		while (!m_abort)
		{
			tcp::socket stream(m_main_context);
			boost::system::error_code ec;

			co_await stream.async_connect(m_nexthop_tcp, net_awaitable[ec]);
			if (ec)
			{
				XLOG_ERR << "tcp connect " << endpoint_to_string(m_nexthop_tcp)
					<< " failed: " << ec.message();
				if (m_abort)
					break;

				net::steady_timer retry(m_main_context);
				retry.expires_after(std::chrono::seconds(3));
				co_await retry.async_wait(net_awaitable[ec]);
				continue;
			}

			boost::system::error_code nd_ec;
			stream.set_option(net::ip::tcp::no_delay(true), nd_ec);

			// 会话已结束或不存在时重建 (旧会话可能已被 close handler 释放).
			if (!m_tunnel || m_tunnel->aborted())
			{
				if (!create_client_tunnel())
					break;
			}

			auto session = m_tunnel;
			co_await session->run_initiator_tcp(std::move(stream));

			// run_initiator_tcp 握手成功后立即返回, 数据通道由后台
			// tcp_read_loop 继续; 只有握手失败才会在这里返回且未建立.
			if (session->established())
			{
				// 等待会话结束 (close handler 释放 m_tunnel 后重连).
				while (!m_abort && session == m_tunnel)
				{
					net::steady_timer wait_timer(m_main_context);
					wait_timer.expires_after(std::chrono::seconds(1));
					co_await wait_timer.async_wait(net_awaitable[ec]);
				}
				if (m_abort)
					break;
				XLOG_WARN << "tcp session ended, reconnecting in 3s";
			}
			else
			{
				XLOG_WARN << "tcp handshake failed, retrying in 3s";
			}

			if (m_abort)
				break;

			net::steady_timer retry(m_main_context);
			retry.expires_after(std::chrono::seconds(3));
			co_await retry.async_wait(net_awaitable[ec]);
		}

		co_return;
	}

	net::awaitable<void> avpn_service::wait_handshake_and_setup_tun()
	{
		net::steady_timer timer(m_main_context);

		while (!m_abort)
		{
			if (m_tunnel && m_tunnel->established())
			{
				// 使用协商的 vaddr/prefix/mtu 配置 tun.
				if (m_tundev)
				{
					m_tundev->configure(m_tunnel->vaddr(),
						m_tunnel->prefix_length(), m_tunnel->mtu());
					// 配置 IPv6 内网地址 (<协商子网> + vaddr).
					const auto& scfg = m_tunnel->negotiated_config();
					m_tundev->configure_v6(scfg.v6_net,
						scfg.v6_prefix, m_tunnel->vaddr());
				}
				// 应用 gateway 推送的路由 (passbyvpn / pushroutes).
				setup_system_routes();

				// 等待会话结束 (close handler 会释放 m_tunnel),
				// 之后继续等待下一次握手并重新配置.
				while (!m_abort && m_tunnel)
				{
					boost::system::error_code ec;
					timer.expires_after(std::chrono::seconds(1));
					co_await timer.async_wait(net_awaitable[ec]);
				}
				continue;
			}

			boost::system::error_code ec;
			timer.expires_after(std::chrono::seconds(1));
			co_await timer.async_wait(net_awaitable[ec]);
		}

		co_return;
	}

	// 解析路由目标字符串 (支持 "IP"、"IP/PREFIX", v4/v6) 为 Netlink 路由表项.
	static bool parse_route_string(const std::string& text, nl_route_entry& rt)
	{
#if defined(__linux__)
		auto slash = text.find('/');
		auto host = slash == std::string::npos ?
			text : text.substr(0, slash);
		auto prefix_text = slash == std::string::npos ?
			std::string() : text.substr(slash + 1);

		boost::system::error_code ec;
		auto v4 = net::ip::make_address_v4(host, ec);
		if (!ec)
		{
			rt.family = AF_INET;
			rt.dst = v4.to_string();
			rt.prefix = prefix_text.empty() ?
				32 : std::atoi(prefix_text.c_str());
			return true;
		}
		auto v6 = net::ip::make_address_v6(host, ec);
		if (!ec)
		{
			rt.family = AF_INET6;
			rt.dst = v6.to_string();
			rt.prefix = prefix_text.empty() ?
				128 : std::atoi(prefix_text.c_str());
			return true;
		}
		return false;
#else
		(void)text;
		(void)rt;
		return false;
#endif
	}

	// 解析路由目标: IP/CIDR 直接返回, 域名解析为全部地址.
	static std::vector<std::string> resolve_route_target(
		const std::string& target, net::io_context& ioc)
	{
		std::vector<std::string> out;
		auto slash = target.find('/');
		auto host = slash == std::string::npos ?
			target : target.substr(0, slash);

		boost::system::error_code ec;
		auto v4 = net::ip::make_address_v4(host, ec);
		if (!ec)
		{
			out.push_back(target);
			return out;
		}
		auto v6 = net::ip::make_address_v6(host, ec);
		if (!ec)
		{
			out.push_back(target);
			return out;
		}

		net::ip::tcp::resolver resolver(ioc);
		auto results = resolver.resolve(host, "https", ec);
		if (ec)
		{
			XLOG_ERR << "resolve bypass target failed: " << target
				<< ", " << ec.message();
			return out;
		}
		for (auto it = results.begin(); it != results.end(); ++it)
		{
			auto addr = it->endpoint().address();
			if (addr.is_v4())
				out.push_back(addr.to_string() + "/32");
			else
				out.push_back(addr.to_string() + "/128");
		}
		return out;
	}

	void avpn_service::setup_system_routes()
	{
		if (!m_tunnel || !m_tundev)
			return;

		const auto& scfg = m_tunnel->negotiated_config();
		if (!scfg.passbyvpn && scfg.routes.empty())
			return;

#if defined(__linux__)
		const std::string& dev = m_tundev->device_name();
		if (dev.empty())
			return;

		// 通过 Netlink 获取当前默认路由, 断开时恢复 (等同 ip route show default).
		m_saved_default_routes.clear();
		std::string nl_err;
		if (!nl_route_dump_default(m_saved_default_routes, nl_err))
			XLOG_ERR << "netlink dump default routes failed: " << nl_err;
		m_routes_modified = true;

		// 隧道对端 (gateway) 虚拟地址: 子网网络地址.
		uint32_t gw = m_tunnel->vaddr();
		auto prefix = m_tunnel->prefix_length();
		if (prefix < 32)
			gw &= ~((1u << (32 - prefix)) - 1u);
		std::string gw_addr = net::ip::address_v4(gw).to_string();

		// 解析物理默认网关, 用于钉住服务器地址与绕过路由.
		std::string phys_via, phys_dev;
		for (auto& rt : m_saved_default_routes)
		{
			if (!rt.gateway.empty() && !rt.ifname.empty())
			{
				phys_via = rt.gateway;
				phys_dev = rt.ifname;
				break;
			}
		}

		// 保护 VPN 服务器地址, 避免隧道连接本身陷入隧道.
		std::string server_ip;
		if (m_use_tcp_transport && m_nexthop_tcp.address().is_v4())
			server_ip = m_nexthop_tcp.address().to_string();
		else if (!m_use_tcp_transport && m_nexthop_udp.address().is_v4())
			server_ip = m_nexthop_udp.address().to_string();

		if (!server_ip.empty() && !phys_via.empty() && !phys_dev.empty())
		{
			nl_route_entry rt;
			rt.family = AF_INET;
			rt.dst = server_ip;
			rt.prefix = 32;
			rt.gateway = phys_via;
			rt.ifname = phys_dev;
			if (nl_route_replace(rt, nl_err))
				XLOG_INFO << "Pin server route: " << server_ip
					<< " via " << phys_via << " dev " << phys_dev;
			else
				XLOG_ERR << "pin server route failed: " << nl_err;
		}

		// 删除现有默认路由, 避免与隧道默认路由竞争.
		for (auto& rt : m_saved_default_routes)
		{
			if (rt.ifname == dev)
				continue;
			if (nl_route_delete(rt, nl_err))
				XLOG_INFO << "Delete default route: "
					<< nl_route_to_string(rt);
			else
				XLOG_DBG << "skip delete default route: " << nl_err;
		}

		if (scfg.passbyvpn)
		{
			nl_route_entry rt;
			rt.family = AF_INET;
			rt.dst = "0.0.0.0";
			rt.prefix = 0;
			rt.gateway = gw_addr;
			rt.ifname = dev;
			if (nl_route_replace(rt, nl_err))
				XLOG_INFO << "Default route via tunnel: " << gw_addr
					<< " dev " << dev;
			else
				XLOG_ERR << "set default route failed: " << nl_err;

			// 隧道出口 NAT: 绑定本地源地址的流量统一以虚拟地址出口.
			::system(("iptables -t nat -C POSTROUTING -o " + dev +
				" -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o " +
				dev + " -j MASQUERADE 2>/dev/null").c_str());
		}

		for (auto& r : scfg.routes)
		{
			if (r.empty())
				continue;
			nl_route_entry rt;
			if (!parse_route_string(r, rt))
			{
				XLOG_ERR << "parse push route failed: " << r;
				continue;
			}
			rt.ifname = dev;
			if (nl_route_replace(rt, nl_err))
				XLOG_INFO << "Push route: " << r << " dev " << dev;
			else
				XLOG_ERR << "push route failed: " << r << ", " << nl_err;
		}

		// 绕过隧道走物理线路的目标 (更具体的路由优先于默认路由).
		for (auto& b : m_config.bypassroutes_)
		{
			if (b.empty() || phys_via.empty() || phys_dev.empty())
				continue;
			auto targets = resolve_route_target(b, m_main_context);
			for (auto& t : targets)
			{
				nl_route_entry rt;
				if (!parse_route_string(t, rt))
					continue;
				rt.gateway = phys_via;
				rt.ifname = phys_dev;
				if (nl_route_replace(rt, nl_err))
					XLOG_INFO << "Bypass route: " << t << " via "
						<< phys_via << " dev " << phys_dev;
				else
					XLOG_ERR << "bypass route failed: " << t
						<< ", " << nl_err;
			}
		}

		// 启动周期刷新, 域名解析结果变化后自动更新绕过路由.
		m_bypass_phys_via = phys_via;
		m_bypass_phys_dev = phys_dev;
		if (!m_config.bypassroutes_.empty() && !m_bypass_refresh_started)
		{
			m_bypass_refresh_started = true;
			auto self = shared_from_this();
			net::co_spawn(m_main_context,
				[this, self]() -> net::awaitable<void>
				{
					co_await bypass_route_refresh_loop();
					co_return;
				}, net::detached);
		}
#else
		XLOG_WARN << "System route setup not supported on this platform";
#endif
	}

	net::awaitable<void> avpn_service::bypass_route_refresh_loop()
	{
		while (!m_abort)
		{
			boost::system::error_code ec;
			m_bypass_timer.expires_after(std::chrono::seconds(60));
			co_await m_bypass_timer.async_wait(net_awaitable[ec]);
			if (m_abort || !m_routes_modified)
				continue;
			refresh_bypass_routes();
		}
		co_return;
	}

	void avpn_service::refresh_bypass_routes()
	{
		if (m_bypass_phys_via.empty() || m_bypass_phys_dev.empty())
			return;

		for (auto& b : m_config.bypassroutes_)
		{
			if (b.empty())
				continue;
			auto targets = resolve_route_target(b, m_main_context);
			for (auto& t : targets)
			{
				nl_route_entry rt;
				if (!parse_route_string(t, rt))
					continue;
				rt.gateway = m_bypass_phys_via;
				rt.ifname = m_bypass_phys_dev;
				std::string nl_err;
				if (nl_route_replace(rt, nl_err))
					XLOG_DBG << "Refresh bypass route: " << t;
				else
					XLOG_DBG << "refresh bypass route failed: "
						<< t << ", " << nl_err;
			}
		}
	}

	void avpn_service::restore_system_routes()
	{
		if (!m_routes_modified)
			return;
		m_routes_modified = false;

#if defined(__linux__)
		std::string nl_err;
		if (m_tundev)
		{
			const std::string& dev = m_tundev->device_name();
			if (!dev.empty())
			{
				nl_route_entry rt;
				rt.family = AF_INET;
				rt.dst = "0.0.0.0";
				rt.prefix = 0;
				rt.ifname = dev;
				if (!nl_route_delete(rt, nl_err))
					XLOG_DBG << "delete default route failed: " << nl_err;
				::system(("iptables -t nat -D POSTROUTING -o " + dev +
					" -j MASQUERADE 2>/dev/null").c_str());
			}
		}

		for (auto& rt : m_saved_default_routes)
		{
			if (nl_route_replace(rt, nl_err))
				XLOG_INFO << "Restore default route: "
					<< nl_route_to_string(rt);
			else
				XLOG_DBG << "restore default route failed: " << nl_err;
		}
		m_saved_default_routes.clear();
#endif
	}

	bool avpn_service::run_as_client()
	{
		// 解析 nexthop, 支持 "udp://host:port" 或 "tcp://host:port".
		std::string nexthop = m_config.nexthop_;
		if (nexthop.compare(0, 6, "tcp://") == 0)
		{
			m_use_tcp_transport = true;
			nexthop = nexthop.substr(6);
		}
		else if (nexthop.compare(0, 6, "udp://") == 0)
		{
			nexthop = nexthop.substr(6);
		}

		if (m_use_tcp_transport)
		{
			if (!parse_endpoint(nexthop, m_nexthop_tcp))
			{
				XLOG_ERR << "Invalid nexthop: " << m_config.nexthop_;
				return false;
			}
		}
		else
		{
			if (!parse_endpoint(nexthop, m_nexthop_udp))
			{
				XLOG_ERR << "Invalid nexthop: " << m_config.nexthop_;
				return false;
			}
		}

		// 打开 tun 设备.
		if (m_config.ifdev_.size() || m_config.ptun_fd_ >= 0 ||
			m_config.utun_fd_ >= 0)
		{
			m_tundev = std::make_unique<tun_device>(m_main_context);
			if (!m_tundev->open(m_config))
				XLOG_ERR << "open tun device failed";
			start_tun_io_task();
		}

		auto self = shared_from_this();

		// 创建客户端会话.
		if (!create_client_tunnel())
			return false;

		if (m_use_tcp_transport)
		{
			net::co_spawn(m_main_context,
				[this, self]() -> net::awaitable<void>
				{
					co_await client_tcp_connect();
					co_return;
				}, net::detached);
		}
		else
		{
			// UDP socket.
			m_client_udp = std::make_shared<net::ip::udp::socket>(m_main_context);
			boost::system::error_code ec;
			m_client_udp->open(net::ip::udp::v4(), ec);
			if (ec)
			{
				XLOG_ERR << "udp open failed: " << ec.message();
				return false;
			}

			// 启动握手.
			net::co_spawn(m_main_context,
				[this, self]() -> net::awaitable<void>
				{
					co_await m_tunnel->run_initiator_udp(m_nexthop_udp);
					co_return;
				}, net::detached);

			// UDP 接收循环 (持有 socket 引用, 重建后旧循环随 socket 关闭退出).
			auto client_sock = m_client_udp;
			for (std::size_t i = 0; i < udp_receive_concurrency; i++)
			{
				net::co_spawn(m_main_context,
					[this, self, client_sock]() -> net::awaitable<void>
					{
						co_await client_udp_receive_loop(client_sock);
						co_return;
					}, net::detached);
			}

			// 网络切换监控: 检测本地出口地址变化, 变化时重建 UDP socket.
			net::co_spawn(m_main_context,
				[this, self]() -> net::awaitable<void>
				{
					co_await client_network_monitor();
					co_return;
				}, net::detached);
		}

		// 带宽统计报告.
		net::co_spawn(m_main_context,
			[this, self]() -> net::awaitable<void>
			{
				co_await bandwidth_report_loop();
				co_return;
			}, net::detached);

		// 等待握手完成后配置 tun.
		net::co_spawn(m_main_context,
			[this, self]() -> net::awaitable<void>
			{
				co_await wait_handshake_and_setup_tun();
				co_return;
			}, net::detached);

		return true;
	}

	bool avpn_service::create_client_tunnel()
	{
		m_tunnel = avpn_session::create(m_main_context, m_config,
			session_role::initiator);
		if (!m_tunnel)
			return false;

		m_tunnel->set_udp_send_handler(
			[self = shared_from_this()](const net::ip::udp::endpoint& ep,
				std::vector<uint8_t> wire)
			{
				if (self->m_client_udp)
					self->m_client_udp->async_send_to(
						net::buffer(wire), ep, net::detached);
			});

		m_tunnel->set_ip_packet_handler(
			[self = shared_from_this()](std::vector<uint8_t> pkt)
			{
				self->write_to_tun(std::move(pkt));
			});

		m_tunnel->set_close_handler(
			[self = shared_from_this()](const std::shared_ptr<avpn_session>&)
			{
				// 会话关闭: 释放引用并恢复被改动的系统路由,
				// 重连成功后由 wait_handshake_and_setup_tun 重新接管.
				self->m_tunnel.reset();
				self->restore_system_routes();
			});

		return true;
	}

	//////////////////////////////////////////////////////////////////////////

	bool avpn_service::start()
	{
		XLOG_DBG << "avpn_service::start, main thread id: " << std::this_thread::get_id();

		m_abort = false;
		m_started_at = std::time(nullptr);

		// 配置了 controller 时, 启动控制通道 (连接 launcher 的 /rpc 服务).
		if (!m_config.controller_.empty())
		{
			m_controller = std::make_shared<vpn_controller>(
				m_ioc_pool, m_config, shared_from_this());
			m_controller->start();
		}

		if (!m_config.nexthop_.empty())
			return run_as_client();

		if (!m_config.udp_listens_.empty() || !m_config.tcp_listens_.empty())
			return run_as_gateway();

		XLOG_WARN << "No nexthop or listen address configured";
		return true;
	}

	void avpn_service::stop()
	{
		XLOG_DBG << "avpn_service::stop";

		m_abort = true;

		// 停止控制通道.
		if (m_controller)
		{
			m_controller->stop();
			m_controller.reset();
		}

		// 取消周期任务定时器, 唤醒挂起的协程检查 m_abort 后自然退出,
		// 使 main_io_context_.run() 无需 stop() 即可返回.
		m_bandwidth_timer.cancel();
		m_bypass_timer.cancel();
		m_netmon_timer.cancel();

		boost::system::error_code ec;

		// 关闭所有会话.
		for (auto& [key, session] : m_sessions)
		{
			if (session)
				session->close();
		}
		m_sessions.clear();

		if (m_tunnel)
		{
			m_tunnel->disconnect();
			m_tunnel.reset();
		}

		// 恢复被修改的系统路由.
		restore_system_routes();

		// 关闭 UDP socket.
		for (auto& socket : m_udp_sockets)
		{
			if (socket)
				socket->close(ec);
		}
		m_udp_sockets.clear();

		if (m_client_udp)
		{
			m_client_udp->close(ec);
			m_client_udp.reset();
		}

		// 关闭 TCP acceptor.
		for (auto& acceptor : m_tcp_acceptors)
		{
			if (acceptor)
				acceptor->close(ec);
		}
		m_tcp_acceptors.clear();

		// 关闭 tun.
		if (m_tundev)
			m_tundev->close();
	}

	boost::json::object avpn_service::status_json() const
	{
		using namespace boost::json;

		// 公钥原始字节转 hex 前缀（供状态展示，避免二进制污染 JSON）。
		auto pub_hex = [](const std::string& pub) -> std::string {
			static const char* hex = "0123456789abcdef";
			std::string out;
			out.reserve(16);
			for (std::size_t i = 0; i < pub.size() && out.size() < 16; i++) {
				out.push_back(hex[static_cast<unsigned char>(pub[i]) >> 4]);
				out.push_back(hex[pub[i] & 0xf]);
			}
			return out;
		};

		object rep;
		rep["ts"] = static_cast<int64_t>(std::time(nullptr));
		rep["started_at"] = static_cast<int64_t>(m_started_at);
		rep["uptime"] = m_started_at > 0 ?
			static_cast<int64_t>(std::time(nullptr) - m_started_at) : 0;
		rep["mode"] = m_config.nexthop_.empty() ? "gateway" : "client";

		int64_t rx_total = 0;
		int64_t tx_total = 0;
		int64_t rx_rate = 0;
		int64_t tx_rate = 0;
		int active = 0;
		array sessions;

		auto add_session = [&](const std::shared_ptr<avpn_session>& session)
		{
			if (!session)
				return;

			object s;
			s["vaddr"] = net::ip::address_v4(session->vaddr()).to_string();
			s["established"] = session->established();
			s["transport"] = session->transport() == transport_type::tcp ?
				"tcp" : "udp";
			s["peer"] = session->peer_public_key().empty() ?
				"" : pub_hex(session->peer_public_key());
			auto remote = session->remote_udp();
			s["remote"] = remote.address().to_string() + ":" +
				std::to_string(remote.port());
			s["rx_bytes"] = session->upload_bytes();
			s["tx_bytes"] = session->download_bytes();
			s["rx_rate_bps"] = session->upload_rate();
			s["tx_rate_bps"] = session->download_rate();

			if (session->established())
			{
				active++;
				rx_total += session->upload_bytes();
				tx_total += session->download_bytes();
				rx_rate += session->upload_rate();
				tx_rate += session->download_rate();
			}
			sessions.emplace_back(std::move(s));
		};

		if (m_tunnel)
			add_session(m_tunnel);
		for (auto& [key, session] : m_sessions)
			add_session(session);

		rep["active_connections"] = active;

		object global;
		global["rx_bytes"] = rx_total;
		global["tx_bytes"] = tx_total;
		rep["global"] = std::move(global);

		object rates;
		rates["rx_rate_bps"] = static_cast<double>(rx_rate);
		rates["tx_rate_bps"] = static_cast<double>(tx_rate);
		rep["rates"] = std::move(rates);

		rep["sessions"] = std::move(sessions);
		return rep;
	}

} // namespace libavpn
