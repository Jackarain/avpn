//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#include "avpn/vpn_tunnel.hpp"
#include "avpn/avpn.hpp"

#include "zlib.h"

namespace avpn
{
	//////////////////////////////////////////////////////////////////////////

	const static std::string test_google_key = "VLTATWJGVH5W7V7DX6V436FG74";
	const static int normal_mtu = 1500;
	const static int static_mtu = 1400;
	const static uint16_t avpn_protocol_version = 1;
	const static int max_client_udp_socket = 4;


	//////////////////////////////////////////////////////////////////////////

	vpn_message::vpn_message(vpn_message&& msg) noexcept
		: type(msg.type)
		, content_(std::move(msg.content_))
	{}

	vpn_message& vpn_message::operator=(vpn_message&& msg) noexcept
	{
		type = msg.type;
		content_ = std::move(msg.content_);

		return *this;
	}

	//////////////////////////////////////////////////////////////////////////

	vpn_remote_endpoint::vpn_remote_endpoint(
		size_t size /*= 0*/, Identity identity /*= Identity::avpn_client*/)
		: endpoints_(size)
		, identity_(identity)
	{}

	void vpn_remote_endpoint::reset(size_t size /*= 0*/, Identity identity /*= Identity::avpn_client*/)
	{
		endpoints_.resize(size);
		identity_ = identity;
	}

	udp::endpoint vpn_remote_endpoint::acquire() const noexcept
	{
		std::shared_lock lock(mutex_);

		if (identity_ == Identity::avpn_client)
			return client_endpoint();

		return server_endpoint();
	}

	std::tuple<int, udp::endpoint> vpn_remote_endpoint::next_endpoint() const noexcept
	{
		auto index = next_endpoint_;
		const auto& endp = endpoints_[next_endpoint_];

		next_endpoint_ = (next_endpoint_ + 1) % endpoints_.size();

		return { index, endp };
	}

	void vpn_remote_endpoint::update(const udp::endpoint& endp) noexcept
	{
		std::lock_guard lock(mutex_);
		endpoints_.push_back(endp);
	}

	void vpn_remote_endpoint::update(const udp::endpoint& endp, int index) noexcept
	{
		std::lock_guard lock(mutex_);
		endpoints_[index] = endp;
	}

	size_t vpn_remote_endpoint::size() const noexcept
	{
		std::shared_lock lock(mutex_);
		return endpoints_.size();
	}

	void vpn_remote_endpoint::clear() noexcept
	{
		std::lock_guard lock(mutex_);
		endpoints_.clear();
	}

	void vpn_remote_endpoint::resize(size_t size)
	{
		std::lock_guard lock(mutex_);
		endpoints_.resize(size);
	}

	const udp::endpoint& vpn_remote_endpoint::client_endpoint() const noexcept
	{
		const auto& endp = endpoints_[next_endpoint_];
		next_endpoint_ = (next_endpoint_ + 1) % endpoints_.size();
		return endp;
	}

	const udp::endpoint& vpn_remote_endpoint::server_endpoint() const noexcept
	{
		return endpoints_.back();
	}

	//////////////////////////////////////////////////////////////////////////

	vpn_connection::vpn_connection(boost::asio::any_io_executor executor,
		const std::string& host, fec::matrix* enc_matrix, fec::matrix* dec_matrix)
		: dec_matrix_(dec_matrix)
		, keepalive_(time_clock::steady_clock::now())
		, enc_matrix_(enc_matrix)
		, remote_host_(host)
		, tcp_stream_(executor)
		, wait_timer_(executor)
	{}

	vpn_connection::~vpn_connection()
	{
		if (remote_host_.empty())
			LOG_WARN << "vpn connection leave: " << connection_id_;
		else
			LOG_WARN << "vpn connection leave: " << connection_id_ << ", remote: " << remote_host_;
	}

	void vpn_connection::reset()
	{
		boost::system::error_code ignore_ec;

		tcp_stream_.close(ignore_ec);

		// tcp_msg_deque_.clear();
		// fec_enc_.clear();
		// fec_dec_.reset();

		keepalive_ = time_clock::steady_clock::now();
		enc_tm_ = keepalive_;

		// remote_host_.clear();
		// endps_.clear();
		// vnet_ = 0;

		deque_writing_ = false;
		fec_enc_size_ = 0;
		gid_ = 0;

		wait_timer_.cancel(ignore_ec);

		connection_id_ = -1;
	}

	//////////////////////////////////////////////////////////////////////////

	bool operator<(const vpn_connection_ptr& lh, const vpn_connection_ptr& rh)
	{
		if (lh < rh)
			return true;
		return false;
	}

	bool operator<(const vpn_connection_weak_ptr& lh, const vpn_connection_weak_ptr& rh)
	{
		auto lhp = lh.lock();
		auto rhp = rh.lock();

		if (lhp < rhp)
			return true;
		return false;
	}

	//////////////////////////////////////////////////////////////////////////

	vpn_tunnel::vpn_tunnel(boost::asio::io_context& io, io_context_pool& ios,
		const tunnel_params& params, avpn_service& service)
		: m_vpn_service(service)
		, m_main_ioc(io)
		, m_ioc_pool(ios)
		, m_params(params)
		, m_enc_matrix(fec::reedsolomon::build_matrix((size_t)(
			params.data_shards_ + params.parity_shards_), params.data_shards_))
		, m_subnet(boost::asio::ip::make_network_v4(params.subnet_))
		, m_ip_assigner(m_subnet.hosts())
		, m_ip_iterator(++m_ip_assigner.begin())
		, m_fec_timer(m_main_ioc)
		, m_connect_retry_timer(m_main_ioc)
		, m_keepalive_timer(m_main_ioc)
	{
		m_server_guid = gen_unique_string(32);
		LOG_DBG << "Start unique counter: " << m_server_guid;
	}

	vpn_tunnel::~vpn_tunnel()
	{
		LOG_WARN << "vpn_tunnel::~vpn_tunnel()";
	}





	//////////////////////////////////////////////////////////////////////////
	/// Server 相关实现.

	void vpn_tunnel::start_server_listen(
		std::vector<std::string> tcp_listens, std::vector<std::string> udp_listens)
	{
		m_tcp_listens = tcp_listens;
		m_udp_listens = udp_listens;

		// 服务器身份.
		m_identity = Identity::avpn_server;

		m_abort = false;

		// 开始启动tcp客户端, 即tcp服务器.
		LOG_DBG << "Start tcp accept socket...";
		init_tcp_acceptors();

		// 启动TCP acceptor服务.
		boost::asio::co_spawn(m_main_ioc.get_executor(),
			[this]() mutable -> boost::asio::awaitable<void>
			{
				int pool_size = static_cast<int>(m_ioc_pool.pool_size());
				for (int i = 0; i < pool_size; i++)
				{
					for (auto& a : m_ws_acceptors)
					{
						boost::asio::co_spawn(a.get_executor(),
							start_tcp_listen(a), boost::asio::detached);
					}
				}
				co_return;
			}, boost::asio::detached);

		// 启动UDP通信.
		LOG_DBG << "Start udp socket...";
		boost::asio::co_spawn(m_main_ioc.get_executor(),
			[this]() mutable -> boost::asio::awaitable<void>
			{
				co_await start_udp_server();
				LOG_WARN << "start_server_listen, Udp server quit...";
				co_return;
			}, boost::asio::detached);

		// 启动fec调度器.
		if (m_params.data_shards_ > 1)
		{
			LOG_DBG << "Start fec dispatch...";
			boost::asio::co_spawn(m_main_ioc.get_executor(),
				[this]() mutable -> boost::asio::awaitable<void>
				{
					co_await run_fec_dispatch();
					LOG_WARN << "start_server_listen, Fec dispatch quit...";
					co_return;
				}, boost::asio::detached);
		}

		// 发起保活协程.
		keepalive();

		tunnel_status cs;
		cs.status_ = connection_status::st_listen;

		m_vpn_service.on_status(cs);
	}

	void vpn_tunnel::server_forward_tun(vpn_message&& msg, endpoint_pair&& endp)
	{
		auto connection_ptr = lookup_connection(endp.dst_.address().to_v4().to_uint());
		if (!connection_ptr)
		{
			LOG_ERR << "server_forward_tun, t -> c, lost connection: " << endp;
			return;
		}

		if (endp.type_ == avpn::ip_icmp)
			LOG_DBG << "server_forward_tun, t -> c, icmp: " << endp;

		auto& stream = connection_ptr->tcp_stream_;
		boost::asio::co_spawn(stream.get_executor(),
			forward_tunnel_write(connection_ptr, std::move(msg)), boost::asio::detached);
	}





	//////////////////////////////////////////////////////////////////////////
	/// Client 相关实现.

	void vpn_tunnel::start_client_connect(const std::vector<std::string>& upstreams)
	{
		m_upstreams = upstreams;
		m_identity = Identity::avpn_client;
		m_abort = false;

		if (m_params.data_shards_ > 1)
		{
			LOG_DBG << "Start fec dispatch";
			boost::asio::co_spawn(m_main_ioc.get_executor(),
				[this]() mutable -> boost::asio::awaitable<void>
				{
					co_await run_fec_dispatch();
					LOG_WARN << "start_client_connect, Fec dispatch quit...";
					co_return;
				}, boost::asio::detached);
		}

		// 发起客户端TCP连接协程.
		LOG_DBG << "Start tcp socket";
		start_client_tcp_connect();

		// 发起保活协程.
		keepalive();
	}

	void vpn_tunnel::client_forward_tun(vpn_message&& msg, endpoint_pair&& endp)
	{
		auto connection_ptr = m_client.lock();
		if (!connection_ptr)
		{
			LOG_ERR << "client_forward_tun, t -> s, lost connection: " << endp;
			return;
		}

		if (endp.type_ == avpn::ip_icmp)
			LOG_DBG << "client_forward_tun, t -> s, icmp: " << endp;

		auto& stream = connection_ptr->tcp_stream_;
		boost::asio::co_spawn(stream.get_executor(),
			forward_tunnel_write(connection_ptr, std::move(msg)), boost::asio::detached);
	}





	//////////////////////////////////////////////////////////////////////////
	/// 共同实现.

	void vpn_tunnel::close()
	{
		m_abort = true;

		boost::system::error_code ignore_ec;
		m_fec_timer.cancel(ignore_ec);

		if (m_identity == Identity::avpn_server)
		{
			for (auto& a : m_ws_acceptors)
				a.close(ignore_ec);

			{
				std::shared_lock lock(m_remotes_mtx);
				for ([[maybe_unused]] auto& [id, connection_ptr] : m_remotes)
				{
					auto connection = connection_ptr.lock();
					if (!connection)
						continue;

					connection->reset();
					LOG_DBG << "Close tcp stream: " << connection->connection_id_;
				}
			}

			{
				std::shared_lock lock(m_incomings_mtx);
				for ([[maybe_unused]] auto& [id, connection_ptr] : m_incomings)
				{
					auto connection = connection_ptr.lock();
					if (!connection)
						continue;

					connection->reset();
					LOG_DBG << "Close incoming tcp stream: " << id;
				}
			}

			m_ws_acceptors.clear();
		}

		if (m_identity == Identity::avpn_client)
		{
			m_cancel_sig.emit(boost::asio::cancellation_type::all);

			auto connection_ptr = m_client.lock();
			if (connection_ptr)
			{
				connection_ptr->reset();
				LOG_DBG << "Close tcp client stream";
			}
		}

		for (auto& u : m_udp_sockets)
			u->sock_.close(ignore_ec);

		m_connect_retry_timer.cancel(ignore_ec);
		m_keepalive_timer.cancel(ignore_ec);

		m_routes.clear();
		m_prefix_length = -1;
		// m_remote_endps.clear();
		m_client = {};
		m_incomings.clear();
		m_remotes.clear();
		// m_udp_sockets.clear();

		LOG_WARN << "Close vpn_tunnel...";
	}

	boost::asio::ip::network_v4 vpn_tunnel::vnet_ipaddr() const
	{
		return m_vnet_ipaddr;
	}

	boost::asio::ip::network_v4 vpn_tunnel::vsubnet() const
	{
		// 总是使用网络中第1个地址作为网关.
		auto endp = *m_subnet.hosts().begin();
		return boost::asio::ip::make_network_v4(endp, m_subnet.prefix_length());
	}

	bool vpn_tunnel::init_tcp_acceptors()
	{
		if (m_tcp_listens.empty())
			return false;

		boost::system::error_code ec;

		for (const auto& wsd : m_tcp_listens)
		{
			tcp::endpoint endp;
			[[maybe_unused]] bool ipv6only = make_listen_endpoint(wsd, endp, ec);
			if (ec)
			{
				LOG_ERR << "TCP server listen error: " << wsd << ", ec: " << ec.message();
				return false;
			}

			tcp::acceptor a{ m_ioc_pool.get_io_context() };

			a.open(endp.protocol(), ec);
			if (ec)
			{
				LOG_ERR << "TCP server open accept error: " << ec.message();
				return false;
			}

			a.set_option(boost::asio::socket_base::reuse_address(true), ec);
			if (ec)
			{
				LOG_ERR << "TCP server accept set option failed: " << ec.message();
				return false;
			}

			if (ipv6only)
			{
				a.set_option(boost::asio::ip::v6_only(true), ec);
				if (ec)
				{
					LOG_ERR << "TCP server accept set v6_only failed: " << ec.message();
					return false;
				}
			}

			a.bind(endp, ec);
			if (ec)
			{
				LOG_ERR << "TCP server bind failed: " << ec.message()
					<< ", address: " << endp.address().to_string() << ", port: " << endp.port();
				return false;
			}

			a.listen(boost::asio::socket_base::max_listen_connections, ec);
			if (ec)
			{
				LOG_ERR << "TCP server listen failed: " << ec.message();
				return false;
			}

			m_ws_acceptors.emplace_back(std::move(a));
		}

		return true;
	}





	//////////////////////////////////////////////////////////////////////////
	/// Server 相关实现.

	boost::asio::awaitable<void> vpn_tunnel::start_tcp_listen(tcp::acceptor& a)
	{
		boost::system::error_code error;
		while (!m_abort)
		{
			tcp::socket socket(m_ioc_pool.get_io_context());
			co_await a.async_accept(socket, uawaitable[error]);
			if (error)
			{
				LOG_ERR << "TCP server, async_accept: " << error.message();

				if (error == boost::asio::error::operation_aborted ||
					error == boost::asio::error::bad_descriptor)
				{
					co_return;
				}

				if (!a.is_open())
					co_return;

				continue;
			}

			{
				boost::asio::socket_base::keep_alive option(true);
				socket.set_option(option, error);
			}

			{
				boost::asio::ip::tcp::no_delay option(true);
				socket.set_option(option);
			}

			static std::atomic_size_t id{ 1 };
			size_t connection_id = id++;

			LOG_DBG << "start_tcp_listen, incoming id: " << connection_id;

			auto executor = socket.get_executor();
			boost::asio::co_spawn(executor,
				start_tcp_connection(connection_id, std::move(socket)), boost::asio::detached);
		}

		LOG_WARN << "start_tcp_listen exit ...";
		co_return;
	}

	std::string vpn_tunnel::make_communication_guid()
	{
		// 协议格式:
		// type(number)
		// tail(skip)
		// communication guid(string)

		std::string msg(normal_mtu, 0);
		stream_endian::bitstream writer((uint8_t*)msg.data(), normal_mtu);

		writer.WriteExponentialGolomb(vpt_communication_guid);
		writer.WriteTail();
		writer.WriteString(m_server_guid.data(), m_server_guid.size());

		msg.resize(writer.ByteOffset());

		return msg;
	}

	boost::asio::awaitable<void> vpn_tunnel::start_tcp_connection(size_t connection_id, tcp::socket stream)
	{
		boost::system::error_code ec;
		std::string remote_host;

		auto endp = stream.remote_endpoint(ec);
		if (!ec)
		{
			if (endp.address().is_v6())
			{
				remote_host = "[" + endp.address().to_string()
					+ "]:" + std::to_string(endp.port());
			}
			else
			{
				remote_host = endp.address().to_string()
					+ ":" + std::to_string(endp.port());
			}
		}

		// 创建connection, 只有在握手完成才加入m_remotes容器进行管理.
		auto executor = stream.get_executor();
		vpn_connection_ptr connection_ptr =
			std::make_shared<vpn_connection>(
				executor, remote_host, &m_enc_matrix, &m_dec_matrix);

		// 将已经连接的socket和分配到的connection_id, 保存到connection_ptr中.
		connection_ptr->tcp_stream_ = std::move(stream);
		connection_ptr->connection_id_ = connection_id;

		// 将connection_ptr保存到临时连接表.
		add_incoming(connection_ptr, connection_id);

		LOG_DBG << "Client incoming: " << remote_host << ", connection id: " << connection_id;

		// 对所有连接上来的client统一发送server的
		// 通信guid, 以便client区别所连接的server.
		co_await forward_tcp_write(connection_ptr, make_communication_guid());

		// 启动读取协议协程.
		boost::asio::co_spawn(executor,
			[this, connection_ptr]() mutable -> boost::asio::awaitable<void>
			{
				// server开始循环读取tcp消息.
				co_await server_tcp_read_loop(connection_ptr);
			},
			[this, id = connection_id](std::exception_ptr) mutable
			{
				remove_incoming(id);
			});

		co_return;
	}

	boost::asio::awaitable<void> vpn_tunnel::server_tcp_read_loop(vpn_connection_ptr connection_ptr)
	{
		auto connection_id = connection_ptr->connection_id_;
		auto stream = &connection_ptr->tcp_stream_;

		boost::asio::streambuf buffer;
		int start_len_tag = 0;

		LOG_DBG << "server_tcp_read_loop, connection id: " << connection_id << ", started.";

		while (!m_abort)
		{
			// 读取一个message到buffer.
			start_len_tag = co_await tcp_read_message(*stream, buffer, connection_id);

			// 发生错误则退出循环.
			if (start_len_tag < 0)
				break;

			// 解析message, 先解析出type.
			const uint8_t* bufptr = boost::asio::buffer_cast<const uint8_t*>(buffer.data());
			stream_endian::bitstream reader(bufptr, start_len_tag);
			uint32_t type = 0;

			if (!reader.ReadExponentialGolomb(&type))
			{
				LOG_ERR << "server_tcp_read_loop, id: "
					<< connection_id << ", verify message type fail.";
				co_return;
			}

			// 处理协议数据.
			co_await process_tcp_packet(type, reader, connection_ptr);

			// 消费掉读取的数据.
			buffer.consume(start_len_tag);

			// 如果作为服务器端时, 连接id发生变化, 说明client中断tcp连接
			// 后重连成功, 此时connection_ptr已经被替换成原来断开时的connection.
			if (connection_ptr->connection_id_ != connection_id)
			{
				LOG_FMT("server_tcp_read_loop, connection id: {} recover to {}",
						connection_id, connection_ptr->connection_id_);

				connection_id = connection_ptr->connection_id_;
				stream = &connection_ptr->tcp_stream_;
			}
		}

		// 如果connection遇到网络错误, 则尝试等待60s, 让client能有机会恢复tcp连接.
		if (!m_abort && connection_ptr->vnet_ != 0)
		{
			LOG_WARN << "server_tcp_read_loop, id: " << connection_id << " wait client for recover...";

			auto& wait_timer = connection_ptr->wait_timer_;
			boost::beast::error_code ec;

			wait_timer.expires_from_now(std::chrono::seconds(60));
			co_await wait_timer.async_wait(uawaitable[ec]);
		}

		co_return;
	}

	boost::asio::awaitable<void> vpn_tunnel::start_udp_server()
	{
		BOOST_ASSERT(m_identity == Identity::avpn_server);
		boost::system::error_code ec;

		for (auto& listen : m_udp_listens)
		{
			LOG_DBG << "start_udp_server, udp listen: " << listen;

			udp::endpoint endp;
			[[maybe_unused]] bool ipv6only = make_listen_endpoint(listen, endp, ec);
			if (ec)
			{
				LOG_ERR << "start_udp_server, make udp error: " << listen << ", ec: " << ec.message();
				continue;
			}

			udp::socket sock(m_main_ioc, endp.protocol());

			if (ipv6only)
			{
				sock.set_option(boost::asio::ip::v6_only(true), ec);
				if (ec)
				{
					LOG_ERR << "start_udp_server, setsockopt IPV6_V6ONLY: " << ec.message();
					continue;
				}
			}

			sock.bind(endp, ec);
			if (ec)
			{
				LOG_ERR << "start_udp_server, udp bind error: " << ec.message();
				continue;
			}

			auto sockptr = std::make_shared<udp_socket>(
				udp_socket{ time_clock::steady_clock::now(), std::move(sock) });

			m_udp_sockets.emplace_back(std::move(sockptr));
		}

		auto tmp_udp_sockets = m_udp_sockets;

		// 按socket数量启动udp读取协程, 为接收提高效率, 发起8倍接收.
		for (size_t fast = 0; fast < 8; fast++)
		{
			for (size_t n = 0; n < tmp_udp_sockets.size(); n++)
			{
				auto usock_ptr = tmp_udp_sockets[n];
				LOG_DBG << "start_udp_server, listen endpoint: ["
					<< usock_ptr->sock_.local_endpoint().address().to_string() << "]:"
					<< usock_ptr->sock_.local_endpoint().port();

				boost::asio::co_spawn(m_main_ioc.get_executor(),
					start_udp_read_loop(n), boost::asio::detached);
			}
		}

		co_return;
	}

	void vpn_tunnel::server_checktimeout()
	{
		// 检查已经完成认证的vpn_connection的超时connection并强制关闭
		// 其tcp socket通信.
		auto check_remotes = [this]() mutable
		{
			auto now = time_clock::steady_clock::now();
			std::shared_lock lock(m_remotes_mtx);

			for ([[maybe_unused]] auto [id, c] : m_remotes)
			{
				auto connection_ptr = c.lock();
				if (!connection_ptr)
					continue;

				auto& connection = *connection_ptr;
				if (now - connection.keepalive_ > std::chrono::seconds(60))
				{
					LOG_IFMT("check_remotes, id: {}, host: {}, vnet: {} is timeout!",
						id, connection.remote_host_, connection.vnet_);

					boost::system::error_code ec;

					// 60s 无通信内容, 则关闭clinet的连接.
					connection.tcp_stream_.close(ec);

					// 彻底关闭client连接, 让该连接没有机会在read loop中等
					// 待60s, 因为已经不再考虑让client时间重连了.
					connection.vnet_ = 0;
				}
			}
		};

		// 检查未完成认证的vpn_connection的超时connection并强制关闭
		// 其tcp socket通信.
		auto check_incomings = [this]() mutable
		{
			auto now = time_clock::steady_clock::now();
			std::shared_lock lock(m_incomings_mtx);

			for ([[maybe_unused]] auto [id, c] : m_incomings)
			{
				auto connection_ptr = c.lock();
				if (!connection_ptr)
					continue;

				auto& connection = *connection_ptr;
				if (now - connection.keepalive_ > std::chrono::seconds(60))
				{
					LOG_IFMT("check_incomings, id: {}, host: {} is timeout!",
						id, connection.remote_host_);

					boost::system::error_code ec;
					connection.tcp_stream_.close(ec);
				}
			}
		};

		boost::asio::io_context ioc(1);
		boost::asio::co_spawn(ioc.get_executor(),
			[this, check_remotes = std::move(check_remotes),
			check_incomings = std::move(check_incomings)] () mutable -> boost::asio::awaitable<void>
			{
				while (!m_abort)
				{
					boost::system::error_code ec;

					m_keepalive_timer.expires_from_now(std::chrono::seconds(60));
					co_await m_keepalive_timer.async_wait(uawaitable[ec]);

					check_remotes();
					check_incomings();
				}

				LOG_DBG << "vpn_tunnel::server_checktimeout, server quit...";
				co_return;
			}, boost::asio::detached);
		ioc.run();
	}







	//////////////////////////////////////////////////////////////////////////
	/// Client 相关实现.

	void vpn_tunnel::start_client_tcp_connect()
	{
		// 每次协议重连之前, 清除m_server_guid, 避免重连逻辑判断错误.
		m_server_guid = "";

		boost::asio::co_spawn(m_main_ioc.get_executor(),
			[this]() mutable -> boost::asio::awaitable<void>
			{
				co_await client_connect_server();
				co_return;
			}, boost::asio::detached);
	}

	std::string vpn_tunnel::make_auth()
	{
		// 发起认证请求.

		// 协议格式:
		// type(number)
		// auth_code(number)
		// tail(skip)

		std::string msg(normal_mtu, 0);
		stream_endian::bitstream writer((uint8_t*)msg.data(), normal_mtu);

		writer.WriteExponentialGolomb(vpt_auth);
		writer.WriteExponentialGolomb((int32_t)google_auth_code(test_google_key));
		writer.WriteTail();

		msg.resize(writer.ByteOffset());

		return msg;
	}

	boost::asio::awaitable<void> vpn_tunnel::client_connect_server()
	{
		static std::atomic_int64_t id{ 1 };

		// 创建一个vpn_connection对象.
		std::shared_ptr<vpn_connection> connection_ptr =
			std::make_shared<vpn_connection>(
				m_main_ioc.get_executor(), "", &m_enc_matrix, &m_dec_matrix);

		// 设置connection id并保存到client weak指针.
		connection_ptr->connection_id_ = id++;
		m_client = connection_ptr;

		// 发起向服务器的连接, 如果连接失败则一直重试.
		while (!m_abort)
		{
			auto ret = co_await connect_server(connection_ptr);
			if (m_abort)
				co_return;

			if (!ret)
				continue;

			break;
		}

		// 发起认证请求.
		co_await forward_tcp_write(connection_ptr, make_auth());

		// 进入tcp读取协程, 循环读取tcp协议并处理.
		while (!m_abort)
		{
			// 发起读写协程.
			auto brk = co_await client_tcp_read_loop(connection_ptr);
			if (brk)
				break;

			// 如果没有中止服务, 则重连后继续服务.
			while (!m_abort)
			{
				auto ret = co_await connect_server(connection_ptr);
				if (m_abort || ret)
				{
					connection_ptr->tcp_msg_deque_.clear();
					m_client = connection_ptr;
					break;
				}
			}
		}

		if (!m_abort)
		{
			// 通知连接断开...
			tunnel_status cs;

			cs.status_ = connection_status::st_disconnect;
			m_vpn_service.on_status(cs);

			LOG_WARN << "client_connect_server, to reconnect...";
			start_client_tcp_connect();
			co_return;
		}

		LOG_WARN << "client_connect_server, quit...";
		co_return;
	}

	boost::asio::awaitable<bool> vpn_tunnel::connect_server(vpn_connection_ptr& connection_ptr)
	{
		auto& connection = *connection_ptr;
		auto& stream = connection_ptr->tcp_stream_;
		bool ok = false;
		boost::system::error_code ec;

		for (auto it = m_upstreams.begin();
			it != m_upstreams.end() && !m_abort && !ok; it++)
		{
			auto upstream = *it;
			util::uri parser;

			if (!parser.parse(upstream))
				continue;

			// skip udp url.
			if (boost::to_lower_copy(std::string(parser.scheme())) == "udp")
				continue;

			tcp::resolver resolver{ m_main_ioc };
			auto const results = co_await resolver.async_resolve(
				std::string(parser.host()), std::string(parser.port()), uawaitable[ec]);
			if (ec)
			{
				LOG_ERR << "connect_server, async_resolve: " << ec.message();
				continue;
			}

			// start async connect to server.
			co_await asio_util::async_connect(stream, results,
				boost::asio::redirect_error(boost::asio::bind_cancellation_slot(m_cancel_sig.slot(),
					boost::asio::use_awaitable), ec));
			if (m_abort)
			{
				LOG_ERR << "connect_server, async_connect abort";
				co_return false;
			}

			if (ec)
			{
				LOG_ERR << "connect_server, async_connect: " << ec.message();
				LOG_DBG << "connect to server fail, wait a moment to reconnect...";

				m_connect_retry_timer.expires_from_now(std::chrono::seconds(5));
				co_await m_connect_retry_timer.async_wait(uawaitable[ec]);

				if (m_abort)
					co_return false;

				continue;
			}

			// connect to server successfully, set no_delay option for tcp socket.
			boost::asio::ip::tcp::no_delay option(true);
			stream.set_option(option);

			ok = true;
		}

		std::string remote_host;
		auto endp = stream.remote_endpoint(ec);
		if (!ec)
		{
			if (endp.address().is_v6())
			{
				remote_host = "[" + endp.address().to_string()
					+ "]:" + std::to_string(endp.port());
			}
			else
			{
				remote_host = endp.address().to_string()
					+ ":" + std::to_string(endp.port());
			}
		}

		connection.remote_host_ = remote_host;
		LOG_DBG << "connect_server, connected to: " << remote_host;

		co_return true;
	}

	boost::asio::awaitable<bool> vpn_tunnel::client_tcp_read_loop(vpn_connection_ptr connection_ptr)
	{
		auto connection_id = connection_ptr->connection_id_;
		auto stream = &connection_ptr->tcp_stream_;

		boost::asio::streambuf buffer;
		int start_len_tag = 0;
		bool force_reconnect = false;

		LOG_DBG << "client_tcp_read_loop, connection id: " << connection_id << ", start...";

		while (!m_abort)
		{
			start_len_tag = co_await tcp_read_message(*stream, buffer, connection_id);

			// 发生错误.
			if (start_len_tag < 0)
				break;

			const uint8_t* bufptr = boost::asio::buffer_cast<const uint8_t*>(buffer.data());
			stream_endian::bitstream reader(bufptr, start_len_tag);
			uint32_t type = 0;

			if (!reader.ReadExponentialGolomb(&type))
			{
				LOG_ERR << "client_tcp_read_loop, id: "
					<< connection_id << ", verify message type fail.";
				co_return false;
			}

			co_await process_tcp_packet(type, reader, connection_ptr);
			buffer.consume(start_len_tag);

			// 作为client的时, 如果通信id发生改变, 则重新协议连接.
			if (m_communication_guid_changed)
			{
				boost::system::error_code ec;
				stream->close(ec);

				force_reconnect = true;
				m_communication_guid_changed = false;
				break;
			}
		}

		if (!force_reconnect)
		{
			LOG_WARN << "client_tcp_read_loop, id: " << connection_id << " quit...";
			co_return false;
		}

		// 重新协议连接服务器.
		co_return true;
	}

	boost::asio::awaitable<void> vpn_tunnel::start_udp_client()
	{
		BOOST_ASSERT(m_identity == Identity::avpn_client);

		m_remote_endps.clear();
		std::vector<udp::endpoint> endps;
		boost::system::error_code ec;

		for (auto it = m_upstreams.begin();
			it != m_upstreams.end() && !m_abort; it++)
		{
			auto upstream = *it;
			util::uri parser;

			if (!parser.parse(upstream))
				continue;

			if (boost::to_lower_copy(std::string(parser.scheme())) != "udp")
				continue;

			tcp::resolver resolver{ m_main_ioc };
			auto const results = co_await resolver.async_resolve(
				std::string(parser.host()), std::string(parser.port()), uawaitable[ec]);
			if (ec)
			{
				LOG_ERR << "start_udp_client, find udp async_resolve: " << ec.message();
				continue;
			}

			for (auto& endp : results)
			{
				auto tmp = endp.endpoint();
				endps.emplace_back(udp::endpoint(tmp.address(), tmp.port()));
			}
		}

		// 将udp结点加入endpoint选择容器.
		m_remote_endps.resize(endps.size());
		for (auto& endp : endps)
			m_remote_endps.update(endp);

		// client模式, 创建固定个数udp socket.
		for (auto& sock_ptr : m_udp_sockets)
		{
			if (!sock_ptr || !sock_ptr->sock_.is_open())
				continue;

			sock_ptr->sock_.close(ec);
		}
		m_udp_sockets.clear();

		// 每个上游都开启 max_client_udp_socket 倍socket通信.
		auto size = m_remote_endps.size() * max_client_udp_socket;
		for (size_t i = 0; i < size; i++)
		{
			auto endp = m_remote_endps.acquire();

			udp::socket sock(m_main_ioc, udp::endpoint(endp.protocol(), 0));
			if (ec)
			{
				LOG_ERR << "start_udp_client, udp open error: " << ec.message();
				continue;
			}

			// 完成udp socket创建后, 向上游服务端发起vpt_udp_handshake消息.
			LOG_DBG << "start_udp_client, start handshake: ["
				<< endp.address().to_string() << "]:" << endp.port();

			auto connection_ptr = m_client.lock();
			if (!connection_ptr)
			{
				LOG_ERR << "start_udp_client, connection is nullptr!";
				co_return;
			}

			std::string msg(normal_mtu, 0);
			stream_endian::bitstream writer((uint8_t*)msg.data(), normal_mtu);

			writer.WriteExponentialGolomb(vpt_udp_handshake);
			writer.WriteExponentialGolomb(connection_ptr->vnet_);
			writer.WriteTail();

			msg.resize(writer.ByteOffset());

			// 向服务器发送握手请求.
			co_await forward_udp_write(sock, endp, std::move(msg));

			// 保存到udp socket容器.
			if (m_udp_sockets.size() == i)
			{
				udp_socket_ptr tmp = std::make_shared<udp_socket>(
					udp_socket{ time_clock::steady_clock::now(), std::move(sock) });

				m_udp_sockets.emplace_back(std::move(tmp));
				auto& usock_ptr = m_udp_sockets[i];

				for (size_t fast = 0; fast < 2; fast++)
				{
					LOG_DBG << "start_udp_client, new udp socket, local endpoint: ["
						<< usock_ptr->sock_.local_endpoint().address().to_string() << "]:"
						<< usock_ptr->sock_.local_endpoint().port();

					boost::asio::co_spawn(m_main_ioc.get_executor(),
						start_udp_read_loop(i), boost::asio::detached);
				}
			}
		}

		co_return;
	}

	void vpn_tunnel::client_checktimeout()
	{
		auto check_clients = [this]() mutable -> boost::asio::awaitable<void> {
			boost::system::error_code ec;

			auto wait_moment = [&]() mutable -> boost::asio::awaitable<void>
			{
				m_keepalive_timer.expires_from_now(std::chrono::milliseconds(m_params.keepalive_));
				co_await m_keepalive_timer.async_wait(uawaitable[ec]);
				co_await boost::asio::this_coro::executor;
			};

			uint32_t vaddr = 0;

			std::random_device rd;
			std::mt19937 g(rd());

			LOG_DBG << "client_checktimeout, start check_clients";

			while (!m_abort)
			{
				// 判断client是否打开.
				auto connection_ptr = m_client.lock();
				if (!connection_ptr)
				{
					co_await wait_moment();
					continue;
				}

				// 判断是否获得虚拟地址, 也就是是否协商认证完成.
				vaddr = connection_ptr->vnet_;

				if (vaddr == 0 ||
					connection_ptr->connection_id_ <= 0 ||
					!connection_ptr->tcp_stream_.is_open())
				{
					// 立即rest, 不再占用connection对象的引用计数.
					connection_ptr.reset();

					co_await wait_moment();
					continue;
				}

				// 复制一份临时的udp socket.
				auto tmp_udp_sockets = m_udp_sockets;

				// 如果client其中某个udp socket长时间没响应, 则关闭后重新创建.
				auto now = time_clock::steady_clock::now();
				for (auto i = 0; i < tmp_udp_sockets.size(); i++)
				{
					if (m_abort)
						break;

					auto& usock_ptr = tmp_udp_sockets[i];
					auto& obj = *usock_ptr;
					auto& usock = obj.sock_;

					if (now - usock_ptr->last_see_ < std::chrono::seconds(60))
						continue;

					auto local_endp = usock.local_endpoint();
					auto protocol = local_endp.protocol();

					usock.close(ec);

					udp::socket new_usock(m_main_ioc, udp::endpoint(protocol, 0));
					auto new_endp = new_usock.local_endpoint(ec);
					if (ec)
					{
						LOG_ERR << "Renew udp socket: "
							<< local_endp << " -> " << new_endp << ", ec: " << ec.message();
					}
					else
					{
						LOG_INFO << "Renew udp socket: " << local_endp << " -> " << new_endp;
					}

					// 新建udp socket.
					usock_ptr = std::make_shared<udp_socket>(now, std::move(new_usock));
					m_udp_sockets[i] = usock_ptr;
				}

				// 随机打乱这些udp socket以排序.
				std::shuffle(tmp_udp_sockets.begin(), tmp_udp_sockets.end(), g);

				// 创建make_keepalive用于创建keepalive消息.
				auto make_keepalive = [&]() -> std::string
				{
					std::string msg(normal_mtu, 0);

					stream_endian::bitstream writer((uint8_t*)msg.data(), normal_mtu);

					writer.WriteExponentialGolomb(vpt_keepalive);
					writer.WriteExponentialGolomb(vaddr);
					writer.WriteTail();

					msg.resize(writer.ByteOffset());

					return msg;
				};

				// 发送udp的keepalive消息.
				for (auto& usock_ptr : tmp_udp_sockets)
				{
					if (m_abort)
						break;

					auto& u = *usock_ptr;
					auto& usock = u.sock_;

					auto endp = m_remote_endps.acquire();
					co_await forward_udp_write(usock, endp, make_keepalive());
				}

#if 0
				// 发送tcp的keepalive消息.
				auto local_endp = connection_ptr->tcp_stream_.local_endpoint(ec);

				LOG_DBG << "vpn_tunnel::keepalive, local endpoint: "
					<< local_endp << ", socket: " << &connection_ptr->tcp_stream_;
#endif

				co_await forward_tcp_write(connection_ptr, make_keepalive());

				// 定时延迟一段时间.
				co_await wait_moment();
			}

			LOG_WARN << "vpn_tunnel::keepalive, client quit...";
			co_return;
		};

		// 作为客户端时, 每隔keepalive时间发送keepavlie消息.
		boost::asio::co_spawn(m_main_ioc.get_executor(),
			[this, check_clients = std::move(check_clients)]() mutable->boost::asio::awaitable<void>
			{
				co_await check_clients();
				co_return;
			}, boost::asio::detached);
	}







	//////////////////////////////////////////////////////////////////////////
	/// 共同实现.

	boost::asio::awaitable<void> vpn_tunnel::start_udp_read_loop(size_t index)
	{
		auto usocket_ptr = m_udp_sockets[index];
		auto& udp_sock = *usocket_ptr;
		auto& sock = udp_sock.sock_;

		LOG_FMT("start_udp_read_loop, udp socket size: {}, index: {}",
			m_udp_sockets.size(), index);

		boost::system::error_code ec;
		char buffer[2048];
		udp::endpoint remote_endp;

		while (!m_abort)
		{
			auto bytes = co_await sock.async_receive_from(
				boost::asio::buffer(buffer), remote_endp, uawaitable[ec]);
			if (ec)
				continue;

			// 根据客户端身份更新udp endpoint.
			if (m_identity == Identity::avpn_client)
				udp_sock.last_see_ = time_clock::steady_clock::now();

			// 开始解析协议.
			stream_endian::bitstream reader((uint8_t*)&buffer[0], bytes);

			// 读取协议字节.
			uint32_t type = 0;
			if (!reader.ReadExponentialGolomb(&type))
			{
				LOG_ERR << "start_udp_read_loop, remote host: " << remote_endp << ", read type error.";
				continue;
			}

			// 处理udp网络数据包.
			co_await process_udp_packet((uint8_t)type, reader, sock, remote_endp);
		}

		LOG_WARN << "start_udp_read_loop, endpoint: " << remote_endp << ", quit...";
	}

	void vpn_tunnel::keepalive()
	{
		// 作为服务器时, 启动一个线程专门处理超时连接.
		if (m_identity == Identity::avpn_server)
		{
			static std::thread keepalive_thread([this]() mutable
			{
				server_checktimeout();
			});
			if (keepalive_thread.joinable())
				keepalive_thread.detach();
			return;
		}

		if (m_identity == Identity::avpn_client)
		{
			client_checktimeout();
			return;
		}
	}

	void vpn_tunnel::reset_connection_expires(vpn_connection& connection)
	{
		connection.keepalive_ = time_clock::steady_clock::now();
	}

	boost::asio::awaitable<void> vpn_tunnel::process_tcp_packet(uint32_t type,
		stream_endian::bitstream& reader, vpn_connection_ptr& connection_ptr)
	{
		std::string bufs;

		switch (type)
		{
		case vpt_auth:
			if (m_identity == Identity::avpn_server)
				co_await do_server_vpt_auth(reader, connection_ptr);
			else
				co_await do_client_vpt_auth(reader, connection_ptr);
			co_return;
		case vpt_communication_guid:
			co_await do_communication_guid(reader, connection_ptr);
			co_return;
		case vpt_keepalive:
			co_await do_tcp_keepalive(reader, connection_ptr);
			break;
		case vpt_udp_handshake:
			break;
		case vpt_compress_tcp:
			[[fallthrough]];
		case vpt_compress_udp:
		{
			bool ret = co_await do_vpt_compress(reader, bufs);
			if (!ret)
				co_return;
			if (type == vpt_compress_udp)
				type = vpt_udp;
			if (type == vpt_compress_tcp)
				type = vpt_tcp;
		}
		[[fallthrough]];
		case vpt_icmp:
			[[fallthrough]];
		case vpt_udp:
			[[fallthrough]];
		case vpt_tcp:
			co_await do_vpt_tcp_packet((uint8_t)type, reader);
			co_return;
		case vpt_fec:
			co_await do_vpt_fec_packet(reader);
			break;
		}

		// 将从网络接收到的数据包转发到设备.
		if (connection_ptr)
			co_await do_fec_process(connection_ptr);

		co_return;
	}

	boost::asio::awaitable<void> vpn_tunnel::process_udp_packet(uint8_t type,
		stream_endian::bitstream& reader, udp::socket& sock, udp::endpoint endp)
	{
		std::string bufs;
		vpn_connection_ptr connection_ptr;

		switch (type)
		{
		case vpt_auth:
			break;
		case vpt_keepalive:
			connection_ptr = co_await do_udp_keepalive(reader, sock, endp);
			if (connection_ptr)
				reset_connection_expires(*connection_ptr);
			break;
		case vpt_keepalive_reply:
			co_return;
		case vpt_udp_handshake:
			co_await do_vpt_udp_handshake(reader, sock, endp);
			co_return;
		case vpt_udp_handshake_reply:
			co_await do_vpt_udp_handshake_reply(reader, endp);
			co_return;
		case vpt_compress_tcp:
			[[fallthrough]];
		case vpt_compress_udp:
		{
			bool ret = co_await do_vpt_compress(reader, bufs);
			if (!ret)
				co_return;
			if (type == vpt_compress_udp)
				type = vpt_udp;
			if (type == vpt_compress_tcp)
				type = vpt_tcp;
		}
		[[fallthrough]];
		case vpt_icmp:
			[[fallthrough]];
		case vpt_udp:
			[[fallthrough]];
		case vpt_tcp:
			co_await do_vpt_udp_packet(type, reader, endp);
			co_return;
		case vpt_compress_fec:
			co_await do_vpt_compress(reader, bufs);
			[[fallthrough]];
		case vpt_fec:
			connection_ptr = co_await do_vpt_fec_packet(reader);
			break;
		}

		if (connection_ptr)
			co_await do_fec_process(connection_ptr);

		co_return;
	}

	boost::asio::awaitable<void> vpn_tunnel::forward_tcp_write(const vpn_connection_ptr& connection_ptr, std::string msg)
	{
		auto& connection = *connection_ptr;

		connection.deque_writing_ = !connection.tcp_msg_deque_.empty();
		auto& message_deque = connection.tcp_msg_deque_;
		message_deque.emplace_back(std::move(msg));

		if (!connection.deque_writing_)
		{
			boost::system::error_code ec;
			while (!m_abort && !message_deque.empty())
			{
				// 直接从队列中取出, 避免遗留在队列中.
				std::string message(std::move(message_deque.front()));

				// 空数据包直接跳过.
				if (message.empty())
				{
					message_deque.pop_front();
					continue;
				}

				// 长度前辍.
				uint32_t start_len_tag = htonl((uint32_t)message.size());

				co_await boost::asio::async_write(connection.tcp_stream_,
					boost::asio::buffer(&start_len_tag, 4), uawaitable[ec]);
				if (ec)
				{
					LOG_ERR << "forward_tcp_write, " << connection.connection_id_
						<< " async_write tag error: " << ec.message();
					co_return;
				}

				co_await boost::asio::async_write(connection.tcp_stream_,
						boost::asio::buffer(message), uawaitable[ec]);
				if (ec)
				{
					LOG_ERR << "forward_tcp_write, " << connection.connection_id_
						<< " async_write body error: " << ec.message();
					co_return;
				}

				message_deque.pop_front();
			}
		}
	}

	boost::asio::awaitable<void> vpn_tunnel::forward_udp_write(
		udp::socket& sock, udp::endpoint endp, std::string msg)
	{
		boost::system::error_code ec;
		co_await sock.async_send_to(boost::asio::buffer(msg), endp, uawaitable[ec]);
		if (ec)
			LOG_WARN << "forward_udp_write, async_send_to " << endp << ", error: " << ec.message();

		co_return;
	}

	boost::asio::awaitable<void> vpn_tunnel::forward_tunnel_write(vpn_connection_ptr connection_ptr, vpn_message msg)
	{
		auto& connection = *connection_ptr;

		// 如果发送模式为tcp, 或为tcp/udp混合发送模式, 并且当
		// 前发送空闲时, 则直接调用tcp发送.
		// 当udp不可用时, 也直接使用tcp发送.
		if (m_params.mode_ == vpn_tcp_mode::only_tcp
			|| (m_params.mode_ == vpn_tcp_mode::tcpudp_mix && !connection.deque_writing_)
			|| m_udp_sockets.size() == 0
			|| (connection.endps_.size() == 0 && m_identity == Identity::avpn_server))
		{
			// 构造数据包.
			std::string pkt(normal_mtu, 0);

			{
				stream_endian::bitstream writer((uint8_t*)pkt.data(), normal_mtu);

				writer.WriteExponentialGolomb(msg.type);
				writer.WriteTail();
				writer.WriteString(msg.content_.data(), msg.content_.size());

				pkt.resize(writer.ByteOffset());
			}

			// 如果启用了压缩, 则先压缩后再发送, 我们只压缩tcp/udp数据包.
			if ((msg.type == vpt_tcp || msg.type == vpt_udp)
				&& m_params.compress_)
			{
				vpt_compress(msg.type, pkt);
			}

			// 开始tcp发送.
			co_await forward_tcp_write(connection_ptr, std::move(pkt));
		}
		else
		{
			// 1个数据包的情况下, 禁用fec并立即发包.
			if (m_params.data_shards_ == 1)
			{
				std::string pkt(normal_mtu, 0);

				{
					stream_endian::bitstream writer((uint8_t*)pkt.data(), normal_mtu);

					writer.WriteExponentialGolomb(msg.type);
					writer.WriteTail();
					writer.WriteString(msg.content_.data(), msg.content_.size());

					pkt.resize(writer.ByteOffset());
				}

				// 如果启用了压缩, 则先压缩.
				if ((msg.type == vpt_tcp || msg.type == vpt_udp)
					&& m_params.compress_)
				{
					vpt_compress(msg.type, pkt);
				}

				// 多倍流量模式, 有多个冗余, 则发送多次.
				auto tmp_udp_sockets = m_udp_sockets;
				auto usize = tmp_udp_sockets.size();

				// 计算冗余数据大小, 并循环发送, 最大5倍发包模式.
				auto num_duplicate = m_params.parity_shards_;
				num_duplicate = num_duplicate <= 0 ? 1 : num_duplicate;
				num_duplicate = num_duplicate > 5 ? 5 : num_duplicate;
				num_duplicate = msg.type != vpt_tcp ? 1 : num_duplicate;

				vpn_remote_endpoint* remote_endpoint = &m_remote_endps;
				if (m_identity == Identity::avpn_server)
					remote_endpoint = &connection.endps_;

				if (num_duplicate == 1)
				{
					auto& usock = tmp_udp_sockets[std::rand() % usize]->sock_;
					auto uendp = remote_endpoint->acquire();

					co_await forward_udp_write(usock, uendp, std::move(pkt));
					co_return;
				}

				for (auto n = 0; n < num_duplicate; n++)
				{
					auto duplicate = pkt;

					auto& usock = tmp_udp_sockets[n % usize]->sock_;
					auto uendp = remote_endpoint->acquire();

					co_await forward_udp_write(usock, uendp, std::move(duplicate));
				}

				co_return;
			}

			// FEC发包模式.
			boost::asio::co_spawn(m_fec_timer.get_executor(),
				[this, connection_ptr, msg = std::move(msg)]() mutable -> boost::asio::awaitable<void>
				{
					auto& connection = *connection_ptr;
					auto& fec_enc = connection.fec_enc_;

					// 记录编码器开始收集tun数据包的起始时间.
					if (fec_enc.empty())
						connection.enc_tm_ = time_clock::steady_clock::now();

					// 计算FEC编码数据大小.
					auto bytes = msg.content_.size();
					connection.fec_enc_size_ += bytes;

					// 存入编码器.
					fec_enc.emplace_back(std::move(msg));

					// 确保编码缓冲数据不要过大, 如果缓冲达到最大, 唤醒FEC Timer处理FEC编码缓冲.
					if (connection.fec_enc_size_ + static_mtu >= static_mtu * m_params.data_shards_)
					{
						boost::system::error_code ignore_ec;
						m_fec_timer.cancel_one(ignore_ec);
					}

					co_return;
				}, boost::asio::detached);
		}

		co_return;
	}

	void vpn_tunnel::add_connection(vpn_connection_ptr& connection_ptr, uint32_t vaddr)
	{
		std::lock_guard lock(m_remotes_mtx);
		m_remotes[vaddr] = connection_ptr;
	}

	void vpn_tunnel::remove_connection(uint32_t vaddr)
	{
		std::lock_guard lock(m_remotes_mtx);
		m_remotes.erase(vaddr);
	}

	vpn_connection_ptr vpn_tunnel::lookup_connection(uint32_t vaddr)
	{
		std::shared_lock lock(m_remotes_mtx);
		auto it = m_remotes.find(vaddr);
		if (it == m_remotes.end())
			return {};
		return it->second.lock();
	}

	void vpn_tunnel::add_incoming(vpn_connection_ptr& connection_ptr, int64_t id)
	{
		std::lock_guard lock(m_incomings_mtx);
		m_incomings[id] = connection_ptr;
	}

	void vpn_tunnel::remove_incoming(int64_t id)
	{
		std::lock_guard lock(m_incomings_mtx);
		m_incomings.erase(id);
	}

	std::tuple<std::string, uint32_t> vpn_tunnel::ip_assigner()
	{
		std::string ip_string;
		uint32_t ipaddr;

		const auto prefix = m_subnet.prefix_length();

		do
		{
			if (m_ip_iterator == m_ip_assigner.begin())
				m_ip_iterator++;
			if (m_ip_iterator == m_ip_assigner.end())
				m_ip_iterator = m_ip_assigner.begin();

			auto ip = *m_ip_iterator++;
			ipaddr = ip.to_uint();

			uint32_t tail = (ipaddr & ((1 << prefix) - 1)) % 256;
			if (tail == 255 || tail == 0)
				continue;

			ip_string = ip.to_string();
		} while (false);

		return { ip_string, ipaddr };
	}





	//////////////////////////////////////////////////////////////////////////
	/// 共同实现.

	boost::asio::awaitable<int> vpn_tunnel::tcp_read_message(
		tcp::socket& stream, boost::asio::streambuf& buffer, int64_t& connection_id)
	{
		boost::system::error_code ec;
		int start_len_tag = -1;

		// 先读取4个字节的头.
		co_await boost::asio::async_read(
			stream, buffer, boost::asio::transfer_exactly(4), uawaitable[ec]);
		if (ec)
		{
			LOG_ERR << "tcp_read_message, id: "
				<< connection_id << ", read tag error: " << ec.message();
			co_return -1;
		}

		{
			const uint8_t* bufptr = boost::asio::buffer_cast<const uint8_t*>(buffer.data());
			start_len_tag = ntohl(*((int*)bufptr));
			if ((uint32_t)start_len_tag > (uint32_t)normal_mtu)
			{
				LOG_ERR << "tcp_read_message, id: "
					<< connection_id << ", verify message size fail: " << start_len_tag;
				co_return -1;
			}
			buffer.consume(4);
		}

		// 读取body本身.
		co_await boost::asio::async_read(
			stream, buffer, boost::asio::transfer_exactly(start_len_tag), uawaitable[ec]);
		if (ec)
		{
			LOG_ERR << "tcp_read_message, id: "
				<< connection_id << ", read body error: " << ec.message();
			co_return -1;
		}

		co_return start_len_tag;
	}

	int vpn_tunnel::vpt_compress(int type, std::string& content)
	{
		auto body_size = content.size();

		std::string compress_bufs(body_size * 2, 0);
		uLong out_size = (uLong)compress_bufs.size();

		auto ok = compress((Bytef*)compress_bufs.data(), &out_size,
			(const Bytef*)content.data(), (uLong)body_size);
		if (ok == Z_OK)
		{
			if (out_size < (uLong)body_size)
			{
				stream_endian::bitstream writer((uint8_t*)content.data(), normal_mtu);

				switch (type)
				{
				case avpn::vpt_tcp:
					type = vpt_compress_tcp;
					break;
				case avpn::vpt_udp:
					type = vpt_compress_udp;
					break;
				case avpn::vpt_fec:
					type = vpt_compress_fec;
					break;
				default:
					BOOST_ASSERT(false && "Compress type unsupported!");
					break;
				}

				writer.WriteExponentialGolomb(type);				// type
				writer.WriteTail();									// tail(skip)
				writer.WriteString(compress_bufs.data(), out_size);	// content

				body_size = writer.ByteOffset();
				content.resize(body_size);
			}
		}

		return type;
	}

	boost::asio::awaitable<void> vpn_tunnel::do_server_vpt_auth(
		stream_endian::bitstream& reader, vpn_connection_ptr& connection_ptr)
	{
		auto& connection = *connection_ptr;

		// 协议格式:
		// type(number)
		// auth_code(number)
		// tail(skip)

		uint32_t auth_code = 0;
		reader.ReadExponentialGolomb(&auth_code);

		// TODO: 作认证操作, test key.
		uint32_t code = (uint32_t)google_auth_code(test_google_key);
		if (code != auth_code)
		{
			LOG_ERR << "Server: " << connection.connection_id_
				<< ", verify auth code fail: " << code << ", got: " << auth_code;
#if 0
			std::string reply(normal_mtu, 0);
			stream_endian::bitstream writer((uint8_t*)reply.data(), normal_mtu);

			writer.WriteExponentialGolomb(vpt_auth);
			writer.WriteExponentialGolomb(0);
			writer.WriteExponentialGolomb(0);
			writer.WriteTail();

			reply.resize(writer.ByteOffset());

			co_await forward_tcp_write(connection_ptr, std::move(reply));
			co_return;
#endif
		}

		uint32_t pushdns = 0;
		if (!m_params.pushdns_.empty())
		{
			boost::system::error_code ec;
			auto addr = boost::asio::ip::address_v4::from_string(m_params.pushdns_, ec);
			if (!ec)
				pushdns = addr.to_uint();
		}

		std::string reply(normal_mtu, 0);
		stream_endian::bitstream writer((uint8_t*)reply.data(), normal_mtu);

		auto [ip_string, ipaddr] = ip_assigner();

		writer.WriteExponentialGolomb(vpt_auth);
		writer.WriteExponentialGolomb(avpn_protocol_version);
		writer.WriteExponentialGolomb(m_subnet.prefix_length());
		writer.WriteExponentialGolomb(ipaddr);
		writer.WriteExponentialGolomb(m_params.passbyvpn_);
		writer.WriteExponentialGolomb(pushdns);
		writer.WriteExponentialGolomb((uint32_t)m_params.routes_.size());
		writer.WriteTail();

		for (auto& route : m_params.routes_)
		{
			if (!writer.WriteUInt8((uint8_t)route.size()))
				break;
			if (!writer.WriteString(route.data(), route.size()))
				break;
		}

		// 重置string大小.
		reply.resize(writer.ByteOffset());

		connection.vnet_ = ipaddr;
		LOG_DBG << "Server assign virtual ip: "
			<< ip_string << " to id: " << connection.connection_id_;

		// 从临时连接表中删除.
		remove_incoming(connection.connection_id_);

		// 添加到连接管理.
		add_connection(connection_ptr, ipaddr);

		// 返回数据.
		co_await forward_tcp_write(connection_ptr, std::move(reply));

		co_return;
	}

	boost::asio::awaitable<void> vpn_tunnel::do_client_vpt_auth(
		stream_endian::bitstream& reader, vpn_connection_ptr& connection_ptr)
	{
		// 协议格式:
		// type(number)
		// version(number)
		// prefix_length(number)
		// vaddr(number)
		// passbyvpn(number)
		// pushdns(number)
		// routes(number)
		// {size(u8), string[size]}[routes]
		// tail(skip)

		auto& connection = *connection_ptr;

		uint32_t version = 0;
		if (!reader.ReadExponentialGolomb(&version))
		{
			LOG_ERR << "Client read protocol version error!";
			co_return;
		}

		if (version != avpn_protocol_version)
		{
			if (version == 0)
			{
				LOG_ERR << "Client auth code invalid!";
			}
			else
			{
				LOG_ERR << "Client protocol version incompatible: "
					<< version << ", expect: " << avpn_protocol_version;
			}

			co_return;
		}

		uint32_t prefix_length = 0;
		if (!reader.ReadExponentialGolomb(&prefix_length))
		{
			LOG_ERR << "Client read protocol version error!";
			co_return;
		}
		m_prefix_length = (uint8_t)prefix_length;

		uint32_t vaddr = 0;
		if (!reader.ReadExponentialGolomb(&vaddr))
		{
			LOG_ERR << "Client read vaddr error!";
			co_return;
		}

		uint32_t passbyvpn = 0;
		if (!reader.ReadExponentialGolomb(&passbyvpn))
		{
			LOG_ERR << "Client read passbyvpn error!";
			co_return;
		}

		uint32_t pushdns = 0;
		if (!reader.ReadExponentialGolomb(&pushdns))
		{
			LOG_ERR << "Client read pushdns error!";
			co_return;
		}

		uint32_t routes = 0;
		if (!reader.ReadExponentialGolomb(&routes))
		{
			LOG_ERR << "Client read routes error!";
			co_return;
		}

		reader.ReadTail();
		m_routes.clear();
		for (uint32_t n = 0; n < routes; n++)
		{
			uint8_t size = 0;
			if (!reader.ReadUInt8(&size))
			{
				LOG_ERR << "Client read route size error!";
				co_return;
			}

			std::string route(size, 0);
			if (!reader.ReadString((char*)route.data(), size))
			{
				LOG_ERR << "Client read route error!";
				co_return;
			}

			m_routes.emplace_back(std::move(route));
		}

		// tcp握手完成, 整合虚拟网络IP相关信息.
		connection.vnet_ = vaddr;

		auto ipaddr = boost::asio::ip::address_v4(vaddr);
		m_vnet_ipaddr = boost::asio::ip::make_network_v4(ipaddr, m_prefix_length);

		boost::asio::ip::address_v4 nw(m_vnet_ipaddr.network().to_uint() + 1);
		m_subnet = boost::asio::ip::make_network_v4(nw, m_prefix_length);

		// client在认证通过后, 启动UDP通信.
		LOG_DBG << "Start udp socket, virutal addr: " << ipaddr.to_string();
		boost::asio::co_spawn(m_main_ioc.get_executor(),
			[this]() mutable -> boost::asio::awaitable<void>
			{
				co_await start_udp_client();
				LOG_DBG << "Start udp client completed...";
				co_return;
			}, boost::asio::detached);

		std::string dns_string;
		if (pushdns != 0)
		{
			auto dns_addr = boost::asio::ip::address_v4(pushdns);
			dns_string = dns_addr.to_string();
		}

		// 通知完成连接...
		tunnel_status cs;
		cs.passbyvpn_ = passbyvpn;
		cs.routes_ = m_routes;
		cs.dns_ = dns_string;
		cs.server_ip_ = connection.tcp_stream_.remote_endpoint().address().to_string();
		cs.status_ = connection_status::st_connected;

		m_vpn_service.on_status(cs);

		co_return;
	}

	boost::asio::awaitable<void> vpn_tunnel::do_communication_guid(
		stream_endian::bitstream& reader, vpn_connection_ptr& connection_ptr)
	{
		reader.ReadTail();

		auto remaining = reader.AllSize() - reader.ByteOffset();
		std::string guid(remaining, 0);
		reader.ReadString((char*)guid.data(), remaining);

		// 如果guid不同, 本client则需要重新从头协议连接.
		// guid不同则说明server重启了, 对于client说, 这
		// 是一个新的server, 所以要重新认证分配ip等操作.
		if (guid != m_server_guid)
		{
			// m_server_guid为空, 则表示第1次发起连接
			// 而不是半路断开重连, 非空则表示半路断开
			// m_server_guid存储的是断开前的guid.
			if (!m_server_guid.empty())
				m_communication_guid_changed = true;

			m_server_guid = guid;
		}

		co_return;
	}

	boost::asio::awaitable<vpn_connection_ptr> vpn_tunnel::do_tcp_keepalive(
		stream_endian::bitstream& reader, vpn_connection_ptr& connection_ptr)
	{
		uint32_t vaddr = 0;

		if (!reader.ReadExponentialGolomb(&vaddr))
		{
			LOG_ERR << "do_tcp_keepalive, read vaddr error!";
			co_return connection_ptr;
		}

		// 客户端发过来的keepalive, 如果vnet为0, 表示
		// 这个客户端正在recover连接.
		if (connection_ptr->vnet_ == 0)
		{
			auto exist = lookup_connection(vaddr);
			auto id = connection_ptr->connection_id_;

			// 在这里替换掉原来的tcp socket.
			exist->tcp_stream_ = std::move(connection_ptr->tcp_stream_);
			exist->tcp_msg_deque_.clear();	// 清理发送队列.
			remove_incoming(id);			// 移除incoming表中的weak指针.

			connection_ptr = exist;

			LOG_FMT("do_tcp_keepalive, recover exist: {} with {}, vaddr: {}",
				exist->connection_id_, id, exist->vnet_);
		}

		reset_connection_expires(*connection_ptr);

		co_return connection_ptr;
	}

	boost::asio::awaitable<vpn_connection_ptr> vpn_tunnel::do_udp_keepalive(
		stream_endian::bitstream& reader, udp::socket& sock, const udp::endpoint& endp)
	{
		uint32_t vaddr = 0;
		vpn_connection_ptr connection_ptr;

		if (!reader.ReadExponentialGolomb(&vaddr))
		{
			LOG_ERR << "do_udp_keepalive read vaddr error!";
			co_return connection_ptr;
		}

		if (m_identity == Identity::avpn_server)
		{
			connection_ptr = lookup_connection(vaddr);
			if (!connection_ptr)
			{
				LOG_ERR << "do_udp_keepalive server lookup connection error!";
				co_return connection_ptr;
			}

			auto& connection = *connection_ptr;
			connection.endps_.update(endp);

			// 响应client的keepalive请求.
			std::string reply(normal_mtu, '\0');
			stream_endian::bitstream writer((uint8_t*)reply.data(), normal_mtu);
			writer.WriteExponentialGolomb(vpt_keepalive_reply);
			writer.WriteExponentialGolomb(200);
			writer.WriteTail();

			reply.resize(writer.ByteOffset());

			co_await forward_udp_write(sock, endp, std::move(reply));
		}

		co_return connection_ptr;
	}

	boost::asio::awaitable<bool> vpn_tunnel::do_vpt_compress(
		stream_endian::bitstream& reader, std::string& bufs)
	{
		// 协议格式:
		// type(number)
		// tail(skip)
		// content

		// 解压缩操作.
		uLongf bufsize = 16384;
		bufs.resize(bufsize);

		reader.ReadTail();

		const Bytef* ptr = reader.GetOriginPtr() + reader.ByteOffset();
		uint32_t content_size = uint32_t(reader.AllSize() - reader.ByteOffset());

		auto ok = uncompress((Bytef*)bufs.data(), &bufsize,
			(const Bytef*)ptr, (uLongf)content_size);
		if (ok != Z_OK)
		{
			LOG_ERR << "Receive vpt_compress_udp uncompress error!";
			co_return false;
		}

		bufs.resize(bufsize);
		reader.Reset((uint8_t*)bufs.data(), bufsize);

		if (!reader.ReadExponentialGolomb(&content_size))	// skip type.
		{
			LOG_ERR << "Receive vpt_compress_udp skip type error!";
			co_return true;
		}

		co_return true;
	}

	boost::asio::awaitable<void> vpn_tunnel::do_vpt_udp_packet(
		uint8_t type, stream_endian::bitstream& reader, const udp::endpoint& endp)
	{
		// 协议格式:
		// type(number)
		// tail(skip)
		// content

		reader.ReadTail();

		auto content = reader.GetOriginPtr() + reader.ByteOffset();
		size_t content_size = reader.RemainingBitCount() / 8;

		// 处理内网数据包.
		auto ep = avpn::lookup_endpoint_pair((const uint8_t*)content, content_size);
		auto& dst_addr = ep.dst_;
		auto& src_addr = ep.src_;

		auto uint_dst = dst_addr.address().to_v4().to_uint();
		udp::endpoint uendp(dst_addr.address(), 0);

		// 只有在身份为server时, 才会更新endpoint.
		if (m_identity == Identity::avpn_server)
		{
			auto uint_src = src_addr.address().to_v4().to_uint();
			auto connection_ptr = lookup_connection(uint_src);
			if (connection_ptr)
			{
				connection_ptr->endps_.update(endp);

				// 更新超时计时.
				reset_connection_expires(*connection_ptr);
			}
		}

		// 只有在身份为server时, 并且为内网数据包, 则直接找到对应链转发.
		if (m_identity == Identity::avpn_server && same_ipv4_network(m_subnet, uint_dst))
		{
			// 不允许内网传输.
			if (!m_params.c2c_)
				co_return;

			auto connection_ptr = lookup_connection(uint_dst);
			if (connection_ptr)
			{
				avpn::vpn_message msg;
				msg.type = type;
				msg.content_.assign((char*)content, content_size);

				// 内网转发.
				co_await forward_tunnel_write(connection_ptr, std::move(msg));
				co_return;
			}
		}

		if (type == vpt_icmp)
			LOG_DBG << "do_vpt_udp_packet, recvive icmp, write tun icmp: " << dst_addr;

		m_vpn_service.do_tuntap_write(std::string((char*)content, content_size));

		co_return;
	}

	boost::asio::awaitable<void> vpn_tunnel::do_vpt_tcp_packet(
		uint8_t type, stream_endian::bitstream& reader)
	{
		// 协议格式:
		// type(number)
		// tail(skip)
		// content

		reader.ReadTail();

		auto content = reader.GetOriginPtr() + reader.ByteOffset();
		size_t content_size = reader.RemainingBitCount() / 8;

		// 处理内网数据包.
		auto ep = avpn::lookup_endpoint_pair((const uint8_t*)content, content_size);
		auto& dst_addr = ep.dst_;

		auto uint_dst = dst_addr.address().to_v4().to_uint();
		udp::endpoint uendp(dst_addr.address(), 0);

		// 只有在身份为server时, 并且为内网数据包, 则直接找到对应链转发.
		if (m_identity == Identity::avpn_server && same_ipv4_network(m_subnet, uint_dst))
		{
			// 不允许内网传输.
			if (!m_params.c2c_)
				co_return;

			auto connection_ptr = lookup_connection(uint_dst);
			if (connection_ptr)
			{
				avpn::vpn_message msg;
				msg.type = type;
				msg.content_.assign((char*)content, content_size);

				// 内网转发.
				co_await forward_tunnel_write(connection_ptr, std::move(msg));
				co_return;
			}
		}

		if (type == vpt_icmp)
			LOG_DBG << "do_vpt_tcp_packet, recvive icmp, write tun icmp: " << dst_addr;

		m_vpn_service.do_tuntap_write(std::string((char*)content, content_size));

		co_return;
	}

	boost::asio::awaitable<vpn_connection_ptr> vpn_tunnel::do_vpt_fec_packet(
		stream_endian::bitstream& reader)
	{
		// 协议格式:
		// type(number)
		// vaddr(number)
		// gid(number)
		// pid(number)
		// ds(number)
		// ps(number)
		// gsize(number)
		// tail(skip)
		// content

		vpn_connection_ptr connection_ptr;

		// 解析fec数据.
		uint32_t vaddr = 0;
		if (!reader.ReadExponentialGolomb(&vaddr))
		{
			LOG_ERR << "Receive do_vpt_fec_packet vaddr error!";
			co_return connection_ptr;
		}

		if (m_identity == Identity::avpn_client)
			connection_ptr = m_client.lock();
		else
			connection_ptr = lookup_connection(vaddr);

		if (!connection_ptr)
		{
			LOG_ERR << "do_vpt_fec_packet vaddr is invalid: " << vaddr;
			co_return connection_ptr;
		}

		reset_connection_expires(*connection_ptr);

		uint32_t gid = 0;
		if (!reader.ReadExponentialGolomb(&gid))
		{
			LOG_ERR << "Receive do_vpt_fec_packet gid error!";
			co_return connection_ptr;
		}

		uint32_t pid = 0;
		if (!reader.ReadExponentialGolomb(&pid))
		{
			LOG_ERR << "Receive do_vpt_fec_packet pid error!";
			co_return connection_ptr;
		}

		uint32_t ds = 0;
		if (!reader.ReadExponentialGolomb(&ds))
		{
			LOG_ERR << "Receive do_vpt_fec_packet ds error!";
			co_return connection_ptr;
		}

		uint32_t ps = 0;
		if (!reader.ReadExponentialGolomb(&ps))
		{
			LOG_ERR << "Receive do_vpt_fec_packet ps error!";
			co_return connection_ptr;
		}

		uint32_t gsize = 0;
		if (!reader.ReadExponentialGolomb(&gsize))
		{
			LOG_ERR << "Receive do_vpt_fec_packet gszie error!";
			co_return connection_ptr;
		}

		reader.ReadTail();

		const uint8_t* bufptr = reader.GetOriginPtr() + reader.ByteOffset();
		int64_t fec_size = (int64_t)reader.AllSize() - (int64_t)reader.ByteOffset();
		if (fec_size <= 0)
		{
			LOG_ERR << "Receive do_vpt_fec_packet fec_size error!";
			co_return connection_ptr;
		}

		auto& fec = connection_ptr->fec_dec_;
		fec.update(gid, (uint16_t)pid, (int)ds, (int)ps,
			(int)gsize, (uint8_t*)bufptr, (size_t)fec_size);

		co_return connection_ptr;
	}

	boost::asio::awaitable<void> vpn_tunnel::do_vpt_udp_handshake(
		stream_endian::bitstream& reader, udp::socket& sock, const udp::endpoint& endp)
	{
		// 协议格式:
		// type(number)
		// vaddr(number)
		// tail(skip)

		if (m_identity == Identity::avpn_server)
		{
			uint32_t vaddr = 0;
			if (!reader.ReadExponentialGolomb(&vaddr))
			{
				LOG_ERR << "Receive do_vpt_udp_handshake read vaddr error!";
				co_return;
			}

			auto connection_ptr = lookup_connection(vaddr);
			if (!connection_ptr)
			{
				LOG_ERR << "Receive do_vpt_udp_handshake lookup connection error!";
				co_return;
			}

			auto& connection = *connection_ptr;
			if (connection.endps_.size() == 0)
				connection.endps_.reset(5, m_identity);

			connection.endps_.update(endp);

			// 回复client已经握手成功.
			std::string reply(normal_mtu, '\0');
			stream_endian::bitstream writer((uint8_t*)reply.data(), normal_mtu);
			writer.WriteExponentialGolomb(vpt_udp_handshake_reply);
			writer.WriteExponentialGolomb(200);
			writer.WriteTail();

			reply.resize(writer.ByteOffset());

			co_await forward_udp_write(sock, endp, std::move(reply));
			co_return;
		}

		BOOST_ASSERT(false && "Invalid m_identity, do_vpt_udp_handshake");

		co_return;
	}

	boost::asio::awaitable<void> vpn_tunnel::do_vpt_udp_handshake_reply(
		stream_endian::bitstream& reader, const udp::endpoint& endp)
	{
		// 协议格式:
		// type(number)
		// status(number)
		// tail(skip)

		if (m_identity == Identity::avpn_client)
		{
			uint32_t status = 0;
			if (!reader.ReadExponentialGolomb(&status))
			{
				LOG_ERR << "Receive vpt_udp_handshake_reply read status error!";
				co_return;
			}

			LOG_DBG << "Client vpt_udp_handshake recv: " << endp << " reply handshake: " << status;
			auto connection_ptr = m_client.lock();
			if (!connection_ptr)
			{
				LOG_ERR << "Receive vpt_udp_handshake_reply lookup connection error!";
				co_return;
			}

			co_return;
		}

		BOOST_ASSERT(false && "Invalid m_identity, do_vpt_udp_handshake_reply");

		co_return;
	}

	boost::asio::awaitable<void> vpn_tunnel::do_fec_process(vpn_connection_ptr& connection_ptr)
	{
		auto& connection = *connection_ptr;
		auto& fec = connection.fec_dec_;

		// 清理FEC缓存垃圾.
		auto garbage_size = fec.garbage_clean();
		if (garbage_size > 0)
			LOG_DBG << "do_process_fec, clean garbage: " << garbage_size;

		auto fecdec_func = [&](fec::fec_group& gop) mutable ->std::vector<std::string>
		{
			auto& dec_matrix = connection.dec_matrix_;

			if ((gop.ds_ > 0
				&& connection.dec_ds_ != gop.ds_
				&& connection.dec_ps_ != gop.ps_) || !dec_matrix)
			{
				connection.dec_ds_ = gop.ds_;
				connection.dec_ps_ = gop.ps_;

				m_dec_matrix =
					fec::reedsolomon::build_matrix(gop.ds_ + gop.ps_, gop.ds_);
				dec_matrix = &m_dec_matrix;
			}

			if (dec_matrix->size() > 0)
				return gop.decode(*dec_matrix);

			return gop.decode();
		};

		// 获取满足条件的FEC数据包集, 然后根据IP包中的信息逐个按
		// 目标位置转发, 如果是虚拟内网转发, 则通过内网透传.
		auto groups = fec.acquire();
		for (auto& gop : groups)
		{
			auto v = fecdec_func(gop);
			for (auto& d : v)
			{
				// 处理内网数据包.
				auto endp = avpn::lookup_endpoint_pair((const uint8_t*)d.data(), d.size());
				auto dst_addr = endp.dst_.address().to_v4().to_uint();
				udp::endpoint uendp(endp.dst_.address(), 0);

				// 非内网数据包, 直接转发到tun设备, 由os处理.
				if (!same_ipv4_network(m_subnet, dst_addr))
				{
					m_vpn_service.do_tuntap_write(std::move(d));
					continue;
				}

				// 不允许内网传输.
				if (!m_params.c2c_)
					continue;

				// 查找内网vpn连接, 如果没找到则直接转发到tun设备.
				auto vlan_connection = lookup_connection(dst_addr);
				if (!vlan_connection)
				{
					m_vpn_service.do_tuntap_write(std::move(d));
					continue;
				}

				// 内网数据包, 直接找到对应链转发.
				avpn::vpn_message msg;
				msg.type = (uint8_t)endp.type_;
				msg.content_ = d;

				if (endp.type_ == avpn::ip_type::ip_tcp)
					msg.type = vpt_tcp;
				else if (endp.type_ == avpn::ip_type::ip_udp)
					msg.type = vpt_udp;
				else if (endp.type_ == avpn::ip_type::ip_icmp)
					msg.type = vpt_icmp;
				else
					BOOST_ASSERT(false && "invalid msg.type");

				co_await forward_tunnel_write(vlan_connection, std::move(msg));
			}
		}
	}

	boost::asio::awaitable<void> vpn_tunnel::run_fec_dispatch()
	{
		if (m_params.mode_ == vpn_tcp_mode::only_tcp)
			co_return;

		LOG_DBG << "Start fec dispath...";

		while (!m_abort) [[likely]]
		{
			boost::system::error_code ec;
			std::vector<vpn_connection_weak_ptr> vpn_peers;
			int delay = 500;

			if (m_identity == Identity::avpn_client)
			{
				if (m_udp_sockets.size() > 0)
					delay = m_params.fec_delay_;
			}
			else
			{
				// 找到所有server的vpn连接, 并判断其是否有udp连接, 只
				// 要有任何udp连接, 则不得降低timer的延迟.
				std::shared_lock lock(m_remotes_mtx);
				for ([[maybe_unused]] auto& [id, conn] : m_remotes)
				{
					if (!conn.lock())
						continue;

					if (delay != m_params.fec_delay_)
					{
						auto c = conn.lock();
						if (c)
						{
							if (c->endps_.size() > 0)
								delay = m_params.fec_delay_;
						}
					}

					vpn_peers.emplace_back(conn);
				}
			}

			m_fec_timer.expires_from_now(std::chrono::milliseconds(delay));
			co_await m_fec_timer.async_wait(uawaitable[ec]);
			if (m_abort) [[unlikely]]
				break;

			// 作为client时, 直接保存client的vpn连接.
			if (m_identity == Identity::avpn_client)
			{
				auto conn = m_client.lock();
				if (!conn)
					continue;
				vpn_peers.emplace_back(conn);
			}

			// 循环处理所有vpn连接的fec数据.
			for (auto& peer_weak_ptr : vpn_peers)
			{
				auto connection_ptr = peer_weak_ptr.lock();
				if (!connection_ptr)
					continue;

				// 连接信息.
				auto& conn = *connection_ptr;

				// 如果连接上没有数据, 则跳过.
				if (conn.fec_enc_size_ <= 0)
					continue;

				// 如果未发送完, 继续发送而不进入等待.
				bool keep_continue = false;
				do {
					if (m_abort) [[unlikely]]
						goto fec_quit;

					keep_continue = co_await do_fec_perform(connection_ptr);
				} while (keep_continue);
			}
		fec_quit:
			continue;
		}

		LOG_WARN << "run_fec_dispatch, quit...";
		co_return;
	}

	boost::asio::awaitable<bool> vpn_tunnel::do_fec_perform(vpn_connection_ptr& connection_ptr)
	{
		// 继续发送.
		bool keep_continue = false;

		auto& connection = *connection_ptr;
		auto& fec_enc = connection.fec_enc_;

		// 通知过来时, 数据已经被发送了.
		if (connection.fec_enc_size_ == 0)
		{
			LOG_ERR << "do_fec_perform, connection.fec_enc_size_ == 0!!!";
			co_return keep_continue;
		}

		// 实在是数据太小了, 无法FEC时, 直接通过tcp发送.
		if ((connection.fec_enc_size_ < static_mtu * 5)
			&& m_params.mode_ != vpn_tcp_mode::only_udp)
		{
			for (auto& msg : fec_enc)
			{
				std::string pkt(normal_mtu, 0);
				stream_endian::bitstream writer((uint8_t*)pkt.data(), normal_mtu);

				writer.WriteExponentialGolomb(msg.type);
				writer.WriteTail();
				writer.WriteString(msg.content_.data(), msg.content_.size());

				pkt.resize(writer.ByteOffset());

				boost::asio::co_spawn(m_main_ioc,
					[this, connection_ptr, pkt = std::move(pkt)]() mutable ->boost::asio::awaitable<void>
					{
						co_await forward_tcp_write(connection_ptr, std::move(pkt));
					}, boost::asio::detached);
			}

			// 清理已发送的数据包.
			fec_enc.clear();
			connection.fec_enc_size_ = 0;

			co_return false;
		}

		// 收集时间未到, 继续收集.
		auto now = time_clock::steady_clock::now();
		auto duration = now - connection.enc_tm_;

		// if (duration < std::chrono::milliseconds(m_params.fec_timeout_))
		//	co_return;

		std::string content;
		int64_t bytes_transferred = 0;
		auto num_packet = fec_enc.size();

		BOOST_ASSERT(num_packet > 0);

		// 按计算出最大数据大小.
		const auto max_data_size = static_mtu * m_params.data_shards_;
		bool clean = false;

		for (auto it = fec_enc.begin(), be = it; it != fec_enc.end(); it++)
		{
			auto& msg = *it;

			// 将IP数据追加到content.
			content.append((const char*)msg.content_.data(), msg.content_.size());
			bytes_transferred += (int64_t)msg.content_.size();

			// max_data_size 是 data_shards 和 mtu 大小计算出来的最大编码数据量.
			// fec编码一次最大数据量不能超过max_data_size, 否则有可能超出mtu大小
			// 导致在发送时被分片而产生丢包.
			if (content.size() + static_mtu >= (size_t)max_data_size)
			{
				// 删除已经添加到content的fec数据.
				fec_enc.erase(be, ++it);

				clean = true;

				// 如果fec编码缓冲还剩余数据, 则持续调度.
				if (fec_enc.size() > 0)
					keep_continue = true;

				break;
			}
		}

		// 如果fec_enc的数据总大小是小于max_data_size时, content包含了所有fec_enc中的数据.
		// 所以这里可以直接清理.
		if (!clean)
		{
			BOOST_ASSERT(bytes_transferred == (int64_t)content.size());
			BOOST_ASSERT(bytes_transferred == (int64_t)connection.fec_enc_size_);

			fec_enc.clear();
		}

		BOOST_ASSERT(bytes_transferred > 0 && bytes_transferred == (int64_t)content.size());

		connection.fec_enc_size_ -= bytes_transferred;
		auto gid = connection.gid_++;

		auto& data_shards = m_params.data_shards_;
		auto& parity_shards = m_params.parity_shards_;
		auto total_shards = data_shards + parity_shards;

		fec::reedsolomon rs(data_shards, parity_shards, *connection.enc_matrix_);

		auto gsize = content.size();
		auto pershard_size = rs.estimate_pershard_size((int)content.size());
		content.resize(pershard_size * total_shards);

		std::vector<std::string_view> shards;
		shards.resize(total_shards);
		for (size_t i = 0; i < (size_t)total_shards; i++)
			shards[i] = { (char*)content.data() + (i * pershard_size), pershard_size };

		rs.encode(shards);

		auto remote_endpoint = &m_remote_endps;
		if (m_identity == Identity::avpn_server)
			remote_endpoint = &connection.endps_;

		auto usize = m_udp_sockets.size();
		size_t send_data_size = 0;

		for (size_t n = 0; n < shards.size(); n++)
		{
			const auto& s = shards[n];

			std::string fec_body(normal_mtu, 0);
			size_t body_size = 0;

			{
				stream_endian::bitstream writer((uint8_t*)fec_body.data(), normal_mtu);

				writer.WriteExponentialGolomb(vpt_fec);				// type
				writer.WriteExponentialGolomb(connection.vnet_);	// vaddr
				writer.WriteExponentialGolomb(gid);					// gid
				writer.WriteExponentialGolomb((uint32_t)n);			// pid
				writer.WriteExponentialGolomb(data_shards);			// ds
				writer.WriteExponentialGolomb(parity_shards);		// ps
				writer.WriteExponentialGolomb((uint32_t)gsize);		// gsize
				writer.WriteTail();									// tail(skip)
				writer.WriteString(s.data(), s.size());				// content

				body_size = writer.ByteOffset();
				fec_body.resize(body_size);
			}

			if (m_params.compress_)
				vpt_compress(vpt_fec, fec_body);

			send_data_size += fec_body.size();
			auto& usock = m_udp_sockets[n % usize]->sock_;
			auto uendp = remote_endpoint->acquire();

			co_await forward_udp_write(usock, uendp, std::move(fec_body));
		}

		auto& fec_dec = connection.fec_dec_;
		LOG_DBG << "Addr: " << connection.vnet_
			<< ", Gid: " << gid
			<< ", Each: " << pershard_size
			<< ", DUR: " << duration.count()
			<< ", IP: " << num_packet
			<< ", Fec: " << shards.size()
			<< ", Data: " << bytes_transferred
			<< ", Whole: " << send_data_size
			<< ", Immed: " << (keep_continue ? "yes" : "no")
			<< ", Mem: " << fec_dec.total_cache_size_
			;

		co_return keep_continue;
	}



}


