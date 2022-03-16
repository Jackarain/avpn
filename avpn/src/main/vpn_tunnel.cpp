//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#include "avpn/vpn_tunnel.hpp"
#include "avpn/avpn.hpp"

namespace avpn
{
	vpn_tunnel::vpn_tunnel(boost::asio::io_context& io, io_context_pool& ios, const channel_params& params, avpn_service& service)
		: m_vpn_service(service)
		, m_main_ioc(io)
		, m_ioc_pool(ios)
		, m_params(params)
		, m_subnet(boost::asio::ip::make_network_v4(params.subnet_))
		, m_ip_assigner(m_subnet.hosts())
		, m_ip_iterator(++m_ip_assigner.begin())
		, m_fec_timer(m_main_ioc)
		, m_wait_timer(m_main_ioc)
	{
		LOG_DBG << "Start unique counter: " << gen_unique_number();
	}

	vpn_tunnel::~vpn_tunnel()
	{
		LOG_DBG << "channel::~channel()";
	}

	void vpn_tunnel::start_listen(std::vector<std::string> tcp_listens, std::vector<std::string> udp_listens)
	{
		m_tcp_listens = tcp_listens;
		m_udp_listens = udp_listens;

		// 服务器身份.
		m_identity = avpn::avpn_server;

		// 开始启动tcp客户端, 即ws服务器.
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
						boost::asio::co_spawn(m_ioc_pool.get_io_context().get_executor(),
							start_ws_listen(a), boost::asio::detached);
				}
				co_return;
			}, boost::asio::detached);

		// 启动UDP通信.
		LOG_DBG << "Start udp socket...";
		boost::asio::co_spawn(m_main_ioc.get_executor(),
			[this]() mutable -> boost::asio::awaitable<void>
			{
				co_await start_udp_server();
				LOG_DBG << "Udp server quit...";
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
					LOG_DBG << "Fec dispatch quit...";
					co_return;
				}, boost::asio::detached);
		}

		channel_status cs;
		cs.status_ = connection_status::st_listen;

		m_vpn_service.on_status(cs);
	}

	void vpn_tunnel::start_connect(const std::vector<std::string>& upstreams)
	{
		m_upstreams = upstreams;
		m_identity = avpn::avpn_client;

		if (m_params.data_shards_ > 1)
		{
			LOG_DBG << "Start fec dispatch.";
			boost::asio::co_spawn(m_main_ioc.get_executor(),
				[this]() mutable -> boost::asio::awaitable<void>
				{
					co_await run_fec_dispatch();
					LOG_DBG << "Fec dispatch quit...";
					co_return;
				}, boost::asio::detached);
		}

		// 发起TCP连接协程.
		LOG_DBG << "Start tcp socket.";
		boost::asio::co_spawn(m_main_ioc.get_executor(),
			[this]() mutable -> boost::asio::awaitable<void>
			{
				co_await start_tcp_connect();
				LOG_DBG << "Tcp socket quit...";
				co_return;
			}, boost::asio::detached);
	}

	void vpn_tunnel::close()
	{
		m_abort = true;

		boost::system::error_code ignore_ec;
		m_fec_timer.cancel(ignore_ec);

		if (m_identity == avpn::avpn_server)
		{
			for (auto& a : m_ws_acceptors)
				a.close(ignore_ec);

			std::lock_guard<std::mutex> lock(m_server_mtx);
			for ([[maybe_unused]] auto& [id, connection_ptr] : m_remotes)
			{
				auto connection = connection_ptr.lock();
				if (!connection)
					continue;

				connection->reconnect_timer_.cancel(ignore_ec);
				boost::beast::get_lowest_layer(connection->ws_stream_).close();

				LOG_DBG << "Close ws stream: " << connection->connection_id_;
			}

			for ([[maybe_unused]] auto& [id, connection_ptr] : m_incomings)
			{
				auto connection = connection_ptr.lock();
				if (!connection)
					continue;

				connection->reconnect_timer_.cancel(ignore_ec);
				boost::beast::get_lowest_layer(connection->ws_stream_).close();

				LOG_DBG << "Close incoming ws stream: " << id;
			}
		}

		if (m_identity == avpn::avpn_client)
		{
			m_cancel_sig.emit(boost::asio::cancellation_type::all);

			auto connection_ptr = m_client.lock();
			if (connection_ptr)
			{
				connection_ptr->reconnect_timer_.cancel(ignore_ec);
				auto& layer = boost::beast::get_lowest_layer(connection_ptr->ws_stream_);
				layer.socket().close(ignore_ec);

				LOG_DBG << "Close ws client stream";
			}
		}

		for (auto& u : m_udp_sockets)
			u->sock_.close(ignore_ec);

		m_wait_timer.cancel(ignore_ec);

		LOG_DBG << "Close udp sockets...";
	}

	void vpn_tunnel::server_forward_tun(vpn_message&& msg, endpoint_pair&& endp)
	{
		auto connection_ptr = lookup_connection(endp.dst_.address().to_v4().to_uint());
		if (!connection_ptr)
		{
			LOG_WARN << "server_forward_tun, t -> c, lost connection: " << endp;
			return;
		}

		if (endp.type_ == avpn::ip_icmp)
			LOG_DBG << "server_forward_tun, t -> c, icmp: " << endp;

		auto& stream = connection_ptr->ws_stream_;
		boost::asio::co_spawn(stream.get_executor(),
			forward_channel_write(connection_ptr, std::move(msg)), boost::asio::detached);
	}

	void vpn_tunnel::client_forward_tun(vpn_message&& msg, endpoint_pair&& endp)
	{
		auto connection_ptr = m_client.lock();
		if (!connection_ptr)
		{
			LOG_WARN << "client_forward_tun, t -> s, lost connection: " << endp;
			return;
		}

		if (endp.type_ == avpn::ip_icmp)
			LOG_DBG << "client_forward_tun, t -> s, icmp: " << endp;

		auto& stream = connection_ptr->ws_stream_;

		boost::asio::co_spawn(stream.get_executor(),
			forward_channel_write(connection_ptr, std::move(msg)), boost::asio::detached);
	}

	boost::asio::ip::network_v4 vpn_tunnel::vnet_ipaddr() const
	{
		return m_vnet_ipaddr;
	}

	boost::asio::ip::network_v4 vpn_tunnel::vnet() const
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
				LOG_ERR << "WS server listen error: " << wsd << ", ec: " << ec.message();
				return false;
			}

			tcp::acceptor a{ m_main_ioc };

			a.open(endp.protocol(), ec);
			if (ec)
			{
				LOG_ERR << "WS server open accept error: " << ec.message();
				return false;
			}

			a.set_option(boost::asio::socket_base::reuse_address(true), ec);
			if (ec)
			{
				LOG_ERR << "WS server accept set option failed: " << ec.message();
				return false;
			}

			if (ipv6only)
			{
				a.set_option(boost::asio::ip::v6_only(true), ec);
				if (ec)
				{
					LOG_ERR << "WS server accept set v6_only failed: " << ec.message();
					return false;
				}
			}

			a.bind(endp, ec);
			if (ec)
			{
				LOG_ERR << "WS server bind failed: "
					<< ec.message() << ", address: " << endp.address().to_string() << ", port: " << endp.port();
				return false;
			}

			a.listen(boost::asio::socket_base::max_listen_connections, ec);
			if (ec)
			{
				LOG_ERR << "WS server listen failed: " << ec.message();
				return false;
			}

			m_ws_acceptors.emplace_back(std::move(a));
		}

		return true;
	}

	boost::asio::awaitable<void> vpn_tunnel::start_ws_listen(tcp::acceptor& a)
	{
		boost::system::error_code error;
		while (!m_abort)
		{
			tcp::socket socket(m_main_ioc);
			co_await a.async_accept(socket, uawaitable[error]);
			if (error)
			{
				LOG_ERR << "WS server, async_accept: " << error.message();

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

			boost::beast::tcp_stream stream(std::move(socket));

			static std::atomic_size_t id{ 0 };
			size_t connection_id = id++;

			LOG_DBG << "start_ws_listen, incoming id: " << connection_id;

			auto executor = stream.get_executor();
			boost::asio::co_spawn(executor,
				start_ws_connection(connection_id, std::move(stream)), boost::asio::detached);
		}

		LOG_DBG << "start_ws_listen exit...";
	}

	boost::asio::awaitable<void> vpn_tunnel::start_ws_connection(size_t connection_id, boost::beast::tcp_stream stream)
	{
		using namespace boost::beast;
		boost::system::error_code ec;
		boost::beast::flat_buffer buffer;

		for (; !m_abort;)
		{
			request_parser parser;
			parser.body_limit(std::numeric_limits<uint64_t>::max());

			co_await http::async_read_header(stream, buffer, parser, uawaitable[ec]);
			if (ec)
			{
				LOG_DBG << "start_ws_connect, id: " << connection_id << ", async_read_header: " << ec.message();
				co_return;
			}

			if (parser.get()[http::field::expect] == "100-continue")
			{
				http::response<http::empty_body> res;
				res.version(11);
				res.result(http::status::continue_);
				co_await http::async_write(stream, res, uawaitable[ec]);
				if (ec)
				{
					LOG_DBG << "start_ws_connect, id: " << connection_id
						<< ", expect async_write: " << ec.message();
					co_return;
				}
			}

			auto req = parser.release();

			std::string target = req.target().to_string();
			if (!boost::beast::websocket::is_upgrade(req))
			{
				http_params params{ {}, connection_id, stream, req, parser, buffer };
				co_return co_await http_response_handle(params, "Illegal request", http_status::bad_request);
			}

			std::string remote_host;
			auto endp = stream.socket().remote_endpoint(ec);
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

			stream.expires_never();

			ws_stream ws{ std::move(stream) };
			co_await ws.async_accept(req, uawaitable[ec]);
			if (ec)
			{
				LOG_DBG << "start_ws_connect, " << connection_id << ", async_accept: " << ec.message();
				break;
			}

			// 创建connection, 只有在握手完成才加入m_remotes容器进行管理.
			vpn_connection_ptr connection_ptr =
				std::make_shared<vpn_connection>(std::forward<ws_stream>(ws), remote_host);

			// 设置超时时间.
			ws_expires_after(*connection_ptr, 60);

			// 保存connection_id.
			connection_ptr->connection_id_ = connection_id;

			// 保存到临时表.
			add_incoming(connection_ptr, connection_id);
			// 发起保活协程.
			keepalive(connection_ptr);

			LOG_DBG << "Client incoming: " << remote_host << ", connection id: " << connection_id;

			// 设置为2进制模式.
			connection_ptr->ws_stream_.binary(true);

			// 收到pong消息, 重置超时.
			vpn_connection_weak_ptr vpnconn_weak_ptr = connection_ptr;
			connection_ptr->ws_stream_.control_callback(
				[this, wsconn_weak_ptr = std::move(vpnconn_weak_ptr)]
			(boost::beast::websocket::frame_type ft, boost::beast::string_view)
			{
				if (ft == boost::beast::websocket::frame_type::pong)
				{
					auto ws_conn_ptr = wsconn_weak_ptr.lock();
					if (!ws_conn_ptr || m_abort)
						return;

					ws_expires_after(*ws_conn_ptr, 60);
				}
			});

			// 启动读写协程.
			auto executor = connection_ptr->ws_stream_.get_executor();
			boost::asio::co_spawn(executor,
				start_tcp_read(connection_ptr), [this, connection_ptr](std::exception_ptr) mutable
				{
					auto& conn = *connection_ptr;

					boost::beast::get_lowest_layer(conn.ws_stream_).close();
					if (conn.vnet_ != 0)
						remove_connection(conn.vnet_);
					else
						remove_incoming(conn.connection_id_);
				});

			co_return;
		}
	}

	void vpn_tunnel::keepalive(vpn_connection_weak_ptr ptr)
	{
		auto connection_ptr = ptr.lock();
		if (!connection_ptr)
			return;

		boost::asio::co_spawn(connection_ptr->ws_stream_.get_executor(),
			[this, ptr = std::move(ptr)]() mutable->boost::asio::awaitable<void>
		{
			auto remote_endpoint = &m_remote_endps;
			int64_t connection_id = -1;
			uint32_t vaddr = 0;
			boost::system::error_code ec;

			std::random_device rd;
			std::mt19937 g(rd());

			while (!m_abort)
			{
				{
					auto connection_ptr = ptr.lock();
					if (!connection_ptr)
						co_return;

					// 如果身份是server, 则使用vpn connection中的endpoint.
					if (m_identity == avpn::avpn_server)
						remote_endpoint = &connection_ptr->endps_;

					connection_id = connection_ptr->connection_id_;
					vaddr = connection_ptr->vnet_;

					if (vaddr == 0)
					{
						m_wait_timer.expires_from_now(std::chrono::milliseconds(m_params.keepalive_));
						co_await m_wait_timer.async_wait(uawaitable[ec]);
						continue;
					}

					// LOG_DBG << "Keepalive for connection id: " << ws_conn_ptr->connection_id_;
					co_await connection_ptr->ws_stream_.async_ping("", uawaitable[ec]);
				}

				std::vector<udp_socket*> udps;

				if (vaddr != 0)
				{
					for (auto& u : m_udp_sockets)
						udps.push_back(u.get());

					std::shuffle(udps.begin(), udps.end(), g);
				}

				if (m_identity == avpn::avpn_client && vaddr != 0)
				{
					auto now = time_clock::steady_clock::now();
					for (auto& usock_ptr : udps)
					{
						if (m_abort)
							break;

						auto& u = *usock_ptr;
						auto& usock = u.sock_;

						if (now - usock_ptr->last_see_ > std::chrono::seconds(60))
						{
							auto local_endp = usock.local_endpoint();
							auto protocol = local_endp.protocol();

							usock.close(ec);

							udp::socket new_usock(m_main_ioc, udp::endpoint(protocol, 0));

							auto new_endp = new_usock.local_endpoint(ec);
							if (ec)
							{
								LOG_WARN << "Reset udp socket: "
									<< local_endp << " -> " << new_endp << ", ec: " << ec.message();
							}
							else
							{
								LOG_WARN << "Reset udp socket: " << local_endp << " -> " << new_endp;
							}

							u.sock_ = std::move(new_usock);
							u.last_see_ = now;
						}
					}
				}

				for (auto& usock_ptr : udps)
				{
					if (m_abort)
						break;

					auto& u = *usock_ptr;
					auto& usock = u.sock_;

					std::string msg(normal_mtu, 0);

					stream_endian::bitstream writer((uint8_t*)msg.data(), normal_mtu);

					writer.WriteExponentialGolomb(vpt_keepalive);
					writer.WriteExponentialGolomb(vaddr);
					writer.WriteTail();

					msg.resize(writer.ByteOffset());

					auto endp = remote_endpoint->acquire();
					co_await forward_udp_write(usock, endp, std::move(msg));
				}

				// 定时处理.
				m_wait_timer.expires_from_now(std::chrono::milliseconds(m_params.keepalive_));
				co_await m_wait_timer.async_wait(uawaitable[ec]);
			}

			LOG_DBG << "channel::keepalive, connection: " << connection_id << " quit...";
		}, boost::asio::detached);
	}

	void vpn_tunnel::ws_expires_after(vpn_connection& connection, int seconds)
	{
		// 设置超时.
		auto& stream = connection.ws_stream_;
		boost::beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(seconds));
	}

	boost::asio::awaitable<void> vpn_tunnel::start_tcp_read(vpn_connection_ptr connection_ptr)
	{
		auto& connection = *connection_ptr;
		auto connection_id = connection.connection_id_;
		auto& stream = connection.ws_stream_;

		boost::beast::error_code ec;
		std::vector<char> data;
		boost::asio::dynamic_vector_buffer buffer(data);

		while (!m_abort)
		{
			auto bytes = co_await stream.async_read(buffer, uawaitable[ec]);
			if (ec == websocket::error::closed)
			{
				LOG_DBG << "start_tcp_read, id: "
					<< connection_id << ", session was closed";
				break;
			}

			if (ec)
			{
				LOG_ERR << "start_tcp_read, id: "
					<< connection_id << ", async_read error: " << ec.message();
				break;
			}

			buffer.commit(bytes);
			ws_expires_after(connection, 60);

			const uint8_t* bufptr = boost::asio::buffer_cast<const uint8_t*>(buffer.data());

			stream_endian::bitstream reader(bufptr, bytes);
			uint32_t type = 0;
			if (!reader.ReadExponentialGolomb(&type))
			{
				LOG_ERR << "start_tcp_read, id: "
					<< connection_id << ", verify message size fail.";
				co_return;
			}

			co_await process_tcp_packet(type, reader, connection_ptr);
			buffer.consume(bytes);
		}

		LOG_WARN << "start_tcp_read, id: " << connection_id << " quit...";
	}

	boost::asio::awaitable<void> vpn_tunnel::process_tcp_packet(uint32_t type,
		stream_endian::bitstream& reader, vpn_connection_ptr& connection_ptr)
	{
		auto& connection = *connection_ptr;
		std::string bufs;

		switch (type)
		{
		case vpt_auth:
			co_await do_vpt_auth(reader, connection_ptr);
			co_return;
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
			co_await do_vpt_packet(type, reader, nullptr);
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
			{
				uint32_t vaddr = 0;
				if (!reader.ReadExponentialGolomb(&vaddr))
				{
					LOG_ERR << "Receive vpt_keepalive read vaddr error!";
					co_return;
				}

				if (m_identity == avpn::avpn_server)
				{
					connection_ptr = lookup_connection(vaddr);
					if (!connection_ptr)
					{
						LOG_ERR << "Server vpt_keepalive lookup connection error!";
						co_return;
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
			}
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
			co_await do_vpt_packet(type, reader, &endp);
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

		connection.deque_writing_ = !connection.ws_msg_deque_.empty();
		auto& message_deque = connection.ws_msg_deque_;
		message_deque.emplace_back(std::move(msg));

		if (!connection.deque_writing_)
		{
			boost::system::error_code ec;
			while (!m_abort && !message_deque.empty())
			{
				co_await connection.ws_stream_.async_write(
					boost::asio::buffer(message_deque.front()), uawaitable[ec]);
				if (ec)
				{
					LOG_ERR << "forward_tcp_write, " << connection.connection_id_
						<< " async_write error: " << ec.message();
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
			LOG_DBG << "forward_udp_write, async_send_to " << endp << ", error: " << ec.message();

		co_return;
	}

	boost::asio::awaitable<void> vpn_tunnel::forward_channel_write(vpn_connection_ptr connection_ptr, vpn_message msg)
	{
		auto& connection = *connection_ptr;
		connection.deque_writing_ = !connection.ws_msg_deque_.empty();

		// 如果发送模式为tcp, 或为tcp/udp混合发送模式, 并且当前发送空闲
		// 时, 则直接调用tcp发送.
		if (m_params.mode_ == vpn_tcp_mode::only_tcp
			|| (m_params.mode_ == vpn_tcp_mode::tcpudp_mix
				&& !connection.deque_writing_))
		{
			// 如果启用了压缩, 则先压缩后再发送, 我们只压缩tcp/udp数据包.
			if ((msg.type == vpt_tcp || msg.type == vpt_udp)
				&& m_params.compress_)
			{
				std::string compress_bufs(msg.content.size() * 2, 0);
				uLong outsize = (uLong)compress_bufs.size();

				auto ok = compress((Bytef*)compress_bufs.data(), &outsize,
					(const Bytef*)msg.content.data(), (uLong)msg.content.size());
				if (ok == Z_OK && outsize < msg.content.size())
				{
					compress_bufs.resize(outsize);
					msg.content = compress_bufs;

					if (msg.type == vpt_tcp)
						msg.type = vpt_compress_tcp;
					else if (msg.type == vpt_udp)
						msg.type = vpt_compress_udp;
					else
						BOOST_ASSERT(false && "forward_channel_write Commpress invalid msg.type");
				}
			}

			// 构造数据包.
			std::string pkt(normal_mtu, 0);
			stream_endian::bitstream writer((uint8_t*)pkt.data(), normal_mtu);

			writer.WriteExponentialGolomb(msg.type);
			writer.WriteTail();
			writer.WriteString(msg.content.data(), msg.content.size());

			pkt.resize(writer.ByteOffset());

			// 加入发送队列, 待发送.
			auto& message_deque = connection.ws_msg_deque_;
			message_deque.emplace_back(std::move(pkt));

			// 开始通过tcp循环发送这个pkt.
			boost::system::error_code ec;
			while (!m_abort && !message_deque.empty())
			{
				co_await connection.ws_stream_.async_write(
					boost::asio::buffer(message_deque.front()), uawaitable[ec]);
				if (ec)
				{
					LOG_ERR << "forward_channel_write, t -> r, "
						<< connection.connection_id_ << " async_write error: " << ec.message();
					co_return;
				}
				message_deque.pop_front();
			}
		}
		else
		{
			// 1个数据包的情况下, 禁用fec并立即发包.
			if (m_params.data_shards_ == 1)
			{
				// 如果启用了压缩, 则先压缩.
				if ((msg.type == vpt_tcp || msg.type == vpt_udp)
					&& m_params.compress_)
				{
					std::string compress_bufs(msg.content.size() * 2, 0);
					uLong outsize = (uLong)compress_bufs.size();

					auto ok = compress((Bytef*)compress_bufs.data(), &outsize,
						(const Bytef*)msg.content.data(), (uLong)msg.content.size());
					if (ok == Z_OK && outsize < msg.content.size())
					{
						compress_bufs.resize(outsize);
						msg.content = compress_bufs;

						if (msg.type == vpt_tcp)
							msg.type = vpt_compress_tcp;
						else if (msg.type == vpt_udp)
							msg.type = vpt_compress_udp;
						else
							BOOST_ASSERT(false && "forward_channel_write Nonfec Commpress invalid msg.type");
					}
				}

				// 构造数据包.
				std::string pkt(normal_mtu, 0);
				stream_endian::bitstream writer((uint8_t*)pkt.data(), normal_mtu);

				writer.WriteExponentialGolomb(msg.type);
				writer.WriteTail();
				writer.WriteString(msg.content.data(), msg.content.size());

				pkt.resize(writer.ByteOffset());

				// 多倍流量模式, 有多个冗余, 则发送多次.
				auto usize = m_udp_sockets.size();

				// 计算冗余数据大小, 并循环发送, 最大5倍发包模式.
				auto parity_shards = m_params.parity_shards_;
				parity_shards = parity_shards <= 0 ? 1 : parity_shards;
				parity_shards = parity_shards > 5 ? 5 : parity_shards;

				vpn_remote_endpoint* remote_endpoint = &m_remote_endps;
				if (m_identity == avpn::avpn_server)
					remote_endpoint = &connection.endps_;

				for (auto n = 0; n < parity_shards && msg.type == vpt_tcp; n++)
				{
					auto duplicate = pkt;

					auto& usock = m_udp_sockets[n % usize]->sock_;
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
					auto bytes = msg.content.size();
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
	}

	boost::asio::awaitable<void> vpn_tunnel::start_udp_server()
	{
		boost::system::error_code ec;
		BOOST_ASSERT(m_identity == avpn::avpn_server);

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

			auto sockptr = std::make_unique<udp_socket>(
				time_clock::steady_clock::now(), std::move(sock));

			m_udp_sockets.emplace_back(std::move(sockptr));
		}

		// 按socket数量启动udp读取协程, 为接收提高效率, 发起2倍接收.
		for (size_t fast = 0; fast < 2; fast++)
		{
			for (size_t n = 0; n < m_udp_sockets.size(); n++)
			{
				LOG_DBG << "start_udp_server, local endpoint: ["
					<< m_udp_sockets[n]->sock_.local_endpoint().address().to_string() << "]:"
					<< m_udp_sockets[n]->sock_.local_endpoint().port();

				boost::asio::co_spawn(m_main_ioc.get_executor(),
					start_udp_read_loop(n), boost::asio::detached);
			}
		}

		co_return;
	}

	boost::asio::awaitable<void> vpn_tunnel::start_udp_client()
	{
		BOOST_ASSERT(m_identity == avpn::avpn_client);

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

		m_remote_endps.resize(endps.size());
		for (auto& endp : endps)
			m_remote_endps.update(endp);

		// client 模式, 创建固定个数udp socket.
		for (auto& sock_ptr : m_udp_sockets)
		{
			if (!sock_ptr || !sock_ptr->sock_.is_open())
				continue;

			sock_ptr->sock_.close(ec);
		}

		// 每个上游都开启 max_client_udp_socket 倍socket通信.
		auto size = m_remote_endps.size() * max_client_udp_socket;
		for (int i = 0; i < size; i++)
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

			auto& conn = *connection_ptr;

			std::string msg(normal_mtu, 0);
			stream_endian::bitstream writer((uint8_t*)msg.data(), normal_mtu);

			writer.WriteExponentialGolomb(vpt_udp_handshake);
			writer.WriteExponentialGolomb(conn.vnet_);
			writer.WriteTail();

			msg.resize(writer.ByteOffset());

			// 向服务器发送握手请求.
			co_await forward_udp_write(sock, endp, std::move(msg));

			// 保存到udp socket容器.
			if (m_udp_sockets.size() == i)
			{
				udp_socket_ptr tmp = std::make_unique<udp_socket>(
					time_clock::steady_clock::now(), std::move(sock));

				m_udp_sockets.emplace_back(std::move(tmp));

				for (size_t fast = 0; fast < 2; fast++)
				{
					LOG_DBG << "start_udp_client, local endpoint: ["
						<< m_udp_sockets[i]->sock_.local_endpoint().address().to_string() << "]:"
						<< m_udp_sockets[i]->sock_.local_endpoint().port();

					boost::asio::co_spawn(m_main_ioc.get_executor(),
						start_udp_read_loop(i), boost::asio::detached);
				}
			}
			else
			{
				m_udp_sockets[i]->sock_.close(ec);

				m_udp_sockets[i]->last_see_ = time_clock::steady_clock::now();
				m_udp_sockets[i]->sock_ = std::move(sock);
			}
		}

		co_return;
	}

	boost::asio::awaitable<void> vpn_tunnel::start_udp_read_loop(size_t index)
	{
		auto udp_sock = m_udp_sockets[index].get();
		auto& sock = udp_sock->sock_;

		LOG_DBG << "start_udp_read_loop, index: " << index << ", udp size: " << m_udp_sockets.size();

		char buffer[2048];
		udp::endpoint remote_endp;
		boost::system::error_code ec;

		while (!m_abort)
		{
			auto bytes = co_await sock.async_receive_from(
				boost::asio::buffer(buffer), remote_endp, uawaitable[ec]);
			if (ec)
				continue;

			// 根据客户端身份更新udp endpoint.
			if (m_identity == avpn::avpn_client)
				udp_sock->last_see_ = time_clock::steady_clock::now();

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
			co_await process_udp_packet(type, reader, sock, remote_endp);
		}

		LOG_ERR << "start_udp_read_loop, endpoint: " << remote_endp << ", quit...";
	}

	boost::asio::awaitable<void> vpn_tunnel::start_tcp_connect()
	{
		boost::system::error_code ec;
		static const auto never =
			std::chrono::hours(std::numeric_limits<int>::max());

		while (!m_abort)
		{
			auto connection_ptr = m_client.lock();
			if (!connection_ptr)
			{
				static std::atomic_int64_t id{ 0 };
				connection_ptr = std::make_shared<vpn_connection>(ws_stream{ m_main_ioc }, "");
				connection_ptr->connection_id_ = id++;
				m_client = connection_ptr;
			}

			auto& connection = *connection_ptr;
			auto& stream = connection_ptr->ws_stream_;

			tcp::socket& sock = boost::beast::get_lowest_layer(stream).socket();
			bool ok = false;

			for (auto it = m_upstreams.begin();
				it != m_upstreams.end() && !m_abort && !ok; it++)
			{
				auto upstream = *it;
				util::uri parser;

				if (!parser.parse(upstream))
					continue;

				if (boost::to_lower_copy(std::string(parser.scheme())) == "udp")
					continue;

				tcp::resolver resolver{ m_main_ioc };
				auto const results = co_await resolver.async_resolve(
					std::string(parser.host()), std::string(parser.port()), uawaitable[ec]);
				if (ec)
				{
					LOG_ERR << "start_tcp_connect, async_resolve: " << ec.message();
					continue;
				}

				co_await asio_util::async_connect(sock, results,
					boost::asio::redirect_error(boost::asio::bind_cancellation_slot(m_cancel_sig.slot(),
						boost::asio::use_awaitable), ec));
				if (ec)
				{
					LOG_ERR << "start_tcp_connect, async_connect: " << ec.message();
					continue;
				}

				std::string origin = "all";
				auto decorator = [origin](boost::beast::websocket::request_type& m) {
					m.insert(boost::beast::http::field::origin, origin);
				};

				stream.set_option(boost::beast::websocket::stream_base::decorator(decorator));
				co_await stream.async_handshake(std::string(parser.host()),
					parser.path().empty() ? "/" : parser.path(), uawaitable[ec]);
				if (ec)
				{
					LOG_ERR << "start_tcp_connect, async_handshake: " << ec.message();
					continue;
				}

				boost::asio::ip::tcp::no_delay option(true);
				sock.set_option(option);

				ok = true;
			}

			if (!ok)
			{
				connection_ptr.reset();

				if (!m_abort)
				{
					LOG_DBG << "connect fail, wait a moment to reconnect...";

					m_wait_timer.expires_from_now(std::chrono::seconds(5));
					co_await m_wait_timer.async_wait(uawaitable[ec]);
				}

				continue;
			}

			// 连接成功, 设置为2进制模式.
			stream.binary(true);

			std::string remote_host;
			auto endp = boost::beast::get_lowest_layer(stream).socket().remote_endpoint(ec);
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
			LOG_DBG << "start_tcp_connect, connected to: " << remote_host;

			connection_ptr->ws_stream_.control_callback(
				[this, wptr = m_client]
			(boost::beast::websocket::frame_type ft, boost::beast::string_view)
			{
				if (ft == boost::beast::websocket::frame_type::pong)
				{
					auto connection_ptr = wptr.lock();
					if (!connection_ptr || m_abort)
						return;

					ws_expires_after(*connection_ptr, 60);
				}
			});

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

			co_await forward_tcp_write(connection_ptr, std::move(msg));

			// 发起保活协程.
			keepalive(connection_ptr);

			// 发起读写协程.
			co_await start_tcp_read(connection_ptr);

			if (!m_abort)
			{
				LOG_DBG << "read error, wait a moment to reconnect...";
				// 通知连接断开...
				channel_status cs;

				cs.status_ = connection_status::st_disconnect;
				m_vpn_service.on_status(cs);

				auto& wait = connection.reconnect_timer_;

				wait.expires_from_now(std::chrono::seconds(5));
				co_await wait.async_wait(uawaitable[ec]);
			}
		}

		co_return;
	}

	void vpn_tunnel::add_connection(vpn_connection_ptr& connection_ptr, uint32_t vaddr)
	{
		std::lock_guard<std::mutex> lock(m_server_mtx);
		m_remotes[vaddr] = connection_ptr;
	}

	void vpn_tunnel::remove_connection(uint32_t vaddr)
	{
		std::lock_guard<std::mutex> lock(m_server_mtx);
		m_remotes.erase(vaddr);
	}

	vpn_connection_ptr vpn_tunnel::lookup_connection(uint32_t vaddr)
	{
		std::lock_guard<std::mutex> lock(m_server_mtx);
		auto it = m_remotes.find(vaddr);
		if (it == m_remotes.end())
			return {};
		return it->second.lock();
	}

	void vpn_tunnel::add_incoming(vpn_connection_ptr& connection_ptr, int64_t id)
	{
		std::lock_guard<std::mutex> lock(m_server_mtx);
		m_incomings[id] = connection_ptr;
	}

	void vpn_tunnel::remove_incoming(int64_t id)
	{
		std::lock_guard<std::mutex> lock(m_server_mtx);
		m_incomings.erase(id);
	}

	boost::asio::awaitable<void> vpn_tunnel::http_response_handle(
		const http_params& params, std::string response, http_status status)
	{
		auto& connection_id = params.connection_id_;
		auto& stream = params.stream_;
		auto& request = params.request_;

		boost::system::error_code ec;
		string_response res{ status, request.version() };
		res.set(boost::beast::http::field::server, HTTPD_VERSION_STRING);
		res.set(boost::beast::http::field::content_type, "text/html");
		res.keep_alive(request.keep_alive());
		res.body() = response;
		res.prepare_payload();

		boost::beast::http::serializer<false, string_body, fields> sr{ res };
		co_await boost::beast::http::async_write(stream, sr, uawaitable[ec]);
		if (ec)
		{
			LOG_WARN << "do_http_response, id: " << connection_id << ", err: " << ec.message();
		}
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

	boost::asio::awaitable<void> vpn_tunnel::do_vpt_auth(
		stream_endian::bitstream& reader, vpn_connection_ptr& connection_ptr)
	{
		auto& connection = *connection_ptr;

		if (m_identity == avpn::avpn_server) // 作为 server.
		{
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
				LOG_WARN << "Server: " << connection.connection_id_
					<< ", verify auth code fail: " << code << ", got: " << auth_code;
				co_return;
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

		if (m_identity == avpn_client) // 作为 client 在认证通过后发起 udp 连接.
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

			uint32_t version = 0;
			if (!reader.ReadExponentialGolomb(&version))
			{
				LOG_ERR << "Client read protocol version error!";
				co_return;
			}

			if (version != avpn_protocol_version)
			{
				LOG_ERR << "Client protocol version incompatible: "
					<< version << ", expect: " << avpn_protocol_version;
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

			// 启动UDP通信.
			LOG_DBG << "Start udp socket, virutal addr: " << ipaddr.to_string();
			boost::asio::co_spawn(m_main_ioc.get_executor(),
				[this]() mutable -> boost::asio::awaitable<void>
				{
					co_await start_udp_client();
					LOG_DBG << "Udp client quit...";
					co_return;
				}, boost::asio::detached);

			co_return;
		}

		BOOST_ASSERT(false && "Invalid m_identity, do_vpt_auth");
		co_return;
	}

	boost::asio::awaitable<bool> vpn_tunnel::do_vpt_compress(
		stream_endian::bitstream& reader, std::string& bufs)
	{
		// 协议格式:
		// type(number)
		// tail(skip)
		// content_size(uint32)
		// content[content_size](bytes)

		// 解压缩操作.
		uLongf bufsize = 16384;
		bufs.resize(bufsize);

		reader.ReadTail();

		uint32_t content_size = 0;
		if (!reader.ReadUInt32(&content_size))
		{
			LOG_ERR << "Receive vpt_compress_udp content size error!";
			co_return false;
		}

		const Bytef* ptr = reader.GetOriginPtr() + reader.ByteOffset();

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

	boost::asio::awaitable<void> vpn_tunnel::do_vpt_packet(uint8_t type,
		stream_endian::bitstream& reader, const udp::endpoint* endp)
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
		if (m_identity == avpn::avpn_server && endp)
		{
			auto uint_src = src_addr.address().to_v4().to_uint();
			auto connection_ptr = lookup_connection(uint_src);
			if (connection_ptr)
				connection_ptr->endps_.update(*endp);
		}

		// 只有在身份为server时, 并且为内网数据包, 则直接找到对应链转发.
		if (m_identity == avpn::avpn_server && same_ipv4_network(m_subnet, uint_dst))
		{
			// 不允许内网传输.
			if (!m_params.c2c_)
				co_return;

			auto connection_ptr = lookup_connection(uint_dst);
			if (connection_ptr)
			{
				avpn::vpn_message msg;
				msg.type = type;
				msg.content.assign((char*)content, content_size);

				// 内网转发.
				co_await forward_channel_write(connection_ptr, std::move(msg));
				co_return;
			}
		}

		if (type == vpt_icmp)
			LOG_DBG << "Recvive udp, write tun icmp: " << dst_addr;

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

		if (m_identity == avpn::avpn_client)
			connection_ptr = m_client.lock();
		else
			connection_ptr = lookup_connection(vaddr);

		if (!connection_ptr)
		{
			LOG_ERR << "do_vpt_fec_packet vaddr is invalid: " << vaddr;
			co_return connection_ptr;
		}

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

		if (m_identity == avpn_server)
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

		if (m_identity == avpn::avpn_client)
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

			// 通知完成连接...
			channel_status cs;
			cs.routes_ = m_routes;
			cs.status_ = connection_status::st_connected;

			m_vpn_service.on_status(cs);

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
		auto num_garbage = fec.garbage_clean();
		if (num_garbage > 0)
			LOG_DBG << "do_process_fec, clean garbage: " << num_garbage;

		// 获取满足条件的FEC数据包集, 然后根据IP包中的信息逐个按
		// 目标位置转发, 如果是虚拟内网转发, 则通过内网透传.
		auto groups = fec.acquire();
		for (auto& gop : groups)
		{
			auto v = gop.decode();
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
				msg.content = d;

				if (endp.type_ == avpn::ip_type::ip_tcp)
					msg.type = vpt_tcp;
				else if (endp.type_ == avpn::ip_type::ip_udp)
					msg.type = vpt_udp;
				else if (endp.type_ == avpn::ip_type::ip_icmp)
					msg.type = vpt_icmp;
				else
					BOOST_ASSERT(false && "invalid msg.type");

				co_await forward_channel_write(vlan_connection, std::move(msg));
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

			m_fec_timer.expires_from_now(std::chrono::milliseconds(m_params.fec_delay_));
			co_await m_fec_timer.async_wait(uawaitable[ec]);
			if (m_abort) [[unlikely]]
				co_return;

			// 所有vpn连接.
			std::vector<vpn_connection_weak_ptr> vpn_peers;

			// 找到所有udp连接.
			if (m_identity == avpn::avpn_server)
			{
				std::lock_guard<std::mutex> lock(m_server_mtx);
				for ([[maybe_unused]] auto& [id, conn] : m_remotes)
				{
					if (!conn.lock())
						continue;
					vpn_peers.emplace_back(conn);
				}
			}
			else
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
						co_return;

					keep_continue = co_await do_fec_perform(connection_ptr);
				} while (keep_continue);
			}
		}

		co_return;
	}

	boost::asio::awaitable<bool> vpn_tunnel::do_fec_perform(vpn_connection_ptr& connection_ptr)
	{
		// 继续发送.
		bool keep_continue = false;

		auto& connection = *connection_ptr;
		auto& fec_enc = connection.fec_enc_;
		auto& fec_dec = connection.fec_dec_;

		// 通知过来时, 数据已经被发送了.
		if (connection.fec_enc_size_ == 0)
		{
			LOG_WARN << "do_fec_perform, connection.fec_enc_size_ == 0!!!";
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
				writer.WriteString(msg.content.data(), msg.content.size());

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
			content.append((const char*)msg.content.data(), msg.content.size());
			bytes_transferred += (int64_t)msg.content.size();

			// max_data_size 是 data_shards 和 mtu 大小计算出来的最大编码数据量.
			// fec编码一次最大数据量不能超过max_data_size, 否则有可能超出mtu大小
			// 导致在发送时被分片而产生丢包.
			if (content.size() + static_mtu >= max_data_size)
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

		fec::reedsolomon rs(data_shards, parity_shards);

		auto gsize = content.size();
		auto pershard_size = rs.estimate_pershard_size((int)content.size());
		content.resize(pershard_size * total_shards);

		std::vector<std::string_view> shards;
		shards.resize(total_shards);
		for (size_t i = 0; i < total_shards; i++)
			shards[i] = { (char*)content.data() + (i * pershard_size), pershard_size };

		rs.encode(shards);

		auto remote_endpoint = &m_remote_endps;
		if (m_identity == avpn::avpn_server)
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
			}

			if (m_params.compress_)
			{
				std::string compress_bufs(body_size * 2, 0);
				uLong out_size = (uLong)compress_bufs.size();

				auto ok = compress((Bytef*)compress_bufs.data(), &out_size,
					(const Bytef*)fec_body.data(), (uLong)body_size);
				if (ok == Z_OK)
				{
					if (out_size < (uLong)body_size)
					{
						stream_endian::bitstream writer((uint8_t*)fec_body.data(), normal_mtu);

						writer.WriteExponentialGolomb(vpt_compress_fec);	// type
						writer.WriteTail();									// tail(skip)
						writer.WriteUInt32((uint32_t)out_size);				// content_size(uint32)
						writer.WriteString(compress_bufs.data(), out_size);	// content

						body_size = writer.ByteOffset();
					}
				}
			}

			fec_body.resize(body_size);

			send_data_size += fec_body.size();
			auto& usock = m_udp_sockets[n % usize]->sock_;
			auto uendp = remote_endpoint->acquire();

			co_await forward_udp_write(usock, uendp, std::move(fec_body));
		}

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


