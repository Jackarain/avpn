//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#pragma once

#include <iostream>
#include <functional>
#include <cstring> // for std::memcpy
#include <map>
#include <unordered_map>
#include <set>

#include <boost/asio/io_context.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/defer.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/ip/v6_only.hpp>
#include <boost/asio/ip/address_v4.hpp>
#include <boost/asio/ip/network_v4.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/read_until.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/buffer.hpp>

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/ssl.hpp>

#include <zlib.h>

#include "avpn/io_context_pool.hpp"
#include "avpn/reedsolomon.hpp"

#include "vpncore/endpoint_pair.hpp"
#include "vpncore/fec_cache.hpp"

#include "utils/scoped_exit.hpp"
#include "utils/bitfield.hpp"
#include "utils/url_parser.hpp"
#include "utils/async_connect.hpp"
#include "utils/yield_cancellation_slot_bind.hpp"
#include "utils/time_clock.hpp"
#include "utils/io.hpp"
#include "utils/logging.hpp"
#include "utils/misc.hpp"

namespace avpn {

	namespace http = boost::beast::http;			// from <boost/beast/http.hpp>
	using tcp = boost::asio::ip::tcp;               // from <boost/asio/ip/tcp.hpp>
	using udp = boost::asio::ip::udp;               // from <boost/asio/ip/udp.hpp>
	namespace websocket = boost::beast::websocket;  // from <boost/beast/websocket.hpp>
	using ws = websocket::stream<tcp::socket>;		// from <boost/beast/websocket.hpp>
	// namespace net = boost::asio;					// from <boost/asio.hpp>
	using time_point = time_clock::steady_clock::time_point;

	using timer = boost::asio::basic_waitable_timer<time_clock::steady_clock>;
	using ws_stream = websocket::stream<boost::beast::tcp_stream>;

	using namespace util;
	using namespace stream_endian;

	enum {
		avpn_server = 0,
		avpn_client = 1
	};

	const static std::string test_google_key = "VLTATWJGVH5W7V7DX6V436FG74";
	const static int normal_mtu = 1500;
	const static int static_mtu = 1400;
	const static uint16_t avpn_protocol_version = 1;
	//////////////////////////////////////////////////////////////////////////

	enum {
		vpt_compress_tcp = 0,
		vpt_tcp,
		vpt_compress_udp,
		vpt_udp,
		vpt_icmp,
		vpt_compress_fec,
		vpt_fec,
		vpt_udp_handshake,
		vpt_udp_handshake_reply,
		vpt_keepalive,
		vpt_auth,
	};

	// nofec type(1) + len(4) + body(len)
	// fec   type(1) + len(4) + (fec ... params + body)(len)
	const static size_t pkt_header_size = 5;
	const static size_t fec_header_size = 11;

	//////////////////////////////////////////////////////////////////////////

	struct vpn_message
	{
		uint8_t type = vpt_tcp;
		std::string content;
	};

	struct udp_connection
	{
		time_point last_see_;
		fec_cache fec_dec_;					// fec 解码缓冲器.
		std::atomic_uint32_t gid_{ 0 };		// fec 编码group id.

		time_point packet_tm_;				// fec 编码缓冲接收起始时间.

		std::vector<vpn_message> fec_enc_;		// fec 编码缓冲.
		std::atomic_int64_t fec_enc_size_{ 0 };			// 缓冲字节数.

		udp::endpoint endp_;
		udp::socket* sock_{ nullptr };
		bool writing_{ false };

		void reset()
		{
			LOG_DBG << "udp connection reset";

			last_see_ = timer::clock_type::now();
			fec_dec_.reset();
			gid_ = 0;
			fec_enc_.clear();
			fec_enc_size_ = 0;
			sock_ = nullptr;
			writing_ = false;
		}

		~udp_connection()
		{
			auto remote_host = endp_.address().to_string();
			if (remote_host.empty())
				LOG_DBG << "udp connection leave";
			else
				LOG_DBG << "udp connection leave, remote: " << remote_host;
		}
	};

	using udp_connection_ptr = std::shared_ptr<udp_connection>;
	using udp_connection_weak_ptr = std::weak_ptr<udp_connection>;

	//////////////////////////////////////////////////////////////////////////

	struct ws_connection
	{
		ws_connection(ws_stream&& ws, int64_t connection_id, const std::string& remote_host)
			: ws_stream_(std::move(ws))
			, ws_timer_(ws_stream_.get_executor())
			, reconnect_timer_(ws_stream_.get_executor())
			, connection_id_(connection_id)
			, remote_host_(remote_host)
		{}

		ws_connection(ws_connection&& c) noexcept
			: ws_stream_(std::move(c.ws_stream_))
			, udp_stream_(std::move(c.udp_stream_))
			, ws_msg_deque_(std::move(c.ws_msg_deque_))
			, deque_writing_(c.deque_writing_)
			, identity_(c.identity_)
			, origin_addr(c.origin_addr)
			, ws_timer_(std::move(c.ws_timer_))
			, reconnect_timer_(std::move(c.reconnect_timer_))
			, connection_id_(c.connection_id_)
			, virtual_ipaddr_(c.virtual_ipaddr_)
			, remote_host_(c.remote_host_)
			, quit_(!!c.quit_)
		{}

		~ws_connection()
		{
			if (remote_host_.empty())
				LOG_DBG << "ws client leave id: " << connection_id_;
			else
				LOG_DBG << "ws client leave id: " << connection_id_ << ", remote: " << remote_host_;
		}

		ws_stream ws_stream_;
		udp_connection_weak_ptr udp_stream_;
		std::deque<std::string> ws_msg_deque_;
		bool deque_writing_{ false };
		int identity_{ 0 }; // 0 server, 1 client.
		avpn::endpoint_pair origin_addr; // 作为服务器时, 用于区分客户端的地址使用.
		timer ws_timer_;
		timer reconnect_timer_;
		int64_t connection_id_;
		uint32_t virtual_ipaddr_{ 0 };
		std::string remote_host_;
		std::atomic_bool quit_{ false };
	};
	using ws_connection_ptr = std::shared_ptr<ws_connection>;
	using ws_connection_weak_ptr = std::weak_ptr<ws_connection>;

	inline bool operator<(const ws_connection_weak_ptr& lh, const ws_connection_weak_ptr& rh)
	{
		auto lhp = lh.lock();
		auto rhp = rh.lock();

		if (lhp < rhp)
			return true;
		return false;
	}

	//////////////////////////////////////////////////////////////////////////

	enum vpn_tcp_mode
	{
		only_udp,
		tcpudp_mix,
		only_tcp,
	};

	struct channel_params
	{
		int data_shards_;			// fec数据设置.
		int parity_shards_;			// fec冗余设置.
		int fec_delay_;				// fec超时设置, 用于指定收集fec数据时间.
		int mode_;					// 在udp网络完全不通的环境下使用tcp网络.
		bool compress_;				// 压缩选项.
		bool auto_fec_;				// 自动调整fec参数以适应网络变化.
		int keepalive_;				// 保持网络活动消息.

		std::vector<std::string> routes_;	// server推送路由.
		std::string pushdns_;				// server推送dns.
		bool passbyvpn_;					// 客户端默认通过vpn.
		bool c2c_;							// 客户端之间通信.
		std::string subnet_;				// vpn子网配置.
	};

	enum connection_status
	{
		st_connected,
		st_disconnect,
		st_listen,
	};

	struct channel_status
	{
		bool passbyvpn_{ false };
		std::vector<std::string> routes_;
		connection_status status_;
	};

	class channel
	{
		using string_body = boost::beast::http::string_body;
		using string_response = boost::beast::http::response<string_body>;

		using dynamic_body = boost::beast::http::dynamic_body;
		using dynamic_request = boost::beast::http::request<dynamic_body>;
		using request_parser = boost::beast::http::request_parser<dynamic_request::body_type>;

		using http_status = boost::beast::http::status;
		using fields = boost::beast::http::fields;

		struct http_params
		{
			std::vector<std::string> command_;
			size_t connection_id_;
			boost::beast::tcp_stream& stream_;
			dynamic_request& request_;
			request_parser& parser_;
			boost::beast::flat_buffer& buffer_;
		};

		using tuntap_writer = std::function<void(std::string&&)>;
		using notify_status = std::function<void(channel_status)>;

		channel(const channel&) = delete;
		channel& operator=(const channel&) = delete;

	public:
		channel(boost::asio::io_context& io, avpn::io_context_pool& ios, const channel_params& params)
			: m_io_context(io)
			, m_ioc_pool(ios)
			, m_params(params)
			, m_subnet(boost::asio::ip::make_network_v4(params.subnet_))
			, m_ip_assigner(m_subnet.hosts())
			, m_ip_iterator(++m_ip_assigner.begin())
			, m_fec_timer(m_io_context)
		{
			LOG_DBG << "Start unique counter: " << gen_unique_number();
		}

	public:
		void start_connect(const std::vector<std::string>& upstreams,
			notify_status notify_func, tuntap_writer writer_func)
		{
			m_upstreams = upstreams;

			m_tuntap_writer = writer_func;
			m_status_notify = notify_func;

			// 客户端身份.
			m_identity = avpn_client;

			std::call_once(m_once_fec_timer, [this]()
				{
					if ((m_params.parity_shards_ <= 0) ||
						(m_params.parity_shards_ == 1 && m_params.data_shards_ == 1))
						return;

					boost::asio::co_spawn(m_io_context.get_executor(),
						on_fec_timer(), boost::asio::detached);
				});

			// 发起连接协程, 进入异步连接.
			boost::asio::co_spawn(m_io_context.get_executor(),
				[this]() mutable -> boost::asio::awaitable<void>
				{
					boost::system::error_code ec;

					static const auto never =
						std::chrono::hours(std::numeric_limits<int>::max());

					// 自动重连逻辑.
					while (!m_abort)
					{
						udp_connection_ptr uconn;
						auto wsclient = m_client.lock();
						if (wsclient)
						{
							uconn = wsclient->udp_stream_.lock();
							boost::beast::get_lowest_layer(wsclient->ws_stream_).socket().close(ec);
							wsclient->reconnect_timer_.cancel_one(ec);
							wsclient->ws_timer_.cancel_one(ec);
						}

						static std::atomic_int64_t id{ 0 };

						// 创建client对象用于发起向server的连接.
						wsclient = std::make_shared<ws_connection>(ws_stream{ m_io_context }, id++, "");
						m_client = wsclient;

						// 如果udp连接信息已经存在, 则重用此连接信息.
						if (uconn)
						{
							wsclient->udp_stream_ = uconn;
							uconn->reset();
						}

						co_await connect(wsclient);

						if (m_abort)
							break;

						timer& reconnect_timer = wsclient->reconnect_timer_;
						reconnect_timer.expires_from_now(never);
						co_await reconnect_timer.async_wait(
							boost::asio::redirect_error(boost::asio::use_awaitable, ec));

						if (m_abort)
							break;

						LOG_DBG << "channel::start_connect, do connect...";
					}

					LOG_WARN << "channel::start_connect, reconnect conroutine quit...";
				}, boost::asio::detached);
		}

		void start_listen(std::vector<std::string> tcp_listens,
			std::vector<std::string> udp_listens, notify_status notify_func, tuntap_writer writer_func)
		{
			m_tcp_listens = tcp_listens;
			m_udp_listens = udp_listens;

			m_tuntap_writer = writer_func;
			m_status_notify = notify_func;

			// 服务器身份.
			m_identity = avpn_server;

			// 开始启动tcp客户端, 即ws服务器.
			init_ws_acceptors();

			int pool_size = static_cast<int>(m_ioc_pool.pool_size());
			for (int i = 0; i < pool_size; i++)
			{
				for (auto& a : m_ws_acceptors)
				{
					boost::asio::co_spawn(m_ioc_pool.get_io_context().get_executor(),
						start_ws_listen(a), boost::asio::detached);
				}
			}

			// 启动udp连接用于接收消息.
			std::call_once(m_once_start_udp, [this]()
				{
					LOG_DBG << "Start udp socket...";

					boost::asio::co_spawn(m_io_context.get_executor(),
						start_udp_socket(), boost::asio::detached);
				});

			// 启动fec定时器, 用于处理fec消息.
			std::call_once(m_once_fec_timer, [this]()
				{
					if ((m_params.parity_shards_ <= 0) ||
						(m_params.parity_shards_ == 1 && m_params.data_shards_ == 1))
						return;

					boost::asio::co_spawn(m_io_context.get_executor(),
						on_fec_timer(), boost::asio::detached);
				});

			channel_status cs;
			cs.status_ = connection_status::st_listen;

			m_status_notify(cs);
		}

		void close()
		{
			m_abort = true;

			m_cancel_sig.emit(boost::asio::cancellation_type::all);

			boost::system::error_code ignore_ec;
			if (m_identity == avpn_client)
			{
				auto conn = m_client.lock();
				if (conn)
				{
					LOG_DBG << "close channel...";

					boost::beast::get_lowest_layer(conn->ws_stream_).socket().close(ignore_ec);
					conn->reconnect_timer_.cancel_one(ignore_ec);
					conn->ws_timer_.cancel_one(ignore_ec);
				}
			}

			if (m_identity == avpn_server)
			{
				LOG_DBG << "close all acceptors...";
				for (auto& a : m_ws_acceptors)
					a.close(ignore_ec);

				LOG_DBG << "close all client...";
				close_all_ws();
			}

			LOG_DBG << "close all udp connection...";
			{
				std::lock_guard<std::mutex> lock(m_udp_mux);
				for (auto& sock : m_udp_sockets)
					sock.close(ignore_ec);
			}

			// close fec timer.
			m_fec_timer.cancel(ignore_ec);
		}

		void client_write(avpn::vpn_message&& msg, avpn::endpoint_pair& endp)
		{
			// 作为客户端时.
			ws_connection_ptr connection_ptr = m_client.lock();
			if (!connection_ptr)
			{
				LOG_DBG << "client_write, t -> s, lost connection: " << endp;
				return;
			}

			if (endp.type_ == avpn::ip_icmp)
				LOG_DBG << "client_write, t -> s, icmp: " << endp;

			auto& stream = connection_ptr->ws_stream_;
			boost::asio::co_spawn(stream.get_executor(),
				on_channel_write(connection_ptr, std::move(msg)), boost::asio::detached);
		}

		void server_write(avpn::vpn_message&& msg, avpn::endpoint_pair& endp)
		{
			auto connection_ptr = lookup_ws(endp.dst_.address().to_v4().to_uint());
			if (!connection_ptr)
			{
				LOG_WARN << "server_write, t -> c, lost connection: " << endp;
				return;
			}

			if (endp.type_ == avpn::ip_icmp)
				LOG_DBG << "server_write, t -> c, icmp: " << endp;

			auto& stream = connection_ptr->ws_stream_;
			boost::asio::co_spawn(stream.get_executor(),
				on_channel_write(connection_ptr, std::move(msg)), boost::asio::detached);
		}

		boost::asio::ip::network_v4 vnet_ipaddr() const
		{
			auto endp = boost::asio::ip::make_address_v4(m_vnet_ipaddr);
			return boost::asio::ip::make_network_v4(endp, m_prefix_length);
		}

		boost::asio::ip::network_v4 vnet() const
		{
			// 总是使用网络中第1个地址作为网关.
			auto endp = *m_subnet.hosts().begin();
			return boost::asio::ip::make_network_v4(endp, m_subnet.prefix_length());
		}

	private:
		bool init_ws_acceptors()
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

				tcp::acceptor a{ m_io_context };

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

		void close_all_ws()
		{
			boost::system::error_code ignore_ec;
			{
				std::lock_guard<std::mutex> lock(m_ws_mux);
				for ([[maybe_unused]] auto& [id, conn_ptr] : m_ws_streams)
				{
					BOOST_ASSERT(conn_ptr);

					if (!conn_ptr) continue;

					auto& conn = *conn_ptr;
					conn.quit_ = true;
					conn.reconnect_timer_.cancel(ignore_ec);
					conn.ws_timer_.cancel(ignore_ec);
					LOG_DBG << "Close ws stream: " << conn.connection_id_;
					boost::beast::get_lowest_layer(conn.ws_stream_).close();
				}
			}

			{
				for (auto& [id, conn_ptr] : m_incoming_ws)
				{
					auto ptr = conn_ptr.lock();
					if (!ptr) continue;

					auto& conn = *ptr;
					conn.quit_ = true;
					conn.reconnect_timer_.cancel(ignore_ec);
					conn.ws_timer_.cancel(ignore_ec);
					LOG_DBG << "Close tmp ws stream: " << conn.connection_id_;
					boost::beast::get_lowest_layer(conn.ws_stream_).close();
				}
			}
		}

		boost::asio::awaitable<void> start_ws_listen(tcp::acceptor& a)
		{
			boost::system::error_code error;
			while (!m_abort)
			{
				tcp::socket socket(m_io_context);
				co_await a.async_accept(socket,
					boost::asio::redirect_error(boost::asio::use_awaitable, error));
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

				auto executor = stream.get_executor();
				boost::asio::co_spawn(executor,
					server_ws_connect(connection_id, std::move(stream)), boost::asio::detached);
			}

			LOG_DBG << "start_ws_listen exit...";
		}

		boost::asio::awaitable<void> server_ws_connect(size_t connection_id, boost::beast::tcp_stream stream)
		{
			using namespace boost::beast;
			boost::system::error_code ec;
			boost::beast::flat_buffer buffer;

			for (; !m_abort;)
			{
				request_parser parser;
				parser.body_limit(std::numeric_limits<uint64_t>::max());

				co_await http::async_read_header(stream, buffer, parser,
					boost::asio::redirect_error(boost::asio::use_awaitable, ec));
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
					co_await http::async_write(stream, res,
						boost::asio::redirect_error(boost::asio::use_awaitable, ec));
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
					co_return co_await do_http_response(params, "Illegal request", http_status::bad_request);
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
				co_await ws.async_accept(req,
					boost::asio::redirect_error(boost::asio::use_awaitable, ec));
				if (ec)
				{
					LOG_DBG << "start_ws_connect, " << connection_id << ", async_accept: " << ec.message();
					break;
				}

				ws_connection_ptr connection_ptr =
					std::make_shared<ws_connection>(std::forward<ws_stream>(ws), connection_id, remote_host);
				ws_expires_after(*connection_ptr, 60);
				connection_ptr->quit_ = false;

				// 加入到临时连接表.
				m_incoming_ws.insert({ connection_id, connection_ptr });
				for (auto it = m_incoming_ws.begin(); it != m_incoming_ws.end(); )
				{
					auto [id, connptr] = *it;

					if (!connptr.lock())
					{
						m_incoming_ws.erase(it++);
						continue;
					}

					++it;
				}

				LOG_DBG << "Client incoming: " << remote_host << ", connection id: " << connection_id;

				// 设置为2进制模式.
				connection_ptr->ws_stream_.binary(true);
				// 收到pong消息, 重置超时.
				ws_connection_weak_ptr wsconn_weak_ptr = connection_ptr;
				connection_ptr->ws_stream_.control_callback(
					[this, wsconn_weak_ptr = std::move(wsconn_weak_ptr)]
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

				// 发起保活协程.
				keepalive(connection_ptr);

				// 启动读写协程.
				auto executor = connection_ptr->ws_stream_.get_executor();
				boost::asio::co_spawn(executor,
					server_start_read(connection_ptr), [this, connection_ptr](std::exception_ptr) mutable
					{
						boost::system::error_code ignore_ec;

						// 取消这个conn上的所有异步对象操作.
						auto& conn = *connection_ptr;

						conn.quit_ = true;
						conn.ws_timer_.cancel(ignore_ec);
						conn.reconnect_timer_.cancel(ignore_ec);
						boost::beast::get_lowest_layer(conn.ws_stream_).close();

						// 移除virtual_ipaddr指定的ws.
						if (conn.virtual_ipaddr_ != 0)
							remove_ws(conn.virtual_ipaddr_);

					});

				co_return;
			}
		}

		boost::asio::awaitable<void> server_start_read(ws_connection_ptr connection_ptr)
		{
			if (!connection_ptr)
				co_return;

			auto& connection = *connection_ptr;
			auto connection_id = connection.connection_id_;
			auto& stream = connection.ws_stream_;

			boost::beast::error_code ec;
			std::vector<char> data;
			boost::asio::dynamic_vector_buffer buffer(data);

			while (!m_abort)
			{
				auto bytes = co_await stream.async_read(buffer,
					boost::asio::redirect_error(boost::asio::use_awaitable, ec));
				if (ec == websocket::error::closed)
				{
					LOG_DBG << "start_server_read, id: "
						<< connection_id << ", session was closed";
					break;
				}

				if (ec)
				{
					LOG_ERR << "start_server_read, id: "
						<< connection_id << ", async_read error: " << ec.message();
					break;
				}

				buffer.commit(bytes);
				ws_expires_after(connection, 60);

				const uint8_t* bufptr = boost::asio::buffer_cast<const uint8_t*>(buffer.data());
				auto type = read_uint8(bufptr);

				// 接下来就是数据.
				std::string_view sv((char*)bufptr, read_int32(bufptr));
				if (sv.size() >= normal_mtu)
				{
					LOG_ERR << "start_server_read, id: "
						<< connection_id << ", verify message size fail.";
					continue;
				}

				co_await process_net_packet(type, sv, connection_ptr);
				buffer.consume(bytes);
			}

			connection.quit_ = true;

			LOG_WARN << "start_server_read, id: " << connection_id << " quit...";
		}

		void add_ws(uint32_t ipaddr, ws_connection_ptr connection_ptr)
		{
			std::lock_guard<std::mutex> lock(m_ws_mux);
			m_ws_streams.emplace(ipaddr, std::move(connection_ptr));
		}

		ws_connection_ptr lookup_ws(uint32_t ipaddr)
		{
			std::lock_guard<std::mutex> lock(m_ws_mux);
			auto it = m_ws_streams.find(ipaddr);
			if (it != m_ws_streams.end())
				return it->second;

			return {};
		}

		void remove_ws(uint32_t ipaddr)
		{
			std::lock_guard<std::mutex> lock(m_ws_mux);
			m_ws_streams.erase(ipaddr);
		}

		void ws_expires_after(uint32_t ipaddr, int seconds)
		{
			auto wsp = lookup_ws(ipaddr);
			if (!wsp)
				return;

			// 设置超时.
			auto& stream = wsp->ws_stream_;
			boost::beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(seconds));
		}

		void ws_expires_after(ws_connection& connection, int seconds)
		{
			// 设置超时.
			auto& stream = connection.ws_stream_;
			boost::beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(seconds));
		}

		boost::asio::awaitable<void> do_http_response(
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
			co_await boost::beast::http::async_write(stream, sr,
				boost::asio::redirect_error(boost::asio::use_awaitable, ec));
			if (ec)
			{
				LOG_WARN << "do_http_response, id: " << connection_id << ", err: " << ec.message();
			}
		}

		boost::asio::awaitable<size_t> direct_channel_udp_write(udp::socket& sock,
			const udp::endpoint& endp, std::string& msg)
		{
			boost::system::error_code ec;
			auto bytes = co_await sock.async_send_to(boost::asio::buffer(msg), endp,
				boost::asio::redirect_error(boost::asio::use_awaitable, ec));
			if (ec)
			{
				LOG_DBG << "direct_channel_udp_write, async_send_to error: " << ec.message();
				co_return bytes;
			}
			co_return bytes;
		}

		boost::asio::awaitable<void> on_fec_timer()
		{
			boost::system::error_code ec;

			if (m_params.mode_ == vpn_tcp_mode::only_tcp)
				co_return;

			LOG_DBG << "Start fec timer for dispath...";

			while (!m_abort) [[likely]]
			{
				m_fec_timer.expires_from_now(std::chrono::milliseconds(m_params.fec_delay_));
				co_await m_fec_timer.async_wait(
					boost::asio::redirect_error(boost::asio::use_awaitable, ec));
				if (m_abort) [[unlikely]]
					co_return;

				std::unordered_map<ws_connection_ptr, udp_connection_weak_ptr> ucs;

				// 找到所有udp连接.
				if (m_identity == avpn_server)
				{
					std::lock_guard<std::mutex> lock(m_ws_mux);
					for ([[maybe_unused]] auto& [id, wsconn] : m_ws_streams)
					{
						if (!wsconn)
							continue;

						ucs.emplace(wsconn, wsconn->udp_stream_.lock());
					}
				}
				else
				{
					auto wsconn = m_client.lock();
					if (!wsconn)
						co_return;
					ucs.emplace(wsconn, wsconn->udp_stream_.lock());
				}

				for (auto& [wsconn, conn_weak_ptr] : ucs)
				{
					auto connptr = conn_weak_ptr.lock();
					if (!connptr)
						continue;

					auto& conn = *connptr;
					if (!conn.sock_)
						continue;

					if (conn.writing_)
						continue;

					if (conn.fec_enc_size_ <= 0)
						continue;

					// 如果未发送完, 继续发送而不进入等待.
					bool keep_continue = false;
					do {
						keep_continue = co_await do_fec_perform(wsconn, conn);
					} while (keep_continue);
				}
			}
		}

		boost::asio::awaitable<bool> do_fec_perform(
			const ws_connection_ptr& wsconn, udp_connection& uconn)
		{
			// 保存当前时间, 用于后面计算fec收集数据包超时使用.
			auto now = time_clock::steady_clock::now();
			// 继续发送.
			bool keep_continue = false;

			auto& sock = *uconn.sock_;
			auto& fec_enc = uconn.fec_enc_;
			auto& fec_dec = uconn.fec_dec_;

			// 通知过来时, 数据已经被发送了.
			if (uconn.fec_enc_size_ == 0)
			{
				LOG_WARN << "do_fec_perform, uconn.fec_enc_size_ == 0!!!";
				co_return keep_continue;
			}

			uconn.writing_ = true;
			scoped_exit scoped([&uconn]() mutable { uconn.writing_ = false; });

			// 实在是数据太小了, 无法fec时, 直接通过ws发送.
			if ((uconn.fec_enc_size_ < static_mtu * 5) &&
				m_params.mode_ != vpn_tcp_mode::only_udp)
			{
				for (auto& msg : fec_enc)
				{
					std::string pkt(pkt_header_size + msg.content.size(), '\0');
					char* wp = (char*)pkt.data();

					write_uint8(msg.type, wp);
					write_int32((int32_t)msg.content.size(), wp);
					write_string(msg.content, wp);

					boost::asio::co_spawn(m_io_context,
						direct_channel_ws_write(wsconn, std::move(pkt)), boost::asio::detached);
				}

				// 清理已发送的数据包.
				fec_enc.clear();
				uconn.fec_enc_size_ = 0;
				co_return false;
			}

			// 收集时间未到, 继续收集.
			auto duration = now - uconn.packet_tm_;
			// if (duration < std::chrono::milliseconds(m_params.fec_timeout_))
			//	co_return;

			std::string content;
			int64_t bytes_transferred = 0;
			auto num_packet = fec_enc.size();

			BOOST_ASSERT(num_packet > 0);

			const auto max_data_size = static_mtu * m_params.data_shards_;
			auto be = fec_enc.begin();
			auto end = fec_enc.end();

			bool removed = false;
			for (auto it = be; it != end; it++)
			{
				auto& msg = *it;
				content.append((const char*)msg.content.data(), msg.content.size());
				bytes_transferred += (int64_t)msg.content.size();

				// max_data_size 是 data_shards 和 mtu 大小计算出来的最大编码数据量.
				// fec编码一次最大数据量不能超过max_data_size, 否则有可能超出mtu大小
				// 导致在发送时被分片而产生丢包.
				if (content.size() + static_mtu >= max_data_size)
				{
					fec_enc.erase(be, it + 1);
					removed = true;

					if (fec_enc.size() > 0)
						keep_continue = true;

					break;
				}
			}

			// 如果fec_enc的数据总大小是小于max_data_size时, content包含了所有fec_enc中的数据.
			// 所以这里可以直接清理.
			if (!removed)
			{
				BOOST_ASSERT(bytes_transferred == (int64_t)content.size());
				BOOST_ASSERT(bytes_transferred == (int64_t)uconn.fec_enc_size_);

				fec_enc.clear();
			}

			BOOST_ASSERT(bytes_transferred > 0 && bytes_transferred == (int64_t)content.size());
			uconn.fec_enc_size_ -= bytes_transferred;
			auto gid = uconn.gid_++;

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

			char* bufptr = nullptr;
			size_t send_data_size = 0;
			for (size_t n = 0; n < shards.size(); n++)
			{
				const auto& s = shards[n];
				const auto body_size = fec_header_size + s.size();

				std::string fec_body(pkt_header_size + body_size, 0);
				char* wp = (char*)fec_body.data();
				char* base = wp;

				write_uint8(vpt_fec, wp);
				write_int32((int32_t)body_size, wp);

				if (m_params.compress_)
					bufptr = wp;

				write_uint32(gid, wp);						// gid
				write_uint8((uint8_t)n, wp);				// pid
				write_uint8((uint8_t)data_shards, wp);		// ds
				write_uint8((uint8_t)parity_shards, wp);	// ds
				write_int32((int32_t)gsize, wp);			// gsize

				write_string(s, wp);	// fec body

				// 如果启用了压缩, 则先压缩.
				if (m_params.compress_)
				{
					int insize = (int)(wp - bufptr);
					BOOST_ASSERT(insize > 0 && insize < 1450);

					std::string compress_bufs(insize * 2, 0);
					uLong outsize = (uLong)compress_bufs.size();

					auto ok = compress((Bytef*)compress_bufs.data(), &outsize,
						(const Bytef*)bufptr, (uLong)insize);
					if (ok == Z_OK)
					{
						if (outsize < (uLong)insize)
						{
							std::memcpy(bufptr, compress_bufs.data(), outsize);

							write_uint8(vpt_compress_fec, base);
							write_int32((int32_t)outsize, base);

							fec_body.resize(outsize + pkt_header_size);
						}
					}
				}

				send_data_size += fec_body.size();
				co_await direct_channel_udp_write(sock, uconn.endp_, fec_body);
			}

			LOG_DBG << "Addr: " << wsconn->virtual_ipaddr_
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

		boost::asio::awaitable<void> on_channel_write(
			ws_connection_ptr connection_ptr, avpn::vpn_message msg)
		{
			avpn::ws_connection& connection = * connection_ptr;
			if (m_params.mode_ == vpn_tcp_mode::only_tcp ||
				(m_params.mode_ == vpn_tcp_mode::tcpudp_mix &&
					!connection.deque_writing_))
			{
				// 如果启用了压缩, 则先压缩.
				if ((msg.type == vpt_tcp || msg.type == vpt_udp) &&
					m_params.compress_)
				{
					std::string compress_bufs(msg.content.size() * 2, 0);
					uLong outsize = (uLong)compress_bufs.size();

					auto ok = compress((Bytef*)compress_bufs.data(), &outsize,
						(const Bytef*)msg.content.data(), (uLong)msg.content.size());
					if (ok == Z_OK)
					{
						if (outsize < msg.content.size())
						{
							compress_bufs.resize(outsize);
							msg.content = compress_bufs;

							if (msg.type == vpt_tcp)
								msg.type = vpt_compress_tcp;
							else if (msg.type == vpt_udp)
								msg.type = vpt_compress_udp;
							else
								BOOST_ASSERT(false && "commpress invalid msg.type");
						}
					}
				}

				std::string pkt(pkt_header_size + msg.content.size(), '\0');
				char* wp = (char*)pkt.data();

				write_uint8(msg.type, wp);
				write_int32((int32_t)msg.content.size(), wp);
				write_string(msg.content, wp);

				connection.deque_writing_ = !connection.ws_msg_deque_.empty();
				auto& message_deque = connection.ws_msg_deque_;
				message_deque.emplace_back(std::move(pkt));

				if (!connection.deque_writing_ && !connection.quit_)
				{
					boost::system::error_code ec;
					while (!m_abort && !message_deque.empty())
					{
						co_await connection.ws_stream_.async_write(
							boost::asio::buffer(message_deque.front()),
								boost::asio::redirect_error(boost::asio::use_awaitable, ec));
						if (ec)
						{
							LOG_ERR << "on_channel_write, t -> r, " << connection.connection_id_
								<< " async_write error: " << ec.message();
							co_return;
						}
						message_deque.pop_front();
					}
				}
			}
			else
			{
				auto uconnptr = connection.udp_stream_.lock();
				if (!uconnptr)
				{
					LOG_WARN << "on_channel_write, t -> r, no network connection to send.";
					co_return;
				}

				auto& uconn = *uconnptr;
				if (!uconn.sock_)
				{
					LOG_WARN << "on_channel_write, t -> r, no udp network connection.";
					co_return;
				}

				// 任何冗余为0的情况下, 禁用fec并立即发包.
				if ((m_params.parity_shards_ <= 0) || m_params.data_shards_ == 1)
				{
					auto& sock = *uconn.sock_;

					// 如果启用了压缩, 则先压缩.
					if ((msg.type == vpt_tcp || msg.type == vpt_udp) &&
						m_params.compress_)
					{
						std::string compress_bufs(msg.content.size() * 2, 0);
						uLong outsize = (uLong)compress_bufs.size();

						auto ok = compress((Bytef*)compress_bufs.data(), &outsize,
							(const Bytef*)msg.content.data(), (uLong)msg.content.size());
						if (ok == Z_OK)
						{
							if (outsize < msg.content.size())
							{
								compress_bufs.resize(outsize);
								msg.content = compress_bufs;

								if (msg.type == vpt_tcp)
									msg.type = vpt_compress_tcp;
								else if (msg.type == vpt_udp)
									msg.type = vpt_compress_udp;
								else
									BOOST_ASSERT(false && "commpress invalid msg.type");
							}
						}
					}

					std::string udp_body(pkt_header_size + msg.content.size(), 0);
					char* wp = (char*)udp_body.data();

					write_uint8(msg.type, wp);
					write_int32((int32_t)msg.content.size(), wp);
					write_string(msg.content, wp);

					// 多倍流量模式.
					for (auto n = 0; n < m_params.parity_shards_ && msg.type == vpt_tcp; n++)
					{
						auto duplicate = udp_body;
						co_await direct_channel_udp_write(sock, uconn.endp_, duplicate);
					}

					co_await direct_channel_udp_write(sock, uconn.endp_, udp_body);
					co_return;
				}

				boost::system::error_code ec;

				uconn.writing_ = true;
				scoped_exit scoped([&uconn]() mutable { uconn.writing_ = false; });

				auto& fec_enc = uconn.fec_enc_;

				// 收集数据包.
				if (fec_enc.empty())
					uconn.packet_tm_ = time_clock::steady_clock::now();

				// move msg to fec_enc queue.
				auto bytes = msg.content.size();
				uconn.fec_enc_size_ += bytes;
				fec_enc.emplace_back(std::move(msg));

				// 如果缓冲达到最大, 唤醒fec timer处理fec缓冲.
				if (uconn.fec_enc_size_ + static_mtu >= static_mtu * m_params.data_shards_)
				{
					m_fec_timer.cancel_one(ec);
				}
			}
		}

		boost::asio::awaitable<void> direct_channel_ws_write(
			const avpn::ws_connection_ptr& connection_ptr, std::string msg)
		{
			auto& connection = *connection_ptr;

			connection.deque_writing_ = !connection.ws_msg_deque_.empty();
			auto& message_deque = connection.ws_msg_deque_;
			message_deque.emplace_back(std::move(msg));

			if (!connection.deque_writing_ && !connection.quit_)
			{
				boost::system::error_code ec;
				while (!m_abort && !message_deque.empty())
				{
					co_await connection.ws_stream_.async_write(
						boost::asio::buffer(message_deque.front()),
							boost::asio::redirect_error(boost::asio::use_awaitable, ec));
					if (ec)
					{
						LOG_ERR << "channel_write, " << connection.connection_id_
							<< " async_write error: " << ec.message();
						co_return;
					}
					message_deque.pop_front();
				}
			}
		}

		boost::asio::awaitable<void> start_udp_socket()
		{
			boost::system::error_code ec;

			if (m_identity == avpn_server)
			{
				// server 模式的时候.
				for (auto& listen : m_udp_listens)
				{
					LOG_DBG << "start_udp_socket, udp listen: " << listen;

					udp::endpoint endp;
					[[maybe_unused]] bool ipv6only = make_listen_endpoint(listen, endp, ec);
					if (ec)
					{
						LOG_ERR << "Start listen udp error: " << listen << ", ec: " << ec.message();
						continue;
					}

					udp::socket sock(m_io_context, endp.protocol());

					if (ipv6only)
					{
						sock.set_option(boost::asio::ip::v6_only(true), ec);
						if (ec)
						{
							LOG_ERR << "Start listen udp setsockopt IPV6_V6ONLY: " << ec.message();
							continue;
						}
					}

					sock.bind(endp, ec);
					if (ec)
					{
						LOG_ERR << "Start listen udp bind error: " << ec.message();
						continue;
					}

					m_udp_sockets.emplace_back(std::move(sock));
				}
			}
			else
			{
				// client 模式, 按upstream数量创建udp socket.
				for (auto& sock : m_udp_sockets)
				{
					if (!sock.is_open())
						continue;
					sock.cancel(ec);
					sock.close(ec);
				}

				m_udp_sockets.clear();

				for (auto& serv : m_udp_servers)
				{
					udp::socket sock(m_io_context, udp::endpoint(serv.protocol(), 0));
					if (ec)
					{
						LOG_ERR << "Start listen udp open error: " << ec.message();
						continue;
					}

					// 完成udp socket创建后, 向各upstream发起ctrl消息.
					LOG_DBG << "start_udp_socket, udp ctrl: ["
						<< serv.address().to_string() << "]:" << serv.port();

					// 回复client已经成功绑定.
					std::string msg(pkt_header_size + m_vnet_ipaddr.size(), '\0');
					char* wp = (char*)msg.data();

					write_uint8(vpt_udp_handshake, wp);
					write_int32((int32_t)m_vnet_ipaddr.size(), wp);
					write_string(m_vnet_ipaddr, wp);

					co_await direct_channel_udp_write(sock, serv, msg);

					// 保存到udp socket容器.
					m_udp_sockets.emplace_back(std::move(sock));
				}
			}

			// 按socket数量启动udp读取协程, 为接收提高效率, 发起4倍接收.
			for (size_t fast = 0; fast < 4; fast++)
			{
				for (size_t n = 0; n < m_udp_sockets.size(); n++)
				{
					LOG_DBG << "start_udp_read_loop, local endpoint: ["
						<< m_udp_sockets[n].local_endpoint().address().to_string() << "]:"
						<< m_udp_sockets[n].local_endpoint().port();

					boost::asio::co_spawn(m_io_context.get_executor(),
						start_udp_read_loop(n), boost::asio::detached);
				}
			}
		}

		boost::asio::awaitable<void> start_udp_read_loop(size_t index)
		{
			auto& sock = m_udp_sockets[index];
			char buffer[2048];
			udp::endpoint remote_endp;
			boost::system::error_code ec;

			while (!m_abort)
			{
				auto bytes = co_await sock.async_receive_from(
					boost::asio::buffer(buffer), remote_endp,
						boost::asio::redirect_error(boost::asio::use_awaitable, ec));
				if (ec)
					continue;

				if (bytes < pkt_header_size)
				{
					LOG_ERR << "start_client_read, remote host: " << remote_endp << ", verify message fail.";
					continue;
				}

				uint8_t* bufptr = (uint8_t*)&buffer[0];
				auto type = read_uint8(bufptr);
				auto bufsize = read_int32(bufptr);

				// 接下来就是数据.
				std::string_view sv((char*)bufptr, bufsize);
				if (sv.size() >= normal_mtu)
				{
					LOG_ERR << "start_client_read, remote host: " << remote_endp << ", verify message size fail.";
					continue;
				}

				// 处理udp网络数据包.
				co_await process_udp_net_packet(type, sv, sock, remote_endp);
			}

			LOG_ERR << "start_udp_read_loop, endpoint: " << remote_endp << ", quit...";
		}

		boost::asio::awaitable<void> connect(ws_connection_ptr& connection_ptr)
		{
			if (m_upstreams.empty())
				co_return;

			ws_stream& stream = connection_ptr->ws_stream_;
			boost::system::error_code ec;

			// 查找udp上游.
			for (auto it = m_upstreams.begin();
				it != m_upstreams.end() && !m_abort; it++)
			{
				auto& upstream = *it;

				util::uri parser;

				if (!parser.parse(upstream))
					continue;

				tcp::resolver resolver{ m_io_context };
				auto const results = co_await resolver.async_resolve(
					std::string(parser.host()), std::string(parser.port()),
						boost::asio::redirect_error(boost::asio::use_awaitable, ec));
				if (ec)
				{
					LOG_ERR << "channel::connect, async_resolve: " << ec.message();
					continue;
				}

				if (boost::to_lower_copy(std::string(parser.scheme())) == "udp")
				{
					for (auto& endp : results)
					{
						auto tmp = endp.endpoint();
						auto u = udp::endpoint(tmp.address(), tmp.port());

						if (m_udp_servers.find(u) == m_udp_servers.end())
							m_udp_servers.emplace(u);
					}
					continue;
				}
			}

			// 循环连接上游server.
			tcp::socket& sock = boost::beast::get_lowest_layer(stream).socket();
			bool ok = false;
			for (auto it = m_upstreams.begin();
				it != m_upstreams.end() && !m_abort; it++)
			{
				auto& upstream = *it;

				util::uri parser;

				if (!parser.parse(upstream))
					continue;

				tcp::resolver resolver{ m_io_context };
				auto const results = co_await resolver.async_resolve(
					std::string(parser.host()), std::string(parser.port()),
						boost::asio::redirect_error(boost::asio::use_awaitable, ec));
				if (ec)
				{
					LOG_ERR << "channel::connect, async_resolve: " << ec.message();
					continue;
				}

				if (boost::to_lower_copy(std::string(parser.scheme())) == "udp")
				{
					for (auto& endp : results)
					{
						auto tmp = endp.endpoint();
						auto u = udp::endpoint(tmp.address(), tmp.port());

						if (m_udp_servers.find(u) == m_udp_servers.end())
						{
							m_udp_servers.emplace(u);
						}
					}
					continue;
				}

				co_await asio_util::async_connect(sock, results,
					boost::asio::redirect_error(boost::asio::bind_cancellation_slot(m_cancel_sig.slot(),
						boost::asio::use_awaitable), ec));
				if (ec)
				{
					LOG_ERR << "channel::connect, async_connect: " << ec.message();
					continue;
				}

				std::string origin = "all";
				auto decorator = [origin](boost::beast::websocket::request_type& m) {
					m.insert(boost::beast::http::field::origin, origin);
				};

				stream.set_option(boost::beast::websocket::stream_base::decorator(decorator));
				co_await stream.async_handshake(std::string(parser.host()),
					parser.path().empty() ? "/" : parser.path(),
						boost::asio::redirect_error(boost::asio::use_awaitable, ec));
				if (ec)
				{
					LOG_ERR << "channel::connect, async_handshake: " << ec.message();
					continue;
				}

				boost::asio::ip::tcp::no_delay option(true);
				sock.set_option(option);

				ok = true;
				if (ok)
					break;
			}

			if (!ok)
			{
				if (m_abort)
					co_return;

				LOG_DBG << "wait a moment to reconnect...";

				// 无论任何原因, 等待15s后再发起连接.
				boost::asio::co_spawn(stream.get_executor(),
					[this, connection_ptr]() mutable -> boost::asio::awaitable<void>
					{
						auto& timer = connection_ptr->ws_timer_;
						boost::system::error_code ec;

						timer.expires_from_now(std::chrono::seconds(15));
						co_await timer.async_wait(
							boost::asio::redirect_error(boost::asio::use_awaitable, ec));

						if (!m_abort)
							do_reconnect(connection_ptr);
					}, boost::asio::detached);

				co_return;
			}

			// 设置为2进制模式.
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

			connection_ptr->quit_ = false;
			connection_ptr->remote_host_ = remote_host;
			LOG_DBG << "ws client connected: " << connection_ptr->connection_id_ << ", remote: " << remote_host;

			// 收到pong消息, 重置超时.
			ws_connection_weak_ptr wsptr = connection_ptr;
			connection_ptr->ws_stream_.control_callback(
				[this, wsptr = std::move(wsptr)]
			(boost::beast::websocket::frame_type ft, boost::beast::string_view)
			{
				if (ft == boost::beast::websocket::frame_type::pong)
				{
					auto ws_conn_ptr = wsptr.lock();
					if (!ws_conn_ptr || m_abort)
						return;

					ws_expires_after(*ws_conn_ptr, 60);
				}
			});

			// 发起认证请求.
			std::string msg(pkt_header_size + 4, '\0');
			char* wp = (char*)msg.data();

			write_uint8(vpt_auth, wp);
			write_int32(4, wp);

			write_int32((int32_t)google_auth_code(test_google_key), wp);
			co_await direct_channel_ws_write(connection_ptr, std::move(msg));

			// 发起保活协程.
			keepalive(connection_ptr);

			// 发起读写协程.
			boost::asio::co_spawn(m_io_context.get_executor(),
				start_client_read(connection_ptr), boost::asio::detached);
		}

		boost::asio::awaitable<void> start_client_read(ws_connection_ptr& connection_ptr)
		{
			BOOST_ASSERT(connection_ptr);

			auto& connection = *connection_ptr;
			auto& stream = connection.ws_stream_;
			auto& connection_id = connection.connection_id_;

			boost::system::error_code ec;
			std::vector<char> data;
			boost::asio::dynamic_vector_buffer buffer(data);

			while (!m_abort)
			{
				auto bytes = co_await stream.async_read(buffer,
					boost::asio::redirect_error(boost::asio::use_awaitable, ec));
				if (ec == websocket::error::closed)
				{
					LOG_DBG << "start_client_read, id: " << connection_id << ", session was closed";
					break;
				}

				if (ec)
				{
					LOG_ERR << "start_client_read, id: " << connection_id << ", async_read error: " << ec.message();
					break;
				}

				buffer.commit(bytes);
				const uint8_t* bufptr = boost::asio::buffer_cast<const uint8_t*>(buffer.data());

				// 读取消息类型.
				auto type = read_uint8(bufptr);

				// 接下来就是数据.
				auto bufsize = read_int32(bufptr);
				std::string_view sv((char*)bufptr, bufsize);
				if (sv.size() >= normal_mtu)
				{
					LOG_ERR << "start_client_read, id: " << connection_id << ", verify message size fail.";
					continue;
				}

				ws_expires_after(connection, 60);
				co_await process_net_packet(type, sv, connection_ptr);

				buffer.consume(buffer.size());
			}

			connection.quit_ = true;

			// 出错后准备重试连接.
			if (!m_abort && connection_ptr)
			{
				co_await connection.ws_stream_.async_close(
					boost::beast::websocket::close_code::none,
						boost::asio::redirect_error(boost::asio::use_awaitable, ec));
				connection.ws_timer_.cancel_one(ec);

				// 通知断开连接.
				if (m_status_notify)
				{
					channel_status cs;
					cs.status_ = connection_status::st_disconnect;
					m_status_notify(cs);
				}

				do_reconnect(connection_ptr);
			}
		}

		void do_reconnect(ws_connection_ptr& connection_ptr)
		{
			boost::system::error_code ignore_ec;
			if (!connection_ptr)
			{
				BOOST_ASSERT("client object is nullptr!" && false);
				return;
			}

			LOG_DBG << "channel::do_reconnect, reset reconnect timer.";
			connection_ptr->reconnect_timer_.cancel_one(ignore_ec);
		}

		void keepalive(ws_connection_weak_ptr ptr)
		{
			auto conn = ptr.lock();
			if (!conn)
				return;

			boost::asio::co_spawn(conn->ws_stream_.get_executor(),
				[this, ptr = std::move(ptr)]() mutable -> boost::asio::awaitable<void>
			{
				while (!m_abort)
				{
					auto ws_conn_ptr = ptr.lock();
					if (!ws_conn_ptr || ws_conn_ptr->quit_)
						co_return;

					boost::system::error_code ec;

					// LOG_DBG << "Keepalive for connection id: " << ws_conn_ptr->connection_id_;
					co_await ws_conn_ptr->ws_stream_.async_ping("",
						boost::asio::redirect_error(boost::asio::use_awaitable, ec));

					do
					{
						auto uconn_ptr = ws_conn_ptr->udp_stream_.lock();
						if (!uconn_ptr)
							break;

						auto& uconn = *uconn_ptr;
						if (!uconn.sock_)
							break;

						// udp保活消息, 避免大nat网络删除udp转发信息.
						std::string msg(pkt_header_size, '\0');
						char* wp = (char*)msg.data();

						write_uint8(vpt_keepalive, wp);
						write_int32(0, wp);

						co_await direct_channel_udp_write(*uconn.sock_, uconn.endp_, msg);
					} while (false);

					auto& timer = ws_conn_ptr->ws_timer_;
					timer.expires_from_now(std::chrono::milliseconds(m_params.keepalive_));

					co_await timer.async_wait(
						boost::asio::redirect_error(boost::asio::use_awaitable, ec));
				}
			}, boost::asio::detached);
		}

		boost::asio::awaitable<void> do_forward_packet(udp_connection_ptr uconn)
		{
			if (!uconn)
				co_return;

			auto& fec = uconn->fec_dec_;

			auto num_garbage = fec.garbage_clean();
			if (num_garbage > 0)
				LOG_DBG << "do_forward_packet, clean garbage: " << num_garbage;

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
						m_tuntap_writer(std::move(d));
						continue;
					}

					// 不允许内网传输.
					if (!m_params.c2c_)
						continue;

					// 内网数据包, 直接找到对应链转发.
					auto conn = lookup_ws(dst_addr);
					if (!conn)
					{
						m_tuntap_writer(std::move(d));
						continue;
					}

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

					co_await on_channel_write(conn, std::move(msg));
				}
			}
		}

		std::tuple<std::string, uint32_t> ip_assigner()
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

			return {ip_string, ipaddr};
		}

		boost::asio::awaitable<void> process_net_packet(
			uint8_t type, std::string_view content, ws_connection_ptr& connection_ptr)
		{
			auto& connection = *connection_ptr;
			std::string bufs;
			udp_connection_ptr uconn = connection.udp_stream_.lock();

			switch (type)
			{
			case vpt_auth:
			{
				if (m_identity == avpn_server) // 作为 server.
				{
					if (content.size() < 4)
						co_return;

					auto bufptr = content.data();
					auto auth_code = read_int32(bufptr);

					// TODO: 作认证操作, test key.
					int32_t code = (int32_t)google_auth_code(test_google_key);
					if (code != auth_code)
					{
						LOG_WARN << "Server: " << connection_ptr->connection_id_
							<< ", verify auth code fail: " << code << ", got: " << auth_code;
						co_return;
					}

					std::string reply(pkt_header_size, 0);

					// 给client分配ip地址.
					std::string ip_content(32, 0);
					std::string ip;

					{
						auto base = (char*)ip_content.data();
						auto p = base;

						auto [ip_string, ipaddr] = ip_assigner();
						connection.virtual_ipaddr_ = ipaddr;
						ip = ip_string;

						write_uint32((uint32_t)ip_string.size(), p);
						write_string(ip_string, p);

						ip_content.resize(p - base);
					}

					// 推送路由.
					std::string routes(1024, 0);
					{
						auto base = (char*)routes.data();
						auto p = base;

						for (auto& route : m_params.routes_)
						{
							if ((p + route.size()) - base >= 1024)
							{
								write_uint32((uint32_t)0, p);
								break;
							}

							write_uint32((uint32_t)route.size(), p);
							write_string(route, p);
						}

						routes.resize(p - base);
					}

					// ((avpn_protocol_version[(uint16)]),
					// ((prefix_length[(uint8)]),
					// (passbyvpn[(uint8)1/0]),
					// (pushdns[u32]),
					// (vip[(u32)size, string]),
					// (pushroutes[(u32(size), string)])
					auto body_size = 4 + 4 + ip_content.size() + routes.size();
					reply.resize(pkt_header_size + body_size);

					auto base = (char*)reply.data();
					auto p = base;

					write_uint8(vpt_auth, p);
					write_uint32((uint32_t)body_size, p);

					// protocol version.
					write_uint16(avpn_protocol_version, p);

					// prefix.
					write_int8((int8_t)m_subnet.prefix_length(), p);

					// passbyvpn.
					write_uint8(m_params.passbyvpn_, p);

					// pushdns.
					if (m_params.pushdns_.empty())
					{
						write_uint32(0, p);
					}
					else
					{
						boost::system::error_code ec;
						auto addr = boost::asio::ip::address_v4::from_string(m_params.pushdns_, ec);
						if (ec)
						{
							LOG_WARN << "push dns params error: " << ec.message();
							write_uint32(0, p);
						}
						else
						{
							write_uint32(addr.to_uint(), p);
						}
					}

					write_string(ip_content, p);
					write_string(routes, p);

					BOOST_ASSERT((size_t)(p - base) == body_size + 5);

					LOG_DBG << "Server assign virtual ip: "
						<< ip << " to id: " << connection.connection_id_;

					// 从临时连接表中删除.
					m_incoming_ws.erase(connection.connection_id_);

					// 添加到连接管理.
					add_ws(connection.virtual_ipaddr_, connection_ptr);

					// 返回数据.
					co_await direct_channel_ws_write(connection_ptr, std::move(reply));

					co_return;
				}

				if (m_identity == avpn_client) // 作为 client 在认证通过后发起 udp 连接.
				{
					if (content.size() < 12) // ip字符串, 至少7个字符.
					{
						LOG_WARN << "Client assign virtual ip error: " << std::string(content);
						co_return;
					}

					int bodysize = (int)content.size();
					auto bufptr = content.data();

					auto version = read_uint16(bufptr);		// server protocol version
					if (version != avpn_protocol_version)
					{
						LOG_ERR << "Client protocol version incompatible: "
							<< version << ", expect: " << avpn_protocol_version;
						co_return;
					}
					bodysize-=2;
					m_prefix_length = read_int8(bufptr);						// prefix_length
					bodysize--;
					[[maybe_unused]] auto passbyvpn = read_uint8(bufptr);		// passbyvpn
					LOG_DBG << "passby vpn: " << (passbyvpn ? "yes" : "no");
					bodysize--;
					[[maybe_unused]] auto pushdns = read_uint32(bufptr);		// pushdns
					if (pushdns != 0)
					{
						auto dns = boost::asio::ip::address_v4(pushdns);
						LOG_DBG << "add dns: " << dns.to_string();
					}
					bodysize -= 4;
					int32_t ipsize = read_int32(bufptr);
					bodysize -= 4;
					if (bodysize - ipsize < 0 || ipsize < 0)
					{
						BOOST_ASSERT(false && "bodysize - ipsize < 0");
						co_return;
					}

					// 保存获得的虚拟ip.
					m_vnet_ipaddr = std::string(bufptr, ipsize);
					bufptr += ipsize;
					bodysize -= ipsize;

					m_routes.clear();
					for (; bodysize >= 4;)
					{
						int sz = (int32_t)read_int32(bufptr);
						bodysize -= 4;
						if (bodysize - sz < 0 || sz < 0)
						{
							BOOST_ASSERT(false && "bodysize - sz < 0");
							co_return;
						}

						std::string route(bufptr, sz);
						bufptr += sz;
						bodysize -= sz;

#if 0
						auto [ret, ok] = add_route(route);
						if (ok)
							LOG_DBG << "add route: " << route << " route added successfully!";
						else
							LOG_DBG << "add route: " << route << " route added fail, reason: " << ret;
#endif

						m_routes.emplace_back(std::move(route));
					}

					auto ipaddr = boost::asio::ip::address_v4::from_string(m_vnet_ipaddr);
					connection_ptr->virtual_ipaddr_ = ipaddr.to_uint();

					// 使用udp发起ctrl命令, 使用得server跟踪到本udp对应的虚拟ip连接.
					boost::asio::co_spawn(m_io_context.get_executor(),
						start_udp_socket(), boost::asio::detached);

					// 通知完成连接.
					if (m_status_notify)
					{
						channel_status cs;
						cs.routes_ = m_routes;
						cs.status_ = connection_status::st_connected;

						m_status_notify(cs);
					}

					co_return;
				}
			}
			break;
			case vpt_udp_handshake:
				break;
			case vpt_compress_tcp:
				[[fallthrough]];
			case vpt_compress_udp:
			{
				// 解压缩操作.
				uLongf bufsize = 16384;
				bufs.resize(bufsize);
				auto ok = uncompress((Bytef*)bufs.data(), &bufsize,
					(const Bytef*)content.data(), (uLongf)content.size());
				if (ok != Z_OK)
					co_return;
				bufs.resize(bufsize);
				content = std::string_view(bufs.data(), bufsize);
			}
			[[fallthrough]];
			case vpt_icmp:
				[[fallthrough]];
			case vpt_udp:
				[[fallthrough]];
			case vpt_tcp:
			{
				// 处理内网数据包.
				auto endp = avpn::lookup_endpoint_pair((const uint8_t*)content.data(), content.size());
				auto dst_addr = endp.dst_.address().to_v4().to_uint();
				udp::endpoint uendp(endp.dst_.address(), 0);

				// 内网数据包, 直接找到对应链转发.
				if (same_ipv4_network(m_subnet, dst_addr))
				{
					// 不允许内网传输.
					if (!m_params.c2c_)
						co_return;

					auto conn = lookup_ws(dst_addr);

					if (conn)
					{
						avpn::vpn_message msg;
						msg.type = type;
						msg.content = content;

						co_await on_channel_write(conn, std::move(msg));
						co_return;
					}
				}

				if (!m_tuntap_writer)
					co_return;

				if (type == vpt_icmp)
					LOG_DBG << "Recvive tcp, write tun icmp: " << endp;

				m_tuntap_writer(std::string(content));
			}
			break;
			case vpt_fec:
			{}
			break;
			}

			// 将从网络接收到的数据包转发到设备.
			if (uconn)
				co_await do_forward_packet(uconn);
		}

		boost::asio::awaitable<void> process_udp_net_packet(
			uint8_t type, std::string_view content, udp::socket& sock, const udp::endpoint& endp)
		{
			udp_connection_ptr uconn;
			std::string bufs;

			switch (type)
			{
			case vpt_auth:
			{}
			break;
			case vpt_keepalive:
			{}
			break;
			case vpt_udp_handshake:
			{
				// 在server模式, 接收到client的虚拟ip, 往对应的ws_connection
				// 中保存udp_connection信息.
				if (m_identity == avpn_server)
				{
					// 没找到udp连接, 则创建udp连接.
					uconn = lookup_udp(endp);
					if (!uconn)
					{
						uconn = std::make_shared<udp_connection>();
						uconn->last_see_ = timer::clock_type::now();
						uconn->sock_ = &sock;
						uconn->endp_ = endp;

						add_udp(endp, uconn);
					}

					// 设置更新最后可见时间.
					uconn->last_see_ = timer::clock_type::now();

					// 通过client汇报的虚拟ip找到对应的tcp连接.
					boost::system::error_code ec;
					auto addr = boost::asio::ip::address_v4::from_string(std::string(content), ec);
					auto wsconn = lookup_ws(addr.to_uint());
					if (!wsconn)
						co_return;

					// 将udp连接绑定到tcp连接.
					LOG_DBG << "udp client: " << uconn->endp_ << " send handshake";
					wsconn->udp_stream_ = uconn;

					// 回复client已经成功绑定.
					std::string reply(pkt_header_size, '\0');
					char* wp = (char*)reply.data();

					write_uint8(vpt_udp_handshake_reply, wp);
					write_int32(0, wp);

					co_await direct_channel_udp_write(sock, endp, reply);
				}
			}
			break;
			case vpt_udp_handshake_reply:
			{
				if (m_identity == avpn_client)
				{
					LOG_DBG << "udp server: " << endp << " reply handshake";
					auto wsconn = m_client.lock();
					if (!wsconn)
						break;

					// 没找到udp连接, 则创建udp连接.
					uconn = wsconn->udp_stream_.lock();
					if (!uconn)
					{
						uconn = std::make_shared<udp_connection>();
						uconn->last_see_ = timer::clock_type::now();
						uconn->sock_ = &sock;
						uconn->endp_ = endp;

						add_udp(endp, uconn);

						// 绑定到tcp连接.
						wsconn->udp_stream_ = uconn;
					}
					else
					{
						uconn->reset();

						uconn->last_see_ = timer::clock_type::now();
						uconn->sock_ = &sock;
						uconn->endp_ = endp;

						add_udp(endp, uconn);
					}

					// 设置更新最后可见时间.
					uconn->last_see_ = timer::clock_type::now();
				}
			}
			break;
			case vpt_compress_tcp:
				[[fallthrough]];
			case vpt_compress_udp:
			{
				// 解压缩操作.
				uLongf bufsize = 16384;
				bufs.resize(bufsize);
				auto ok = uncompress((Bytef*)bufs.data(), &bufsize,
					(const Bytef*)content.data(), (uLongf)content.size());
				if (ok != Z_OK)
					co_return;
				bufs.resize(bufsize);
				content = std::string_view(bufs.data(), bufsize);
			}
			[[fallthrough]];
			case vpt_icmp:
				[[fallthrough]];
			case vpt_udp:
				[[fallthrough]];
			case vpt_tcp:
			{
				// 处理内网数据包.
				auto dst_addr = avpn::lookup_endpoint_pair((const uint8_t*)content.data(), content.size()).dst_;
				auto uint_dst = dst_addr.address().to_v4().to_uint();
				udp::endpoint uendp(dst_addr.address(), 0);

				// 内网数据包, 直接找到对应链转发.
				if (same_ipv4_network(m_subnet, uint_dst))
				{
					// 不允许内网传输.
					if (!m_params.c2c_)
						co_return;

					auto conn = lookup_ws(uint_dst);

					if (conn)
					{
						avpn::vpn_message msg;
						msg.type = type;
						msg.content = content;

						co_await on_channel_write(conn, std::move(msg));
						co_return;
					}
				}

				if (!m_tuntap_writer)
					co_return;

				if (type == vpt_icmp)
					LOG_DBG << "Recvive udp, write tun icmp: " << endp;

				m_tuntap_writer(std::string(content));
			}
			break;
			case vpt_compress_fec:
			{
				// 解压缩操作.
				uLongf bufsize = 16384;
				bufs.resize(bufsize);
				auto ok = uncompress((Bytef*)bufs.data(), &bufsize,
					(const Bytef*)content.data(), (uLongf)content.size());
				if (ok != Z_OK)
					co_return;
				bufs.resize(bufsize);
				content = std::string_view(bufs.data(), bufsize);
			}
			[[fallthrough]];
			case vpt_fec:
			{
				// 数据大小太小, 直接丢弃.
				if (content.size() < fec_header_size)
					co_return;

				// 如果没找到udp连接, 此时这个fec包不可信, 则直接丢弃.
				uconn = lookup_udp(endp);
				if (!uconn)
					co_return;

				// 解析fec数据.
				auto bufptr = content.data();

				auto gid = read_uint32(bufptr);		// gid
				auto pid = read_uint8(bufptr);		// pid
				auto ds = read_uint8(bufptr);		// ds
				auto ps = read_uint8(bufptr);		// ps
				auto gsize = read_int32(bufptr);	// gsize

				auto fec_size = content.size() - fec_header_size;
				if (fec_size <= 0)
					co_return;

				auto& fec = uconn->fec_dec_;
				fec.update(gid, pid, ds, ps, gsize, (uint8_t*)bufptr, fec_size);
			}
			break;
			}

			// 将从网络接收到的数据包转发到设备.
			co_await do_forward_packet(uconn);
		}

		void add_udp(const udp::endpoint& endp, udp_connection_ptr& ptr)
		{
			std::lock_guard<std::mutex> lock(m_udp_mux);
			m_udp_connections[endp] = ptr;
		}

		udp_connection_ptr lookup_udp(const udp::endpoint& endp)
		{
			std::lock_guard<std::mutex> lock(m_udp_mux);
			auto it = m_udp_connections.find(endp);
			if (it != m_udp_connections.end())
				return it->second;
			return {};
		}

		void remove_udp(const udp::endpoint& endp)
		{
			std::lock_guard<std::mutex> lock(m_udp_mux);
			m_udp_connections.erase(endp);
		}

	private:
		boost::asio::io_context& m_io_context;
		avpn::io_context_pool& m_ioc_pool;

		// 通道参数配置, 包含fec参数.
		channel_params m_params;
		boost::asio::ip::network_v4 m_subnet;

		std::vector<std::string> m_upstreams;
		std::vector<std::string> m_tcp_listens;
		std::vector<std::string> m_udp_listens;

		// 作为server时, 用于ws的服务器acceptor.
		std::vector<tcp::acceptor> m_ws_acceptors;

		// udp 通信 socket, 无论是client还是server
		// 都只会初始化1次.
		std::once_flag m_once_start_udp;
		std::vector<udp::socket> m_udp_sockets;

		// 专门用于退出时取消asio_util::async_connect.
		boost::asio::cancellation_signal m_cancel_sig;

		// tuntap设备写入函数及状态通知函数.
		tuntap_writer m_tuntap_writer;
		notify_status m_status_notify;

		// 运行的身份.
		int m_identity{ -1 };

		// channel for server.
		std::mutex m_ws_mux;

		// key's 32bit, use ipv4
		// address, virtual ipaddr.
		std::unordered_map<uint32_t, ws_connection_ptr> m_ws_streams;
		std::unordered_map<int64_t, ws_connection_weak_ptr> m_incoming_ws;

		// 作为server时, 虚拟 ip 分配器.
		boost::asio::ip::address_v4_range m_ip_assigner;
		boost::asio::ip::address_v4_range::iterator m_ip_iterator;

		// channel for client.
		ws_connection_weak_ptr m_client;
		std::once_flag m_once_fec_timer;
		timer m_fec_timer;

		// 作为client时, 参数中 upstreams 解析
		// 出的 udp server 的endpoint.
		std::set<udp::endpoint> m_udp_servers;

		// 本机作为client时, server为其分配的虚拟ip.
		std::string m_vnet_ipaddr;
		// 本机作为client时, server通告的prefix长度.
		int8_t m_prefix_length{ -1 };

		// 作为client时, server推送的route, 用于退出时
		// 清除路由.
		std::vector<std::string> m_routes;

		// udp 连接信息列表.
		std::mutex m_udp_mux;
		std::unordered_map<udp::endpoint, udp_connection_ptr> m_udp_connections;

		std::atomic_bool m_abort{ false };
	};
}
