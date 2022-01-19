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

#include <boost/asio/io_context.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/defer.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/ip/address_v4.hpp>
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

#include "vpncore/ip_buffer.hpp"
#include "vpncore/endpoint_pair.hpp"

#include "dchs/reedsolomon.hpp"
#include "dchs/bitfield.hpp"
#include "dchs/url_parser.hpp"
#include "dchs/async_connect.hpp"
#include "dchs/time_clock.hpp"
#include "dchs/io.hpp"
#include "protocol/ptvpn_generated.h"

#include "utils/logging.hpp"

namespace avpn {

	namespace http = boost::beast::http;			// from <boost/beast/http.hpp>
	using tcp = boost::asio::ip::tcp;               // from <boost/asio/ip/tcp.hpp>
	using udp = boost::asio::ip::udp;               // from <boost/asio/ip/udp.hpp>
	namespace websocket = boost::beast::websocket;  // from <boost/beast/websocket.hpp>
	using ws = websocket::stream<tcp::socket>;		// from <boost/beast/websocket.hpp>
	namespace net = boost::asio;					// from <boost/asio.hpp>
	using time_point = time_clock::steady_clock::time_point;

	using timer = boost::asio::basic_waitable_timer<time_clock::steady_clock>;
	using ws_stream = websocket::stream<boost::beast::tcp_stream>;

	using namespace util;

	const static std::string test_google_key = "VLTATWJGVH5W7V7DX6V436FG74";

	// ce_id
	// max_id

	// tcp queue
	// | - ---  ----->|
	// ce            max

	// [.......  .. .... .][.   ....... .... .]
	// [gid](group id)

	// [.. ... .... ......]
	// (pid)(packet id)

	// control message
	// [max, ce, array of lose id]

	// timeout, 从ce位置开始的所有lose, 如果其前一个包的接收时间
	// 减于max包接收到的时间, 这个duration大于timeout, 则加入lid
	// 数组.

	// 发送端保存远端控制信息中ce后所有pkt.
	// 每次通过更新ce, 清除queue.
	// 若queue无限增大, 增大到一定程度, reset all.

	//////////////////////////////////////////////////////////////////////////

	struct fec_group
	{
	public:
		const static size_t max_ptk_size = 512 * 1024;

		std::vector<boost::beast::multi_buffer> pkts_;
		int64_t gid_{-1};
		bitfield bs_;
		int ps_;
		size_t gsize_;
		int ds_{-1};
		size_t total_{0};
		timer::time_point time_;

		fec_group(fec_group&& pg) noexcept
			: pkts_(std::move(pg.pkts_))
			, gid_(pg.gid_)
			, bs_(pg.bs_)
			, ps_(pg.ps_)
			, gsize_(pg.gsize_)
			, time_(pg.time_)
		{
			pg.gid_ = -1;
			pg.pkts_.clear();
			pg.bs_.clear_all();
			pg.ps_ = 0;
			pg.gsize_ = 0;
			pg.total_ = 0;
		}

		fec_group() = delete;
		fec_group(int data_shards, int parity_shards, int size)
		{
			BOOST_ASSERT(data_shards + parity_shards < 256
				&& "dataShards + parityShards >= 255");

			ds_ = data_shards;
			ps_ = parity_shards;
			gsize_ = (size_t)size;

			auto total = ds_ + ps_;
			bs_.resize(total, false);
			for (int i = 0; i < total; i++)
				pkts_.emplace_back(boost::beast::multi_buffer{ max_ptk_size });
		}

		void update(int64_t gid, uint16_t pid, uint8_t* data, size_t size)
		{
			time_ = timer::clock_type::now();
			gid_ = gid;

			auto& pkt = pkts_[pid];
			auto p = pkt.prepare(size);

			boost::asio::buffer_copy(p, boost::asio::buffer(data, size));
			pkt.commit(size);
			bs_.set_bit(pid);

			total_ += size;
		}

		// 完整接收.
		bool full() noexcept
		{
			return bs_.count() == (ds_ + ps_);
		}

		// 接收数据已达到可解码.
		bool accord() const
		{
			return bs_.count() >= ds_;
		}

		// 总数据量.
		size_t count() const
		{
			return bs_.count();
		}

		// rs解码数据, 返回的vector中每个元素将是一个完整的ip包.
		std::vector<std::string> decode()
		{
			if (!accord())
				return {};

			std::vector<std::vector<uint8_t>> data;

			fec::reedsolomon fec_dec(ds_, ps_);
			data.resize(ds_ + ps_);

			for (size_t i = 0; i < data.size(); i++)
			{
				auto& d = data[i];
				auto& s = pkts_[i];

				d.resize(s.size());
				boost::asio::buffer_copy(boost::asio::buffer(d), s.data());
			}

			// fec解码.
			try {
				fec_dec.decode(data);
			}
			catch (const std::exception& e) {
				LOG_WARN << "fec decode exception: " << e.what();
				return {};
			}

			std::vector<std::string> result;
			std::string ip;
			int left = 0;
			int ip_size = 0;

			enum class fec_ip_state {
				ip_start = 0,
				ip_parsing = 1,
			} state = fec_ip_state::ip_start;

			// 从fec解码的数据还原ip包.
			for (auto i = 0; i < ds_; i++)
			{
				auto& d = data[i];

				while (true)
				{
					uint8_t* bufptr = (uint8_t*)d.data() + left;
					int bufsize = (int)d.size() - left;

					// 没有数据了, 跳向下一个.
					if (bufsize <= 0)
					{
						left = 0;
						break;
					}

					switch (state)
					{
					case fec_ip_state::ip_start:
					{
						if (ip.size() < 4)
						{
							int n = 4 - (int)ip.size();
							n = std::min<int>((int)bufsize, n);

							ip.append((char*)bufptr, n);
							left += n;

							if (ip.size() < 4)
								continue;
						}

						// 必然等于4.
						BOOST_ASSERT(ip.size() == 4);

						// 获取ip包大小.
						ip_size = ntohs(*(uint16_t*)(ip.data() + 2));
						BOOST_ASSERT(ip_size > 0);

						// 跳过已经拷贝的4字节head.
						bufptr += left;
						bufsize -= left;
						ip_size -= 4;

						auto num = std::min<int>(ip_size, bufsize);

						// 如果ip包大小小于已有数据大小, 则直接拷入ip字符串.
						if (num == ip_size)
						{
							ip.append((char*)bufptr, num);
							result.push_back(ip);
							ip.clear();
							left += num;
						}
						else
						{
							// 否则拷入已有的部分ip数据到ip字符串, 然后接着拷.
							ip.append((char*)bufptr, num);
							left += num;
							ip_size -= num;
							state = fec_ip_state::ip_parsing;
						}
					}
					break;
					case fec_ip_state::ip_parsing:
					{
						auto num = std::min<int>(ip_size, bufsize);
						if (num == ip_size)
						{
							ip.append((char*)bufptr, num);
							result.push_back(ip);
							ip.clear();
							left += num;
							state = fec_ip_state::ip_start;
						}
						else
						{
							// 否则拷入已有的部分ip数据到ip字符串, 然后接着拷.
							ip.append((char*)bufptr, num);
							left += num;
							ip_size -= num;
							state = fec_ip_state::ip_parsing;
						}
					}
					break;
					}
				}
			}

			return result;
		}

	private:
		fec_group(const fec_group&) = delete;
		fec_group& operator=(const fec_group&) = delete;
	};


	//////////////////////////////////////////////////////////////////////////

	struct fec_cache
	{
	public:
		const static size_t max_cache_size = 5 * 1024 * 1024;
		std::map<int64_t, fec_group> groups_;
		size_t total_size_ = 0;
		int64_t start_gid_ = -1;

		void update(int64_t gid, uint16_t pid,
			int data_shards, int parity_shards, int gsize,
			uint8_t* data, size_t size)
		{
			auto f = groups_.find(gid);
			if (f == groups_.end())
			{
				// 如果gid小于start_gid, 则表示数据已经过期
				// 不再需要了, 便可丢了.
				if (gid < start_gid_)
				{
					LOG_DBG << "recv pkt gid: " << gid
						<< ", because start gid: "<< start_gid_
						<< ", so drop it.";
					return;
				}

				fec_group pkt(data_shards, parity_shards, gsize);
				pkt.update(gid, pid, data, size);
				groups_.emplace(gid, std::move(pkt));
			}
			else
			{
				auto& pkt = f->second;
				pkt.update(gid, pid, data, size);
			}

			total_size_ += size;
		}

		std::vector<fec_group> clean()
		{
			std::vector<fec_group> result;

			for (auto it = groups_.begin(); it != groups_.end();)
			{
				auto& [gid, gop] = *it++;
				if (gop.full() || gop.accord())
				{
					start_gid_ = gop.gid_ + 1;
					total_size_ -= gop.total_;
					result.emplace_back(std::move(gop));
					continue;
				}

				break;
			}

			for (auto& pkt : result)
				groups_.erase(pkt.gid_);

			// 大于max_cache_size时, 无论是否full, 都将清理.
			if (total_size_ > max_cache_size)
			{
				for (auto it = groups_.begin(); it != groups_.end();)
				{
					auto& [gid, gop] = *it;

					total_size_ -= gop.total_;
					groups_.erase(it++);

					if (total_size_ <= max_cache_size)
						break;
				}
			}

			return result;
		}

		fec_cache() = default;

	private:
		fec_cache(const fec_cache&) = delete;
		fec_cache& operator=(const fec_cache&) = delete;
	};

	//////////////////////////////////////////////////////////////////////////


	struct udp_connection
	{
		time_point last_see_;
		fec_cache fec_dec_;					// fec 解码缓冲器.

		time_point packet_tm_;				// fec 编码缓冲接收起始时间.
		std::vector<MessageT> fec_enc_;		// fec 编码缓冲.
		int64_t incoming_{ 0 };				// 缓冲字节数.

		udp::socket* sock_;
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
			, gid_(c.gid_)
			, pid_(c.pid_)
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
		int64_t gid_{ 0 };
		uint16_t pid_{ 0 };
		timer ws_timer_;
		timer reconnect_timer_;
		int64_t connection_id_;
		uint32_t virtual_ipaddr_{ 0 };
		std::string remote_host_;
		std::atomic_bool quit_{ false };
	};
	using ws_connection_ptr = std::shared_ptr<ws_connection>;
	using ws_connection_weak_ptr = std::weak_ptr<ws_connection>;


	//////////////////////////////////////////////////////////////////////////

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
		boost::asio::yield_context& yield_;
	};


	//////////////////////////////////////////////////////////////////////////

	enum channel_status
	{
		st_connected,
		st_disconnect,
		st_listen,
	};

	class channel
	{
		using tuntap_writer = std::function<void(std::string&&)>;
		using notify_status = std::function<void(channel_status)>;

		channel(const channel&) = delete;
		channel& operator=(const channel&) = delete;

	public:
		channel(boost::asio::io_context& io, avpn::io_context_pool& ios,
			int data_shards, int parity_shards, int double_tcp)
			: m_io_context(io)
			, m_io_pool(ios)
			, m_data_shards(data_shards)
			, m_parity_shards(parity_shards)
			, m_double_tcp(double_tcp)
		{}

	public:
		void start_connect(const std::vector<std::string>& upstreams,
			notify_status notify_func, tuntap_writer writer_func)
		{
			m_upstreams = upstreams;

			m_tuntap_writer = writer_func;
			m_status_notify = notify_func;

			// 客户端身份.
			m_identity = 1;

			// 发起连接协程, 进入异步连接.
			boost::asio::spawn(m_io_context.get_executor(),
			[this](boost::asio::yield_context yield) mutable
			{
				boost::system::error_code ec;

				static const auto never =
					std::chrono::hours(std::numeric_limits<int>::max());

				// 自动重连逻辑.
				while (!m_abort)
				{
					// 创建client对象用于发起向server的连接.
					auto client = std::make_shared<ws_connection>(ws_stream{m_io_context}, m_connection_id++, "");
					ws_stream& stream = client->ws_stream_;

					connect(client, yield);

					if (m_abort)
						break;

					timer& reconnect_timer = client->reconnect_timer_;
					reconnect_timer.expires_from_now(never);
					reconnect_timer.async_wait(yield[ec]);

					if (m_abort)
						break;

					LOG_DBG << "channel::start_connect, do connect...";
				}

				LOG_WARN << "channel::start_connect, reconnect conroutine quit...";
			});
		}

		void start_listen(std::vector<std::string> tcp_listens,
			std::vector<std::string> udp_listens, notify_status notify_func, tuntap_writer writer_func)
		{
			m_tcp_listens = tcp_listens;
			m_udp_listens = udp_listens;

			m_tuntap_writer = writer_func;
			m_status_notify = notify_func;

			// 服务器身份.
			m_identity = 0;

			// 开始启动tcp客户端, 即ws服务器.
			init_ws_acceptors();

			int pool_size = static_cast<int>(m_io_pool.pool_size());
			for (int i = 0; i < pool_size; i++)
			{
				for (auto& a : m_ws_acceptors)
				{
					boost::asio::spawn(m_io_pool.get_io_context().get_executor(),
						[this, &a](boost::asio::yield_context yield) mutable {
							start_ws_listen(a, yield);
						});
				}
			}

			// 启动udp连接用于接收消息.
			std::call_once(m_once_start_udp, [this]()
				{
					LOG_DBG << "Start udp socket...";

					boost::asio::spawn(m_io_context.get_executor(),
						[this](boost::asio::yield_context yield) mutable {
							start_udp_socket(yield);
						});
				});

			m_status_notify(channel_status::st_listen);
		}

		void close()
		{
			m_abort = true;

			boost::system::error_code ignore_ec;
			if (m_identity == 1)
			{
				auto conn = m_client.lock();
				if (conn)
				{
					LOG_DBG << "close channel...";

					boost::beast::get_lowest_layer(conn->ws_stream_).socket().cancel(ignore_ec);
					boost::beast::get_lowest_layer(conn->ws_stream_).socket().close(ignore_ec);
					conn->reconnect_timer_.cancel_one(ignore_ec);
					conn->ws_timer_.cancel_one(ignore_ec);
				}
			}

			if (m_identity == 0)
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
		}

		void client_write(avpn::MessageT&& msg, avpn::endpoint_pair& endp)
		{
			switch (endp.type_)
			{
			case avpn::ip_tcp:
				LOG_DBG << "client_write, tcp: " << endp;
				break;
			case avpn::ip_udp:
				LOG_DBG << "client_write, udp: " << endp;
				break;
			case avpn::ip_icmp:
				LOG_DBG << "client_write, icmp: " << endp;
				break;
			}

			// 作为客户端时.
			ws_connection_ptr connection_ptr;

			if (m_identity == 1)
			{
				static int pick = 0;
				std::lock_guard<std::mutex> lock(m_ws_mux);
				connection_ptr = m_ws_streams[pick++ % m_ws_streams.size()];
			}

			if (!connection_ptr)
				return;

			auto& stream = connection_ptr->ws_stream_;
			boost::asio::spawn(stream.get_executor(),
				[this, connection_ptr, msg = std::move(msg)](boost::asio::yield_context yield) mutable {
				auto& connection = *connection_ptr;
				on_channel_write(connection, msg, yield);
			});
		}

		void server_write(avpn::MessageT&& msg, avpn::endpoint_pair& endp)
		{
			switch (endp.type_)
			{
			case avpn::ip_tcp:
				LOG_DBG << "server_write, tcp: " << endp;
				break;
			case avpn::ip_udp:
				LOG_DBG << "server_write, udp: " << endp;
				break;
			case avpn::ip_icmp:
				LOG_DBG << "server_write, icmp: " << endp;
				break;
			}

			auto connection_ptr = lookup_ws(endp.dst_.address().to_v4().to_uint());
			if (!connection_ptr)
				return;

			auto& stream = connection_ptr->ws_stream_;
			boost::asio::spawn(stream.get_executor(),
				[this, connection_ptr, msg = std::move(msg)](boost::asio::yield_context yield) mutable {
				auto& connection = *connection_ptr;
				on_channel_write(connection, msg, yield);
			});
		}

		std::string virtual_ipaddr() const
		{
			return m_virtual_ipaddr;
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
				bool ipv6only = make_listen_endpoint(wsd, endp, ec);
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

#if __linux__
				if (ipv6only)
				{
					int on = 1;
					if (::setsockopt(a.native_handle(), IPPROTO_IPV6, IPV6_V6ONLY, (char*)&on, sizeof(on)) == -1)
					{
						LOG_ERR << "WS server setsockopt IPV6_V6ONLY";
						return false;
					}
				}
#else
				boost::ignore_unused(ipv6only);
#endif
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
			std::lock_guard<std::mutex> lock(m_ws_mux);
			for (auto& [id, conn_ptr] : m_ws_streams)
			{
				boost::ignore_unused(id);
				BOOST_ASSERT(conn_ptr);

				if (!conn_ptr) continue;

				auto& conn = *conn_ptr;
				conn.quit_ = true;
				conn.ws_timer_.cancel(ignore_ec);
				boost::beast::get_lowest_layer(conn.ws_stream_).close();
			}
		}

		void start_ws_listen(tcp::acceptor& a, boost::asio::yield_context& yield)
		{
			boost::system::error_code error;
			while (!m_abort)
			{
				tcp::socket socket(m_io_pool.get_io_context());
				a.async_accept(socket, yield[error]);
				if (error)
				{
					LOG_ERR << "WS server, async_accept: " << error.message();

					if (error == boost::asio::error::operation_aborted ||
						error == boost::asio::error::bad_descriptor)
					{
						return;
					}

					if (!a.is_open())
						return;

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
				boost::asio::spawn(executor,
					[this, connection_id, stream = std::move(stream)](boost::asio::yield_context yield) mutable
				{
					start_ws_connect(connection_id, std::move(stream), yield);
				}, boost::coroutines::attributes(5 * 1024 * 1024));
			}

			LOG_DBG << "start_ws_listen exit...";
		}

		void start_ws_connect(size_t connection_id,
			boost::beast::tcp_stream stream, boost::asio::yield_context& yield)
		{
			using namespace boost::beast;
			boost::system::error_code ec;
			boost::beast::flat_buffer buffer;

			for (; !m_abort;)
			{
				request_parser parser;
				parser.body_limit(std::numeric_limits<uint64_t>::max());

				http::async_read_header(stream, buffer, parser, yield[ec]);
				if (ec)
				{
					LOG_DBG << "start_ws_connect, id: " << connection_id << ", async_read_header: " << ec.message();
					return;
				}

				if (parser.get()[http::field::expect] == "100-continue")
				{
					http::response<http::empty_body> res;
					res.version(11);
					res.result(http::status::continue_);
					http::async_write(stream, res, yield[ec]);
					if (ec)
					{
						LOG_DBG << "start_ws_connect, id: " << connection_id << ", expect async_write: " << ec.message();
						return;
					}
				}

				auto req = parser.release();

				std::string target = req.target().to_string();
				if (!boost::beast::websocket::is_upgrade(req) ||
					target != "/ws/channel")
				{
					http_params params{ {}, connection_id, stream, req, parser, buffer, yield };
					return do_http_response(params, "Illegal request", http_status::bad_request);
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
				ws.async_accept(req, yield[ec]);
				if (ec)
				{
					LOG_DBG << "start_ws_connect, " << connection_id << ", async_accept: " << ec.message();
					break;
				}

				ws_connection_ptr connection_ptr =
					std::make_shared<ws_connection>(std::forward<ws_stream>(ws), connection_id, remote_host);
				ws_expires_after(*connection_ptr, 60);
				connection_ptr->quit_ = false;

				LOG_DBG << "Client incoming: " << remote_host << ", connection id: " << connection_id;

				// 设置为2进制模式.
				connection_ptr->ws_stream_.binary(true);
				// 收到pong消息, 重置超时.
				ws_connection_weak_ptr wsptr = connection_ptr;
				connection_ptr->ws_stream_.control_callback(
				[this, wsptr = std::move(wsptr)]
				(boost::beast::websocket::frame_type ft, boost::beast::string_view)
				{
					if (ft == boost::beast::websocket::frame_type::pong)
					{
						auto ptr = wsptr.lock();
						if (!ptr)
							return;

						LOG_DBG << "Server pong recevied, id: " << ptr->connection_id_;
						ws_expires_after(*ptr, 60);
					}
				});

				// 发起保活协程.
				keepalive(connection_ptr);

				// 启动读写协程.
				auto executor = connection_ptr->ws_stream_.get_executor();
				boost::asio::spawn(executor,
				[this, connection_ptr](boost::asio::yield_context yield) mutable
				{
					start_server_read(connection_ptr, yield);

					// 移除virtual_ipaddr指定的ws.
					connection_ptr->quit_ = true;
					if (connection_ptr->virtual_ipaddr_ != 0)
					{
						boost::system::error_code ignore_ec;
						connection_ptr->ws_timer_.cancel(ignore_ec);
						remove_ws(connection_ptr->virtual_ipaddr_);
					}
				}, boost::coroutines::attributes(20 * 1024 * 1024));

				return;
			}
		}

		void start_server_read(ws_connection_ptr connection_ptr, boost::asio::yield_context& yield)
		{
			if (!connection_ptr)
				return;
			auto& connection = *connection_ptr;
			auto connection_id = connection.connection_id_;
			auto& stream = connection.ws_stream_;

			boost::beast::error_code ec;
			std::vector<char> data;
			boost::asio::dynamic_vector_buffer buffer(data);

			while (!m_abort)
			{
				auto bytes = stream.async_read(buffer, yield[ec]);
				if (ec == websocket::error::closed)
				{
					LOG_DBG << "start_server_read, id: " << connection_id << ", session was closed";
					break;
				}

				if (ec)
				{
					LOG_ERR << "start_server_read, id: " << connection_id << ", async_read error: " << ec.message();
					break;
				}

				buffer.commit(bytes);
				ws_expires_after(connection, 60);

				auto bufptr = boost::asio::buffer_cast<const void*>(buffer.data());

				// 处理数据包.
				auto msg = flatbuffers::GetRoot<avpn::Message>(bufptr);
				if (!msg)
				{
					LOG_ERR << "start_server_read, id: " << connection_id << ", get message root is nullptr";
					break;
				}

				flatbuffers::Verifier v((const uint8_t*)bufptr, bytes);
				if (!msg->Verify(v))
				{
					LOG_ERR << "start_server_read, id: " << connection_id << ", verify message fail";
					break;
				}

				process_net_packet(msg, connection_ptr);
				buffer.consume(bytes);
			}

			connection.quit_ = true;

			LOG_WARN << "start_server_read, id: " << connection_id << " quit..";
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

		void do_http_response(const http_params& params, std::string response, http_status status)
		{
			auto& connection_id = params.connection_id_;
			auto& stream = params.stream_;
			auto& request = params.request_;
			auto& yield = params.yield_;

			boost::system::error_code ec;
			string_response res{ status, request.version() };
			res.set(boost::beast::http::field::server, HTTPD_VERSION_STRING);
			res.set(boost::beast::http::field::content_type, "text/html");
			res.keep_alive(request.keep_alive());
			res.body() = response;
			res.prepare_payload();

			boost::beast::http::serializer<false, string_body, fields> sr{ res };
			boost::beast::http::async_write(stream, sr, yield[ec]);
			if (ec)
			{
				LOG_WARN << "do_http_response, id: " << connection_id << ", err: " << ec.message();
				return;
			}
		}

		void on_channel_write(avpn::ws_connection& connection,
			avpn::MessageT& msg, boost::asio::yield_context& yield)
		{
			bool use_tcp_protocol = true;

			// pt_auth协议直接走tcp传输.
			if (msg.type == pkt_type::pt_auth || msg.type == pkt_type::pt_icmp)
				use_tcp_protocol = true;
			else
			{
				// 动态选择使用tcp/udp传输.
				auto sel = rand_discrete({ 8, 2 });



				// use_tcp_protocol = !!use_tcp_protocol; // TODO: 根据配置来确定使用ws还是udp传输.
			}

			// 确定使用ws协议传输, 直接序列化后丢入ws发送队列进行发送.
			if (use_tcp_protocol)
			{
				// 先更新协议中的id, 确保每个group在ws中不超过data shards份数据.
				flatbuffers::FlatBufferBuilder flatbuilder;
				flatbuilder.Finish(avpn::Message::Pack(flatbuilder, &msg));

				auto bufptr = reinterpret_cast<const char*>(flatbuilder.GetBufferPointer());
				auto bufsize = flatbuilder.GetSize();

				connection.deque_writing_ = !connection.ws_msg_deque_.empty();
				auto& message_deque = connection.ws_msg_deque_;
				message_deque.emplace_back(std::string{ bufptr, bufsize });

				if (!connection.deque_writing_ && !connection.quit_)
				{
					boost::system::error_code ec;
					while (!m_abort && !message_deque.empty())
					{
						connection.ws_stream_.async_write(boost::asio::buffer(message_deque.front()), yield[ec]);
						if (ec)
						{
							LOG_ERR << "on_channel_write, " << connection.connection_id_ << " async_write error: " << ec.message();
							return;
						}
						message_deque.pop_front();
					}
				}
			}
		}

		void direct_channel_write(avpn::ws_connection_ptr& connection_ptr, avpn::MessageT& msg)
		{
			boost::asio::spawn(connection_ptr->ws_stream_.get_executor(),
				[this, connection_ptr, msg = std::move(msg)](boost::asio::yield_context yield) mutable
			{
				auto& connection = *connection_ptr;
				flatbuffers::FlatBufferBuilder flatbuilder;
				flatbuilder.Finish(avpn::Message::Pack(flatbuilder, &msg));

				auto bufptr = reinterpret_cast<const char*>(flatbuilder.GetBufferPointer());
				auto bufsize = flatbuilder.GetSize();

				connection.deque_writing_ = !connection.ws_msg_deque_.empty();
				auto& message_deque = connection.ws_msg_deque_;
				message_deque.emplace_back(std::string{ bufptr, bufsize });

				if (!connection.deque_writing_ && !connection.quit_)
				{
					boost::system::error_code ec;
					while (!m_abort && !message_deque.empty())
					{
						connection.ws_stream_.async_write(boost::asio::buffer(message_deque.front()), yield[ec]);
						if (ec)
						{
							LOG_ERR << "channel_write, " << connection.connection_id_ << " async_write error: " << ec.message();
							return;
						}
						message_deque.pop_front();
					}
				}
			});
		}

		void start_udp_socket(boost::asio::yield_context& yield)
		{
			boost::system::error_code ec;

			if (m_identity == 0)
			{
				for (auto& listen : m_udp_listens)
				{
					udp::endpoint endp;
					bool ipv6only = make_listen_endpoint(listen, endp, ec);
					if (ec)
					{
						LOG_ERR << "Start listen udp error: " << listen << ", ec: " << ec.message();
						continue;
					}

					udp::socket sock(m_io_context, endp.protocol());

#if __linux__
					if (ipv6only)
					{
						int on = 1;
						if (::setsockopt(sock.native_handle(), IPPROTO_IPV6, IPV6_V6ONLY, (char*)&on, sizeof(on)) == -1)
						{
							LOG_ERR << "Start listen udp setsockopt IPV6_V6ONLY";
							continue;
						}
					}
#else
					boost::ignore_unused(ipv6only);
#endif
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
				for (auto& serv : m_udp_servers)
				{
					udp::socket sock(m_io_context);
					sock.open(serv.protocol(), ec);
					if (ec)
					{
						LOG_ERR << "Start listen udp open error: " << ec.message();
						continue;
					}

					m_udp_sockets.emplace_back(std::move(sock));
				}
			}

			// 按socket数量启动udp读取协程, 为接收提高效率, 发起2倍接收.
			for (size_t fast = 0; fast < 2; fast++)
			{
				for (size_t n = 0; n < m_udp_sockets.size(); n++)
				{
					boost::asio::spawn(m_io_context.get_executor(),
						[this, index = n](boost::asio::yield_context yield) mutable
						{
							start_udp_read_loop(index, yield);
						});
				}
			}
		}

		void start_udp_read_loop(size_t index, boost::asio::yield_context& yield)
		{
			auto& sock = m_udp_sockets[index];
			char buffer[2048];
			udp::endpoint remote_endp;
			boost::system::error_code ec;

			while (!m_abort)
			{
				auto bytes = sock.async_receive_from(boost::asio::buffer(buffer), remote_endp, yield[ec]);
				if (ec)
					continue;

				auto msg = flatbuffers::GetRoot<avpn::Message>(buffer);
				if (!msg)
				{
					LOG_ERR << "start_client_read, remote host: " << remote_endp << ", get message root is nullptr";
					break;
				}

				flatbuffers::Verifier v((const uint8_t*)buffer, bytes);
				if (!msg->Verify(v))
				{
					LOG_ERR << "start_client_read, remote host: " << remote_endp << ", verify message fail";
					break;
				}

				// 没找到udp连接, 则创建连接.
				auto connection = lookup_udp(remote_endp);
				if (!connection)
				{
					connection = std::make_shared<udp_connection>();
					connection->last_see_ = timer::clock_type::now();
					connection->sock_ = &sock;

					add_udp(remote_endp, connection);
				}

				// 更新最后可见时间.
				connection->last_see_ = timer::clock_type::now();

				process_udp_net_packet(msg, connection);
			}

			LOG_ERR << "start_udp_read_loop, endpoint: " << remote_endp << ", quit...";
		}

		void connect(ws_connection_ptr& connection_ptr, boost::asio::yield_context& yield)
		{
			if (m_upstreams.empty())
				return;

			ws_stream& stream = connection_ptr->ws_stream_;

			boost::system::error_code ec;
			tcp::socket& sock = boost::beast::get_lowest_layer(stream).socket();

			// 循环连接上游server.
			bool ok = false;
			for (auto it = m_upstreams.begin();
				it != m_upstreams.end() && !m_abort; it++)
			{
				auto& upstream = *it;

				util::uri parser;

				if (!parser.parse(upstream))
					continue;

				tcp::resolver resolver{ m_io_context };
				auto const results = resolver.async_resolve(
					std::string(parser.host()), std::string(parser.port()), yield[ec]);
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

				boost::asio::async_connect(sock, results, yield[ec]);
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
				stream.async_handshake(std::string(parser.host()),
					parser.path().empty() ? "/" : parser.path(), yield[ec]);
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

			// 启动udp连接用于向服务器发送消息.
			std::call_once(m_once_start_udp, [this]()
				{
					LOG_DBG << "Start udp socket...";

					boost::asio::spawn(m_io_context.get_executor(),
						[this](boost::asio::yield_context yield) mutable {
							start_udp_socket(yield);
						});
				});

			if (!ok)
			{
				if (m_abort)
					return;

				LOG_DBG << "wait a moment to reconnect...";

				// 无论任何原因, 等待15s后再发起连接.
				boost::asio::spawn(stream.get_executor(),
				[this, connection_ptr](boost::asio::yield_context yield) mutable
				{
					auto& timer = connection_ptr->ws_timer_;
					boost::system::error_code ec;

					timer.expires_from_now(std::chrono::seconds(15));
					timer.async_wait(yield[ec]);

					if (!m_abort)
						do_reconnect(connection_ptr);
				});

				return;
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
					auto ptr = wsptr.lock();
					if (!ptr)
						return;

					LOG_DBG << "Client pong recevied, id: " << ptr->connection_id_;
					ws_expires_after(*ptr, 60);
				}
			});

			// 发起认证请求.
			avpn::MessageT msg;
			msg.type = pkt_type::pt_auth;
			msg.auth = std::make_unique<avpn::AuthMessageT>();
			// TODO: 做google auth, test key.
			msg.auth->auth_code = (int32_t)google_auth_code(test_google_key);
			msg.auth->cliend_id = "test";
			direct_channel_write(connection_ptr, msg);

			// 发起保活协程.
			keepalive(connection_ptr);

			// 发起读写协程.
			boost::asio::spawn(m_io_context.get_executor(),
			[this, wsptr = connection_ptr](boost::asio::yield_context yield) mutable
			{
				start_client_read(wsptr, yield);
			});
		}

		void start_client_read(ws_connection_ptr& connection_ptr, boost::asio::yield_context& yield)
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
				auto bytes = stream.async_read(buffer, yield[ec]);
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
				auto bufptr = boost::asio::buffer_cast<const void*>(buffer.data());

				auto msg = flatbuffers::GetRoot<avpn::Message>(bufptr);
				if (!msg)
				{
					LOG_ERR << "start_client_read, id: " << connection_id << ", get message root is nullptr";
					break;
				}

				ws_expires_after(connection, 60);

				flatbuffers::Verifier v((const uint8_t*)bufptr, bytes);
				if (!msg->Verify(v))
				{
					LOG_ERR << "start_client_read, id: " << connection_id << ", verify message fail";
					break;
				}

				process_net_packet(msg, connection_ptr);
				buffer.consume(buffer.size());
			}

			connection.quit_ = true;

			// 出错后准备重试连接.
			if (!m_abort && connection_ptr)
			{
				connection.ws_stream_.async_close(boost::beast::websocket::close_code::none, yield[ec]);
				connection.ws_timer_.cancel_one(ec);

				// 通知断开连接.
				if (m_status_notify)
					m_status_notify(channel_status::st_disconnect);

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

			boost::asio::spawn(conn->ws_stream_.get_executor(),
				[this, ptr = std::move(ptr)](boost::asio::yield_context yield) mutable
				{
					while (!m_abort)
					{
						auto conn = ptr.lock();
						if (!conn || conn->quit_)
							return;

						auto& timer = conn->ws_timer_;
						boost::system::error_code ec;

						timer.expires_from_now(std::chrono::seconds(29));
						timer.async_wait(yield[ec]);

						LOG_DBG << "Keepalive for connection id: " << conn->connection_id_;
						conn->ws_stream_.async_ping("", yield[ec]);
					}
				});
		}

		void process_net_packet(const avpn::Message* msg, ws_connection_ptr& connection_ptr)
		{
			auto& connection = *connection_ptr;

			std::string_view content;
			if (msg->content())
				content = std::string_view{(const char*)msg->content()->data(), msg->content()->size() };

			switch (msg->type())
			{
			case avpn::pkt_type::pt_auth:
			{
				if (m_identity == 0) // 作为 server.
				{
					auto auth = msg->auth();
					if (!auth)
						return;

					// TODO: 作认证操作, test key.
					int32_t code = (int32_t)google_auth_code(test_google_key);
					if (code != auth->auth_code())
					{
						LOG_WARN << "Server verify auth code fail: " << code << ", got: " << auth->auth_code();
						return;
					}

					// 返回获取的ip地址.
					avpn::MessageT reply;
					reply.type = msg->type();

					reply.auth_reply = std::make_unique<avpn::AuthMessageReplyT>();
					std::string ip_string;
					uint32_t ipaddr;

					do
					{
						ipaddr = m_ip_assigned++;

						auto addr = boost::asio::ip::make_address_v4(ipaddr);
						auto addr_bytes = addr.to_bytes();

						// 过滤无效ip.
						if (addr_bytes[3] == 255 || addr_bytes[3] == 0)
							continue;

						// 重头开始(10.0.0.10).
						if (addr_bytes[2] == 255)
						{
							m_ip_assigned = 0x0a00000a;
							continue;
						}

						ip_string = addr.to_string();

						reply.auth_reply->virtual_ipaddr = ip_string;
						connection.virtual_ipaddr_ = ipaddr;

					} while (false);

					LOG_DBG << "Server assign virtual ip: "
						<< ip_string << " to id: " << connection.connection_id_;

					// 添加到连接管理.
					add_ws(ipaddr, connection_ptr);

					// 返回数据.
					direct_channel_write(connection_ptr, reply);

					return;
				}

				if (m_identity == 1) // 作为 client.
				{
					auto auth_reply = msg->auth_reply();
					if (!auth_reply)
						return;

					avpn::AuthMessageReplyT auth;
					auth_reply->UnPackTo(&auth);

					if (!auth.error.empty())
					{
						LOG_WARN << "Client assign virtual ip error: " << auth.error;
						return;
					}

					// 保存获得的虚拟ip.
					m_virtual_ipaddr = auth.virtual_ipaddr;

					// 保存连接.
					m_client = connection_ptr;

					// 通知完成连接.
					if (m_status_notify)
						m_status_notify(channel_status::st_connected);

					return;
				}
			}
			break;
			case avpn::pkt_type::pt_ctrl:
				break;
			case avpn::pkt_type::pt_icmp:
			[[fallthrough]];
			case avpn::pkt_type::pt_udp:
			{
				if (!m_tuntap_writer)
					return;

				m_tuntap_writer(std::string(content));
			}
			break;
			case avpn::pkt_type::pt_tcp:
			{
				m_tuntap_writer(std::string(content));
			}
			break;
			case avpn::pkt_type::pt_fec:
			{}
			break;
			}
		}

		void process_udp_net_packet(const avpn::Message* msg, udp_connection_ptr& connection_ptr)
		{
			auto& fec = connection_ptr->fec_dec_;
			auto do_forward = [this, &connection_ptr, &fec]() mutable
			{
				auto groups = fec.clean();
				for (auto& pkts : groups)
				{
					auto v = pkts.decode();
					for (auto& d : v)
						m_tuntap_writer(std::move(d));
				}
			};

			std::string_view content;
			if (msg->content())
				content = std::string_view{ (const char*)msg->content()->data(), msg->content()->size() };

			switch (msg->type())
			{
			case avpn::pkt_type::pt_auth:
			{}
			break;
			case avpn::pkt_type::pt_ctrl:
			{
				// 在server模式, 接收到client的虚拟ip, 往对应的ws_connection
				// 中保存udp_connection信息.
				if (m_identity == 0)
				{
					boost::system::error_code ec;
					auto addr = boost::asio::ip::address_v4::from_string(std::string(content), ec);
					auto ws_conn = lookup_ws(addr.to_uint());
					if (!ws_conn)
						return;
					ws_conn->udp_stream_ = connection_ptr;
				}
			}
			break;
			case avpn::pkt_type::pt_icmp:
			[[fallthrough]];
			case avpn::pkt_type::pt_udp:
			{
				if (!m_tuntap_writer)
					return;

				m_tuntap_writer(std::string(content));
			}
			break;
			case avpn::pkt_type::pt_tcp:
			{
				m_tuntap_writer(std::string(content));
			}
			break;
			case avpn::pkt_type::pt_fec:
			{
				auto pkt = msg->fec_pkt();
				if (!pkt)
					break;

				fec.update(pkt->gid(), pkt->pid(), pkt->ds(), pkt->ps(),
					pkt->gsize(), (uint8_t*)content.data(), content.size());
			}
			break;
			}

			// 将从网络接收到的数据包转发到设备.
			do_forward();
		}

		void add_udp(const udp::endpoint& endp, udp_connection_ptr& ptr)
		{
			std::lock_guard<std::mutex> lock(m_udp_mux);
			auto it = m_udp_connections.find(endp);
			if (it == m_udp_connections.end())
				m_udp_connections[endp] = ptr;
		}

		udp_connection_ptr lookup_udp(const udp::endpoint& endp)
		{
			std::lock_guard<std::mutex> lock(m_udp_mux);
			auto it = m_udp_connections.find(endp);
			if (it == m_udp_connections.end())
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
		avpn::io_context_pool& m_io_pool;

		std::vector<std::string> m_upstreams;
		std::vector<std::string> m_tcp_listens;
		std::vector<std::string> m_udp_listens;

		// 作为server时, 用于ws的服务器acceptor.
		std::vector<tcp::acceptor> m_ws_acceptors;

		// udp socket, 无论是client还是server, 都只会
		// 初始化1次.
		std::once_flag m_once_start_udp;
		std::vector<udp::socket> m_udp_sockets;

		// tuntap设备写入函数及状态通知函数.
		tuntap_writer m_tuntap_writer;
		notify_status m_status_notify;

		// 运行的身份.
		int m_identity{-1};

		// fec参数.
		int m_data_shards;
		int m_parity_shards;

		// double tcp.
		int m_double_tcp;

		// channel for server.
		std::mutex m_ws_mux;
		// key's 32bit, use ipv4 address, virtual ipaddr.
		std::unordered_map<uint32_t, ws_connection_ptr> m_ws_streams;

		// 作为server时, 虚拟 ip 分配器.
		std::atomic_uint32_t m_ip_assigned{ 0x0a00000a };

		// channel for client.
		ws_connection_weak_ptr m_client;

		// upstreams 中 udp server 的endpoint.
		std::set<udp::endpoint> m_udp_servers;

		// 本机作为client时的虚拟ip.
		std::string m_virtual_ipaddr;

		// udp 连接信息列表.
		std::mutex m_udp_mux;
		std::unordered_map<udp::endpoint, udp_connection_ptr> m_udp_connections;

		std::atomic_int64_t m_pkt_id{ 0 };
		std::atomic_int64_t m_connection_id{ 0 };
		std::atomic_bool m_abort{ false };
	};
}
