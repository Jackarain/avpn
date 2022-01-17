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
#include <boost/asio/streambuf.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/read_until.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/strand.hpp>

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/ssl.hpp>

#include "vpncore/intrusive_ptr_base.hpp"
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
	using udp = boost::asio::ip::tcp;               // from <boost/asio/ip/udp.hpp>
	namespace websocket = boost::beast::websocket;  // from <boost/beast/websocket.hpp>
	using ws = websocket::stream<tcp::socket>;		// from <boost/beast/websocket.hpp>
	namespace net = boost::asio;					// from <boost/asio.hpp>

	using timer = boost::asio::basic_waitable_timer<time_clock::steady_clock>;
	using ws_stream = websocket::stream<boost::beast::tcp_stream>;

	using namespace util;

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

	struct ws_connection
	{
		ws_connection(ws_stream&& ws, int64_t connection_id, const std::string& remote_host)
			: ws_stream_(std::move(ws))
			, ws_timer_(ws_stream_.get_executor())
			, reconnect_timer_(ws_stream_.get_executor())
			, connection_id_(connection_id)
			, remote_host_(remote_host)
			, is_challenge_(false)
		{}

		ws_connection(ws_connection&& c) noexcept
			: ws_stream_(std::move(c.ws_stream_))
			, ws_msg_deque_(std::move(c.ws_msg_deque_))
			, udp_msg_deque_(std::move(c.udp_msg_deque_))
			, identity_(c.identity_)
			, origin_addr(c.origin_addr)
			, gid_(c.gid_)
			, pid_(c.pid_)
			, ws_timer_(std::move(c.ws_timer_))
			, reconnect_timer_(std::move(c.reconnect_timer_))
			, connection_id_(c.connection_id_)
			, remote_host_(c.remote_host_)
			, quit_(!!c.quit_)
			, is_challenge_(c.is_challenge_)
		{}

		~ws_connection()
		{
			LOG_DBG << "ws client leave: " << connection_id_ << ", remote: " << remote_host_;
		}

		ws_stream ws_stream_;
		std::deque<std::string> ws_msg_deque_;
		std::deque<std::string> udp_msg_deque_;
		int identity_{0}; // 0 server, 1 client.
		avpn::endpoint_pair origin_addr; // 作为服务器时, 用于区分客户端的地址使用.
		int64_t gid_{0};
		uint16_t pid_{0};
		timer ws_timer_;
		timer reconnect_timer_;
		int64_t connection_id_;
		std::string remote_host_;
		std::atomic_bool quit_{false};
		bool is_challenge_;
	};
	using ws_connection_ptr = std::shared_ptr<ws_connection>;


	//////////////////////////////////////////////////////////////////////////

	enum channel_status
	{
		st_connected,
		st_disconnect,
	};

	class channel
	{
		using tuntap_writer = std::function<void(std::string&&)>;
		using notify_status = std::function<void(channel_status)>;

		channel(const channel&) = delete;
		channel& operator=(const channel&) = delete;

	public:
		explicit channel(boost::asio::io_context& io)
			: m_io_context(io)
			, m_udp_client(io)
		{}

	public:
		void start_connect(const std::vector<std::string>& upstreams,
			notify_status notify_func, tuntap_writer writer_func)
		{
			m_upstreams = upstreams;

			m_tuntap_writer = writer_func;
			m_status_notify = notify_func;

			if (m_client)
			{
				BOOST_ASSERT("client is exist!" && false);
				return;
			}

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
					m_client = std::make_shared<ws_connection>(ws_stream{m_io_context}, m_connection_id++, "");
					ws_stream& stream = m_client->ws_stream_;

					connect(stream, yield);

					timer& reconnect_timer = m_client->reconnect_timer_;
					reconnect_timer.expires_from_now(never);
					reconnect_timer.async_wait(yield[ec]);

					if (m_abort)
						break;

					LOG_DBG << "channel::start_connect, do connect...";
				}

				LOG_DBG << "channel::start_connect, reconnect conroutine quit...";
			});
		}

		void start_listen()
		{}

		void close()
		{
			m_abort = true;
			boost::system::error_code ignore_ec;
			if (m_client)
			{
				boost::beast::get_lowest_layer(m_client->ws_stream_).socket().close(ignore_ec);
				m_client->reconnect_timer_.cancel_one(ignore_ec);
				m_client->ws_timer_.cancel_one(ignore_ec);
			}
		}

		void client_write(avpn::MessageT&& msg, avpn::endpoint_pair endp)
		{
			auto& connection_ptr = m_client;
			if (!connection_ptr)
				return;

			auto& ws = connection_ptr->ws_stream_;
			boost::asio::post(ws.get_executor(), [this, connection_ptr, msg = std::move(msg), endp]() mutable
			{
				auto& connection = *connection_ptr;

				on_client_write(connection, msg, endp);
			});
		}

	private:
		void on_client_write(avpn::ws_connection& connection, avpn::MessageT& msg, avpn::endpoint_pair& endp)
		{
			// TODO: 根据配置来确定使用ws还是udp传输
			boost::ignore_unused(endp);

			// 确定使用ws协议传输, 直接序列化后丢入ws发送队列进行发送.
			{
				// 先更新协议中的id, 确保每个group在ws中不超过data shards份数据.
				flatbuffers::FlatBufferBuilder flatbuilder;
				flatbuilder.Finish(avpn::Message::Pack(flatbuilder, &msg));

				auto bufptr = reinterpret_cast<const char*>(flatbuilder.GetBufferPointer());
				auto bufsize = flatbuilder.GetSize();

				connection.ws_msg_deque_.emplace_back(std::string{ bufptr, bufsize });
			}
		}

		void connect(ws_stream& stream, boost::asio::yield_context& yield)
		{
			if (m_upstreams.empty())
				return;

			boost::system::error_code ec;
			tcp::socket& sock = boost::beast::get_lowest_layer(stream).socket();

			// 循环连接上游server.
			bool ok = false;
			for (auto& upstream : m_upstreams)
			{
				util::uri parser;

				if (!parser.parse(upstream))
					return;

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
						m_udp_endps.emplace_back(endp.endpoint());
					continue;
				}

				asio_util::async_connect(sock, results, yield[ec]);
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

				ok = true;
				if (ok)
					break;
			}

			if (!ok)
			{
				LOG_DBG << "wait a moment to reconnect...";

				// 无论任何原因, 等待15s后再发起连接.
				timer delay_timer(m_io_context);

				delay_timer.expires_from_now(std::chrono::seconds(15));
				delay_timer.async_wait(yield[ec]);

				if (!m_abort)
					do_reconnect();

				return;
			}

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

			m_client->remote_host_ = remote_host;
			LOG_DBG << "ws client connected: " << m_client->connection_id_ << ", remote: " << remote_host;

			// 通知完成连接.
			if (m_status_notify)
				m_status_notify(channel_status::st_connected);

			// 发起读写协程.
			boost::asio::spawn(m_io_context.get_executor(),
			[this](boost::asio::yield_context yield) mutable
			{
				start_client_read(yield);
			});

			boost::asio::spawn(m_io_context.get_executor(),
			[this](boost::asio::yield_context yield) mutable
			{
				start_client_write(yield);
			});
		}

		void start_client_read(boost::asio::yield_context& yield)
		{
			auto connection_ptr = m_client;
			auto& stream = connection_ptr->ws_stream_;
			auto& connection_id = connection_ptr->connection_id_;

			boost::system::error_code ec;

			while (!m_abort)
			{
				boost::beast::multi_buffer buffer{ 512 * 1024 };
				auto bytes_transferred = stream.async_read(buffer, yield[ec]);
				boost::ignore_unused(bytes_transferred);
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

				auto result = boost::beast::buffers_to_string(buffer.data());
				auto msg = flatbuffers::GetRoot<avpn::Message>(result.data());
				if (!msg)
				{
					LOG_ERR << "start_client_read, id: " << connection_id << ", get message root is nullptr";
					break;
				}

				flatbuffers::Verifier v((const uint8_t*)result.data(), result.size());
				if (!msg->Verify(v))
				{
					LOG_ERR << "start_client_read, id: " << connection_id << ", verify message fail";
					break;
				}

				process_net_packet(msg);
			}

			if (!m_abort && m_client)
			{
				connection_ptr->ws_stream_.async_close(boost::beast::websocket::close_code::none, yield[ec]);
				connection_ptr->ws_timer_.cancel_one(ec);
				connection_ptr->quit_ = true;

				// 通知断开连接.
				if (m_status_notify)
					m_status_notify(channel_status::st_disconnect);

				do_reconnect();
			}
		}

		void start_client_write(boost::asio::yield_context& yield)
		{
			auto connection_ptr = m_client;

			auto& message_deque = connection_ptr->ws_msg_deque_;
			auto& ws_timer = connection_ptr->ws_timer_;
			auto& stream = connection_ptr->ws_stream_;
			auto& connection_id = connection_ptr->connection_id_;

			boost::system::error_code ec;

			while (!m_abort && !connection_ptr->quit_)
			{
				while (!m_abort && !message_deque.empty())
				{
					stream.async_write(boost::asio::buffer(message_deque.front()), yield[ec]);
					if (ec)
					{
						LOG_ERR << "start_client_write, " << connection_id << " async_write error: " << ec.message();
						return;
					}
					message_deque.pop_front();
				}

				while (!m_abort)
				{
					ws_timer.expires_from_now(std::chrono::seconds(10)); // 每10s发起一次ping以保活.
					ws_timer.async_wait(yield[ec]);
					if (ec == boost::system::errc::operation_canceled || message_deque.size() > 0)
						break;
					if (ec)
					{
						LOG_ERR << "start_client_write, " << connection_id << " async_wait, error: " << ec.message();
						continue;
					}
					stream.async_ping("", yield[ec]);
					if (ec)
					{
						LOG_ERR << "start_client_write, " << connection_id << " async_ping, error: " << ec.message();
						return;
					}
				}
			}

			LOG_DBG << "start_client_write quit..";
		}

		void do_reconnect()
		{
			boost::system::error_code ignore_ec;
			if (!m_client)
			{
				BOOST_ASSERT("client object is nullptr!" && false);
				return;
			}

			LOG_DBG << "channel::do_reconnect, reset reconnect timer.";
			m_client->reconnect_timer_.cancel_one(ignore_ec);
		}

		void process_net_packet(const avpn::Message* msg)
		{
			auto do_forward = [this]() mutable
			{
				auto groups = m_cache.clean();
				for (auto& pkts : groups)
				{
					auto v = pkts.decode();
					for (auto &d : v)
						m_tuntap_writer(std::move(d));
				}
			};

			std::string_view content;
			if (msg->content())
				content = std::string_view{(const char*)msg->content()->data(), msg->content()->size() };

			switch (msg->type())
			{
			case avpn::pkt_type::pt_auth:
				break;
			case avpn::pkt_type::pt_ctrl:
				break;
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

			// 将从网络接收到的数据包转发到设备.
			do_forward();
		}

	private:
		boost::asio::io_context& m_io_context;

		std::vector<std::string> m_upstreams;
		std::vector<std::string> m_tcp_listens;
		std::vector<std::string> m_udp_listens;

		std::vector<tcp::acceptor> m_ws_acceptors;

		tuntap_writer m_tuntap_writer;
		notify_status m_status_notify;

		// channel for server.
		std::mutex m_ws_mux;
		// key's 32bit, use ipv4 address.
		std::unordered_map<uint32_t, ws_connection_ptr> m_ws_streams;

		// channel for client.
		ws_connection_ptr m_client;
		udp::socket m_udp_client;
		std::vector<udp::endpoint> m_udp_endps;

		int m_data_shards{ 0 };
		int m_parity_shards{ 0 };
		fec_cache m_cache;

		std::atomic_int64_t m_pkt_id{ 0 };
		std::atomic_int64_t m_connection_id{ 0 };
		std::atomic_bool m_abort{ false };
	};
}
