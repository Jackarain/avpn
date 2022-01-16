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




	//////////////////////////////////////////////////////////////////////////

	struct pkt_group
	{
	public:
		const static size_t max_ptk_size = 512 * 1024;

		int64_t gid_{-1};
		std::vector<boost::beast::multi_buffer> pkts_;
		bitfield bs_;
		int total_;
		size_t total_size_{0};
		timer::time_point time_;

		pkt_group(pkt_group&& pg) noexcept
			: pkts_(std::move(pg.pkts_))
			, gid_(pg.gid_)
			, bs_(pg.bs_)
			, total_(pg.total_)
			, time_(pg.time_)
		{
			pg.gid_ = -1;
			pg.pkts_.clear();
			pg.bs_.clear_all();
			pg.total_ = 0;
			pg.total_size_ = 0;
		}

		pkt_group() = delete;
		pkt_group(int data_shards, int parity_shards)
		{
			BOOST_ASSERT(data_shards + parity_shards < 256 && "dataShards + parityShards >= 255");
			total_ = data_shards + parity_shards;
			bs_.resize(total_, false);
			for (int i = 0; i < total_; i++)
				pkts_.emplace_back(boost::beast::multi_buffer{ max_ptk_size });
		}

		void update(int64_t gid, int pid, uint8_t* data, size_t size)
		{
			time_ = timer::clock_type::now();
			gid_ = gid;

			auto& pkt = pkts_[pid];
			auto p = pkt.prepare(size);

			boost::asio::buffer_copy(p, boost::asio::buffer(data, size));
			pkt.commit(size);
			bs_.set_bit(pid);
			total_size_ += size;
		}

		bool full() noexcept
		{
			return bs_.count() == total_;
		}

	private:
		pkt_group(const pkt_group&) = delete;
		pkt_group& operator=(const pkt_group&) = delete;
	};


	//////////////////////////////////////////////////////////////////////////

	struct ptk_cache
	{
	public:
		const static size_t max_cache_size = 5 * 1024 * 1024;
		std::map<int64_t, pkt_group> groups_;
		size_t total_size_ = 0;
		int64_t start_gid_ = -1;

		void update(int64_t gid, int pid,
			int data_shards, int parity_shards,
			uint8_t* data, size_t size)
		{
			auto f = groups_.find(gid);
			if (f == groups_.end())
			{
				pkt_group pkt(data_shards, parity_shards);
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

		std::vector<pkt_group> clean()
		{
			std::vector<pkt_group> result;

			for (auto& [gid, pkt] : groups_)
			{
				if (pkt.full())
				{
					total_size_ -= pkt.total_size_;
					result.emplace_back(std::move(pkt));
				}

				start_gid_ = gid;
				break;
			}

			for (auto& pkt : result)
				groups_.erase(pkt.gid_);

			// 大于max_cache_size时, 无论是否full, 都将清理并返回.
			if (total_size_ > max_cache_size)
			{
				for (auto it = groups_.begin(); it != groups_.end();)
				{
					auto& [gid, pkt] = *it;

					total_size_ -= pkt.total_size_;
					if (pkt.total_size_ > 0)
						result.emplace_back(std::move(pkt));

					groups_.erase(it++);

					if (total_size_ <= max_cache_size)
						break;
				}
			}

			return result;
		}

		ptk_cache() = default;

	private:
		ptk_cache(const ptk_cache&) = delete;
		ptk_cache& operator=(const ptk_cache&) = delete;
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
		{
			LOG_DBG << "ws client connected: " << connection_id_ << ", remote: " << remote_host_;
		}

		ws_connection(ws_connection&& c) noexcept
			: ws_stream_(std::move(c.ws_stream_))
			, message_deque_(std::move(c.message_deque_))
			, ws_timer_(std::move(c.ws_timer_))
			, reconnect_timer_(std::move(c.reconnect_timer_))
			, connection_id_(c.connection_id_)
			, remote_host_(c.remote_host_)
			, is_challenge_(c.is_challenge_)
		{}

		~ws_connection()
		{
			LOG_DBG << "ws client leave: " << connection_id_ << ", remote: " << remote_host_;
		}

		ws_stream ws_stream_;
		std::deque<std::string> message_deque_;
		int identity_{0}; // 0 server, 1 client.
		timer ws_timer_;
		timer reconnect_timer_;
		int64_t connection_id_;
		std::string remote_host_;
		bool is_challenge_;
	};
	using ws_connection_ptr = std::shared_ptr<ws_connection>;


	//////////////////////////////////////////////////////////////////////////

	class channel
		: public intrusive_ptr_base<channel>
	{
	public:
		explicit channel(boost::asio::io_context& io)
			: m_io_context(io)
		{}

	public:
		void start_connect(const std::vector<std::string>& upstreams)
		{
			m_upstreams = upstreams;

			if (m_client)
			{
				BOOST_ASSERT("client is exist!" && false);
				return;
			}

			// 创建client对象用于发起向server的连接.
			m_client = std::make_shared<ws_connection>(ws_stream{ m_io_context }, 0, "");

			// 发起连接协程, 进入异步连接.
			boost::asio::spawn(m_io_context.get_executor(),
			[this](boost::asio::yield_context yield) mutable
			{
				boost::system::error_code ec;

				auto& ws = m_client->ws_stream_;
				connect(ws, yield);

				static const auto never =
					std::chrono::hours(std::numeric_limits<int>::max());
				timer& reconnect_timer = m_client->reconnect_timer_;

				// 自动重连逻辑, .
				while (!m_abort)
				{
					reconnect_timer.expires_from_now(never);
					reconnect_timer.async_wait(yield[ec]);

					if (m_abort)
						break;

					connect(ws, yield);
				}

				LOG_DBG << "channel::start_connect, reconnect conroutine quit...";
			});
		}

		void start_listen()
		{}

		void stop()
		{}

	private:
		void connect(ws_stream& ws, boost::asio::yield_context& yield)
		{
			if (m_upstreams.empty())
				return;

			boost::system::error_code ec;
			tcp::socket& sock = boost::beast::get_lowest_layer(ws).socket();

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
					return;
				}

				asio_util::async_connect(sock, results, yield[ec]);
				if (ec)
				{
					LOG_ERR << "channel::connect, async_connect: " << ec.message();
					return;
				}

				std::string origin = "all";
				auto decorator = [origin](boost::beast::websocket::request_type& m) {
					m.insert(boost::beast::http::field::origin, origin);
				};

				ws.set_option(boost::beast::websocket::stream_base::decorator(decorator));
				ws.async_handshake(std::string(parser.host()),
					parser.path().empty() ? "/" : parser.path(), yield[ec]);
				if (ec)
				{
					LOG_ERR << "channel::connect, async_handshake: " << ec.message();
					return;
				}

				ok = true;
				if (ok)
					break;
			}

			if (!ok)
			{
				// 无论任何原因, 等待15s后再发起连接.
				timer delay_timer(m_io_context);

				delay_timer.expires_from_now(std::chrono::seconds(15));
				delay_timer.async_wait(yield[ec]);

				if (!m_abort)
					do_reconnect();

				return;
			}

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
			boost::ignore_unused(yield);

			// first step, do auth.
			// second step, read pkt from server.

			auto& ws = m_client->ws_stream_;
			auto& connection_id = m_client->connection_id_;

			boost::beast::error_code ec;

			while (!m_abort)
			{
				boost::beast::multi_buffer buffer{ 512 * 1024 };
				auto bytes_transferred = ws.async_read(buffer, yield[ec]);
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
				auto msg = flatbuffers::GetRoot<avpn::message>(result.data());
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

				auto sv{msg->content()->string_view()};
			}
		}

		void start_client_write(boost::asio::yield_context& yield)
		{
			auto& message_deque = m_client->message_deque_;
			auto& ws_timer = m_client->ws_timer_;
			auto& ws = m_client->ws_stream_;
			auto& connection_id = m_client->connection_id_;

			boost::system::error_code ec;

			while (!m_abort)
			{
				while (!m_abort && !message_deque.empty())
				{
					ws.async_write(boost::asio::buffer(message_deque.front()), yield[ec]);
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
					ws.async_ping("", yield[ec]);
					if (ec)
					{
						LOG_ERR << "start_client_write, " << connection_id << " async_ping, error: " << ec.message();
						return;
					}
				}
			}

			LOG_DBG << "start_client_write quit..";
		}

		void websocket_write(size_t connection_id, std::string&& message)
		{
			ws_connection_ptr connection_ptr;

			if (connection_id == 0)
				connection_ptr = m_client;

			if (!connection_ptr)
				return;

			auto& ws = connection_ptr->ws_stream_;
			boost::asio::post(ws.get_executor(), [this, connection_ptr, message = std::move(message)]() mutable
			{
				connection_ptr->message_deque_.emplace_back(std::move(message));
				boost::system::error_code ignore_ec;
				connection_ptr->ws_timer_.cancel(ignore_ec);
			});
		}

		void do_reconnect()
		{
			boost::system::error_code ignore_ec;
			if (!m_client)
			{
				BOOST_ASSERT("client object is nullptr!" && false);
				return;
			}

			m_client->reconnect_timer_.cancel_one(ignore_ec);
		}

	private:
		boost::asio::io_context& m_io_context;

		std::vector<std::string> m_upstreams;
		std::vector<std::string> m_tcp_listens;
		std::vector<std::string> m_udp_listens;

		std::vector<tcp::acceptor> m_ws_acceptors;

		// channel for server.
		std::mutex m_ws_mux;
		// key's 32bit, use ipv4 address.
		std::unordered_map<uint32_t, ws_connection_ptr> m_ws_streams;

		// channel for client.
		ws_connection_ptr m_client;

// 		std::unique_ptr<ws_stream> m_ws_client;
// 		timer m_reconnect_timer;
// 		timer m_write_timer;
// 		std::deque<std::string> m_message_deque_;

		std::atomic_int64_t m_pkt_id{ 0 };
		std::atomic_bool m_abort{ false };
	};
}
