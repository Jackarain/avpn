//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#include <functional>
#include <cstring> // for std::memcpy

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

#include "utils/logging.hpp"
#include "utils/misc.hpp"
#include "utils/uawaitable.hpp"

#include "avpn/avpn.hpp"

namespace avpn {

	class controller
	{
		// c++11 noncopyable.
		controller(const controller&) = delete;
		controller& operator=(const controller&) = delete;

		using ws_stream = websocket::stream<boost::beast::tcp_stream>;

	public:
		controller(io_context_pool& ioc_pool, const server_config& cfg);
		~controller() = default;

	public:
		void start();
		void stop();

	private:
		boost::asio::awaitable<void> start_connect();
		boost::asio::awaitable<void> start_client_read();

	private:
		io_context_pool& m_ioc_pool;
		boost::asio::io_context& m_io_context;
		boost::asio::signal_set m_signal;
		server_config m_config;
		avpn_service m_service;
		ws_stream m_ws_stream;
		bool m_start{ false };
		bool m_abort{ false };
	};
}
