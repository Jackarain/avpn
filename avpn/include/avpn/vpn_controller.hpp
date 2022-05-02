//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#include "utils/misc.hpp"
#include "utils/uawaitable.hpp"

#include "avpn/avpn.hpp"

#include <functional>
#include <cstring> // for std::memcpy

#include <boost/asio/io_context.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/defer.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>


namespace avpn {

	class vpn_controller
	{
		// c++11 noncopyable.
		vpn_controller(const vpn_controller&) = delete;
		vpn_controller& operator=(const vpn_controller&) = delete;

		using ws_stream = websocket::stream<boost::beast::tcp_stream>;

	public:
		vpn_controller(io_context_pool& ioc_pool, const service_config& cfg);
		~vpn_controller() = default;

	public:
		void start();
		void stop();

	private:
		boost::asio::awaitable<void> start_connect();
		boost::asio::awaitable<void> start_client_read();
		boost::asio::awaitable<void> keepalive();

	private:
		io_context_pool& m_ioc_pool;
		boost::asio::io_context& m_io_context;
		boost::asio::signal_set m_signal;
		service_config m_config;
		avpn_service m_service;
		ws_stream m_ws_stream;
		timer m_timer;
		int m_keepalive_cnt{ 0 };
		bool m_start{ false };
		bool m_abort{ false };
	};
}
