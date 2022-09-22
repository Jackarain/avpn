//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#include "utils/misc.hpp"
#include "utils/asio_util.hpp"

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
		vpn_controller(net::io_context&, const service_config&);
		~vpn_controller() = default;

	public:
		void start();
		void stop();

	private:
		net::awaitable<void> start_connect();
		net::awaitable<void> start_client_read();
		net::awaitable<void> keepalive();

		net::awaitable<bool> on_json_rpc(std::string_view);

	private:

		// 用于本vpn_controller相关操作.
		net::io_context& m_main_context;

		// 用以响应用户ctrl+c操作.
		net::signal_set m_signal;

		// vpn服务相关配置, 启用vpn服务时
		// 用此配置启动vpn服务.
		service_config m_config;

		// vpn服务对象.
		std::shared_ptr<avpn_service> m_avpn_service;
		avpn_service& m_service;

		// websocket连到控制端的客户端对象.
		// 控制端通过发送消息控制vpn服务的
		// 开启关闭, vpn服务通过它汇报vpn
		// 当前上下行实时速率等信息.
		ws_stream m_ws_stream;

		// 汇报定时器, 定时汇报上下行实时速率
		// 等信息.
		asio_timer m_timer;

		// keepalive计数, 计数超过指定值则表示
		// 控制端已无响应, vpn服务应退出.
		int m_keepalive_cnt{ 0 };

		// vpn服务是否启动标志.
		bool m_start{ false };

		// 退出标志.
		bool m_abort{ false };
	};
}
