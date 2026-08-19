//
// vpn_controller.cpp
// ~~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2023 Jack (jack dot wgm at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// 控制通道实现: 由 avpn_service 在配置了 controller 地址时创建, 主动连接到
// launcher 的 /rpc WebSocket 控制通道, 上报注册信息与运行状态, 并响应
// launcher 下发的 shutdown / get_status 请求.
//

#include "libavpn/vpn_controller.hpp"
#include "libavpn/logging.hpp"
#include "libavpn/asio_util.hpp"
#include "libavpn/avpn_protocol.hpp"

#include <boost/url.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>

#include <chrono>
#include <ctime>
#include <thread>
#ifdef _WIN32
# include <process.h>
#endif

namespace libavpn {

	namespace json = boost::json;

	using net::ip::tcp;

	// 状态上报间隔.
	inline constexpr std::chrono::milliseconds k_status_interval{ 2000 };
	// 连接失败后的重连间隔.
	inline constexpr std::chrono::seconds k_reconnect_base{ 3 };

	vpn_controller::vpn_controller(io_context_pool& ioc_pool,
		const service_config& config, std::weak_ptr<avpn_service> service)
		: m_ioc_pool(ioc_pool)
		, m_main_context(ioc_pool.main_io_context())
		, m_config(config)
		, m_service(std::move(service))
	{
	}

	void vpn_controller::start()
	{
		if (m_abort)
			return;

		// 协程闭包持有 shared_from_this: service 的 stop() 会 reset 本对象,
		// 但 worker/serve 协程运行期间仍由该引用保活, 协程结束后再析构.
		net::co_spawn(m_main_context.get_executor(),
			[self = shared_from_this()]() mutable -> net::awaitable<void>
			{
				co_await self->worker();
				co_return;
			}, net::detached);
	}

	void vpn_controller::stop()
	{
		if (m_abort)
			return;

		m_abort = true;

		boost::system::error_code ec;

		if (m_session)
		{
			// 让 jsonrpc 会话停止: 取消挂起的 RPC 调用、异步发送 close 帧.
			m_session->stop();
			// 直接关闭底层 TCP 连接: 同步 ws.close() 会等待对端 close 帧
			// 完成关闭握手, 而对端 (launcher) 可能在 stop_proc 阻塞期间
			// 无法响应, 导致本线程被拖住数秒 (最坏直到 SIGKILL). 直接关闭
			// socket 即可让对端读循环以 EOF/错误正常退出.
			auto& ws_stream = m_session->stream();
			ws_stream.next_layer().close(ec);
		}

		asio_util::cancel(m_timer, ec);
	}

	net::awaitable<void> vpn_controller::worker()
	{
		while (!m_abort)
		{
			if (co_await connect())
			{
				co_await serve();
			}

			if (m_abort)
				break;

			// 固定间隔重连.
			boost::system::error_code ec;
			m_timer.expires_after(k_reconnect_base);
			co_await m_timer.async_wait(net_awaitable[ec]);
		}

		co_return;
	}

	net::awaitable<bool> vpn_controller::connect()
	{
		boost::system::error_code ec;

		// 解析 controller URI.
		auto result = boost::urls::parse_uri(m_config.controller_);
		if (!result)
		{
			XLOG_ERR << "Invalid controller URI: " << m_config.controller_
				<< ", error: " << result.error().message();
			co_return false;
		}

		auto url = result.value();
		if (url.scheme() != "ws")
		{
			XLOG_ERR << "Unsupported URI scheme: " << std::string(url.scheme())
				<< ", only 'ws' is supported.";
			co_return false;
		}

		std::string host = url.host();
		std::string port = url.port();
		if (port.empty())
			port = "80";

		// 握手目标: 路径 + 查询参数 (如 /rpc?instance=..&token=..).
		// pct_string_view 不能隐式转 std::string, 按 data/size 显式构造.
		auto enc_path = url.encoded_path();
		auto enc_query = url.encoded_query();
		std::string target(enc_path.data(), enc_path.size());
		if (target.empty())
			target = "/";
		if (!enc_query.empty())
			target += "?" + std::string(enc_query.data(), enc_query.size());

		auto executor = co_await net::this_coro::executor;
		tcp::resolver resolver(executor);
		auto results = co_await resolver.async_resolve(host, port, net_awaitable[ec]);
		if (ec)
		{
			XLOG_WARN << "Failed to resolve controller " << m_config.controller_
				<< ", error: " << ec.message();
			co_return false;
		}

		auto ws_stream = ws(executor);

		co_await net::async_connect(
			beast::get_lowest_layer(ws_stream), results, net_awaitable[ec]);
		if (ec)
		{
			XLOG_WARN << "Failed to connect to controller " << m_config.controller_
				<< ", error: " << ec.message();
			co_return false;
		}

		std::string origin = "all";

		using beast::websocket::stream_base;
		auto decorator = [origin](beast::websocket::request_type& m) {
			m.insert(beast::http::field::origin, origin);
			};

		ws_stream.set_option(stream_base::decorator(decorator));

		co_await ws_stream.async_handshake(host, target, net_awaitable[ec]);
		if (ec)
		{
			XLOG_WARN << "WebSocket handshake failed with controller " << m_config.controller_
				<< ", error: " << ec.message();
			beast::get_lowest_layer(ws_stream).close(ec);
			co_return false;
		}

		ws_stream.binary(true);
		ws_stream.read_message_max(16 * 1024 * 1024);

		m_session = std::make_unique<jsonrpc::jsonrpc_session<ws>>(std::move(ws_stream));
		m_session_closed = false;

		XLOG_DBG << "Controller connected: " << m_config.controller_;
		co_return true;
	}

	net::awaitable<void> vpn_controller::serve()
	{
		auto sess = m_session.get();
		if (!sess)
			co_return;

		// 响应 launcher 下发的请求.
		sess->bind_method("get_status",
			[this](json::object) -> json::object
			{
				return status_report();
			});

		sess->bind_method("shutdown",
			[this](json::object) -> json::object
			{
				// 延迟退出: 先让本请求的响应帧写出, launcher 才能收到确认.
				auto service = m_service;
				net::co_spawn(m_main_context.get_executor(),
					[service]() -> net::awaitable<void>
					{
						auto ex = co_await net::this_coro::executor;
						net::steady_timer t(ex);
						t.expires_after(std::chrono::milliseconds(200));
						boost::system::error_code sec;
						co_await t.async_wait(net_awaitable[sec]);
						if (auto svc = service.lock())
							svc->stop();
					}, net::detached);
				return json::object{};
			});

		sess->closed_callback([this]() { m_session_closed = true; });

		// 先启动读循环, 再发送通知; 否则会话尚未进入运行态,
		// 入队的写消息可能无法发出.
		sess->start();

		// 注册实例信息.
		send_register();
		// 立即上报一次状态.
		send_status();

		// 状态上报循环: 连接断开或 stop 时退出.
		auto ex = co_await net::this_coro::executor;
		net::steady_timer timer(ex);
		boost::system::error_code sec;
		while (!m_abort && !m_session_closed)
		{
			timer.expires_after(k_status_interval);
			co_await timer.async_wait(net_awaitable[sec]);
			if (m_abort || m_session_closed)
				break;
			send_status();
		}

		// 清理: 关闭会话, 断开连接.
		m_session->stop();
		if (m_session->stream().is_open())
		{
			m_session->stream().next_layer().close(sec);
		}
		m_session.reset();

		co_return;
	}

	void vpn_controller::send_register()
	{
		if (!m_session)
			return;

		json::object reg;
#ifdef _WIN32
		reg["pid"] = static_cast<int64_t>(::_getpid());
#else
		reg["pid"] = static_cast<int64_t>(::getpid());
#endif
#ifdef VERSION_GIT
		reg["version"] = std::string(VERSION_GIT);
#endif
		reg["started_at"] = static_cast<int64_t>(std::time(nullptr));
		m_session->notify("register", reg);
	}

	void vpn_controller::send_status()
	{
		if (!m_session)
			return;
		m_session->notify("status", status_report());
	}

	boost::json::object vpn_controller::status_report() const
	{
		if (auto svc = m_service.lock())
			return svc->status_json();
		json::object rep;
		rep["ts"] = static_cast<int64_t>(std::time(nullptr));
		return rep;
	}

} // namespace libavpn
