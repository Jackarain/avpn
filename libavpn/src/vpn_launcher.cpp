//
// vpn_launcher.cpp
// ~~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2023 Jack (jack dot wgm at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// 控制通道实现: 由 avpn_service 在配置了 launcher 地址时创建, 主动连接到
// launcher 的 /rpc WebSocket 控制通道, 上报注册信息与运行状态, 并响应
// launcher 下发的 shutdown / get_status 请求.
//

#include "libavpn/vpn_launcher.hpp"
#include "libavpn/launcher_log.hpp"
#include "libavpn/logging.hpp"
#include "libavpn/asio_util.hpp"
#include "libavpn/avpn_protocol.hpp"

#include <boost/url.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#if defined(OPENSSL_VERSION_NUMBER)
#	include <openssl/ssl.h>
#endif

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

	vpn_launcher::vpn_launcher(io_context_pool& ioc_pool,
		const service_config& config, std::weak_ptr<avpn_service> service)
		: m_ioc_pool(ioc_pool)
		, m_main_context(ioc_pool.main_io_context())
		, m_config(config)
		, m_service(std::move(service))
	{
	}

	void vpn_launcher::start()
	{
		if (m_abort)
			return;

		// 启用日志采集: logger_tag 钩子收集日志, 由控制通道上报时批量发送.
		detail::launcher_log_set_enabled(true);

		// 协程闭包持有 shared_from_this: service 的 stop() 会 reset 本对象,
		// 但 worker/serve 协程运行期间仍由该引用保活, 协程结束后再析构.
		net::co_spawn(m_main_context.get_executor(),
			[self = shared_from_this()]() mutable -> net::awaitable<void>
			{
				co_await self->worker();
				co_return;
			}, net::detached);
	}

	void vpn_launcher::stop()
	{
		if (m_abort)
			return;

		// 停止日志采集.
		detail::launcher_log_set_enabled(false);

		m_abort = true;

		boost::system::error_code ec;

		std::visit([&ec, this](auto& sess)
			{
				if (!sess)
					return;
				// 让 jsonrpc 会话停止: 取消挂起的 RPC 调用、异步发送 close 帧.
				sess->stop();
				// 直接关闭底层 TCP 连接: 同步 ws.close() 会等待对端 close 帧
				// 完成关闭握手, 而对端 (launcher) 可能在 stop_proc 阻塞期间
				// 无法响应, 导致本线程被拖住数秒 (最坏直到 SIGKILL). 直接关闭
				// socket 即可让对端读循环以 EOF/错误正常退出.
				auto& ws_stream = sess->stream();
				beast::get_lowest_layer(ws_stream).close(ec);
			}, m_session);

		asio_util::cancel(m_timer, ec);
	}

	net::awaitable<void> vpn_launcher::worker()
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

	net::awaitable<bool> vpn_launcher::connect()
	{
		boost::system::error_code ec;

		// 解析 launcher URI.
		auto result = boost::urls::parse_uri(m_config.launcher_);
		if (!result)
		{
			XLOG_ERR << "Invalid launcher URI: " << m_config.launcher_
				<< ", error: " << result.error().message();
			co_return false;
		}

		auto url = result.value();
		std::string scheme = url.scheme();
		if (scheme != "ws" && scheme != "wss")
		{
			XLOG_ERR << "Unsupported URI scheme: " << scheme
				<< ", only 'ws' and 'wss' are supported.";
			co_return false;
		}

		std::string host = url.host();
		std::string port = url.port();
		if (port.empty())
			port = scheme == "wss" ? "443" : "80";

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
			XLOG_WARN << "Failed to resolve launcher " << m_config.launcher_
				<< ", error: " << ec.message();
			co_return false;
		}

		std::string origin = "all";

		using beast::websocket::stream_base;
		auto decorator = [origin](beast::websocket::request_type& m) {
			m.insert(beast::http::field::origin, origin);
			};

		if (scheme == "wss")
		{
			if (!m_ssl_ctx)
				m_ssl_ctx = std::make_unique<net::ssl::context>(net::ssl::context::tls_client);

			auto ws_stream = wss(executor, *m_ssl_ctx);

			co_await net::async_connect(
				beast::get_lowest_layer(ws_stream), results, net_awaitable[ec]);
			if (ec)
			{
				XLOG_WARN << "Failed to connect to launcher " << m_config.launcher_
					<< ", error: " << ec.message();
				co_return false;
			}

			// TLS 握手. 证书不做校验: 控制通道凭 URL 信任端点, 便于自签名证书部署.
			auto& ssl_stream = ws_stream.next_layer();
			ssl_stream.set_verify_mode(net::ssl::verify_none, ec);
			if (ec)
			{
				XLOG_WARN << "TLS setup failed with launcher " << m_config.launcher_
					<< ", error: " << ec.message();
				beast::get_lowest_layer(ws_stream).close(ec);
				co_return false;
			}

			// 仅主机名需要设置 SNI, IP 地址不设置.
			boost::system::error_code addr_ec;
			(void)net::ip::make_address(host, addr_ec);
			if (addr_ec)
			{
#if defined(OPENSSL_VERSION_NUMBER)
				if (::SSL_set_tlsext_host_name(
						ssl_stream.native_handle(), host.c_str()) != 1)
					XLOG_WARN << "Failed to set TLS SNI for launcher: " << host;
#endif
			}

			co_await ssl_stream.async_handshake(
				net::ssl::stream_base::client, net_awaitable[ec]);
			if (ec)
			{
				XLOG_WARN << "TLS handshake failed with launcher " << m_config.launcher_
					<< ", error: " << ec.message();
				beast::get_lowest_layer(ws_stream).close(ec);
				co_return false;
			}

			ws_stream.set_option(stream_base::decorator(decorator));

			co_await ws_stream.async_handshake(host, target, net_awaitable[ec]);
			if (ec)
			{
				XLOG_WARN << "WebSocket handshake failed with launcher " << m_config.launcher_
					<< ", error: " << ec.message();
				beast::get_lowest_layer(ws_stream).close(ec);
				co_return false;
			}

			ws_stream.binary(true);
			ws_stream.read_message_max(16 * 1024 * 1024);

			m_session.emplace<1>(
				std::make_unique<jsonrpc::jsonrpc_session<wss>>(std::move(ws_stream)));
			m_session_closed = false;

			XLOG_DBG << "Launcher connected: " << m_config.launcher_;
			co_return true;
		}

		auto ws_stream = ws(executor);

		co_await net::async_connect(
			beast::get_lowest_layer(ws_stream), results, net_awaitable[ec]);
		if (ec)
		{
			XLOG_WARN << "Failed to connect to launcher " << m_config.launcher_
				<< ", error: " << ec.message();
			co_return false;
		}

		ws_stream.set_option(stream_base::decorator(decorator));

		co_await ws_stream.async_handshake(host, target, net_awaitable[ec]);
		if (ec)
		{
			XLOG_WARN << "WebSocket handshake failed with launcher " << m_config.launcher_
				<< ", error: " << ec.message();
			beast::get_lowest_layer(ws_stream).close(ec);
			co_return false;
		}

		ws_stream.binary(true);
		ws_stream.read_message_max(16 * 1024 * 1024);

		m_session.emplace<0>(
			std::make_unique<jsonrpc::jsonrpc_session<ws>>(std::move(ws_stream)));
		m_session_closed = false;

		XLOG_DBG << "Launcher connected: " << m_config.launcher_;
		co_return true;
	}

	net::awaitable<void> vpn_launcher::serve()
	{
		co_await std::visit([this](auto& sess) -> net::awaitable<void>
			{
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

				// 动态修改运行参数 (如 keepalive 热更新, 其余字段自动重启生效).
				sess->bind_method("update_config",
					[this](json::object req) -> json::object
					{
						json::object result;
						result["ok"] = false;
						auto service = m_service.lock();
						if (!service)
						{
							result["error"] = "service not running";
							return result;
						}
						// 请求参数位于 jsonrpc 请求的 params 字段.
						json::object params;
						if (auto it = req.find("params");
							it != req.end() && it->value().is_object())
							params = it->value().as_object();
						int rc = service->update_config(params);
						if (rc < 0)
						{
							result["error"] = "invalid config or service not running";
							return result;
						}
						result["ok"] = true;
						result["restarting"] = rc > 0;
						return result;
					});

				// 注入外部 tun fd (Android VpnService 建立后).
				sess->bind_method("set_tun_fd",
					[this](json::object req) -> json::object
					{
						json::object result;
						result["ok"] = false;
						auto service = m_service.lock();
						if (!service)
						{
							result["error"] = "service not running";
							return result;
						}
						// 请求参数位于 jsonrpc 请求的 params 字段.
						json::object params;
						if (auto it = req.find("params");
							it != req.end() && it->value().is_object())
							params = it->value().as_object();
						auto it = params.find("ptun_fd");
						if (it == params.end() || !it->value().is_int64())
						{
							result["error"] = "invalid ptun_fd";
							return result;
						}
						int fd = static_cast<int>(it->value().as_int64());
						if (!service->set_tun_fd(fd))
						{
							result["error"] = "set tun fd failed";
							return result;
						}
						result["ok"] = true;
						return result;
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
				sess->stop();
				if (beast::get_lowest_layer(sess->stream()).is_open())
				{
					beast::get_lowest_layer(sess->stream()).close(sec);
				}
				m_session = decltype(m_session){};
				co_return;
			}, m_session);

		co_return;
	}

	net::awaitable<bool> vpn_launcher::call_protect(int fd)
	{
		co_return co_await std::visit(
			[fd](auto& sess) -> net::awaitable<bool>
			{
				if (!sess)
					co_return true;

				json::object params;
				params["fd"] = fd;
				try
				{
					auto result = co_await sess->async_call("protect", params);
					if (result.contains("ok"))
						co_return result["ok"].as_bool();
				}
				catch (...)
				{
					// 控制通道异常时放行, 避免阻塞握手/连接.
					XLOG_WARN << "protect rpc failed, allow socket";
				}
				co_return true;
			}, m_session);
	}

	void vpn_launcher::notify(std::string_view method,
		const boost::json::value& params)
	{
		std::visit([method, &params](auto& sess)
			{
				if (sess)
					sess->notify(method, params);
			}, m_session);
	}

	void vpn_launcher::send_register()
	{
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
		std::visit([&reg](auto& sess)
			{
				if (sess)
					sess->notify("register", reg);
			}, m_session);
	}

	void vpn_launcher::send_status()
	{
		std::visit([this](auto& sess)
			{
				if (!sess)
					return;
				sess->notify("status", status_report());

				// 批量转发经 logger_tag 钩子采集的日志 (逐条 notify 开销大).
				auto lines = detail::launcher_log_drain();
				if (!lines.empty())
				{
					json::array arr;
					for (auto& l : lines)
						arr.emplace_back(std::move(l));
					json::object log;
					log["lines"] = std::move(arr);
					sess->notify("log", log);
				}
			}, m_session);
	}

	boost::json::object vpn_launcher::status_report() const
	{
		if (auto svc = m_service.lock())
			return svc->status_json();
		json::object rep;
		rep["ts"] = static_cast<int64_t>(std::time(nullptr));
		return rep;
	}

} // namespace libavpn
