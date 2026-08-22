//
// Copyright (C) 2025 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#ifndef INCLUDE__2025_11_22__VPN_LAUNCHER_HPP
#define INCLUDE__2025_11_22__VPN_LAUNCHER_HPP

#include "libavpn/io_context_pool.hpp"
#include "libavpn/use_awaitable.hpp"
#include "libavpn/avpn.hpp"
#include "libavpn/jsonrpc.hpp"

#include <boost/asio/io_context.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast/websocket/ssl.hpp>

#include <memory>
#include <variant>

namespace libavpn {

	namespace beast = boost::beast;
	namespace net = boost::asio;


	class vpn_launcher
		: public std::enable_shared_from_this<vpn_launcher>
	{
		vpn_launcher(const vpn_launcher&) = delete;
		vpn_launcher& operator=(const vpn_launcher&) = delete;

	public:
		vpn_launcher(io_context_pool& ioc_pool, const service_config& config,
			std::weak_ptr<avpn_service> service);
		~vpn_launcher() = default;

	public:
		void start();
		void stop();

		// 经控制通道请求 app 对 socket 执行 protect (Android VpnService),
		// 无会话时视为放行. 须在 io_context 协程中调用.
		net::awaitable<bool> call_protect(int fd);

		// 经控制通道发送通知 (如 vaddr 下发).
		void notify(std::string_view method, const boost::json::value& params);

	private:
		// 连接重试主循环: 连接 → 服务 → 断开后按退避重连.
		net::awaitable<void> worker();

		// 连接并握手, 成功返回 true.
		net::awaitable<bool> connect();

		// 在已建立的会话上运行: 注册实例、状态上报循环、处理请求.
		// 连接断开或 stop 时返回.
		net::awaitable<void> serve();

		// 上报实例注册信息与状态.
		void send_register();
		void send_status();

		// 采集状态快照.
		boost::json::object status_report() const;

	private:
		io_context_pool& m_ioc_pool;
		net::io_context& m_main_context;

		service_config m_config;
		// 被控制的 avpn 服务 (状态快照来源).
		std::weak_ptr<avpn_service> m_service;

		// 控制通道 WebSocket 流: ws 明文, wss 走 TLS.
		using ws = beast::websocket::stream<net::ip::tcp::socket>;
		using wss = beast::websocket::stream<net::ssl::stream<net::ip::tcp::socket>>;
		std::variant<std::unique_ptr<jsonrpc::jsonrpc_session<ws>>,
			std::unique_ptr<jsonrpc::jsonrpc_session<wss>>> m_session;

		// wss 连接使用的 TLS 上下文 (须存活于整个会话生命周期).
		std::unique_ptr<net::ssl::context> m_ssl_ctx;

		net::steady_timer m_timer{ m_ioc_pool.main_io_context() };

		// 会话是否已关闭 (由 closed_callback 置位).
		std::atomic_bool m_session_closed{ false };

		std::atomic_bool m_abort{ false };
	};

} // namespace libavpn

#endif // INCLUDE__2025_11_22__VPN_LAUNCHER_HPP
