//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#include "avpn/vpn_controller.hpp"
#include "utils/logging.hpp"
#include "utils/scoped_exit.hpp"
#include "avpn/avpn.hpp"

#if defined(__cpp_lib_format)
#	include <format>
#endif

#if !defined(__cpp_lib_format)
#ifdef _MSC_VER
#	pragma warning(push)
#	pragma warning(disable: 4244 4127)
#endif // _MSC_VER

#ifdef __clang__
#	pragma clang diagnostic push
#	pragma clang diagnostic ignored "-Wexpansion-to-defined"
#endif

#include <fmt/ostream.h>
#include <fmt/printf.h>
#include <fmt/format.h>

namespace std {
	using ::fmt::format;
	using ::fmt::format_to;
	using ::fmt::vformat;
	using ::fmt::vformat_to;
	using ::fmt::make_format_args;
}

#ifdef __clang__
#	pragma clang diagnostic pop
#endif

#ifdef _MSC_VER
#	pragma warning(pop)
#endif
#endif

#include <boost/json/src.hpp>

#include <iterator>
#include <string>
#include <regex>

namespace avpn {
	static std::string controller_server_host = "127.0.0.1";

	enum class controller_type
	{
		ct_start = 0,
		ct_stop = 1,

		ct_speed = 2,
		ct_remote = 3,
		ct_test = 4,
	};

	vpn_controller::vpn_controller(
		net::io_context& ioc, const service_config& cfg)
		: m_main_context(ioc)
		, m_signal(m_main_context)
		, m_avpn_config(std::make_unique<service_config>(cfg))
		, m_config(*m_avpn_config)
		, m_avpn_service(avpn_service::make_avpn_service(ioc, cfg))
		, m_service(*m_avpn_service)
		, m_ws_stream(m_main_context)
		, m_timer(m_main_context)
	{}

	void vpn_controller::start()
	{
		m_signal.add(SIGINT);
		m_signal.add(SIGTERM);
#if defined(SIGQUIT)
		m_signal.add(SIGQUIT);
#endif // defined(SIGQUIT)

		m_signal.async_wait(
			[this](const boost::system::error_code&, int) mutable
			{
				XLOG_DBG << "terminator is called!";
				stop();
			});

		net::co_spawn(m_main_context.get_executor(),
			[this]() mutable -> net::awaitable<void>
			{
				co_await start_connect();
				XLOG_DBG << "controller quit...";
				co_return;
			}, net::detached);
	}

	void vpn_controller::stop()
	{
		if (m_abort)
			return;

		m_abort = true;
		m_start = false;

		boost::system::error_code ec;
		m_ws_stream.close(beast::websocket::close_code::none, ec);
		m_ws_stream.next_layer().socket().close(ec);
		m_signal.cancel(ec);
		m_timer.cancel(ec);

		m_service.stop();
		m_main_context.stop();
	}

	net::awaitable<void> vpn_controller::start_connect()
	{
		boost::system::error_code ec;
		std::string real_contorller;

		// 构造控制服务器的endpoint.
		tcp::endpoint endp;
		make_listen_endpoint(m_config.controller_, endp, ec);
		if (ec)
		{
			real_contorller = controller_server_host +
				":" + m_config.controller_;
			make_listen_endpoint(real_contorller, endp, ec);
		}
		tcp::socket& sock = beast::get_lowest_layer(m_ws_stream).socket();

		// 连接到服务器.
		co_await sock.async_connect(endp, net_awaitable[ec]);
		if (ec)
		{
			XLOG_ERR << "controller::start_connect"
				<< ", connect: " << m_config.controller_
				<< ", error: " << ec.message();

			// 全部退出.
			m_main_context.stop();
			co_return;
		}

		XLOG_DBG << "controller::start_connect"
			<< ", connect " << real_contorller
			<< " successfully!";

		std::string origin = "all";

		using beast::websocket::stream_base;
		auto decorator = [origin](beast::websocket::request_type& m) {
			m.insert(beast::http::field::origin, origin);
		};

		m_ws_stream.set_option(stream_base::decorator(decorator));
		co_await m_ws_stream.async_handshake(
			controller_server_host, "/", net_awaitable[ec]);
		if (ec)
		{
			XLOG_ERR << "controller::start_connect"
				", handshake: " << ec.message();

			// 全部退出.
			m_main_context.stop();
			co_return;
		}

		tcp::no_delay option(true);
		sock.set_option(option);

		// 设置为非2进制模式.
		m_ws_stream.binary(false);

		m_ws_stream.control_callback([this]
		(beast::websocket::frame_type ft, beast::string_view)
		{
			if (ft == beast::websocket::frame_type::pong)
			{
				if (m_abort)
					return;

				m_keepalive_cnt = 0;
			}
		});

		// 开启keepalive协程.
		net::co_spawn(m_main_context.get_executor(),
			keepalive(), net::detached);

		// 发起消息读取协程.
		net::co_spawn(m_main_context.get_executor(),
			start_client_read(), net::detached);

		co_return;
	}

	net::awaitable<void> vpn_controller::start_client_read()
	{
		boost::system::error_code ec;
		std::vector<char> data;
		net::dynamic_vector_buffer buffer{ data };
		auto& stream = m_ws_stream;

		while (!m_abort)
		{
			auto bytes = co_await stream.async_read(buffer, net_awaitable[ec]);
			if (ec == beast::websocket::error::closed)
			{
				XLOG_DBG << "controller::start_client_read, vpn was closed";
				break;
			}

			if (ec)
			{
				XLOG_ERR << "start_client_read, read error: " << ec.message();
				break;
			}

			buffer.commit(bytes);
			scoped_exit se([&buffer]() mutable {
					buffer.consume(buffer.size());
				});
			const char* bufptr = net::buffer_cast<const char*>(buffer.data());

			// 简单的控制协议, 前面由一个数字表示命令id, 空白字符隔开, 后面为内容.
			// 正则表达式如：(\d+)\ +(.*)$
			std::regex ctrl_regex(R"(^(\d+)\s*(.*)$)");
			std::cmatch match;

			if (!std::regex_match(bufptr, match, ctrl_regex))
			{
				auto sv = std::string_view(bufptr, bytes);
				auto ret = co_await on_json_rpc(sv);

				if (!ret)
				{
					XLOG_WARN << "start_client_read, regex match faild: "
						<< std::string_view(bufptr, bytes);
					break;
				}

				continue;
			}

			if (!co_await on_legacy_rpc(match[1].str()))
				break;
		}

		// 一旦ws退出, 则退出整个程序.
		stop();

		co_return;
	}

	net::awaitable<void> vpn_controller::keepalive()
	{
		boost::system::error_code ec;

		while (!m_abort)
		{
			m_timer.expires_from_now(std::chrono::milliseconds(1000));
			co_await m_timer.async_wait(net_awaitable[ec]);
			if (ec)
				co_return;

			if (++m_keepalive_cnt >= 5)
				break;

			co_await m_ws_stream.async_ping("", net_awaitable[ec]);
			if (ec)
				co_return;
		}

		if (m_ws_stream.next_layer().socket().is_open())
			m_ws_stream.next_layer().socket().close(ec);

		co_return;
	}

	net::awaitable<bool> vpn_controller::on_legacy_rpc(std::string_view sv)
	{
		boost::system::error_code ec;
		auto type = controller_type(atoi(sv.data()));

		switch (type)
		{
		case controller_type::ct_stop:
			if (!m_start)
			{
				XLOG_DBG << "start_client_read, do vpn already stoped";
				break;
			}
			XLOG_DBG << "start_client_read, do vpn stop";
			m_service.stop();
			m_start = false;
			break;
		case controller_type::ct_start:
			if (m_start)
			{
				XLOG_WARN << "start_client_read, do vpn already started";
				break;
			}
			XLOG_DBG << "start_client_read, do vpn start";
			m_service.start();
			m_start = true;
			break;
		case controller_type::ct_speed:
			if (!m_start)
				break;
			XLOG_DBG << "start_client_read, "
				<< "do vpn speed: " << m_service.upload_rate()
				<< ", " << m_service.download_rate();
			{
				auto str = std::to_string((int)type) + " "
					+ std::to_string(m_service.upload_rate())
					+ " "
					+ std::to_string(m_service.download_rate());

				co_await m_ws_stream.async_write(
					net::buffer(str), net_awaitable[ec]);
				if (ec)
				{
					XLOG_ERR << "start_client_read, "
						<< "ct_speed async_write error: " << ec.message();
					co_return false;
				}
			}
			break;
		case controller_type::ct_remote:
		case controller_type::ct_test:
			break;
		default:
			break;
		}

		co_return true;
	}

	net::awaitable<bool> vpn_controller::on_json_rpc(std::string_view sv)
	{
		boost::system::error_code ec;
		auto jv = boost::json::parse(sv, ec);
		if (ec)
			co_return false;

		try
		{
			auto& content = jv.as_object();
			std::string_view version = content["jsonrpc"].as_string();
			if (version != "2.0")
				co_return false;

			std::string_view method = content["method"].as_string();
			int64_t id = content["id"].as_int64();

			if (method == "stop")
			{
				std::string result = std::format(
					R"({{"jsonrpc":"2.0", "id": {}, "result": {}}})",
					id,
					"completed");

				co_await m_ws_stream.async_write(
					net::buffer(result), net::use_awaitable);

				if (!m_start)
				{
					XLOG_DBG << "on_json_rpc, do vpn already stoped";
					co_return true;
				}

				XLOG_DBG << "on_json_rpc, do vpn stop";
				m_service.stop();
				m_start = false;

				co_return true;
			}

			if (method == "start")
			{
				std::string result = std::format(
					R"({{"jsonrpc":"2.0", "id": {}, "result": {}}})",
					id,
					"completed");

				co_await m_ws_stream.async_write(
					net::buffer(result), net::use_awaitable);

				if (m_start)
				{
					XLOG_WARN << "on_json_rpc, do vpn already started";
					co_return true;
				}

				XLOG_DBG << "on_json_rpc, do vpn start";
				m_service.start();
				m_start = true;
			}

			if (method == "method")
			{
				auto urate = m_service.upload_rate();
				auto drate = m_service.download_rate();

				if (!m_start)
				{
					urate = 0;
					drate = 0;
				}

				XLOG_DBG << "on_json_rpc, "
					<< "do vpn speed, upload: " << urate
					<< ", download: " << drate;

				std::string result = std::format(
					R"({{"jsonrpc":"2.0", "id": {}, "result": [{}, {}]}})",
					id, urate, drate);

				co_await m_ws_stream.async_write(
					net::buffer(result), net::use_awaitable);

				co_return true;
			}
		}
		catch (const std::exception& e)
		{
			XLOG_DBG << "jsonrpc exception: " << e.what();
		}

		co_return false;
	}

}
