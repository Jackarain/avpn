//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#include "avpn/vpn_controller.hpp"
#include "utils/logging.hpp"
#include "utils/scoped_exit.hpp"

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

	using namespace boost::asio;
	namespace beast = boost::beast;

	vpn_controller::vpn_controller(io_context_pool& ioc_pool, const service_config& cfg)
		: m_ioc_pool(ioc_pool)
		, m_main_context(ioc_pool.main_io_context())
		, m_signal(m_main_context)
		, m_config(cfg)
		, m_avpn_service(make_avpn_service(ioc_pool, cfg))
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

		m_signal.async_wait([this](const boost::system::error_code&, int) mutable
			{
				LOG_DBG << "terminator is called!";
				stop();
			});

		net::co_spawn(m_main_context.get_executor(),
			[this]() mutable -> net::awaitable<void>
			{
				co_await start_connect();
				LOG_DBG << "controller quit...";
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
		m_ioc_pool.stop();
	}

	net::awaitable<void> vpn_controller::start_connect()
	{
		boost::system::error_code ec;

		// 构造控制服务器的endpoint.
		tcp::endpoint endp;
		make_listen_endpoint(m_config.controller_, endp, ec);
		tcp::socket& sock = beast::get_lowest_layer(m_ws_stream).socket();

		// 连接到服务器.
		co_await sock.async_connect(endp, uawaitable[ec]);
		if (ec)
		{
			LOG_ERR << "controller::start_connect, async_connect: " << ec.message();

			// 全部退出.
			m_ioc_pool.stop();
			co_return;
		}

		LOG_DBG << "controller::start_connect, connect successfully!";

		std::string origin = "all";
		auto decorator = [origin](beast::websocket::request_type& m) {
			m.insert(beast::http::field::origin, origin);
		};

		m_ws_stream.set_option(beast::websocket::stream_base::decorator(decorator));
		co_await m_ws_stream.async_handshake(controller_server_host, "/", uawaitable[ec]);
		if (ec)
		{
			LOG_ERR << "controller::start_connect, async_handshake: " << ec.message();

			// 全部退出.
			m_ioc_pool.stop();
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
		bool exit = false;

		while (!m_abort || exit)
		{
			auto bytes = co_await m_ws_stream.async_read(buffer, uawaitable[ec]);
			if (ec == beast::websocket::error::closed)
			{
				LOG_DBG << "controller::start_client_read, vpn was closed";
				break;
			}

			if (ec)
			{
				LOG_ERR << "start_client_read, async_read error: " << ec.message();
				break;
			}

			buffer.commit(bytes);
			scoped_exit se([&buffer]() mutable { buffer.consume(buffer.size()); });
			const char* bufptr = net::buffer_cast<const char*>(buffer.data());

			// 简单的控制协议, 前面由一个数字表示命令id, 空白字符隔开, 后面为内容.
			// 正则表达式如：(\d+)\ +(.*)$
			std::regex ctrl_regex(R"(^(\d+)\s*(.*)$)");
			std::cmatch match;

			if (!std::regex_match(bufptr, match, ctrl_regex))
			{
				LOG_WARN << "start_client_read, regex match faild: " << std::string_view(bufptr, bytes);
				continue;
			}

			auto type = controller_type(atoi(match[1].str().c_str()));

			switch (type)
			{
			case controller_type::ct_stop:
				if (!m_start)
				{
					LOG_DBG << "start_client_read, do vpn already stoped";
					break;
				}
				LOG_DBG << "start_client_read, do vpn stop";
				m_service.stop();
				m_start = false;
				break;
			case controller_type::ct_start:
				if (m_start)
				{
					LOG_WARN << "start_client_read, do vpn already started";
					break;
				}
				LOG_DBG << "start_client_read, do vpn start";
				m_service.start();
				m_start = true;
				break;
			case controller_type::ct_speed:
				if (!m_start)
					break;
				LOG_DBG << "start_client_read, do vpn speed: "
					<< m_service.upload_rate() << ", " << m_service.download_rate();
				{
					auto str = std::to_string((int)type) + " "
						+ std::to_string(m_service.upload_rate())
						+ " "
						+ std::to_string(m_service.download_rate());

					co_await m_ws_stream.async_write(net::buffer(str), uawaitable[ec]);
					if (ec)
					{
						LOG_ERR << "start_client_read, ct_speed async_write error: " << ec.message();
						exit = true;
					}
				}
				break;
			case controller_type::ct_remote:
			case controller_type::ct_test:
				break;
			default:
				break;
			}
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
			co_await m_timer.async_wait(uawaitable[ec]);
			if (ec)
				co_return;

			if (++m_keepalive_cnt >= 5)
				break;

			co_await m_ws_stream.async_ping("", uawaitable[ec]);
			if (ec)
				co_return;
		}

		if (m_ws_stream.next_layer().socket().is_open())
			m_ws_stream.next_layer().socket().close(ec);

		co_return;
	}

}
