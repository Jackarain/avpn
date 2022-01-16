#include "dchs/dchs.hpp"
#include "dchs/mainnet_genesis_block.hpp"
#include "dchs/async_connect.hpp"
#include "dchs/url_parser.hpp"
#include "dchs/scoped_exit.hpp"
#include "dchs/simple_http.hpp"
#include "dchs/multipart.hpp"
#include "dchs/fileop.hpp"
#include "dchs/version.hpp"

#include "vpncore/endpoint_pair.hpp"

#include <chrono>
#include <iomanip>

#include <boost/json.hpp>
#include <boost/date_time.hpp>

#include <boost/regex.hpp>


#ifdef __clang__
#	pragma clang diagnostic push
#	pragma clang diagnostic ignored "-Wexpansion-to-defined"
#endif

#include <fmt/ostream.h>
#include <fmt/printf.h>
#include <fmt/format.h>

#ifdef __clang__
#	pragma clang diagnostic pop
#endif


namespace dchs {
	using namespace std::chrono_literals;

	dchs_service::dchs_service(io_context_pool& ios, const server_config& config)
		: m_io_context_pool(ios)
		, m_io_context(m_io_context_pool.server_io_context())
		, m_config(config)
		, m_tuntap(m_io_context)
		, m_tuntap_timer(m_io_context)
		, m_channel(m_io_context)
	{
		avpn::dev_config dc = { "10.0.0.1", "255.255.0.0", "10.0.0.0" };
		dc.dev_name_ = config.ifdev_;
		auto dev_list = m_tuntap.take_device_list();
		std::string guid;
		for (auto& i : dev_list)
		{
			if (i.name_ == dc.dev_name_)
			{
				dc.guid_ = i.guid_;
				break;
			}
		}

#ifdef AVPN_LINUX
		dc.dev_name_ = "";
		dc.guid_ = "";
		dc.dev_type_ = avpn::dev_tun;
		dc.tun_fd_ = -1;
#else
		dc.dev_type_ = avpn::dev_tun;
#endif

		if (!m_tuntap.open(dc))
		{
			LOG_ERR << "open tun device: " << dc.dev_name_ << " fail!";
			return;
		}

	}

	dchs_service::~dchs_service()
	{
		LOG_DBG << "~dchs_service()";
	}

	void dchs_service::start()
	{
		init_ws_acceptors();

		int pool_size = static_cast<int>(m_io_context_pool.pool_size());
		for (int i = 0; i < pool_size; i++)
		{
			for (auto& a : m_ws_acceptors)
			{
				boost::asio::spawn(m_io_context_pool.get_io_context().get_executor(),
					[this, &a](boost::asio::yield_context yield) mutable {
						start_ws_listen(a, yield);
					});
			}
		}

		// 启动vpn设备io, 根据数据包中ip:port找到对应连接进行数据收发.
		// 如果是client, 则将从vpn设备io读取到的packet, 通过与server通信的通道
		// 发送, 同时server通信通道上的任何数据回复, 写回到vpn设备.
		// client端根据server回复的功能packet中指定的数据包标号, 进行
		// 数据lose重发, 同时根据功能包中标号进行清除释放cache.
		// 同时定期在通信通道上发送功能包到server, 以指示当前已知lose数据包及
		// last数据包.

		// 如果是server, 则将vpn设备io读取到的packet, 找到与client通信的通道,
		// 具体根据packet中的target, 找与之对应的client的虚拟ip匹配的通信通道.
		// 同时所有客户端通信通道中接收到的任何完整数据包, 将写入vpn设备io.
		// 定期在所有通道上发送功能数据包, 以指示当前接收到的last数据包, 及已知
		// 的lose数据包.
		// 同时server也将根据client发来的功能数据包, 进行重传lose数据包, 及清理
		// 释放cache.

		start_net();
	}

	void dchs_service::stop()
	{
		boost::system::error_code ignore_ec;
		m_abort = true;

		LOG_DBG << "close server listen...";
		for (auto& a : m_ws_acceptors)
			a.close(ignore_ec);

		LOG_DBG << "close all ws...";
		close_all_ws();

		LOG_DBG << "dchs_service.stop()";
	}

	bool dchs_service::init_ws_acceptors()
	{
		boost::system::error_code ec;

		for (const auto& wsd : m_config.ws_listens_)
		{
			tcp::endpoint endp;

			bool ipv6only = make_listen_endpoint(wsd, endp, ec);
			if (ec)
			{
				LOG_ERR << "WS server listen error: " << wsd << ", ec: " << ec.message();
				return false;
			}

			tcp::acceptor a{ m_io_context };

			a.open(endp.protocol(), ec);
			if (ec)
			{
				LOG_ERR << "WS server open accept error: " << ec.message();
				return false;
			}

			a.set_option(boost::asio::socket_base::reuse_address(true), ec);
			if (ec)
			{
				LOG_ERR << "WS server accept set option failed: " << ec.message();
				return false;
			}

#if __linux__
			if (ipv6only)
			{
				int on = 1;
				if (::setsockopt(a.native_handle(), IPPROTO_IPV6, IPV6_V6ONLY, (char*)&on, sizeof(on)) == -1)
				{
					LOG_ERR << "WS server setsockopt IPV6_V6ONLY";
					return false;
				}
			}
#else
			boost::ignore_unused(ipv6only);
#endif
			a.bind(endp, ec);
			if (ec)
			{
				LOG_ERR << "WS server bind failed: "
					<< ec.message() << ", address: " << endp.address().to_string() << ", port: " << endp.port();
				return false;
			}

			a.listen(boost::asio::socket_base::max_listen_connections, ec);
			if (ec)
			{
				LOG_ERR << "WS server listen failed: " << ec.message();
				return false;
			}

			m_ws_acceptors.emplace_back(std::move(a));
		}

		return true;
	}

	void dchs_service::start_ws_listen(tcp::acceptor& a, boost::asio::yield_context& yield)
	{
		boost::system::error_code error;
		while (!m_abort)
		{
			tcp::socket socket(m_io_context_pool.get_io_context());
			a.async_accept(socket, yield[error]);
			if (error)
			{
				LOG_ERR << "WS server, async_accept: " << error.message();

				if (error == boost::asio::error::operation_aborted ||
					error == boost::asio::error::bad_descriptor)
				{
					return;
				}

				if (!a.is_open())
					return;

				continue;
			}

			boost::asio::socket_base::keep_alive option(true);
			socket.set_option(option, error);

			boost::beast::tcp_stream stream(std::move(socket));

			static std::atomic_size_t id{ 0 };
			size_t connection_id = id++;

			boost::asio::spawn(m_io_context.get_executor(),
				[this, connection_id, stream = std::move(stream)](boost::asio::yield_context yield) mutable
			{
				start_ws_connect(connection_id, std::move(stream), yield);
			}, boost::coroutines::attributes(10 * 1024 * 1024));
		}

		LOG_DBG << "start_ws_listen exit...";
	}

	void dchs_service::start_ws_connect(size_t connection_id,
		boost::beast::tcp_stream stream, boost::asio::yield_context& yield)
	{
		using namespace boost::beast;
		const auto httpd_receive_buffer_size = 5 * 1024 * 1024;
		boost::system::error_code ec;
		boost::beast::flat_buffer buffer;
		bool keep_alive = false;
		buffer.reserve(httpd_receive_buffer_size);

		for (; !m_abort;)
		{
			request_parser parser;
			parser.body_limit(std::numeric_limits<uint64_t>::max());
			http::async_read_header(stream, buffer, parser, yield[ec]);
			if (ec)
			{
				LOG_DBG << "start_ws_connect, id: " << connection_id << ", async_read_header: " << ec.message();
				return;
			}

			if (parser.get()[http::field::expect] == "100-continue")
			{
				http::response<http::empty_body> res;
				res.version(11);
				res.result(http::status::continue_);
				http::async_write(stream, res, yield[ec]);
				if (ec)
				{
					LOG_DBG << "start_ws_connect, id: " << connection_id << ", expect async_write: " << ec.message();
					return;
				}
			}

			auto req = parser.release();

			std::string target = req.target().to_string();
			keep_alive = req.keep_alive();
			if (!beast::websocket::is_upgrade(req))
			{
				boost::beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(60));

				http_params params{ {}, connection_id, stream, req, parser, buffer, yield };
				boost::smatch what;

				#define BEGIN_HTTP_EVENT() if (false) {}
				#define ON_HTTP_EVENT(exp, func) \
				else if (boost::regex_match(target, what, boost::regex{ exp })) { \
					for (auto i = 1; i < static_cast<int>(what.size()); i++) \
						params.command_.emplace_back(what[i]); \
					func(params); \
				}
				#define END_HTTP_EVENT() else { \
					do_http_response(params, "Illegal request", http_status::bad_request ); }

				BEGIN_HTTP_EVENT()
					ON_HTTP_EVENT("^/getfile/(.*)$", on_getfile)
					ON_HTTP_EVENT("^/putfile/(.*)$", on_putfile)
					ON_HTTP_EVENT("^/version$", on_version)
					ON_HTTP_EVENT("^.*?$", on_http_root)
				END_HTTP_EVENT()

				if (!keep_alive) break;
				continue;
			}

			if (target != "/wsrpc")
			{
				if (!keep_alive) break;
				continue;
			}

			std::string remote_host;
			auto endp = stream.socket().remote_endpoint(ec);
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

			stream.expires_never();

			ws_stream ws{ std::move(stream) };
			ws.async_accept(req, yield[ec]);
			if (ec)
			{
				LOG_DBG << "start_ws_connect, " << connection_id << ", async_accept: " << ec.message();
				break;
			}

			// 获取executor.
			auto executor = ws.get_executor();

			// 设置为2进制模式.
			ws.binary(true);

			// 接收到pong, 重置超时定时器.
			ws.control_callback([this, connection_id](beast::websocket::frame_type ft, beast::string_view)
			{
				if (ft == boost::beast::websocket::frame_type::pong)
					ws_expires_after(connection_id, 60);
			});

			// 将连接加入到连接表.
			add_ws(connection_id, remote_host, std::move(ws));

			// 设置超时定时器.
			ws_expires_after(connection_id, 60);

			// 启动读写协程.
			boost::asio::spawn(executor,
				[this, connection_id](boost::asio::yield_context yield) mutable
				{
					do_ws_read(connection_id, yield);

					// 移除connection_id指定的ws.
					remove_ws(connection_id);
				}, boost::coroutines::attributes(20 * 1024 * 1024));

			boost::asio::spawn(executor,
				[this, connection_id](boost::asio::yield_context yield) mutable
				{
					do_ws_write(connection_id, yield);

					// 移除connection_id指定的ws.
					remove_ws(connection_id);
				});

			return;
		}
	}

	void dchs_service::do_ws_read(size_t connection_id, boost::asio::yield_context& yield)
	{
		auto connection_ptr = lookup_ws(connection_id);
		if (!connection_ptr)
			return;

		auto& ws = connection_ptr->ws_stream_;

		boost::beast::error_code ec;

		while (!m_abort)
		{
			boost::beast::multi_buffer buffer{ 4 * 1024 * 1024 }; // max multi_buffer size 4M.
			ws.async_read(buffer, yield[ec]);
			if (ec == websocket::error::closed)
			{
				LOG_DBG << "do_ws_read, id: " << connection_id << ", session was closed";
				break;
			}

			if (ec)
			{
				LOG_ERR << "do_ws_read, id: " << connection_id << ", async_read error: " << ec.message();
				break;
			}

			auto result = boost::beast::buffers_to_string(buffer.data());
			boost::ignore_unused(result);

			ws_expires_after(connection_id, 60);
		}
	}

	void dchs_service::do_ws_write(size_t connection_id, boost::asio::yield_context& yield)
	{
		boost::ignore_unused(connection_id);
		boost::ignore_unused(yield);
	}

	ws_connection_ptr dchs_service::lookup_ws(size_t connection_id)
	{
		std::lock_guard<std::mutex> lock(m_ws_mux);
		auto it = m_ws_streams.find(connection_id);
		if (it != m_ws_streams.end())
			return it->second;

		return {};
	}

	void dchs_service::remove_ws(size_t connection_id)
	{
		std::lock_guard<std::mutex> lock(m_ws_mux);
		m_ws_streams.erase(connection_id);
	}

	void dchs_service::add_ws(size_t connection_id, const std::string& remote_host, ws_stream&& ws)
	{
		std::lock_guard<std::mutex> lock(m_ws_mux);
		ws_connection_ptr connection_ptr =
			std::make_shared<ws_connection>(std::forward<ws_stream>(ws), connection_id, remote_host);
		m_ws_streams.emplace(connection_id, std::move(connection_ptr));
	}

	void dchs_service::close_all_ws()
	{
		boost::system::error_code ignore_ec;
		std::lock_guard<std::mutex> lock(m_ws_mux);
		for (auto& ws : m_ws_streams)
		{
			auto& conn_ptr = ws.second;
			if (!conn_ptr) continue;
			auto& conn = *conn_ptr;
			conn.ws_timer_.cancel(ignore_ec);
			conn.ws_stream_.next_layer().close();
		}
	}

	void dchs_service::ws_expires_after(size_t connection_id, int seconds)
	{
		auto wsp = lookup_ws(connection_id);
		if (!wsp)
			return;

		// 设置超时.
		auto& ws = wsp->ws_stream_;
		boost::beast::get_lowest_layer(ws).expires_after(std::chrono::seconds(seconds));
	}

	void dchs_service::on_http_root(const http_params& params)
	{
		auto& request = params.request_;
		auto& stream = params.stream_;
		auto& connection_id = params.connection_id_;
		auto& yield = params.yield_;

		boost::system::error_code ec;
		std::string target;
		unescape_path(request.target().to_string(), target);

		const static std::wstring head_fmt =
			LR"(<html><head><meta charset="UTF-8"><title>Index of {}</title></head><body bgcolor="white"><h1>Index of {}</h1><hr><pre>)";
		const static std::wstring tail_fmt =
			L"</pre><hr></body></html>";
		const static std::wstring body_fmt =
			L"<a href=\"{}\">{}</a>{}{}              {}\r\n";

		std::wstring body;
		if (!boost::ends_with(target, "/"))
			return on_getfile(params, target);

		std::wstring h = fmt::format(head_fmt,
			boost::nowide::widen(target), boost::nowide::widen(target));

		body += fmt::format(body_fmt, L"../", L"../", L"", L"", L"");
		boost::ireplace_first(target, "/", "");
		auto doc_path = boost::nowide::widen(m_config.doc_path_);
		auto path = std::filesystem::path{ doc_path } / boost::nowide::widen(target);
		std::filesystem::directory_iterator end;
		std::filesystem::directory_iterator it(path, ec);
		if (ec)
		{
			string_response res{ http_status::found, request.version() };
			res.set(boost::beast::http::field::server, HTTPD_VERSION_STRING);
			res.set(boost::beast::http::field::location, "/");
			res.keep_alive(request.keep_alive());
			res.prepare_payload();

			boost::beast::http::serializer<false, string_body, fields> sr{ res };
			boost::beast::http::async_write(stream, sr, yield[ec]);
			if (ec)
				LOG_WARN << "on_http_root, id: " << connection_id << ", err: " << ec.message();
			return;
		}

		std::vector<std::wstring> item;
		for (; it != end && !m_abort; it++)
		{
			const auto& sub = it->path();
			auto ftime = std::filesystem::last_write_time(sub, ec);
			auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(ftime
				- std::filesystem::file_time_type::clock::now()
				+ std::chrono::system_clock::now());
			auto write_time = std::chrono::system_clock::to_time_t(sctp);

			char tmbuf[64] = { 0 };
			std::strftime(tmbuf, sizeof(tmbuf), "%m-%d-%Y %H:%M", std::localtime(&write_time));
			auto time_string = boost::nowide::widen(tmbuf);

			auto name = boost::ireplace_first_copy(sub.wstring(), doc_path, "");
			if (std::filesystem::is_directory(sub, ec))
			{
				auto leaf = fs::path(name).leaf().string();
				name = fs::path(name).leaf().wstring() + L"/";

				int width = 50 - ((int)leaf.size() + 1);
				width = width < 0 ? 10 : width;
				std::wstring space(width, L' ');
				auto str = fmt::format(body_fmt, name, name, space, time_string, L"[DIRECTORY]");
				item.push_back(str);
			}
			else
			{
				name = fs::path(name).leaf().wstring();
				auto leaf = fs::path(name).leaf().string();
				int width = 50 - (int)leaf.size();
				width = width < 0 ? 10 : width;
				std::wstring space(width, L' ');
				auto str = fmt::format(body_fmt, name, name, space, time_string,
					boost::nowide::widen(add_suffix(static_cast<float>(std::filesystem::file_size(sub, ec)))));
				item.push_back(str);
			}
		}

		std::sort(item.begin(), item.end());
		for (auto& s : item)
			body += s;
		body = h + body + tail_fmt;

		string_response res{ boost::beast::http::status::ok, request.version() };
		res.set(boost::beast::http::field::server, HTTPD_VERSION_STRING);
		res.keep_alive(request.keep_alive());
		res.body() = boost::nowide::narrow(body);
		res.prepare_payload();

		boost::beast::http::serializer<false, string_body, fields> sr{ res };
		boost::beast::http::async_write(stream, sr, yield[ec]);
		if (ec)
			LOG_WARN << "on_http_root, id: " << connection_id << ", err: " << ec.message();
	}

	void dchs_service::on_getfile(const http_params& params, std::string filename/* = ""*/)
	{
		static std::map<std::string, std::string> mime_map =
		{
			{ ".html", "text/html; charset=utf-8" },
			{ ".js", "application/javascript" },
			{ ".css", "text/css" },
			{ ".woff", "application/x-font-woff" },
			{ ".png", "image/png" },
			{ ".jpg", "image/jpg" },
			{ ".wav", "audio/x-wav" },
			{ ".mp4", "video/mp4" }
		};

		auto& stream = params.stream_;
		auto& request = params.request_;
		auto& yield = params.yield_;
		auto& connection_id = params.connection_id_;
		boost::system::error_code ec;

		if (request.method() == http::verb::get &&
			params.command_.size() > 0 &&
			filename.empty())
			filename = params.command_[0];

		if (filename.empty())
		{
			LOG_WARN << "on_getfile, id: " << connection_id << ", bad request filename";
			return do_http_response(params, "bad request filename", http_status::bad_request);
		}

		auto path = std::filesystem::path{ m_config.doc_path_ } / boost::nowide::widen(filename);
		if (!std::filesystem::exists(path))
		{
			LOG_WARN << "on_getfile, id: " << connection_id << ", " << filename << " file not exists";
			return do_http_response(params, "file not exists", http_status::bad_request);
		}

		std::fstream file(path, std::ios_base::binary | std::ios_base::in | std::ios_base::out);

		LOG_DBG << "on_getfile, id: " << connection_id
			<< ", file: " << filename << ", size: " << std::filesystem::file_size(path);

		buffer_response res{ boost::beast::http::status::ok, request.version() };
		res.set(boost::beast::http::field::server, HTTPD_VERSION_STRING);
		auto ext = boost::filesystem::path(path).extension().string();
		if (mime_map.count(ext))
			res.set(boost::beast::http::field::content_type, mime_map[ext]);
		else
			res.set(boost::beast::http::field::content_type, "text/html");
		res.keep_alive(params.request_.keep_alive());
		res.content_length(std::filesystem::file_size(path));

		response_serializer sr{ res };

		res.body().data = nullptr;
		res.body().more = false;

		boost::beast::http::async_write_header(stream, sr, yield[ec]);
		if (ec)
		{
			LOG_WARN << "on_getfile, id: " << connection_id << ", async_write_header: " << ec.message();
			return;
		}

		const auto buf_size = 5 * 1024 * 1024;
		char buf[buf_size];
		do
		{
			auto bytes_transferred = fileop::read(file, buf);
			if (bytes_transferred == 0)
			{
				res.body().data = nullptr;
				res.body().more = false;
			}
			else
			{
				res.body().data = buf;
				res.body().size = bytes_transferred;
				res.body().more = true;
			}

			boost::beast::http::async_write(stream, sr, yield[ec]);
			if (ec == boost::beast::http::error::need_buffer)
			{
				ec = {};
				continue;
			}
			if (ec)
			{
				LOG_WARN << "on_getfile, id: " << connection_id << ", async_write: " << ec.message();
				return;
			}
		} while (!sr.is_done());
	}

	void dchs_service::on_putfile(const http_params& params)
	{
		auto& connection_id = params.connection_id_;
		auto& stream = params.stream_;
		auto& request = params.request_;
		auto& parser = params.parser_;
		auto& buffer = params.buffer_;
		auto& yield = params.yield_;

		std::string filename;

		if ((request.method() == http::verb::put ||
			request.method() == http::verb::post) && params.command_.size() > 0)
		{
			filename = params.command_[0];
		}

		auto content_type = request[boost::beast::http::field::content_type].to_string();
		auto is_multipart = !!boost::find_first(content_type, "multipart/form-data");

		boost::system::error_code ec;
		auto path = std::filesystem::path{ m_config.doc_path_ } / filename;
		if (std::filesystem::exists(path))
		{
			do_http_response(params, "file is exists", http_status::bad_request);
			LOG_WARN << "on_putfile, id: " << connection_id << ", putfile exists: " << path.string();
			return;
		}

		std::fstream file(path, std::ios_base::binary | std::ios_base::out | std::ios_base::trunc);
		size_t total_size = 0;
		std::string multipart_data;

		while (!parser.is_done())
		{
			auto bytes = http::async_read_some(stream, buffer, parser, yield[ec]);
			boost::ignore_unused(bytes);
			bytes = buffer.capacity();

			auto& body = parser.get().body();
			auto bodysize = body.size();
			total_size += bodysize;

			for (auto const buf : boost::beast::buffers_range(body.data()))
			{
				auto bufsize = buf.size();
				auto bufptr = static_cast<const char*>(buf.data());

				if (is_multipart)
					multipart_data.append(bufptr, bufsize);
				else
					file.write(bufptr, bufsize);
			}
			body.consume(bodysize);
		}

		if (is_multipart)
		{
			auto e = decode<lazy_part>(multipart_data.begin(), multipart_data.end());
			fileop::write(file, e.content());
		}

		file.close();

		LOG_DBG << "on_putfile, id: " << connection_id << ", file: " << filename << ", size: " << total_size;

		string_response res{ boost::beast::http::status::ok, request.version() };
		res.set(boost::beast::http::field::server, HTTPD_VERSION_STRING);
		res.keep_alive(request.keep_alive());
		res.prepare_payload();

		boost::beast::http::serializer<false, string_body, fields> sr{ res };
		boost::beast::http::async_write(stream, sr, yield[ec]);
		if (ec)
		{
			LOG_WARN << "on_putfile, id: " << connection_id << ", err: " << ec.message();
			return;
		}
	}

	void dchs_service::on_version(const http_params& params)
	{
		boost::system::error_code ec;
		string_response res{ boost::beast::http::status::ok, params.request_.version() };
		res.set(boost::beast::http::field::server, HTTPD_VERSION_STRING);
		res.set(boost::beast::http::field::content_type, "text/html");
		res.keep_alive(params.request_.keep_alive());
		res.body() = DCHS_VERSION_MIME;
		res.prepare_payload();

		boost::beast::http::serializer<false, string_body, fields> sr{ res };
		boost::beast::http::async_write(params.stream_, sr, params.yield_[ec]);
		if (ec)
		{
			LOG_WARN << "on_version, id: " << params.connection_id_ << ", err: " << ec.message();
			return;
		}
	}

	void dchs_service::do_http_response(const http_params& params, std::string response, http_status status)
	{
		auto& connection_id = params.connection_id_;
		auto& stream = params.stream_;
		auto& request = params.request_;
		auto& yield = params.yield_;

		boost::system::error_code ec;
		string_response res{ status, request.version() };
		res.set(boost::beast::http::field::server, HTTPD_VERSION_STRING);
		res.set(boost::beast::http::field::content_type, "text/html");
		res.keep_alive(request.keep_alive());
		res.body() = response;
		res.prepare_payload();

		boost::beast::http::serializer<false, string_body, fields> sr{ res };
		boost::beast::http::async_write(stream, sr, yield[ec]);
		if (ec)
		{
			LOG_WARN << "do_http_response, id: " << connection_id << ", err: " << ec.message();
			return;
		}
	}

	void dchs_service::start_tun(boost::asio::yield_context& yield)
	{
		boost::asio::streambuf buffer;
		boost::system::error_code ec;

		while (!m_abort)
		{
			auto bytes = m_tuntap.async_read_some(buffer.prepare(128 * 1024), yield[ec]);
			if (ec)
			{
				LOG_WARN << "start_tun, async_read_some: " << ec.message();
				return;
			}

			buffer.commit(bytes);

			auto buf = boost::asio::buffer_cast<const uint8_t*>(buffer.data());
			auto endp = avpn::lookup_endpoint_pair(buf, bytes);

			// 解析不出来的ip包, 直接跳过...
			if (endp.empty())
			{
				buffer.consume(bytes);
				continue;
			}

			if (endp.type_ == avpn::ip_udp)
			{
				std::string_view sv((char*)buf + 28, bytes - 28);
				LOG_DBG << sv.size() << " data: " << std::string(sv);
			}

			buffer.consume(bytes);

			// 根据程序的身份, 准备透传.
			if (m_config.identity_ == dchs_server)
			{
				// 作为server时, 要根据ip寻找到对应的通信通道.
			}
			else if (m_config.identity_ == dchs_client)
			{
				// 未连接状态, 丢弃所有packet.
				if (m_channel_status != avpn::channel_status::st_connected)
					return;

				// 透传到channel.
				m_channel.client_write(std::string((char*)buf, bytes));
			}
		}
	}

	void dchs_service::start_net()
	{
		boost::system::error_code ec;

		m_channel.start_connect(m_config.upstreams_,
			[this](avpn::channel_status status)
			{
				m_channel_status = status;

				if (status == avpn::channel_status::st_connected) // 连接成功, 如果没有启动tun, 则启动tun设备.
				{
					if (m_start_tuntap)
						return;
					m_start_tuntap = true;

					boost::asio::spawn(m_io_context_pool.get_io_context().get_executor(),
					[this](boost::asio::yield_context yield) mutable
					{
						start_tun(yield);
					});
				}

				if (status == avpn::channel_status::st_disconnect)
				{
				}
			},
			std::bind(&dchs_service::do_tuntap_write, this, std::placeholders::_1));
	}

	void dchs_service::start_tuntap_write(boost::asio::yield_context& yield)
	{
		boost::system::error_code ec;

		while (!m_abort)
		{
			while (!m_abort && !m_tuntap_write_deque.empty())
			{
				m_tuntap.async_write_some(boost::asio::buffer(m_tuntap_write_deque.front()), yield[ec]);
				if (ec)
				{
					LOG_ERR << "start_tuntap_write, async_write error: " << ec.message();
					return;
				}
				m_tuntap_write_deque.pop_front();
			}

			while (!m_abort)
			{
				m_tuntap_timer.expires_from_now(std::chrono::seconds(10)); // 每10s发起一次ping以保活.
				m_tuntap_timer.async_wait(yield[ec]);
				if (ec == boost::system::errc::operation_canceled
					|| m_tuntap_write_deque.size() > 0)
					break;
			}
		}

		LOG_DBG << "start_tuntap_write quit..";
	}

	void dchs_service::do_tuntap_write(std::string&& message)
	{
		boost::asio::post(m_io_context.get_executor(), [this, message = std::move(message)]() mutable
		{
			m_tuntap_write_deque.emplace_back(std::move(message));
			boost::system::error_code ignore_ec;
			m_tuntap_timer.cancel(ignore_ec);
		});
	}
}
