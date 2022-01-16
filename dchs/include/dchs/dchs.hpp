//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#pragma once

#include "dchs/internal.hpp"
#include "vpncore/tuntap.hpp"
#include "vpncore/channel.hpp"

namespace dchs {

	enum {
		dchs_server = 0,
		dchs_client = 1
	};

	struct server_config
	{
		std::vector<std::string> upstreams_;
		std::vector<std::string> ws_listens_;

		std::vector<std::string> tcp_listens_;
		std::vector<std::string> udp_listens_;

		std::string ifdev_;
		std::string reedsolomon_;
		std::string doc_path_;
		int identity_;
	};


	using ws_stream = websocket::stream<boost::beast::tcp_stream>;
	struct ws_connection
	{
		ws_connection(ws_stream&& ws, int64_t connection_id, const std::string& remote_host)
			: ws_stream_(std::move(ws))
			, ws_timer_(ws_stream_.get_executor())
			, connection_id_(connection_id)
			, remote_host_(remote_host)
		{
			LOG_DBG << "ws client incoming: " << connection_id_ << ", remote: " << remote_host_;
		}

		ws_connection(ws_connection&& c) noexcept
			: ws_stream_(std::move(c.ws_stream_))
			, message_deque_(std::move(c.message_deque_))
			, ws_timer_(std::move(c.ws_timer_))
			, connection_id_(c.connection_id_)
			, remote_host_(c.remote_host_)
		{}

		~ws_connection()
		{
			LOG_DBG << "ws client leave: " << connection_id_ << ", remote: " << remote_host_;
		}

		ws_stream ws_stream_;
		std::deque<std::string> message_deque_;
		timer ws_timer_;
		int64_t connection_id_;
		std::string remote_host_;
	};
	using ws_connection_ptr = std::shared_ptr<ws_connection>;

	class dchs_service
	{
		using string_body = boost::beast::http::string_body;
		using dynamic_body = boost::beast::http::dynamic_body;
		using buffer_body = boost::beast::http::buffer_body;
		using fields = boost::beast::http::fields;
		using dynamic_request = boost::beast::http::request<dynamic_body>;
		using string_response = boost::beast::http::response<string_body>;
		using buffer_response = boost::beast::http::response<buffer_body>;
		using response_serializer = boost::beast::http::response_serializer<buffer_body, fields>;
		using request_parser = boost::beast::http::request_parser<dynamic_request::body_type>;
		using http_status = boost::beast::http::status;

		struct http_params
		{
			std::vector<std::string> command_;
			size_t connection_id_;
			boost::beast::tcp_stream& stream_;
			dynamic_request& request_;
			request_parser& parser_;
			boost::beast::flat_buffer& buffer_;
			boost::asio::yield_context& yield_;
		};

		// c++11 noncopyable.
		dchs_service(const dchs_service&) = delete;
		dchs_service& operator=(const dchs_service&) = delete;

	public:
		dchs_service(io_context_pool& ios, const server_config& config);
		~dchs_service();

	public:
		void start();
		void stop();

	private:
		//////////////////////////////////////////////////////////////////////////
		bool init_ws_acceptors();
		void start_ws_listen(tcp::acceptor& a, boost::asio::yield_context& yield);
		void start_ws_connect(size_t connection_id,
			boost::beast::tcp_stream stream, boost::asio::yield_context& yield);

		void do_ws_read(size_t connection_id, boost::asio::yield_context& yield);
		void do_ws_write(size_t connection_id, boost::asio::yield_context& yield);

		ws_connection_ptr lookup_ws(size_t connection_id);
		void remove_ws(size_t connection_id);
		void add_ws(size_t connection_id, const std::string& remote_host, ws_stream&& ws);
		void close_all_ws();
		void ws_expires_after(size_t connection_id, int seconds);

		void on_http_root(const http_params& params);
		void on_getfile(const http_params& params, std::string filename = "");
		void on_putfile(const http_params& params);
		void on_version(const http_params& params);
		void do_http_response(const http_params& params,
			std::string response = "Illegal request",
			http_status status = http_status::ok);

		//////////////////////////////////////////////////////////////////////////
		void start_tun(boost::asio::yield_context& yield);
		void start_net();

		void start_tuntap_write(boost::asio::yield_context& yield);
		void do_tuntap_write(std::string&& message);

	private:
		io_context_pool& m_io_context_pool;
		boost::asio::io_context& m_io_context;

		server_config m_config;
		std::vector<tcp::acceptor> m_ws_acceptors;
		std::mutex m_ws_mux;
		std::unordered_map<size_t, ws_connection_ptr> m_ws_streams;

		bool m_start_tuntap{ false };
		avpn::channel_status m_channel_status;
		avpn::tuntap m_tuntap;
		std::deque<std::string> m_tuntap_write_deque;
		timer m_tuntap_timer;
		avpn::channel m_channel;

		std::atomic_bool m_abort{false};
	};
}
