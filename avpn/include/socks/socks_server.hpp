//
// socks_server.hpp
// ~~~~~~~~~~~~~~~~
//
// Copyright (c) 2019 Jack (jack dot wgm at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include <memory>
#include <string>
#include <array>

#include <boost/asio/io_context.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>

#include "utils/logging.hpp"

namespace socks {

	using tcp = boost::asio::ip::tcp;               // from <boost/asio/ip/tcp.hpp>
	using udp = boost::asio::ip::udp;               // from <boost/asio/ip/udp.hpp>

	enum {
		SOCKS_VERSION_4 = 4,
		SOCKS_VERSION_5 = 5
	};

	enum {
		SOCKS5_AUTH_NONE = 0x00,
		SOCKS5_AUTH = 0x02,
		SOCKS5_AUTH_UNACCEPTABLE = 0xFF
	};

	enum {
		SOCKS5_ATYP_IPV4 = 0x01,
		SOCKS5_ATYP_DOMAINNAME = 0x03,
		SOCKS5_ATYP_IPV6 = 0x04
	};

	class socks_session
		: public std::enable_shared_from_this<socks_session>
	{
		socks_session(const socks_session&) = delete;
		socks_session& operator=(const socks_session&) = delete;

	public:
		socks_session(tcp::socket&& socket, size_t id);
		~socks_session() = default;

	public:
		void start();

	private:
		boost::asio::awaitable<void> start_socks_proxy();

		boost::asio::awaitable<void> socks_connect_v5();

		boost::asio::awaitable<bool> socks_auth();

	private:
		tcp::socket m_local_socket;
		size_t m_connection_id;
		int m_method{ 0 };
		std::array<char, 2048> m_local_buffer;
	};

	using socks_session_ptr = std::shared_ptr<socks_session>;
	using socks_session_weak_ptr = std::weak_ptr<socks_session>;



	class socks_server
	{
		socks_server(const socks_server&) = delete;
		socks_server& operator=(const socks_server&) = delete;

	public:
		socks_server(boost::asio::io_context& ioc, const tcp::endpoint& endp);
		~socks_server() = default;

	public:
		void close();

	private:
		boost::asio::awaitable<void> start_socks_listen(tcp::acceptor& a);

	private:
		boost::asio::io_context& m_io_context;
		tcp::acceptor m_acceptor;

		std::unordered_map<size_t, socks_session_weak_ptr> m_clients;

		bool m_abort{ false };
	};

}
