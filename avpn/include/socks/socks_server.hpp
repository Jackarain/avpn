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
#include <unordered_map>

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

	enum {
		SOCKS_CMD_CONNECT = 0x01,
		SOCKS_CMD_BIND = 0x02,
		SOCKS5_CMD_UDP = 0x03
	};

	enum {
		SOCKS5_SUCCEEDED = 0x00,
		SOCKS5_GENERAL_SOCKS_SERVER_FAILURE,
		SOCKS5_CONNECTION_NOT_ALLOWED_BY_RULESET,
		SOCKS5_NETWORK_UNREACHABLE,
		SOCKS5_CONNECTION_REFUSED,
		SOCKS5_TTL_EXPIRED,
		SOCKS5_COMMAND_NOT_SUPPORTED,
		SOCKS5_ADDRESS_TYPE_NOT_SUPPORTED,
		SOCKS5_UNASSIGNED
	};

	class socks_server;
	class socks_session
		: public std::enable_shared_from_this<socks_session>
	{
		socks_session(const socks_session&) = delete;
		socks_session& operator=(const socks_session&) = delete;

	public:
		socks_session(tcp::socket&& socket, size_t id, std::weak_ptr<socks_server> server);
		~socks_session();

	public:
		void start();
		void close();

	private:
		boost::asio::awaitable<void> start_socks_proxy();
		boost::asio::awaitable<void> socks_connect_v5();
		boost::asio::awaitable<bool> socks_auth();
		boost::asio::awaitable<void> transfer(tcp::socket& from, tcp::socket& to);

	private:
		tcp::socket m_local_socket;
		tcp::socket m_remote_socket;
		size_t m_connection_id;
		std::array<char, 2048> m_local_buffer{};
		std::weak_ptr<socks_server> m_socks_server;
		bool m_abort{ false };
	};

	using socks_session_ptr = std::shared_ptr<socks_session>;
	using socks_session_weak_ptr = std::weak_ptr<socks_session>;


	//////////////////////////////////////////////////////////////////////////

	class socks_server
		: public std::enable_shared_from_this<socks_server>
	{
		socks_server(const socks_server&) = delete;
		socks_server& operator=(const socks_server&) = delete;

	public:
		socks_server(boost::asio::io_context& ioc, const tcp::endpoint& endp);
		~socks_server() = default;

	public:
		void open();
		void close();
		void remove_client(size_t id);

	private:
		boost::asio::awaitable<void> start_socks_listen(tcp::acceptor& a);

	private:
		boost::asio::io_context& m_io_context;
		tcp::acceptor m_acceptor;

		std::unordered_map<size_t, socks_session_weak_ptr> m_clients;

		bool m_abort{ false };
	};

}
