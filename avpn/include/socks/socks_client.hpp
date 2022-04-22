//
// socks_client.hpp
// ~~~~~~~~~~~~~~~~
//
// Copyright (c) 2019 Jack (jack dot wgm at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include <string>
#include <memory>

#include <boost/system/error_code.hpp>

#include <boost/asio/io_context.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>

#include "socks/socks_error_code.hpp"

namespace socks {

	using boost::asio::ip::tcp;
	using boost::asio::ip::udp;

	struct socks_client_option
	{
		// socks server
		std::string host;
		uint16_t port;

		// user auth info
		std::string username;
		std::string password;

		// socks version: 4 or 5
		int version{ 5 };

		// pass hostname to proxy
		bool proxy_hostname{ true };
	};

	boost::asio::awaitable<boost::system::error_code>
	async_socks_handshake(tcp::socket& socket, socks_client_option opt = {});
}

