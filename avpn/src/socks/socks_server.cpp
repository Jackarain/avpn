//
// socks_server.cpp
// ~~~~~~~~~~~~~~~~
//
// Copyright (c) 2019 Jack (jack dot wgm at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include "socks/socks_server.hpp"
#include "socks/socks_client.hpp"
#include "socks/socks_enums.hpp"

#include "utils/uawaitable.hpp"
#include "utils/scoped_exit.hpp"
#include "utils/async_connect.hpp"
#include "utils/logging.hpp"

#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>


namespace socks {

	//////////////////////////////////////////////////////////////////////////

	socks_server::socks_server(net::any_io_executor& executor,
		const tcp::endpoint& endp, socks_server_option opt)
		: m_executor(executor)
		, m_acceptor(executor, endp)
		, m_option(std::move(opt))
	{
		boost::system::error_code ec;
		m_acceptor.listen(net::socket_base::max_listen_connections, ec);
	}

	void socks_server::start()
	{
		// 同时启动32个连接协程, 开始为socks client提供服务.
		for (int i = 0; i < 32; i++)
		{
			net::co_spawn(m_executor,
				start_socks_listen(m_acceptor), net::detached);
		}
	}

	void socks_server::close()
	{
		boost::system::error_code ignore_ec;
		m_abort = true;

		m_acceptor.close(ignore_ec);

		for (auto& [id, c] : m_clients)
		{
			auto client = c.lock();
			if (!client)
				continue;
			client->close();
		}
	}

	void socks_server::remove_client(size_t id)
	{
		m_clients.erase(id);
	}

	const socks::socks_server_option& socks_server::option()
	{
		return m_option;
	}

	net::awaitable<void> socks_server::start_socks_listen(tcp::acceptor& a)
	{
		auto self = shared_from_this();
		boost::system::error_code error;

		while (!m_abort)
		{
			tcp::socket socket(m_executor);
			co_await a.async_accept(socket, uawaitable[error]);
			if (error)
			{
				LOG_ERR << "start_socks_listen, async_accept: " << error.message();

				if (error == net::error::operation_aborted ||
					error == net::error::bad_descriptor)
				{
					co_return;
				}

				if (!a.is_open())
					co_return;

				continue;
			}

			{
				net::socket_base::keep_alive option(true);
				socket.set_option(option, error);
			}

			{
				net::ip::tcp::no_delay option(true);
				socket.set_option(option);
			}

			static std::atomic_size_t id{ 1 };
			size_t connection_id = id++;

			LOG_DBG << "start client incoming id: " << connection_id;

			auto new_session = std::make_shared<socks_session<>>(
				std::move(socket), connection_id, self);
			m_clients[connection_id] = new_session;

			new_session->start();
		}

		LOG_WARN << "start_socks_listen exit ...";
		co_return;
	}

}
