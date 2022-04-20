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
#include "utils/uawaitable.hpp"

#include "utils/misc.hpp"
#include "utils/io.hpp"
#include "vpncore/endpoint_pair.hpp"

namespace socks {
	using namespace stream_endian;
	using namespace util;

	socks_session::socks_session(tcp::socket&& socket, size_t id)
		: m_local_socket(std::move(socket))
		, m_connection_id(id)
	{
	}

	void socks_session::start()
	{
		boost::asio::co_spawn(m_local_socket.get_executor(),
			start_socks_proxy(), boost::asio::detached);
	}

	boost::asio::awaitable<void> socks_session::start_socks_proxy()
	{
		// read
		//  +----+----------+----------+
		//  |VER | NMETHODS | METHODS  |
		//  +----+----------+----------+
		//  | 1  |    1     | 1 to 255 |
		//  +----+----------+----------+
		//  [               ]
		// or
		//  +----+----+----+----+----+----+----+----+----+----+....+----+
		//  | VN | CD | DSTPORT |      DSTIP        | USERID       |NULL|
		//  +----+----+----+----+----+----+----+----+----+----+....+----+
		//    1    1      2        4                  variable       1
		//  [         ]
		// 读取[]里的部分.

		boost::system::error_code ec;

		auto bytes = co_await boost::asio::async_read(m_local_socket,
			boost::asio::buffer(m_local_buffer, 2), boost::asio::transfer_exactly(2),
				uawaitable[ec]);
		if (ec)
		{
			LOG_ERR << "read socks version: " << ec.message();
			co_return;
		}

		char* p = m_local_buffer.data();
		int socks_version = read_int8(p);
		if (socks_version == SOCKS_VERSION_5)
		{
			co_await socks_connect_v5();
			co_return;
		}

		co_return;
	}

	boost::asio::awaitable<void> socks_session::socks_connect_v5()
	{
		char* p = m_local_buffer.data();

		auto socks_version = read_int8(p);
		BOOST_ASSERT(socks_version == SOCKS_VERSION_5);
		int nmethods = read_int8(p);
		if (nmethods <= 0 || nmethods > 255)
		{
			LOG_ERR << "unsupported method: " << nmethods;
			co_return;
		}

		//  +----+----------+----------+
		//  |VER | NMETHODS | METHODS  |
		//  +----+----------+----------+
		//  | 1  |    1     | 1 to 255 |
		//  +----+----------+----------+
		//                  [          ]

		boost::system::error_code ec;
		auto bytes = co_await boost::asio::async_read(m_local_socket,
			boost::asio::buffer(m_local_buffer, nmethods),
				boost::asio::transfer_exactly(nmethods),
					uawaitable[ec]);
		if (ec)
		{
			LOG_ERR << "read socks methods: " << ec.message();
			co_return;
		}

		// 循环读取客户端支持的代理方式.
		p = m_local_buffer.data();

		m_method = SOCKS5_AUTH_UNACCEPTABLE;
		bool support_auth = false;
		while (bytes != 0)
		{
			int m = read_int8(p);

			if (m == SOCKS5_AUTH_NONE || m == SOCKS5_AUTH)
				m_method = m;

			if (m == SOCKS5_AUTH)
				support_auth = true;

			bytes--;
		}

		// 客户端不支持认证, 而如果服务端需要认证, 回复客户端不接受.
		if (!support_auth && false)
		{
			// 回复客户端, 不接受客户端的的代理请求.
			p = m_local_buffer.data();
			write_int8(socks_version, p);
			write_int8(SOCKS5_AUTH_UNACCEPTABLE, p);

			m_method = SOCKS5_AUTH_UNACCEPTABLE;
		}
		else
		{
			// 回复客户端, server所选择的代理方式.
			p = m_local_buffer.data();
			write_int8(socks_version, p);
			write_int8(m_method, p);
		}

		//  +----+--------+
		//  |VER | METHOD |
		//  +----+--------+
		//  | 1  |   1    |
		//  +----+--------+
		//  [             ]
		bytes = co_await boost::asio::async_write(m_local_socket,
			boost::asio::buffer(m_local_buffer, 2),
				boost::asio::transfer_exactly(2),
					uawaitable[ec]);
		if (ec)
		{
			LOG_WARN << "write server method error: " << ec.message();
			co_return;
		}

		if (m_method == SOCKS5_AUTH_UNACCEPTABLE)
		{
			LOG_WARN << "no acceptable methods for server";
			co_return;
		}

		// 认证模式, 则进入认证子协程.
		if (m_method == SOCKS5_AUTH)
		{
			auto ret = co_await socks_auth();
			if (!ret)
				co_return;
		}

		//  +----+-----+-------+------+----------+----------+
		//  |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
		//  +----+-----+-------+------+----------+----------+
		//  | 1  |  1  | X'00' |  1   | Variable |    2     |
		//  +----+-----+-------+------+----------+----------+
		//  [                          ]
		bytes = co_await boost::asio::async_read(m_local_socket,
			boost::asio::buffer(m_local_buffer, 5),
				boost::asio::transfer_exactly(5),
					uawaitable[ec]);
		if (ec)
		{
			LOG_WARN << "read client request error: " << ec.message();
			co_return;
		}

		p = m_local_buffer.data();
		auto ver = read_int8(p);
		if (ver != SOCKS_VERSION_5)
		{
			LOG_WARN << "socks requests, invalid protocol: " << ver;
			co_return;
		}

		int command = read_int8(p);		// CONNECT/BIND/UDP
		read_int8(p);					// reserved.
		int atyp = read_int8(p);		// atyp.

		//  +----+-----+-------+------+----------+----------+
		//  |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
		//  +----+-----+-------+------+----------+----------+
		//  | 1  |  1  | X'00' |  1   | Variable |    2     |
		//  +----+-----+-------+------+----------+----------+
		//                              [                   ]
		int length = 0;
		int prefix = 1;

		// 保存第一个字节.
		m_local_buffer[0] = m_local_buffer[4];

		if (atyp == SOCKS5_ATYP_IPV4)
			length = 5; // 6 - 1
		else if (atyp == SOCKS5_ATYP_DOMAINNAME)
		{
			length = read_uint8(p) + 2;
			prefix = 0;
		}
		else if (atyp == SOCKS5_ATYP_IPV6)
			length = 17; // 18 - 1

		bytes = co_await boost::asio::async_read(m_local_socket,
			boost::asio::buffer(m_local_buffer.data() + prefix, length),
				boost::asio::transfer_exactly(length),
					uawaitable[ec]);
		if (ec)
		{
			LOG_WARN << "read client request dst.addr error: " << ec.message();
			co_return;
		}

		tcp::endpoint dst_endpoint;
		std::string domain;
		uint16_t port = 0;

		p = m_local_buffer.data();
		if (atyp == SOCKS5_ATYP_IPV4)
		{
			dst_endpoint.address(boost::asio::ip::address_v4(read_uint32(p)));
			dst_endpoint.port(read_uint16(p));
			LOG_DBG << m_local_socket.remote_endpoint() << " use ipv4: " << dst_endpoint;
		}
		else if (atyp == SOCKS5_ATYP_DOMAINNAME)
		{
			for (int i = 0; i < bytes - 2; i++)
				domain.push_back(read_int8(p));
			port = read_uint16(p);
			LOG_DBG << m_local_socket.remote_endpoint() << " use domain: " << domain << ":" << port;
		}
		else if (atyp == SOCKS5_ATYP_IPV6)
		{
			boost::asio::ip::address_v6::bytes_type addr;
			for (boost::asio::ip::address_v6::bytes_type::iterator i = addr.begin();
				i != addr.end(); ++i)
			{
				*i = read_int8(p);
			}

			dst_endpoint.address(boost::asio::ip::address_v6(addr));
			dst_endpoint.port(read_uint16(p));
			std::cout << m_local_socket.remote_endpoint() << " use ipv6: " << dst_endpoint << std::endl;
		}

	}

	boost::asio::awaitable<bool> socks_session::socks_auth()
	{
		//  +----+------+----------+------+----------+
		//  |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
		//  +----+------+----------+------+----------+
		//  | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
		//  +----+------+----------+------+----------+
		//  [           ]

		boost::system::error_code ec;

		auto bytes = co_await boost::asio::async_read(m_local_socket,
			boost::asio::buffer(m_local_buffer, 2),
			boost::asio::transfer_exactly(2),
			uawaitable[ec]);
		if (ec)
		{
			LOG_WARN << "read client username/passwd error: " << ec.message();
			co_return false;
		}

		auto p = m_local_buffer.data();
		int auth_version = read_int8(p);
		if (auth_version != 1)
		{
			LOG_WARN << "socks negotiation, unsupported socks5 protocol";
			co_return false;
		}
		int name_length = read_uint8(p);
		if (name_length <= 0 || name_length > 255)
		{
			LOG_WARN << "socks negotiation, invalid name length";
			co_return false;
		}
		name_length += 1;

		//  +----+------+----------+------+----------+
		//  |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
		//  +----+------+----------+------+----------+
		//  | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
		//  +----+------+----------+------+----------+
		//              [                 ]

		bytes = co_await boost::asio::async_read(m_local_socket,
			boost::asio::buffer(m_local_buffer, name_length),
			boost::asio::transfer_exactly(name_length),
			uawaitable[ec]);
		if (ec)
		{
			LOG_WARN << "read client username error: " << ec.message();
			co_return false;
		}

		std::string uname;

		p = m_local_buffer.data();
		for (int i = 0; i < bytes - 1; i++)
			uname.push_back(read_int8(p));

		int passwd_len = read_uint8(p);
		if (passwd_len <= 0 || passwd_len > 255)
		{
			LOG_WARN << "socks negotiation, invalid passwd length\n";
			co_return false;
		}

		//  +----+------+----------+------+----------+
		//  |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
		//  +----+------+----------+------+----------+
		//  | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
		//  +----+------+----------+------+----------+
		//                                [          ]

		bytes = co_await boost::asio::async_read(m_local_socket,
			boost::asio::buffer(m_local_buffer, passwd_len),
			boost::asio::transfer_exactly(passwd_len),
			uawaitable[ec]);
		if (ec)
		{
			LOG_WARN << "read client passwd error: " << ec.message();
			co_return false;
		}

		std::string passwd;

		p = m_local_buffer.data();
		for (int i = 0; i < bytes; i++)
			passwd.push_back(read_int8(p));

		// SOCKS5验证用户和密码.
		auto endp = m_local_socket.remote_endpoint();
		auto client = endp.address().to_string();
		client += ":" + std::to_string(endp.port());

		bool verify_passed = true; // verify_passed = do_auth(client, m_uname, m_passwd);

		p = m_local_buffer.data();
		write_int8(0x01, p);			// version 只能是1.
		if (verify_passed)
		{
			write_int8(0x00, p);		// 认证通过返回0x00, 其它值为失败.
		}
		else
		{
			write_int8(0x01, p);		// 认证返回0x01为失败.
		}

		// 返回认证状态.
		//  +----+--------+
		//  |VER | STATUS |
		//  +----+--------+
		//  | 1  |   1    |
		//  +----+--------+
		co_await boost::asio::async_write(m_local_socket,
			boost::asio::buffer(m_local_buffer, 2),
			boost::asio::transfer_exactly(2),
			uawaitable[ec]);
		if (ec)
		{
			LOG_WARN << "server write status error: " << ec.message();
			co_return false;
		}

		co_return true;
	}

	//////////////////////////////////////////////////////////////////////////

	socks_server::socks_server(boost::asio::io_context& ioc, const tcp::endpoint& endp)
		: m_io_context(ioc)
		, m_acceptor(ioc, endp)
	{
		// 同时启动32个连接协程, 开始为socks client提供服务.
		for (int i = 0; i < 32; i++)
		{
			boost::asio::co_spawn(m_io_context,
				start_socks_listen(m_acceptor), boost::asio::detached);
		}
	}

	void socks_server::close()
	{

	}

	boost::asio::awaitable<void> socks_server::start_socks_listen(tcp::acceptor& a)
	{
		boost::system::error_code error;
		while (!m_abort)
		{
			tcp::socket socket(m_io_context);
			co_await a.async_accept(socket, uawaitable[error]);
			if (error)
			{
				LOG_ERR << "start_socks_listen, async_accept: " << error.message();

				if (error == boost::asio::error::operation_aborted ||
					error == boost::asio::error::bad_descriptor)
				{
					co_return;
				}

				if (!a.is_open())
					co_return;

				continue;
			}

			{
				boost::asio::socket_base::keep_alive option(true);
				socket.set_option(option, error);
			}

			{
				boost::asio::ip::tcp::no_delay option(true);
				socket.set_option(option);
			}

			static std::atomic_size_t id{ 1 };
			size_t connection_id = id++;

			LOG_DBG << "start_socks_listen, client incoming id: " << connection_id;

			boost::shared_ptr<socks_session> new_session =
				boost::make_shared<socks_session>(std::move(socket), connection_id);

		}

		LOG_WARN << "start_socks_listen exit ...";
		co_return;
	}

}
