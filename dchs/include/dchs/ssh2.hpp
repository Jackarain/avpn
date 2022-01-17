//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#pragma once

#include <atomic>

#include <boost/core/ignore_unused.hpp>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/asio/spawn.hpp>

#include <libssh2_config.h>
#include <libssh2.h>
#include <libssh2_sftp.h>

namespace ssh2
{
	class error_category_impl;
	template<class error_category>
	const boost::system::error_category& error_category_single()
	{
		static error_category error_category_instance;
		return reinterpret_cast<const boost::system::error_category&>(error_category_instance);
	}

	inline const boost::system::error_category& error_category()
	{
		return error_category_single<ssh2::error_category_impl>();
	}

	namespace errc {
		enum errc_t
		{
			ssh2_error_socket_none = LIBSSH2_ERROR_SOCKET_NONE,
			ssh2_error_banner_recv = LIBSSH2_ERROR_BANNER_RECV,
			ssh2_error_banner_send = LIBSSH2_ERROR_BANNER_SEND,
			ssh2_error_invalid_mac = LIBSSH2_ERROR_INVALID_MAC,
			ssh2_error_kex_failure = LIBSSH2_ERROR_KEX_FAILURE,
			ssh2_error_alloc = LIBSSH2_ERROR_ALLOC,
			ssh2_error_socket_send = LIBSSH2_ERROR_SOCKET_SEND,
			ssh2_error_key_exchange_failure = LIBSSH2_ERROR_KEY_EXCHANGE_FAILURE,
			ssh2_error_timeout = LIBSSH2_ERROR_TIMEOUT,
			ssh2_error_hostkey_init = LIBSSH2_ERROR_HOSTKEY_INIT,
			ssh2_error_hostkey_sign = LIBSSH2_ERROR_HOSTKEY_SIGN,
			ssh2_error_decrypt = LIBSSH2_ERROR_DECRYPT,
			ssh2_error_socket_disconnect = LIBSSH2_ERROR_SOCKET_DISCONNECT,
			ssh2_error_proto = LIBSSH2_ERROR_PROTO,
			ssh2_error_password_expired = LIBSSH2_ERROR_PASSWORD_EXPIRED,
			ssh2_error_file = LIBSSH2_ERROR_FILE,
			ssh2_error_method_none = LIBSSH2_ERROR_METHOD_NONE,
			ssh2_error_authentication_failed = LIBSSH2_ERROR_AUTHENTICATION_FAILED,
			ssh2_error_publickey_unverified = LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED,
			ssh2_error_channel_outoforder = LIBSSH2_ERROR_CHANNEL_OUTOFORDER,
			ssh2_error_channel_failure = LIBSSH2_ERROR_CHANNEL_FAILURE,
			ssh2_error_channel_request_denied = LIBSSH2_ERROR_CHANNEL_REQUEST_DENIED,
			ssh2_error_channel_unknown = LIBSSH2_ERROR_CHANNEL_UNKNOWN,
			ssh2_error_channel_window_exceeded = LIBSSH2_ERROR_CHANNEL_WINDOW_EXCEEDED,
			ssh2_error_channel_packet_exceeded = LIBSSH2_ERROR_CHANNEL_PACKET_EXCEEDED,
			ssh2_error_channel_closed = LIBSSH2_ERROR_CHANNEL_CLOSED,
			ssh2_error_channel_eof_sent = LIBSSH2_ERROR_CHANNEL_EOF_SENT,
			ssh2_error_scp_protocol = LIBSSH2_ERROR_SCP_PROTOCOL,
			ssh2_error_zlib = LIBSSH2_ERROR_ZLIB,
			ssh2_error_socket_timeout = LIBSSH2_ERROR_SOCKET_TIMEOUT,
			ssh2_error_sftp_protocol = LIBSSH2_ERROR_SFTP_PROTOCOL,
			ssh2_error_request_denied = LIBSSH2_ERROR_REQUEST_DENIED,
			ssh2_error_method_not_supported = LIBSSH2_ERROR_METHOD_NOT_SUPPORTED,
			ssh2_error_inval = LIBSSH2_ERROR_INVAL,
			ssh2_error_invalid_poll_type = LIBSSH2_ERROR_INVALID_POLL_TYPE,
			ssh2_error_publickey_protocol = LIBSSH2_ERROR_PUBLICKEY_PROTOCOL,
			ssh2_error_eagain = LIBSSH2_ERROR_EAGAIN,
			ssh2_error_buffer_too_small = LIBSSH2_ERROR_BUFFER_TOO_SMALL,
			ssh2_error_bad_use = LIBSSH2_ERROR_BAD_USE,
			ssh2_error_compress = LIBSSH2_ERROR_COMPRESS,
			ssh2_error_out_of_boundary = LIBSSH2_ERROR_OUT_OF_BOUNDARY,
			ssh2_error_agent_protocol = LIBSSH2_ERROR_AGENT_PROTOCOL,
			ssh2_error_socket_recv = LIBSSH2_ERROR_SOCKET_RECV,
			ssh2_error_encrypt = LIBSSH2_ERROR_ENCRYPT,
			ssh2_error_bad_socket = LIBSSH2_ERROR_BAD_SOCKET,
			ssh2_error_known_hosts = LIBSSH2_ERROR_KNOWN_HOSTS,
			ssh2_error_channel_window_full = LIBSSH2_ERROR_CHANNEL_WINDOW_FULL,
			ssh2_error_keyfile_auth_failed = LIBSSH2_ERROR_KEYFILE_AUTH_FAILED,
			ssh2_error_randgen = LIBSSH2_ERROR_RANDGEN,
			ssh2_unknown_error = -100000,
		};

		inline boost::system::error_code make_error_code(errc_t e) noexcept
		{
			return boost::system::error_code(static_cast<int>(e), ssh2::error_category());
		}
	}

	class error_category_impl
		: public boost::system::error_category
	{
		virtual const char* name() const BOOST_SYSTEM_NOEXCEPT
		{
			return "SSH2";
		}

		virtual std::string message(int e) const
		{
			switch (e)
			{
			case errc::errc_t::ssh2_error_socket_none:             return "SSH2 ERROR SOCKET NONE";
			case errc::errc_t::ssh2_error_banner_recv:             return "SSH2 ERROR BANNER RECV";
			case errc::errc_t::ssh2_error_banner_send:             return "SSH2 ERROR BANNER SEND";
			case errc::errc_t::ssh2_error_invalid_mac:             return "SSH2 ERROR INVALID MAC";
			case errc::errc_t::ssh2_error_kex_failure:             return "SSH2 ERROR KEX FAILURE";
			case errc::errc_t::ssh2_error_alloc:                   return "SSH2 ERROR ALLOC";
			case errc::errc_t::ssh2_error_socket_send:             return "SSH2 ERROR SOCKET SEND";
			case errc::errc_t::ssh2_error_key_exchange_failure:    return "SSH2 ERROR KEY EXCHANGE FAILURE";
			case errc::errc_t::ssh2_error_timeout:                 return "SSH2 ERROR TIMEOUT";
			case errc::errc_t::ssh2_error_hostkey_init:            return "SSH2 ERROR HOSTKEY INIT";
			case errc::errc_t::ssh2_error_hostkey_sign:            return "SSH2 ERROR HOSTKEY SIGN";
			case errc::errc_t::ssh2_error_decrypt:                 return "SSH2 ERROR DECRYPT";
			case errc::errc_t::ssh2_error_socket_disconnect:       return "SSH2 ERROR SOCKET DISCONNECT";
			case errc::errc_t::ssh2_error_proto:                   return "SSH2 ERROR PROTO";
			case errc::errc_t::ssh2_error_password_expired:        return "SSH2 ERROR PASSWORD EXPIRED";
			case errc::errc_t::ssh2_error_file:                    return "SSH2 ERROR FILE";
			case errc::errc_t::ssh2_error_method_none:             return "SSH2 ERROR METHOD NONE";
			case errc::errc_t::ssh2_error_authentication_failed:   return "SSH2 ERROR AUTHENTICATION FAILED";
			case errc::errc_t::ssh2_error_publickey_unverified:    return "SSH2 ERROR PUBLICKEY UNVERIFIED";
			case errc::errc_t::ssh2_error_channel_outoforder:      return "SSH2 ERROR CHANNEL OUTOFORDER";
			case errc::errc_t::ssh2_error_channel_failure:         return "SSH2 ERROR CHANNEL FAILURE";
			case errc::errc_t::ssh2_error_channel_request_denied:  return "SSH2 ERROR CHANNEL REQUEST DENIED";
			case errc::errc_t::ssh2_error_channel_unknown:         return "SSH2 ERROR CHANNEL UNKNOWN";
			case errc::errc_t::ssh2_error_channel_window_exceeded: return "SSH2 ERROR CHANNEL WINDOW EXCEEDED";
			case errc::errc_t::ssh2_error_channel_packet_exceeded: return "SSH2 ERROR CHANNEL PACKET EXCEEDED";
			case errc::errc_t::ssh2_error_channel_closed:          return "SSH2 ERROR CHANNEL CLOSED";
			case errc::errc_t::ssh2_error_channel_eof_sent:        return "SSH2 ERROR CHANNEL EOF SENT";
			case errc::errc_t::ssh2_error_scp_protocol:            return "SSH2 ERROR SCP PROTOCOL";
			case errc::errc_t::ssh2_error_zlib:                    return "SSH2 ERROR ZLIB";
			case errc::errc_t::ssh2_error_socket_timeout:          return "SSH2 ERROR SOCKET TIMEOUT";
			case errc::errc_t::ssh2_error_sftp_protocol:           return "SSH2 ERROR SFTP PROTOCOL";
			case errc::errc_t::ssh2_error_request_denied:          return "SSH2 ERROR REQUEST DENIED";
			case errc::errc_t::ssh2_error_method_not_supported:    return "SSH2 ERROR METHOD NOT SUPPORTED";
			case errc::errc_t::ssh2_error_inval:                   return "SSH2 ERROR INVAL";
			case errc::errc_t::ssh2_error_invalid_poll_type:       return "SSH2 ERROR INVALID POLL TYPE";
			case errc::errc_t::ssh2_error_publickey_protocol:      return "SSH2 ERROR PUBLICKEY PROTOCOL";
			case errc::errc_t::ssh2_error_eagain:                  return "SSH2 ERROR EAGAIN";
			case errc::errc_t::ssh2_error_buffer_too_small:        return "SSH2 ERROR BUFFER TOO SMALL";
			case errc::errc_t::ssh2_error_bad_use:                 return "SSH2 ERROR BAD USE";
			case errc::errc_t::ssh2_error_compress:                return "SSH2 ERROR COMPRESS";
			case errc::errc_t::ssh2_error_out_of_boundary:         return "SSH2 ERROR OUT OF BOUNDARY";
			case errc::errc_t::ssh2_error_agent_protocol:          return "SSH2 ERROR AGENT PROTOCOL";
			case errc::errc_t::ssh2_error_socket_recv:             return "SSH2 ERROR SOCKET RECV";
			case errc::errc_t::ssh2_error_encrypt:                 return "SSH2 ERROR ENCRYPT";
			case errc::errc_t::ssh2_error_bad_socket:              return "SSH2 ERROR BAD SOCKET";
			case errc::errc_t::ssh2_error_known_hosts:             return "SSH2 ERROR KNOWN HOSTS";
			case errc::errc_t::ssh2_error_channel_window_full:     return "SSH2 ERROR CHANNEL WINDOW FULL";
			case errc::errc_t::ssh2_error_keyfile_auth_failed:     return "SSH2 ERROR KEYFILE AUTH FAILED";
			case errc::errc_t::ssh2_error_randgen:                 return "SSH2 ERROR RANDGEN";
			default:                                               return "SSH2 ERROR UNKNOWN";
			}
		}
	};
}

namespace boost {
	namespace system {

		template <>
		struct is_error_code_enum<ssh2::errc::errc_t>
		{
			static const bool value = true;
		};

	} // namespace system
} // namespace boost

namespace ssh2
{
	using boost::asio::ip::tcp;

	class ssh2_init
	{
	public:
		ssh2_init()
		{
			bool expected = false;
			if (!init_.compare_exchange_strong(expected, true))
				return;

			auto rc = libssh2_init(0);
			if (rc != 0)
			{
				fprintf(stderr, "libssh2 initialization failed (%d)\n", rc);
				exit(-1);
			}
		}

		~ssh2_init()
		{
			libssh2_exit();
		}

	private:
		static std::atomic_bool init_;
	};

	std::atomic_bool ssh2_init::init_ = false;
	ssize_t session_send(libssh2_socket_t socket, void* buffer, size_t length, int flags, void** abstract);
	ssize_t session_recv(libssh2_socket_t socket, void* buffer, size_t length, int flags, void** abstract);

	class ssh2_handle
	{
		// c++11 noncopyable.
		ssh2_handle(const ssh2_handle&) = delete;
		ssh2_handle& operator=(const ssh2_handle&) = delete;

		enum event_type {
			wait_none,
			wait_read_available,
			wait_write_available,
		};

		friend ssize_t session_send(libssh2_socket_t socket, void* buffer, size_t length, int flags, void** abstract);
		friend ssize_t session_recv(libssh2_socket_t socket, void* buffer, size_t length, int flags, void** abstract);

	public:
		ssh2_handle(ssh2_handle&& h) noexcept
			: m_socket(std::move(h.m_socket))
			, m_session(h.m_session)
			, m_sftp_session(h.m_sftp_session)
			, m_sftp_handle(h.m_sftp_handle)
			, m_event_type(h.m_event_type)
		{
			h.m_session = nullptr;
			h.m_sftp_session = nullptr;
			h.m_sftp_handle = nullptr;
		}

	public:
		explicit ssh2_handle(tcp::socket&& sock)
			: m_socket(std::move(sock))
		{
			auto abstract = libssh2_session_abstract(m_session);
			*abstract = (void*)this;

			// auto session_send_func = &session_send;
			typedef ssize_t(*ssh2_callback_type)(libssh2_socket_t, void*, size_t, int, void**);
			ssh2_callback_type sfunc = &session_send;
			libssh2_session_callback_set(m_session, LIBSSH2_CALLBACK_SEND, (void*)sfunc);
			ssh2_callback_type rfunc = &session_recv;
			libssh2_session_callback_set(m_session, LIBSSH2_CALLBACK_RECV, (void*)rfunc);

			libssh2_session_set_blocking(m_session, 0);
			m_socket.non_blocking(true);
		}

		~ssh2_handle()
		{
			if (m_session)
			{
				libssh2_session_set_blocking(m_session, 1);
				if (m_socket.is_open())
				{
					if (m_sftp_handle)
						libssh2_sftp_close(m_sftp_handle);
					if (m_sftp_session)
						libssh2_sftp_shutdown(m_sftp_session);
					libssh2_session_disconnect(m_session, "Normal Shutdown");
				}

				libssh2_session_free(m_session);
			}
		}

		tcp::socket& socket()
		{
			return m_socket;
		}

	public:
		template <typename Handler>
		BOOST_ASIO_INITFN_RESULT_TYPE(Handler, void(boost::system::error_code, int))
		async_handshake(BOOST_ASIO_MOVE_ARG(Handler) handler)
		{
			auto initiate_do_handshake = [this](auto&& handler) mutable
			{
				auto executor = m_socket.get_executor();
				boost::asio::spawn(executor,
					[this, executor, handler = std::move(handler)](boost::asio::yield_context yield) mutable
				{
					boost::system::error_code ec;
					int result = -1;
					while (true)
					{
						wait_socket(yield, ec);
						if (ec)
							break;

						result = libssh2_session_handshake(m_session, m_socket.native_handle());
						if (result == LIBSSH2_ERROR_EAGAIN)
							continue;

						m_event_type = wait_none;
						break;
					}

					if (result < 0)
						ec = ssh2::errc::make_error_code((ssh2::errc::errc_t)result);

					handler(ec, result);
				});
			};

			return boost::asio::async_initiate<Handler, void(boost::system::error_code, int)>
				(initiate_do_handshake, handler);
		}

		const char* hostkey_hash() noexcept
		{
			return libssh2_hostkey_hash(m_session, LIBSSH2_HOSTKEY_HASH_SHA1);
		}

		template <typename Handler>
		BOOST_ASIO_INITFN_RESULT_TYPE(Handler, void(boost::system::error_code, char*))
			async_userauth_list(const std::string& username, BOOST_ASIO_MOVE_ARG(Handler) handler)
		{
			auto initiate_do_userauth_list = [this, &username](auto&& handler) mutable
			{
				auto executor = m_socket.get_executor();
				boost::asio::spawn(executor,
					[this, executor, username, handler = std::move(handler)](boost::asio::yield_context yield) mutable
				{
					boost::system::error_code ec;
					char* result = nullptr;
					int rc = -1;

					while (true)
					{
						wait_socket(yield, ec);
						if (ec)
							break;

						result = libssh2_userauth_list(m_session, username.c_str(), static_cast<unsigned int>(username.size()));
						rc = libssh2_session_last_errno(m_session);
						if (!result && rc == LIBSSH2_ERROR_EAGAIN)
							continue;

						m_event_type = wait_none;
						break;
					}

					if (rc < 0)
						ec = ssh2::errc::make_error_code((ssh2::errc::errc_t)rc);

					handler(ec, result);
				});
			};

			return boost::asio::async_initiate<Handler, void(boost::system::error_code, char*)>
				(initiate_do_userauth_list, handler);
		}

		template <typename Handler>
		BOOST_ASIO_INITFN_RESULT_TYPE(Handler, void(boost::system::error_code, int))
			async_userauth_password(const std::string& username, const std::string& password, BOOST_ASIO_MOVE_ARG(Handler) handler)
		{
			auto initiate_do_userauth_password = [this, &username, &password](auto&& handler) mutable
			{
				auto executor = m_socket.get_executor();
				boost::asio::spawn(executor,
					[this, executor, username, password, handler = std::move(handler)](boost::asio::yield_context yield) mutable
				{
					boost::system::error_code ec;
					int result = -1;

					while (true)
					{
						wait_socket(yield, ec);
						if (ec)
							break;

						result = libssh2_userauth_password_ex(m_session,
							username.c_str(), static_cast<unsigned int>(username.size()),
							password.c_str(), static_cast<unsigned int>(password.size()), nullptr);
						if (result == LIBSSH2_ERROR_EAGAIN)
							continue;

						m_event_type = wait_none;
						break;
					}

					if (result < 0)
						ec = ssh2::errc::make_error_code((ssh2::errc::errc_t)result);

					handler(ec, result);
				});
			};

			return boost::asio::async_initiate<Handler, void(boost::system::error_code, int)>
				(initiate_do_userauth_password, handler);
		}

		template <typename Handler>
		BOOST_ASIO_INITFN_RESULT_TYPE(Handler, void(boost::system::error_code, int))
			async_userauth_publickey_fromfile(const std::string& username, const std::string& passphrase,
				const std::string& publickey, const std::string& privatekey, BOOST_ASIO_MOVE_ARG(Handler) handler)
		{
			auto initiate_do_userauth_publickey_fromfile = [this,
				&username, &passphrase, &publickey, &privatekey](auto&& handler) mutable
			{
				auto executor = m_socket.get_executor();
				boost::asio::spawn(executor, [this, executor,
					username, passphrase, publickey, privatekey, handler = std::move(handler)]
					(boost::asio::yield_context yield) mutable
				{
					boost::system::error_code ec;
					int result = -1;

					while (true)
					{
						wait_socket(yield, ec);
						if (ec)
							break;

						result = libssh2_userauth_publickey_fromfile_ex(m_session,
							username.c_str(), username.size(), publickey.c_str(), privatekey.c_str(), passphrase.c_str());
						if (result == LIBSSH2_ERROR_EAGAIN)
							continue;

						m_event_type = wait_none;
						break;
					}

					if (result < 0)
						ec = ssh2::errc::make_error_code((ssh2::errc::errc_t)result);

					handler(ec, result);
				});
			};

			return boost::asio::async_initiate<Handler, void(boost::system::error_code, int)>
				(initiate_do_userauth_publickey_fromfile, handler);
		}

		template <typename Handler>
		BOOST_ASIO_INITFN_RESULT_TYPE(Handler, void(boost::system::error_code, bool))
			async_sftp_init(BOOST_ASIO_MOVE_ARG(Handler) handler)
		{
			auto initiate_do_sftp_init = [this](auto&& handler) mutable
			{
				auto executor = m_socket.get_executor();
				boost::asio::spawn(executor,
					[this, executor, handler = std::move(handler)](boost::asio::yield_context yield) mutable
				{
					boost::system::error_code ec;
					bool result = false;
					int rc = 0;

					while (true)
					{
						wait_socket(yield, ec);
						if (ec)
							break;

						m_sftp_session = libssh2_sftp_init(m_session);
						rc = libssh2_session_last_errno(m_session);
						if (!m_sftp_session && rc == LIBSSH2_ERROR_EAGAIN)
							continue;

						if (m_sftp_session)
						{
							rc = LIBSSH2_ERROR_NONE;
							result = true;
						}

						m_event_type = wait_none;
						break;
					}

					if (rc < 0)
						ec = ssh2::errc::make_error_code((ssh2::errc::errc_t)rc);

					handler(ec, result);
				});
			};

			return boost::asio::async_initiate<Handler, void(boost::system::error_code, bool)>
				(initiate_do_sftp_init, handler);
		}

		template <typename Handler>
		BOOST_ASIO_INITFN_RESULT_TYPE(Handler, void(boost::system::error_code, bool))
			async_sftp_open(const std::string& filepath, unsigned long flags, BOOST_ASIO_MOVE_ARG(Handler) handler)
		{
			auto initiate_do_sftp_open = [this, &filepath, &flags](auto&& handler) mutable
			{
				auto executor = m_socket.get_executor();
				boost::asio::spawn(executor,
					[this, executor, filepath, flags, handler = std::move(handler)](boost::asio::yield_context yield) mutable
				{
					boost::system::error_code ec;
					bool result = false;
					int rc = -1;

					while (true)
					{
						wait_socket(yield, ec);
						if (ec)
							break;

						m_sftp_handle = libssh2_sftp_open_ex(m_sftp_session,
							filepath.c_str(), static_cast<unsigned int>(filepath.size()),
							flags, 0, LIBSSH2_SFTP_OPENFILE);
						rc = libssh2_session_last_errno(m_session);
						if (!m_sftp_handle && rc == LIBSSH2_ERROR_EAGAIN)
							continue;

						if (m_sftp_handle)
						{
							rc = LIBSSH2_ERROR_NONE;
							result = true;
						}

						m_event_type = wait_none;
						break;
					}

					if (rc < 0)
						ec = ssh2::errc::make_error_code((ssh2::errc::errc_t)rc);

					handler(ec, result);
				});
			};

			return boost::asio::async_initiate<Handler, void(boost::system::error_code, bool)>
				(initiate_do_sftp_open, handler);
		}

		template <typename MutableBufferSequence, typename Handler>
		BOOST_ASIO_INITFN_RESULT_TYPE(Handler, void(boost::system::error_code, ssize_t))
			async_sftp_read(const MutableBufferSequence& buffers, BOOST_ASIO_MOVE_ARG(Handler) handler)
		{
			auto initiate_do_sftp_read = [this, &buffers](auto&& handler) mutable
			{
				auto executor = m_socket.get_executor();
				boost::asio::spawn(executor,
					[this, executor, buffers = std::move(buffers), handler = std::move(handler)](boost::asio::yield_context yield) mutable
				{
					boost::system::error_code ec;
					ssize_t rc = 0;
					ssize_t bytes_transferred = 0;

					auto iter = buffers.begin();
					auto end = buffers.end();

					for (; iter != end; ++iter)
					{
						boost::asio::mutable_buffer buffer(*iter);

						auto size = boost::asio::buffer_size(buffer);
						auto bufptr = boost::asio::buffer_cast<char*>(buffer);
						while (true)
						{
							wait_socket(yield, ec);
							if (ec)
								break;

							bytes_transferred = libssh2_sftp_read(m_sftp_handle, bufptr, size);
							if (bytes_transferred == LIBSSH2_ERROR_EAGAIN)
								continue;
							break;
						}

						if (bytes_transferred > 0)
							rc += bytes_transferred;

						if (static_cast<size_t>(bytes_transferred) != size)
							break;
					}

					if (bytes_transferred < 0)
						ec = ssh2::errc::make_error_code((ssh2::errc::errc_t)bytes_transferred);

					m_event_type = wait_none;
					handler(ec, rc);
				});
			};

			return boost::asio::async_initiate<Handler, void(boost::system::error_code, ssize_t)>
				(initiate_do_sftp_read, handler);
		}

		template <typename ConstBufferSequence, typename Handler>
		BOOST_ASIO_INITFN_RESULT_TYPE(Handler, void(boost::system::error_code, ssize_t))
			async_sftp_write(const ConstBufferSequence& buffers, BOOST_ASIO_MOVE_ARG(Handler) handler)
		{
			auto initiate_do_sftp_write = [this, &buffers](auto&& handler) mutable
			{
				auto executor = m_socket.get_executor();
				boost::asio::spawn(executor,
					[this, executor, buffers = std::move(buffers), handler = std::move(handler)](boost::asio::yield_context yield) mutable
				{
					boost::system::error_code ec;
					ssize_t rc = 0;
					ssize_t bytes_transferred = 0;

					auto iter = buffers.begin();
					auto end = buffers.end();

					for (; iter != end; ++iter)
					{
						auto buffer(*iter);

						auto size = boost::asio::buffer_size(buffer);
						auto bufptr = boost::asio::buffer_cast<const char*>(buffer);

						while (true)
						{
							wait_socket(yield, ec);
							if (ec)
								break;

							bytes_transferred = libssh2_sftp_write(m_sftp_handle, bufptr, size);
							if (bytes_transferred == LIBSSH2_ERROR_EAGAIN)
								continue;

							if (bytes_transferred > 0)
								rc += bytes_transferred;

							break;
						}

						if (bytes_transferred < 0)
						{
							ec = ssh2::errc::make_error_code((ssh2::errc::errc_t)bytes_transferred);
							break;
						}

						if (static_cast<size_t>(bytes_transferred) != size)
							break;
					}

					m_event_type = wait_none;
					handler(ec, rc);
				});
			};

			return boost::asio::async_initiate<Handler, void(boost::system::error_code, ssize_t)>
				(initiate_do_sftp_write, handler);
		}

		template <typename Handler>
		BOOST_ASIO_INITFN_RESULT_TYPE(Handler, void(boost::system::error_code, bool))
			async_close(BOOST_ASIO_MOVE_ARG(Handler) handler)
		{
			auto initiate_do_sftp_close = [this](auto&& handler) mutable
			{
				auto executor = m_socket.get_executor();
				boost::asio::spawn(executor,
					[this, executor, handler = std::move(handler)](boost::asio::yield_context yield) mutable
				{
					boost::system::error_code ec;
					bool result = false;
					ssize_t rc = 0;
					LIBSSH2_SESSION* se = m_session;

					while (true)
					{
						wait_socket(yield, ec);
						if (ec)
							break;

						if (m_sftp_handle)
						{
							rc = libssh2_sftp_close(m_sftp_handle);
							if (rc == LIBSSH2_ERROR_EAGAIN)
								continue;
							if (rc < 0)
								break;
							m_sftp_handle = nullptr;
						}

						if (m_sftp_session)
						{
							rc = libssh2_sftp_shutdown(m_sftp_session);
							if (rc == LIBSSH2_ERROR_EAGAIN)
								continue;
							if (rc < 0)
								break;
							m_sftp_session = nullptr;
						}

						if (m_session)
						{
							rc = libssh2_session_disconnect(m_session, "Normal Shutdown");
							if (rc == LIBSSH2_ERROR_EAGAIN)
								continue;
							if (rc < 0)
								break;
							m_session = nullptr;
						}

						if (se)
						{
							rc = libssh2_session_free(se);
							if (rc == LIBSSH2_ERROR_EAGAIN)
								continue;
							if (rc < 0)
								break;
							se = nullptr;
						}

						m_event_type = wait_none;
						break;
					}

					if (rc < 0)
						ec = ssh2::errc::make_error_code((ssh2::errc::errc_t)rc);

					handler(ec, result);
				});
			};

			return boost::asio::async_initiate<Handler, void(boost::system::error_code, bool)>
				(initiate_do_sftp_close, handler);
		}

	private:
		void wait_socket(boost::asio::yield_context& yield, boost::system::error_code& ec)
		{
			switch (m_event_type)
			{
			case wait_read_available:
				m_socket.async_wait(tcp::socket::wait_read, yield[ec]);
				break;
			case wait_write_available:
				m_socket.async_wait(tcp::socket::wait_write, yield[ec]);
				break;
			case wait_none:
				break;
			}
		}

		ssize_t wirte_handle(void* buffer, size_t length)
		{
			ssize_t sz = 0;

			boost::system::error_code ec;
			sz = m_socket.write_some(boost::asio::buffer(buffer, length), ec);
			if (ec == boost::asio::error::try_again || ec == boost::asio::error::would_block)
			{
				m_event_type = wait_write_available;
				return -EAGAIN;
			}

			return sz;
		}

		ssize_t read_handle(void* buffer, size_t length)
		{
			ssize_t sz = 0;

			boost::system::error_code ec;
			sz = m_socket.read_some(boost::asio::buffer(buffer, length), ec);
			if (ec == boost::asio::error::try_again || ec == boost::asio::error::would_block)
			{
				m_event_type = wait_read_available;
				return -EAGAIN;
			}

			return sz;
		}

	private:
		tcp::socket m_socket;
		LIBSSH2_SESSION* m_session = libssh2_session_init();
		LIBSSH2_SFTP* m_sftp_session = nullptr;
		LIBSSH2_SFTP_HANDLE* m_sftp_handle = nullptr;
		event_type m_event_type = wait_none;
	};

		ssize_t session_send(libssh2_socket_t socket, void* buffer, size_t length, int flags, void** abstract)
		{
			boost::ignore_unused(socket);
			boost::ignore_unused(flags);

			ssh2_handle* pt = (ssh2_handle*)*abstract;
			return pt->wirte_handle(buffer, length);
		}

		ssize_t session_recv(libssh2_socket_t socket, void* buffer, size_t length, int flags, void** abstract)
		{
			boost::ignore_unused(socket);
			boost::ignore_unused(flags);

			ssh2_handle* pt = (ssh2_handle*)*abstract;
			return pt->read_handle(buffer, length);
		}


}
