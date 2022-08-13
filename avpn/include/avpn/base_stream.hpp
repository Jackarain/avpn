//
// Copyright (C) 2022 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#pragma once

#include <boost/variant.hpp>
#include <boost/system/error_code.hpp>

#include <boost/asio/socket_base.hpp>
#include <boost/asio/any_io_executor.hpp>

namespace avpn {

	template<typename... T>
	class base_stream : public boost::variant<T...>
	{
	public:
		template <typename S>
		explicit base_stream(S device)
			: boost::variant<T...>(std::move(device))
		{
			static_assert(std::is_move_constructible<S>::value
				, "must be move constructible");
		}
		~base_stream() = default;

		base_stream(const base_stream&) = delete;
		base_stream& operator=(base_stream const&) = delete;

		base_stream& operator=(base_stream&&) = default;
		base_stream(base_stream&&) = default;

		using executor_type = net::any_io_executor;

		net::any_io_executor get_executor()
		{
			return boost::apply_visitor([&](auto& t) mutable
				{ return t.get_executor(); }, *this);
		}

		template <typename MutableBufferSequence, typename ReadHandler>
		BOOST_ASIO_INITFN_AUTO_RESULT_TYPE(ReadHandler,
			void(boost::system::error_code, std::size_t))
			async_read_some(const MutableBufferSequence& buffers,
				ReadHandler&& handler)
		{
			return boost::apply_visitor([&](auto& t) mutable
				{ return t.async_read_some(buffers,
					std::forward<ReadHandler>(handler)); }, *this);
		}

		template <typename ConstBufferSequence, typename WriteHandler>
		BOOST_ASIO_INITFN_AUTO_RESULT_TYPE(WriteHandler,
			void(boost::system::error_code, std::size_t))
			async_write_some(const ConstBufferSequence& buffers,
				WriteHandler&& handler)
		{
			return boost::apply_visitor([&](auto& t) mutable
				{ return t.async_write_some(buffers,
					std::forward<WriteHandler>(handler)); }, *this);
		}

		tcp::endpoint remote_endpoint()
		{
			return boost::apply_visitor([&](auto& t) mutable
				{ return t.remote_endpoint(); }, *this);
		}

		void shutdown(net::socket_base::shutdown_type what,
			boost::system::error_code& ec)
		{
			boost::apply_visitor([&](auto& t) mutable
				{ t.shutdown(what, ec); }, *this);
		}

		void close(boost::system::error_code& ec)
		{
			boost::apply_visitor([&](auto& t) mutable
				{ t.close(ec); }, *this);
		}
	};
}
