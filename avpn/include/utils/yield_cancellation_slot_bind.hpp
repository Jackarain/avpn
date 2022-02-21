//
// yield_cancellation_slot_bind.hpp
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2019 Jack (jack dot wgm at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#pragma once

#include <boost/asio/io_context.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/asio/async_result.hpp>
#include <boost/asio/cancellation_signal.hpp>

template <typename Handler>
class yield_cancellation_slot_bind
	: public boost::asio::basic_yield_context<Handler>
{
public:
	yield_cancellation_slot_bind(boost::asio::cancellation_slot slot,
		boost::asio::basic_yield_context<Handler>&& t)
		: boost::asio::basic_yield_context<Handler>(t)
		, slot_(slot)
	{}

	boost::asio::cancellation_slot slot_;
};

namespace boost::asio::detail
{
	template <typename Handler, typename T>
	class yield_coro_async_result
	{
	public:
		struct completion_handler_type : public coro_handler<Handler, T>
		{
			using cancellation_slot_type = boost::asio::cancellation_slot;

			explicit completion_handler_type(yield_cancellation_slot_bind<Handler> ctx)
				: coro_handler<Handler, T>(ctx)
				, slot_(ctx.slot_)
			{}

			cancellation_slot_type get_cancellation_slot() const
			{
				return slot_;
			}

			cancellation_slot_type slot_;
		};

		using return_type = T;

		explicit yield_coro_async_result(completion_handler_type& h)
			: coro_handler_(h),
			ca_(coro_handler_.ca_),
			ready_(2)
		{
			coro_handler_.ready_ = &ready_;
			out_ec_ = coro_handler_.ec_;
			if (!out_ec_) coro_handler_.ec_ = &ec_;
			coro_handler_.value_ = &value_;
		}

		return_type get()
		{
			coro_handler_.coro_.reset();

			if (--ready_ != 0)
				ca_();
			if (!out_ec_ && ec_) throw boost::system::system_error(ec_);
			return BOOST_ASIO_MOVE_CAST(return_type)(value_);
		}

	private:
		completion_handler_type& coro_handler_;
		typename basic_yield_context<Handler>::caller_type& ca_;
		atomic_count ready_;
		boost::system::error_code* out_ec_;
		boost::system::error_code ec_;
		return_type value_;
	};

	template <typename Handler>
	class yield_coro_async_result<Handler, void>
	{
	public:
		struct completion_handler_type : public coro_handler<Handler, void>
		{
			using cancellation_slot_type = boost::asio::cancellation_slot;

			explicit completion_handler_type(yield_cancellation_slot_bind<Handler> ctx)
				: coro_handler<Handler, void>(ctx)
				, slot_(ctx.slot_)
			{}

			cancellation_slot_type get_cancellation_slot() const
			{
				return slot_;
			}

			cancellation_slot_type slot_;
		};

		using return_type = void;

		explicit yield_coro_async_result(completion_handler_type& h)
			: coro_handler_(h),
			ca_(coro_handler_.ca_),
			ready_(2)
		{
			coro_handler_.ready_ = &ready_;
			out_ec_ = coro_handler_.ec_;
			if (!out_ec_) coro_handler_.ec_ = &ec_;
		}

		void get()
		{
			coro_handler_.coro_.reset();

			if (--ready_ != 0)
				ca_();
			if (!out_ec_ && ec_) throw boost::system::system_error(ec_);
		}

	private:
		completion_handler_type& coro_handler_;
		typename basic_yield_context<Handler>::caller_type& ca_;
		atomic_count ready_;
		boost::system::error_code* out_ec_;
		boost::system::error_code ec_;
	};
}

namespace boost::asio
{
	template <typename Handler, typename ReturnType>
	class async_result<yield_cancellation_slot_bind<Handler>, ReturnType()>
		: public detail::yield_coro_async_result<Handler, void>
	{
	public:
		explicit async_result(
			typename detail::yield_coro_async_result<Handler,
			void>::completion_handler_type& h)
			: detail::yield_coro_async_result<Handler, void>(h)
		{}
	};

	template <typename Handler, typename ReturnType, typename Arg1>
	class async_result<yield_cancellation_slot_bind<Handler>, ReturnType(Arg1)>
		: public detail::yield_coro_async_result<Handler, typename decay<Arg1>::type>
	{
	public:
		explicit async_result(
			typename detail::yield_coro_async_result<Handler,
			typename decay<Arg1>::type>::completion_handler_type& h)
			: detail::yield_coro_async_result<Handler, typename decay<Arg1>::type>(h)
		{}
	};

	template <typename Handler, typename ReturnType>
	class async_result<yield_cancellation_slot_bind<Handler>,
		ReturnType(boost::system::error_code)>
		: public detail::yield_coro_async_result<Handler, void>
	{
	public:
		explicit async_result(
			typename detail::yield_coro_async_result<Handler,
			void>::completion_handler_type& h)
			: detail::yield_coro_async_result<Handler, void>(h)
		{}
	};

	template <typename Handler, typename ReturnType, typename Arg2>
	class async_result<yield_cancellation_slot_bind<Handler>,
		ReturnType(boost::system::error_code, Arg2)>
		: public detail::yield_coro_async_result<Handler, typename decay<Arg2>::type>
	{
	public:
		explicit async_result(
			typename detail::yield_coro_async_result<Handler,
			typename decay<Arg2>::type>::completion_handler_type& h)
			: detail::yield_coro_async_result<Handler, typename decay<Arg2>::type>(h)
		{}
	};
}
