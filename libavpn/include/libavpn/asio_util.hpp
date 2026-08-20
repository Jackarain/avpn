//
// logging.hpp
// ~~~~~~~~~~~
//
// Copyright (c) 2023 Jack (jack dot wgm at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef INCLUDE__2025_11_22__ASIO_UTIL_HPP
#define INCLUDE__2025_11_22__ASIO_UTIL_HPP

#include <boost/system/error_code.hpp>
#include <boost/system/system_error.hpp>
#include <exception>
#include <concepts>

namespace asio_util {

    template <typename T>
    concept Cancellable = requires(T t) {
        { t.cancel() };
    };

    template <typename T>
    concept CancelOneable = requires(T t) {
        { t.cancel_one() };
    };

    void cancel(Cancellable auto& t) noexcept
    {
        try
        {
            t.cancel();
        }
        catch (const std::exception&)
        {}
    }

    void cancel_one(CancelOneable auto& t) noexcept
    {
        try
        {
            t.cancel_one();
        }
        catch (const std::exception&)
        {}
    }

    void cancel(Cancellable auto& t, boost::system::error_code& ec) noexcept
    {
        try
        {
            t.cancel();
        }
        catch (const boost::system::system_error& e)
        {
            ec = e.code();
        }
        catch (const std::exception&)
        {
            ec = boost::system::errc::make_error_code(
                boost::system::errc::operation_canceled);
        }
    }

    void cancel_one(CancelOneable auto& t, boost::system::error_code& ec) noexcept
    {
        try
        {
            t.cancel_one();
        }
        catch (const boost::system::system_error& e)
        {
            ec = e.code();
        }
        catch (const std::exception&)
        {
            ec = boost::system::errc::make_error_code(
                boost::system::errc::operation_canceled);
        }
    }
}

#endif // INCLUDE__2025_11_22__ASIO_UTIL_HPP
