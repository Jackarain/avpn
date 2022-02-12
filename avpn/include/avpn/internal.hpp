//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#pragma once

#include <type_traits>
#include <tuple>
#include <any>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <string>
#include <functional>
#include <memory>
#include <chrono>
#include <variant>
#include <exception>
#include <system_error>
#include <stdexcept>
#include <thread>
#include <algorithm>
#include <numeric>
#include <optional>
#include <random>
#include <shared_mutex>
#include <unordered_map>
#include <unordered_set>


#pragma warning(push)
#pragma warning(disable: 4702 4459)

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-private-field"
#endif

#include <boost/asio/post.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/defer.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/ip/network_v4.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/read_until.hpp>
#include <boost/asio/signal_set.hpp>

#ifdef __clang__
#pragma clang diagnostic pop
#endif // __clang__


#ifndef _MSC_VER
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Warray-bounds"
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warray-bounds"
#endif // _MSC_VER

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/ssl.hpp>

#ifndef _MSC_VER
#pragma GCC diagnostic pop
#pragma clang diagnostic pop
#endif // _MSC_VER

#include <boost/algorithm/string/trim.hpp>
#include <boost/algorithm/string/find.hpp>

#pragma warning(pop)

#include <boost/thread.hpp>
#include <boost/smart_ptr/local_shared_ptr.hpp>
#include <boost/smart_ptr/make_local_shared.hpp>

#include <boost/json.hpp>

#include <boost/filesystem.hpp>


#include <boost/signals2.hpp>

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-parameter"
#endif

#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/cpp_dec_float.hpp>

#include <boost/circular_buffer.hpp>

#ifdef __clang__
#pragma clang diagnostic pop
#endif

#ifndef ENABLE_LOGGER
#define ENABLE_LOGGER
#endif

#pragma warning(push)
#pragma warning(disable: 4244 4127 4702)

#include "utils/logging.hpp"

#pragma warning(pop)
