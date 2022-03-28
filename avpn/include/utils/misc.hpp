//
// Copyright (C) 2020 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#pragma once

#ifdef USE_MIMALLOC

#ifdef MI_OVERRIDE
#	include <mimalloc.h>
#else
#	include <mimalloc-new-delete.h>
#endif

#ifdef _WIN32
#	include <mimalloc-new-delete.h>
#endif

#endif // USE_MIMALLOC

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


#ifdef _MSC_VER
#	pragma warning(push)
#	pragma warning(disable: 4702 4459)
#endif // _MSC_VER

#ifdef __clang__
#	pragma clang diagnostic push
#	pragma clang diagnostic ignored "-Wunused-private-field"
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
#	pragma clang diagnostic pop
#endif // __clang__


#ifdef __GNUC__
#	pragma GCC diagnostic push
#	pragma GCC diagnostic ignored "-Warray-bounds"
#endif

#ifdef __clang__
#	pragma clang diagnostic push
#	pragma clang diagnostic ignored "-Warray-bounds"
#endif

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/websocket.hpp>

#ifdef __GNUC__
#	pragma GCC diagnostic pop
#endif

#ifdef __clang__
#	pragma clang diagnostic pop
#endif

#include <boost/algorithm/string/trim.hpp>
#include <boost/algorithm/string/find.hpp>

#ifdef _MSC_VER
#	pragma warning(pop)
#endif

#include <boost/thread.hpp>
#include <boost/smart_ptr/local_shared_ptr.hpp>
#include <boost/smart_ptr/make_local_shared.hpp>

#include <boost/signals2.hpp>

#ifdef __clang__
#	pragma clang diagnostic push
#	pragma clang diagnostic ignored "-Wunused-parameter"
#endif

#include <boost/circular_buffer.hpp>

#ifdef __clang__
#	pragma clang diagnostic pop
#endif

#include "utils/logging.hpp"
#include "utils/url_parser.hpp"
#include "utils/time_clock.hpp"

#include "avpn/io_context_pool.hpp"

#define APP_NAME "avpn"
#define HTTPD_VERSION_STRING	     APP_NAME "/1.0"

using tcp = boost::asio::ip::tcp;               // from <boost/asio/ip/tcp.hpp>
using udp = boost::asio::ip::udp;               // from <boost/asio/ip/udp.hpp>
namespace websocket = boost::beast::websocket;  // from <boost/beast/websocket.hpp>
using ws = websocket::stream<tcp::socket>;

using timer = boost::asio::basic_waitable_timer<time_clock::steady_clock>;

template<class ... T> inline constexpr bool always_false = false;

// 转换成字符串类型.
std::string to_string(const boost::posix_time::ptime& t);
std::string to_string(float v, int width, int precision = 3);

// base64编解码.
std::string base64_encode(std::string_view input);
std::string base64_decode(std::string_view input);

// 百分编码解码.
bool unescape_path(const std::string& in, std::string& out);

// 转换成存储单位.
std::string add_suffix(float val, char const* suffix = nullptr);

// 获取进程id.
uint64_t get_process_id();

// 随机字符串相关.
int gen_random_int(int start, int end);
std::string gen_unique_string(const unsigned int max_str_len);
uint32_t gen_unique_number();
std::string gen_uuid();

// 设置线程名.
void set_thread_name(const char* name);
void set_thread_name(boost::thread* thread, const char* name);

// google认证码相关.
int google_auth_code(const std::string& secret, unsigned long tm = 0, unsigned long duration = 30);
std::string google_code_to_string(int google_code);
std::string google_generate_secret();

// 用于解析listen使用的endpoint.
bool make_listen_endpoint(const std::string& address, tcp::endpoint& endp, boost::system::error_code& ec);
bool make_listen_endpoint(const std::string& address, udp::endpoint& endp, boost::system::error_code& ec);

bool same_ipv4_network(const boost::asio::ip::network_v4& net, uint32_t u32_addr);

// 设置local_ip所指定的设备的dns, 若local_ip为空, 则设定全局dns.
bool set_dns(const std::string& dns, std::string local_ip = "");

// 设置默认网络通过虚拟网络.
bool set_default_route(const std::string& vaddr, const std::string& vgateway,
	const std::string& gateway, const std::string& server_ip);

// 运行一个命令, 返回命令输出的信息.
std::tuple<std::string, bool> run_command(const std::string& cmd) noexcept;

// 添加或删除指定路由.
std::tuple<std::string, bool> add_route(const std::string& route);
std::tuple<std::string, bool> del_route(const std::string& route);


template <class RandomIt>
void rand_shuffle(RandomIt first, RandomIt last)
{
	static thread_local std::default_random_engine g =
		std::default_random_engine(std::random_device()());
	std::shuffle(first, last, g);
}

template <class Ty>
Ty rand_int(Ty first, Ty last)
{
	static thread_local std::default_random_engine g =
		std::default_random_engine(std::random_device()());
	std::uniform_int_distribution<Ty> uid(first, last);
	return uid(g);
}

template <class Ty>
Ty rand_discrete(std::initializer_list<Ty> ilist)
{
	static thread_local std::default_random_engine g =
		std::default_random_engine(std::random_device()());
	std::discrete_distribution<Ty> dd(ilist.begin(), ilist.end());
	return dd(g);
}

