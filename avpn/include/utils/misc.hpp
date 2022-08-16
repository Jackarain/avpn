//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#pragma once

#include "utils/internal.hpp"

#include "utils/uri_view.hpp"
#include "utils/io_context_pool.hpp"

#define APP_NAME "avpn"
#define HTTPD_VERSION_STRING	     APP_NAME "/1.0"

// 将一个string_view转成16进制的字符串.
std::string to_hex(std::string_view data);
std::string to_hex_prefixed(std::string_view data);

// 将1个16进制字符串转成vector<uint8_t>
bool from_hexstring(std::string_view src, std::vector<uint8_t>& result);

// 转换成字符串类型.
std::string to_string(const boost::posix_time::ptime& t);
std::string to_string(float v, int width, int precision = 3);

// base64编解码.
std::string base64_encode(std::string_view input);
std::string base64_decode(std::string_view input);

// base58编解码.
std::string base58_decode(std::string_view input);
std::string base58_encode(std::string_view input);

// 百分编码解码.
bool unescape_path(const std::string& in, std::string& out);

// 转换成存储单位.
std::string add_suffix(float val, char const* suffix = nullptr);

// 获取进程id.
uint64_t get_process_id();

#ifdef WIN32
#ifdef AVPN_USE_WINTUN

bool install_wintun();
HANDLE open_wintun(const std::string& name);

enum windows_driver_type {
	WINDOWS_DRIVER_UNSPECIFIED,
	WINDOWS_DRIVER_TAP_WINDOWS6,
	WINDOWS_DRIVER_WINTUN
};

struct windows_driver
{
	std::string name_;
	std::string guid_;
	windows_driver_type type_;
};

std::vector<windows_driver> enum_windows_devices();

#endif
#endif // WIN32

// 创建pid文件.
void create_pid(std::string suffix, std::filesystem::path pidfile = {});
// 检查pid文件.
uint64_t check_pid(std::string suffix);

// 随机字符串相关.
int gen_random_int(int start, int end);
std::string gen_unique_string(const unsigned int len);
uint32_t gen_unique_number();
std::string gen_uuid();

// 设置线程名.
void set_thread_name(const char* name);
void set_thread_name(std::thread* thread, const char* name);

// 用于解析listen使用的endpoint.
bool parse_endpoint_string(std::string_view str,
	std::string& host, std::string& port, bool& ipv6only);
bool make_listen_endpoint(const std::string& address,
	tcp::endpoint& endp, boost::system::error_code& ec);
bool make_listen_endpoint(const std::string& address,
	udp::endpoint& endp, boost::system::error_code& ec);

bool same_ipv4_network(const net::ip::network_v4& net, uint32_t u32_addr);

net::ip::network_v4
make_network(uint32_t u32_addr, unsigned short prefix_length);

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
