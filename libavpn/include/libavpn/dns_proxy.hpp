//
// dns_proxy.hpp
// ~~~~~~~~~~~~~
//
// Copyright (c) 2026 Jack (jack dot wgm at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// tun 上 53 端口 DNS 拦截分流.
// 拦截本地 DNS 请求并解析目标域名: 命中 gfwlist 的域名改用 DoH 加密解析,
// 其余域名经 Android protect 直通的 UDP socket 转发给国内 DNS, 回复重组为
// 标准 DNS 包写回 tun, 兼顾防污染与国内网站解析速度.
//

#ifndef INCLUDE__2026_08_22__DNS_PROXY_HPP
#define INCLUDE__2026_08_22__DNS_PROXY_HPP

#include <boost/asio/io_context.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/steady_timer.hpp>

#include <atomic>
#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace libavpn {

namespace net = boost::asio;

class dns_proxy
	: public std::enable_shared_from_this<dns_proxy>
{
public:
	struct config
	{
		// 是否启用 DNS 拦截.
		bool enabled{ false };

		// DoH 服务地址, 如 https://1.1.1.1/dns-query.
		std::string doh_url{ "https://1.1.1.1/dns-query" };

		// 直连 DNS 服务器, 支持 "ip" 或 "ip:port", 默认 114.114.114.114.
		std::string direct_dns{ "114.114.114.114" };

		// gfwlist 下载地址.
		std::string gfwlist_url{
			"https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt" };

		// gfwlist 缓存文件路径, 为空则不落盘缓存.
		std::string gfwlist_cache;
	};

	// 写回 tun 的回调 (须在 io_context 线程调用).
	using write_cb = std::function<void(std::vector<uint8_t>)>;
	// 放行对外 socket 的回调 (Android VpnService), 返回 false 表示未放行.
	using protect_cb = std::function<net::awaitable<bool>(int)>;

	static std::shared_ptr<dns_proxy> create(
		net::io_context& ioc, const config& cfg,
		write_cb write_to_tun, protect_cb protect);

	~dns_proxy();

	// 启动: 加载 gfwlist 缓存, 打开直连 socket, 启动每日更新循环.
	void start();

	// 停止: 关闭所有资源, 协程自然退出.
	void stop();

	// 热更新配置 (io_context 线程调用).
	void update_config(const config& cfg);

	bool enabled() const { return m_enabled; }

	// 处理 tun 中读到的 IP 包 (仅 UDP/53), 返回 true 表示已消费拦截.
	// 须在 io_context 线程调用.
	bool on_tun_packet(std::vector<uint8_t> ip_packet);

private:
	dns_proxy(net::io_context& ioc, const config& cfg,
		write_cb write_to_tun, protect_cb protect);

	// 加载 gfwlist: 先读缓存, 再异步检查是否需要更新.
	void load_gfwlist();

	// 从字符串解析 gfwlist 规则并重建匹配集.
	void parse_gfwlist(const std::string& content);

	// 从缓存文件加载 gfwlist.
	bool load_gfwlist_from_cache();

	// 写 gfwlist 到缓存文件 (原子替换).
	void save_gfwlist_cache(const std::string& content);

	// 异步下载并更新 gfwlist.
	net::awaitable<void> update_gfwlist();

	// 每日更新循环.
	net::awaitable<void> gfwlist_refresh_loop();

	// 域名是否命中 gfwlist (true=命中), 例外规则优先.
	bool domain_in_gfwlist(const std::string& domain) const;

	// 打开/重建直连 DNS socket (protect 后 connect 到 direct_dns).
	net::awaitable<void> renew_direct_socket();

	// 直连 DNS 接收循环.
	net::awaitable<void> direct_receive_loop();

	// 超时清理循环.
	net::awaitable<void> pending_clean_loop();

	// 发起 DoH 查询并写回 tun.
	net::awaitable<void> doh_query(
		std::vector<uint8_t> ip_packet, const std::string& qname);

	// 将 DNS 回复重组为 IP 包写回 tun.
	void reply_to_tun(const std::vector<uint8_t>& ip_packet,
		const uint8_t* dns_msg, std::size_t dns_len);

	// 从 doh_url 提取并缓存 DoH 主机名 (小写).
	void refresh_doh_host();

	// 直连转发: 发送 DNS 消息并记录 pending.
	void forward_direct(const std::vector<uint8_t>& ip_packet,
		const uint8_t* dns_msg, std::size_t dns_len);

	// 处理直连 socket 收到的 DNS 回复.
	void on_direct_reply(const uint8_t* msg, std::size_t len);

private:
	// io_context (单线程).
	net::io_context& m_ioc;

	// 运行配置.
	config m_cfg;

	// 写回 tun 回调.
	write_cb m_write_to_tun;
	// protect 回调.
	protect_cb m_protect;

	// 中止标志.
	std::atomic_bool m_abort{ false };
	// 启用开关 (供 tun 拦截快速判断).
	std::atomic_bool m_enabled{ false };

	// gfwlist 域名后缀集合 (小写, 不含首点).
	std::unordered_set<std::string> m_gfwlist;
	// gfwlist 例外域名后缀集合.
	std::unordered_set<std::string> m_gfwlist_exceptions;

	// 直连 DNS socket.
	std::shared_ptr<net::ip::udp::socket> m_direct_socket;
	// 直连 DNS endpoint.
	net::ip::udp::endpoint m_direct_ep;

	// 直连接收循环是否已启动.
	bool m_direct_loop_started{ false };

	// 挂起查询: (DNS 事务 ID, 客户端地址:端口) -> 原始请求 IP 包 + 时间戳.
	// 以客户端端点区分, 避免不同客户端相同事务 ID 的回复互相串扰.
	struct pending_query
	{
		std::vector<uint8_t> ip_packet;
		std::chrono::steady_clock::time_point at;
	};
	std::map<std::pair<uint16_t, std::string>, pending_query> m_pending;

	// DoH 进行中并发计数 (防止恶意流量打爆连接).
	std::atomic_uint m_doh_inflight{ 0 };
	static constexpr unsigned m_doh_max_inflight{ 16 };

	// DoH 服务主机名 (小写). 用于跳过对 DoH 自身的解析查询, 避免递归.
	std::string m_doh_host;

	// 定时器: gfwlist 每日更新.
	net::steady_timer m_refresh_timer;
	// 定时器: 挂起查询超时清理.
	net::steady_timer m_clean_timer;
};

} // namespace libavpn

#endif // INCLUDE__2026_08_22__DNS_PROXY_HPP
