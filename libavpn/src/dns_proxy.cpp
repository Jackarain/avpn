//
// dns_proxy.cpp
// ~~~~~~~~~~~~~
//
// Copyright (c) 2026 Jack (jack dot wgm at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// tun 上 53 端口 DNS 拦截分流实现.
//

#include "libavpn/dns_proxy.hpp"
#include "libavpn/asio_util.hpp"
#include "libavpn/avpn_crypto.hpp"
#include "libavpn/dns_packet.hpp"
#include "libavpn/logging.hpp"
#include "libavpn/use_awaitable.hpp"
#include "httpc/httpc.hpp"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/post.hpp>
#include <boost/filesystem.hpp>
#include <boost/url.hpp>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
#include <sstream>

namespace libavpn {

namespace fs = boost::filesystem;
namespace urls = boost::urls;
namespace beast = boost::beast;
namespace http = beast::http;

namespace {

	// 判断字符串是否为合法域名 (小写字母/数字/点/连字符).
	bool is_valid_domain(const std::string& s)
	{
		if (s.empty() || s.size() > 253 || s.front() == '.' || s.back() == '.')
			return false;
		if (s.find('.') == std::string::npos)
			return false;
		for (char c : s)
		{
			if (!(std::isalnum(static_cast<unsigned char>(c))
				|| c == '.' || c == '-' || c == '_'))
				return false;
		}
		return true;
	}

	// 从 gfwlist 正则规则中尽力提取域名, 失败返回空串.
	std::string extract_domain_from_regex(const std::string& regex)
	{
		if (regex.size() < 3 || regex.front() != '/' || regex.back() != '/')
			return {};
		std::string body = regex.substr(1, regex.size() - 2);
		std::size_t i = 0;
		while (i < body.size())
		{
			unsigned char c = static_cast<unsigned char>(body[i]);
			if (std::isalnum(c))
			{
				std::size_t j = i;
				std::string cand;
				while (j < body.size())
				{
					char d = body[j];
					if (std::isalnum(static_cast<unsigned char>(d))
						|| d == '.' || d == '-' || d == '\\')
						cand.push_back(d);
					else
						break;
					j++;
				}
				// 去掉转义符 (如 \\.).
				std::string clean;
				for (std::size_t k = 0; k < cand.size(); k++)
				{
					if (cand[k] == '\\')
					{
						// 转义符后跟字符时消费该字符, 尾部孤立的 '\' 忽略.
						if (k + 1 < cand.size())
						{
							clean.push_back(cand[k + 1]);
							k++;
						}
					}
					else
						clean.push_back(cand[k]);
				}
				if (is_valid_domain(clean))
					return clean;
				i = j;
			}
			else
				i++;
		}
		return {};
	}

	// 去除空白字符.
	std::string strip_whitespace(std::string_view s)
	{
		std::string out;
		out.reserve(s.size());
		for (char c : s)
		{
			if (!std::isspace(static_cast<unsigned char>(c)))
				out.push_back(c);
		}
		return out;
	}

	// 百分号解码 URL 片段 (如 userinfo 中的 %2D).
	std::string pct_decode(const urls::pct_string_view& s)
	{
		auto hex = [](char h) -> int
		{
			if (h >= '0' && h <= '9')
				return h - '0';
			if (h >= 'a' && h <= 'f')
				return h - 'a' + 10;
			if (h >= 'A' && h <= 'F')
				return h - 'A' + 10;
			return -1;
		};
		std::string out;
		out.reserve(s.size());
		for (std::size_t i = 0; i < s.size(); i++)
		{
			char c = s[i];
			if (c == '%' && i + 2 < s.size())
			{
				int hi = hex(s[i + 1]);
				int lo = hex(s[i + 2]);
				if (hi >= 0 && lo >= 0)
				{
					out.push_back(static_cast<char>((hi << 4) | lo));
					i += 2;
					continue;
				}
			}
			out.push_back(c);
		}
		return out;
	}

	// 常见 DoH 服务器域名 -> IP (避免经系统 DNS 解析时被污染或回环).
	// 域名大小写不敏感, 统一转小写后查表.
	std::string known_doh_ip(const std::string& host)
	{
		static const std::unordered_map<std::string, std::string> table = {
			{ "cloudflare-dns.com", "1.1.1.1" },
			{ "one.one.one.one", "1.1.1.1" },
			{ "dns.google", "8.8.8.8" },
			{ "dns.alidns.com", "223.5.5.5" },
			{ "doh.pub", "1.12.12.12" },
			{ "doh.360.cn", "101.226.4.6" },
		};
		std::string key = host;
		std::transform(key.begin(), key.end(), key.begin(),
			[](unsigned char c) { return static_cast<char>(std::tolower(c)); });
		auto it = table.find(key);
		return it == table.end() ? std::string{} : it->second;
	}

} // namespace

dns_proxy::dns_proxy(net::io_context& ioc, const config& cfg,
	write_cb write_to_tun, protect_cb protect)
	: m_ioc(ioc)
	, m_cfg(cfg)
	, m_write_to_tun(std::move(write_to_tun))
	, m_protect(std::move(protect))
	, m_refresh_timer(ioc)
	, m_clean_timer(ioc)
{}

dns_proxy::~dns_proxy()
{
	XLOG_DBG << "dns_proxy::~dns_proxy()";
}

std::shared_ptr<dns_proxy> dns_proxy::create(
	net::io_context& ioc, const config& cfg,
	write_cb write_to_tun, protect_cb protect)
{
	return std::shared_ptr<dns_proxy>(
		new dns_proxy(ioc, cfg, std::move(write_to_tun), std::move(protect)));
}

void dns_proxy::start()
{
	auto self = shared_from_this();
	net::post(m_ioc, [self]()
		{
			if (self->m_abort)
				return;
			self->m_enabled = self->m_cfg.enabled;
			self->refresh_doh_host();
			self->load_gfwlist();
			net::co_spawn(self->m_ioc,
				[self]() -> net::awaitable<void>
				{
					co_await self->renew_direct_socket();
					co_return;
				}, net::detached);
			net::co_spawn(self->m_ioc,
				[self]() -> net::awaitable<void>
				{
					co_await self->gfwlist_refresh_loop();
					co_return;
				}, net::detached);
			net::co_spawn(self->m_ioc,
				[self]() -> net::awaitable<void>
				{
					co_await self->pending_clean_loop();
					co_return;
				}, net::detached);
		});
}

void dns_proxy::stop()
{
	m_abort = true;
	m_enabled = false;
	auto self = shared_from_this();
	net::post(m_ioc, [self]()
		{
			boost::system::error_code ec;
			asio_util::cancel(self->m_refresh_timer, ec);
			asio_util::cancel(self->m_clean_timer, ec);
			if (self->m_direct_socket)
			{
				self->m_direct_socket->cancel(ec);
				self->m_direct_socket->close(ec);
			}
			self->m_pending.clear();
			self->m_gfwlist.clear();
			self->m_gfwlist_exceptions.clear();
		});
}

void dns_proxy::update_config(const config& cfg)
{
	bool direct_changed = m_cfg.direct_dns != cfg.direct_dns;
	bool list_changed = m_cfg.gfwlist_url != cfg.gfwlist_url
		|| m_cfg.gfwlist_cache != cfg.gfwlist_cache;
	m_cfg = cfg;
	m_enabled = cfg.enabled;
	refresh_doh_host();

	if (direct_changed && !m_abort)
	{
		auto self = shared_from_this();
		net::co_spawn(m_ioc,
			[self]() -> net::awaitable<void>
			{
				co_await self->renew_direct_socket();
				co_return;
			}, net::detached);
	}
	if (list_changed && cfg.enabled && !cfg.gfwlist_url.empty() && !m_abort)
	{
		auto self = shared_from_this();
		net::co_spawn(m_ioc,
			[self]() -> net::awaitable<void>
			{
				co_await self->update_gfwlist();
				co_return;
			}, net::detached);
	}
}

//////////////////////////////////////////////////////////////////////////
// gfwlist 加载与更新

void dns_proxy::parse_gfwlist(const std::string& content)
{
	std::unordered_set<std::string> rules;
	std::unordered_set<std::string> exceptions;

	std::istringstream ss(content);
	std::string line;
	while (std::getline(ss, line))
	{
		// 去首尾空白.
		auto b = line.find_first_not_of(" \t\r\n");
		if (b == std::string::npos)
			continue;
		auto e = line.find_last_not_of(" \t\r\n");
		line = line.substr(b, e - b + 1);

		if (line.empty() || line[0] == '!')
			continue;

		bool is_exception = false;
		if (line.rfind("@@", 0) == 0)
		{
			is_exception = true;
			line = line.substr(2);
		}

		std::string domain;
		if (line.rfind("||", 0) == 0)
			domain = line.substr(2);
		else if (line.rfind("|http", 0) == 0 || line.rfind("|https", 0) == 0)
			domain = line.substr(1);
		else if (line[0] == '*')
			domain = line.substr(1);
		else if (line[0] == '.')
			domain = line.substr(1);
		else if (line[0] == '/' && line.back() == '/')
			domain = extract_domain_from_regex(line);
		else
			domain = line;

		// 去协议前缀与路径.
		auto proto = domain.find("://");
		if (proto != std::string::npos)
			domain = domain.substr(proto + 3);
		auto slash = domain.find('/');
		if (slash != std::string::npos)
			domain = domain.substr(0, slash);
		// 去通配符结尾 (如 example.com^).
		while (!domain.empty() && (domain.back() == '^'
			|| domain.back() == '*' || domain.back() == '.'))
			domain.pop_back();
		while (!domain.empty() && domain.front() == '*')
			domain.erase(domain.begin());

		if (!is_valid_domain(domain))
			continue;

		(is_exception ? exceptions : rules).insert(std::move(domain));
	}

	m_gfwlist = std::move(rules);
	m_gfwlist_exceptions = std::move(exceptions);
	XLOG_INFO << "gfwlist parsed: " << m_gfwlist.size()
		<< " rules, " << m_gfwlist_exceptions.size() << " exceptions";
}

bool dns_proxy::load_gfwlist_from_cache()
{
	if (m_cfg.gfwlist_cache.empty())
		return false;
	boost::system::error_code ec;
	if (!fs::exists(m_cfg.gfwlist_cache, ec) || ec)
		return false;
	std::ifstream f(m_cfg.gfwlist_cache, std::ios::binary);
	if (!f)
		return false;
	std::string content((std::istreambuf_iterator<char>(f)),
		std::istreambuf_iterator<char>());
	if (content.size() < 1024)
		return false;
	parse_gfwlist(content);
	XLOG_INFO << "gfwlist loaded from cache: " << m_cfg.gfwlist_cache;
	return true;
}

void dns_proxy::save_gfwlist_cache(const std::string& content)
{
	if (m_cfg.gfwlist_cache.empty())
		return;
	boost::system::error_code ec;
	if (!fs::exists(fs::path(m_cfg.gfwlist_cache).parent_path(), ec) || ec)
		return;
	std::string tmp = m_cfg.gfwlist_cache + ".tmp";
	std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
	if (!f)
		return;
	f.write(content.data(), static_cast<std::streamsize>(content.size()));
	f.close();
	if (f)
		fs::rename(tmp, m_cfg.gfwlist_cache, ec);
}

void dns_proxy::load_gfwlist()
{
	load_gfwlist_from_cache();

	// 缓存超过一天或不存在时异步拉取更新.
	bool fresh = false;
	if (!m_cfg.gfwlist_cache.empty())
	{
		boost::system::error_code ec;
		if (fs::exists(m_cfg.gfwlist_cache, ec) && !ec)
		{
			auto mtime = fs::last_write_time(m_cfg.gfwlist_cache, ec);
			if (!ec)
				fresh = std::time(nullptr) - static_cast<std::time_t>(mtime) < 24 * 3600;
		}
	}
	if (fresh || m_cfg.gfwlist_url.empty())
		return;

	auto self = shared_from_this();
	net::co_spawn(m_ioc,
		[self]() -> net::awaitable<void>
		{
			co_await self->update_gfwlist();
			co_return;
		}, net::detached);
}

net::awaitable<void> dns_proxy::update_gfwlist()
{
	if (m_abort || m_cfg.gfwlist_url.empty())
		co_return;

	httpc::http_client client(m_ioc.get_executor());
	client.timeout(std::chrono::seconds(20));
	client.connect_timeout(std::chrono::seconds(20));

	httpc::http_request req{ httpc::verb::get, "/", 11 };
	req.set(httpc::http::field::user_agent, "avpn-dns-proxy/1.0");

	auto result = co_await client.async_perform(m_cfg.gfwlist_url, req);
	if (!result)
	{
		XLOG_WARN << "gfwlist download failed: "
			<< result.error().message();
		co_return;
	}
	auto& resp = *result;
	if (resp.result_int() != 200)
	{
		XLOG_WARN << "gfwlist download http status: " << resp.result_int();
		co_return;
	}
	auto body = beast::buffers_to_string(resp.body().data());
	if (body.size() < 1024)
	{
		XLOG_WARN << "gfwlist download too small, ignored: " << body.size();
		co_return;
	}

	// gfwlist 官方格式为 base64 文本; 解码成功且内容符合规则特征
	// (注释/域名规则) 则用解码内容, 否则按纯文本处理 (兼容自建列表).
	std::string content;
	auto decoded = crypto::base64_decode(strip_whitespace(body));
	bool looks_like_rules = decoded.size() >= 1024
		&& (decoded.find("||") != std::string::npos
			|| decoded.find("@@") != std::string::npos
			|| decoded.find("\n!") != std::string::npos);
	if (looks_like_rules)
		content = std::move(decoded);
	else
		content = std::move(body);

	parse_gfwlist(content);
	save_gfwlist_cache(content);
	XLOG_INFO << "gfwlist updated from " << m_cfg.gfwlist_url;
}

net::awaitable<void> dns_proxy::gfwlist_refresh_loop()
{
	// 连续更新失败次数: 列表为空且失败未超限时缩短重试间隔,
	// 避免首次启动时网络尚未就绪导致长时间没有规则可用.
	int failures = 0;
	while (!m_abort)
	{
		std::chrono::seconds delay(24 * 3600);
		if (m_gfwlist.empty() && failures < 5)
			delay = std::chrono::seconds(60);

		boost::system::error_code ec;
		m_refresh_timer.expires_after(delay);
		co_await m_refresh_timer.async_wait(net_awaitable[ec]);
		if (m_abort)
			break;

		co_await update_gfwlist();
		if (m_gfwlist.empty())
			failures++;
		else
			failures = 0;
	}
}

void dns_proxy::refresh_doh_host()
{
	m_doh_host.clear();
	auto url_res = urls::parse_uri_reference(m_cfg.doh_url);
	if (!url_res)
		return;
	auto host = url_res->host();
	if (host.empty())
		return;
	m_doh_host = std::string(host);
	std::transform(m_doh_host.begin(), m_doh_host.end(),
		m_doh_host.begin(),
		[](unsigned char c) { return static_cast<char>(std::tolower(c)); });
}

bool dns_proxy::domain_in_gfwlist(const std::string& domain) const
{
	// 例外规则优先 (命中例外则放行直连).
	std::string suffix = domain;
	while (true)
	{
		if (m_gfwlist_exceptions.count(suffix))
			return false;
		auto dot = suffix.find('.');
		if (dot == std::string::npos)
			break;
		suffix = suffix.substr(dot + 1);
	}

	suffix = domain;
	while (true)
	{
		if (m_gfwlist.count(suffix))
			return true;
		auto dot = suffix.find('.');
		if (dot == std::string::npos)
			break;
		suffix = suffix.substr(dot + 1);
	}
	return false;
}

//////////////////////////////////////////////////////////////////////////
// 直连 DNS

net::awaitable<void> dns_proxy::renew_direct_socket()
{
	if (m_abort)
		co_return;

	boost::system::error_code ec;

	auto old = m_direct_socket;
	if (old)
	{
		old->cancel(ec);
		old->close(ec);
	}

	// 解析直连 DNS 地址 (支持 "ip" 或 "ip:port").
	std::string host = m_cfg.direct_dns;
	std::string port = "53";
	auto colon = host.rfind(':');
	if (colon != std::string::npos && host.find(':') == colon)
	{
		port = host.substr(colon + 1);
		host = host.substr(0, colon);
	}

	net::ip::udp::resolver resolver(m_ioc);
	auto results = co_await resolver.async_resolve(host, port, net_awaitable[ec]);
	if (ec || results.empty())
	{
		XLOG_ERR << "dns direct resolve " << m_cfg.direct_dns
			<< " failed: " << ec.message();
		co_return;
	}

	auto ep = *results.begin();
	auto socket = std::make_shared<net::ip::udp::socket>(m_ioc);
	socket->open(ep.endpoint().protocol(), ec);
	if (ec)
	{
		XLOG_ERR << "dns direct socket open failed: " << ec.message();
		co_return;
	}

	// 放行对外 socket (Android VpnService), 避免直连 DNS 流量回环进 tun.
	if (m_protect)
	{
		if (!(co_await m_protect(socket->native_handle())))
			XLOG_WARN << "protect dns direct socket failed";
	}

	socket->connect(ep, ec);
	if (ec)
	{
		XLOG_ERR << "dns direct connect " << m_cfg.direct_dns
			<< " failed: " << ec.message();
		socket->close(ec);
		co_return;
	}

	m_direct_socket = socket;
	m_direct_ep = ep;

	if (!m_direct_loop_started)
	{
		m_direct_loop_started = true;
		auto self = shared_from_this();
		net::co_spawn(m_ioc,
			[self]() -> net::awaitable<void>
			{
				co_await self->direct_receive_loop();
				co_return;
			}, net::detached);
	}

	XLOG_INFO << "dns direct socket ready: " << m_cfg.direct_dns;
}

net::awaitable<void> dns_proxy::direct_receive_loop()
{
	while (!m_abort)
	{
		// 每次迭代取当前 socket: 热更新直连 DNS 后旧 socket 关闭,
		// 循环需自动切换到新 socket 继续接收回复.
		auto sock = m_direct_socket;
		if (!sock || !sock->is_open())
			break;
		std::vector<uint8_t> buf(65536);
		boost::system::error_code ec;
		std::size_t n = co_await sock->async_receive(
			net::buffer(buf), net_awaitable[ec]);
		if (m_abort)
			break;
		if (ec)
		{
			if (sock != m_direct_socket)
				continue; // socket 已重建, 使用新 socket 继续.
			// 当前 socket 出错 (网络切换/上游不可达): 短暂等待后重建,
			// 避免直连 DNS 路径永久失效.
			boost::system::error_code ignore;
			net::steady_timer t(m_ioc);
			t.expires_after(std::chrono::seconds(3));
			co_await t.async_wait(net_awaitable[ignore]);
			if (m_abort)
				break;
			co_await renew_direct_socket();
			continue;
		}
		on_direct_reply(buf.data(), n);
	}
}

net::awaitable<void> dns_proxy::pending_clean_loop()
{
	while (!m_abort)
	{
		boost::system::error_code ec;
		m_clean_timer.expires_after(std::chrono::seconds(1));
		co_await m_clean_timer.async_wait(net_awaitable[ec]);
		if (m_abort)
			break;
		auto now = std::chrono::steady_clock::now();
		for (auto it = m_pending.begin(); it != m_pending.end();)
		{
			if (now - it->second.at > std::chrono::seconds(5))
				it = m_pending.erase(it);
			else
				++it;
		}
	}
}

namespace {

	// 从 IP 包提取客户端端点字符串 "ip:port" (小写), 用于区分不同客户端的
	// 相同事务 ID 查询; 解析失败返回空串 (仅 IPv4/IPv6 无扩展头 UDP).
	std::string client_endpoint(const std::vector<uint8_t>& ip_packet)
	{
		if (ip_packet.size() < 28)
			return {};
		const uint8_t* ip = ip_packet.data();
		std::size_t udp_off = 0;
		uint16_t port = 0;
		std::string addr;
		if (((ip[0] >> 4) & 0x0f) == 4)
		{
			udp_off = (ip[0] & 0x0f) * 4;
			if (udp_off < 20 || ip_packet.size() < udp_off + 8)
				return {};
			addr = std::to_string(ip[12]) + "." + std::to_string(ip[13])
				+ "." + std::to_string(ip[14]) + "." + std::to_string(ip[15]);
		}
		else if (((ip[0] >> 4) & 0x0f) == 6)
		{
			if (ip[6] != 17 || ip_packet.size() < 40 + 8)
				return {};
			udp_off = 40;
			addr = "v6:";
			for (int i = 0; i < 16; i += 2)
			{
				char buf[8];
				std::snprintf(buf, sizeof(buf), "%02x%02x", ip[8 + i], ip[9 + i]);
				addr += buf;
			}
		}
		else
			return {};
		port = (static_cast<uint16_t>(ip[udp_off]) << 8) | ip[udp_off + 1];
		return addr + ":" + std::to_string(port);
	}

} // namespace

void dns_proxy::forward_direct(const std::vector<uint8_t>& ip_packet,
	const uint8_t* dns_msg, std::size_t dns_len)
{
	if (!m_direct_socket || !m_direct_socket->is_open())
		return;
	if (m_pending.size() >= 1024)
	{
		XLOG_WARN << "dns direct pending full, drop query";
		return;
	}

	uint16_t id = (static_cast<uint16_t>(dns_msg[0]) << 8) | dns_msg[1];
	auto key = std::make_pair(id, client_endpoint(ip_packet));
	if (key.second.empty())
		return;
	m_pending[key] = pending_query{ ip_packet,
		std::chrono::steady_clock::now() };

	boost::system::error_code ec;
	m_direct_socket->send(net::buffer(dns_msg, dns_len), 0, ec);
	if (ec)
	{
		m_pending.erase(key);
		XLOG_WARN << "dns direct forward failed: " << ec.message();
	}
}

void dns_proxy::on_direct_reply(const uint8_t* msg, std::size_t len)
{
	if (len < 12 || m_pending.empty())
		return;
	uint16_t id = (static_cast<uint16_t>(msg[0]) << 8) | msg[1];
	// 回复不携带客户端端点, 只能按事务 ID 匹配; 同一 ID 可能有多个客户端
	// 挂起, 取最早注册的 (对端通常按序应答, 早注册者先得到回复).
	auto it = m_pending.lower_bound(std::make_pair(id, std::string{}));
	if (it == m_pending.end() || it->first.first != id)
		return;
	auto best = it;
	for (auto cur = it; cur != m_pending.end() && cur->first.first == id; ++cur)
	{
		if (cur->second.at < best->second.at)
			best = cur;
	}
	auto ip_packet = std::move(best->second.ip_packet);
	m_pending.erase(best);
	reply_to_tun(ip_packet, msg, len);
}

//////////////////////////////////////////////////////////////////////////
// DoH 查询

net::awaitable<void> dns_proxy::doh_query(
	std::vector<uint8_t> ip_packet, const std::string& qname)
{
	// 定位原始 DNS 请求消息 (on_tun_packet 已校验过, 此处必然命中).
	const uint8_t* dns_msg = nullptr;
	std::size_t dns_len = 0;
	if (!dns_packet::locate_udp53(ip_packet, dns_msg, dns_len))
		co_return;

	// 解析 DoH 地址.
	auto url_res = urls::parse_uri_reference(m_cfg.doh_url);
	if (!url_res)
	{
		XLOG_ERR << "invalid doh url: " << m_cfg.doh_url;
		co_return;
	}
	auto url = *url_res;
	std::string doh_host(url.host());
	if (doh_host.empty())
		co_return;

	// 以 URL 路径作为请求目标; 无路径时补全 /dns-query. 常见 DoH
	// 域名映射为 IP 直连, 避免系统 DNS 解析被污染或回环.
	std::string url_str = m_cfg.doh_url;
	try
	{
		auto mutable_url = urls::url(m_cfg.doh_url);
		if (mutable_url.encoded_path().empty()
			|| mutable_url.encoded_path() == "/")
		{
			mutable_url.set_path("/dns-query");
		}
		auto ip = known_doh_ip(doh_host);
		if (!ip.empty() && mutable_url.host() != ip)
			mutable_url.set_host(ip);
		url_str = mutable_url.buffer();
	}
	catch (const std::exception&)
	{}

	httpc::http_client client(m_ioc.get_executor());
	client.timeout(std::chrono::seconds(10));
	client.connect_timeout(std::chrono::seconds(10));
	client.set_sni(doh_host);

	httpc::http_request req{ httpc::verb::post, "/dns-query", 11 };
	req.set(httpc::http::field::host, doh_host);
	req.set(httpc::http::field::content_type, "application/dns-message");
	req.set(httpc::http::field::accept, "application/dns-message");
	// URL userinfo (user:pass) -> HTTP Basic 认证.
	if (url.has_userinfo())
	{
		auto user = pct_decode(url.user());
		auto pass = pct_decode(url.password());
		auto token = crypto::base64_encode(user + ":" + pass);
		if (!token.empty())
			req.set(httpc::http::field::authorization, "Basic " + token);
	}
	req.body().assign(reinterpret_cast<const char*>(dns_msg), dns_len);
	req.prepare_payload();

	auto result = co_await client.async_perform(url_str, req);
	if (!result)
	{
		XLOG_WARN << "doh query failed for " << qname
			<< ": " << result.error().message();
		co_return;
	}
	auto& resp = *result;
	if (resp.result_int() != 200)
	{
		XLOG_WARN << "doh query http status " << resp.result_int()
			<< " for " << qname;
		co_return;
	}
	auto body = beast::buffers_to_string(resp.body().data());
	if (body.size() < 12)
		co_return;
	reply_to_tun(ip_packet,
		reinterpret_cast<const uint8_t*>(body.data()), body.size());
}

//////////////////////////////////////////////////////////////////////////
// tun 拦截与回复



bool dns_proxy::on_tun_packet(std::vector<uint8_t> ip_packet)
{
	if (!m_enabled.load() || m_abort.load())
		return false;

	const uint8_t* dns = nullptr;
	std::size_t dns_len = 0;
	if (!dns_packet::locate_udp53(ip_packet, dns, dns_len))
		return false;

	// 仅拦截标准查询 (QR=0, opcode=0, 至少一个问题).
	uint16_t flags = (static_cast<uint16_t>(dns[2]) << 8) | dns[3];
	uint16_t qdcount = (static_cast<uint16_t>(dns[4]) << 8) | dns[5];
	if ((flags & 0x8000) != 0 || ((flags >> 11) & 0x0f) != 0 || qdcount == 0)
		return false;

	std::string qname;
	if (!dns_packet::parse_qname(dns, dns_len, qname))
		return false;

	// 对 DoH 服务自身域名的解析查询不拦截 (交回正常转发, 由对端解析),
	// 避免自定义 DoH 域名在 gfwlist 中时形成 DoH 自递归.
	if (!m_doh_host.empty()
		&& (qname == m_doh_host
			|| (qname.size() > m_doh_host.size() + 1
				&& qname.compare(qname.size() - m_doh_host.size() - 1,
					m_doh_host.size() + 1, "." + m_doh_host) == 0)))
		return false;

	if (domain_in_gfwlist(qname))
	{
		// 命中 gfwlist: 走 DoH 加密解析.
		if (m_doh_inflight.load() < m_doh_max_inflight)
		{
			m_doh_inflight++;
			auto self = shared_from_this();
			net::co_spawn(m_ioc,
				[self, pkt = std::move(ip_packet), qname]() mutable
					-> net::awaitable<void>
				{
					struct inflight_guard
					{
						std::atomic_uint& counter;
						~inflight_guard() { counter--; }
					} guard{ self->m_doh_inflight };
					co_await self->doh_query(std::move(pkt), qname);
					co_return;
				}, net::detached);
		}
		else
		{
			XLOG_WARN << "dns doh inflight limit reached, drop: " << qname;
		}
	}
	else
	{
		// 未命中: 直连国内 DNS.
		forward_direct(ip_packet, dns, dns_len);
	}
	return true;
}

void dns_proxy::reply_to_tun(const std::vector<uint8_t>& ip_packet,
	const uint8_t* dns_msg, std::size_t dns_len)
{
	if (!m_write_to_tun)
		return;

	std::vector<uint8_t> out;
	if (!dns_packet::build_reply(ip_packet, dns_msg, dns_len, out))
		return;
	m_write_to_tun(std::move(out));
}

} // namespace libavpn
