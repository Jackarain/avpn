#include "libavpn/netlink_route.hpp"

#if defined(__linux__)

#include <linux/rtnetlink.h>
#include <net/if.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

namespace libavpn {
namespace {

	// 打开 NETLINK_ROUTE 套接字并绑定, 类似 iproute2 的 rtnl_open.
	static int nl_open()
	{
		int fd = ::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
		if (fd < 0)
			return -1;

		struct sockaddr_nl addr;
		std::memset(&addr, 0, sizeof(addr));
		addr.nl_family = AF_NETLINK;
		if (::bind(fd, reinterpret_cast<struct sockaddr*>(&addr),
				sizeof(addr)) < 0)
		{
			::close(fd);
			return -1;
		}

		// 防止意外情况下 recv 永久阻塞 (与 iproute2 的 rtnl_talk 超时行为一致).
		struct timeval tv;
		tv.tv_sec = 2;
		tv.tv_usec = 0;
		::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
		return fd;
	}

	// 生成消息序列号, 用于过滤本进程的响应.
	static unsigned int nl_next_seq()
	{
		static unsigned int seq = 0;
		return ++seq;
	}

	// 向内核发送 netlink 请求.
	static bool nl_send_request(int fd, struct nlmsghdr* nlh)
	{
		struct sockaddr_nl addr;
		std::memset(&addr, 0, sizeof(addr));
		addr.nl_family = AF_NETLINK;

		if (::sendto(fd, nlh, nlh->nlmsg_len, 0,
				reinterpret_cast<struct sockaddr*>(&addr),
				sizeof(addr)) < 0)
			return false;
		return true;
	}

	// 执行路由修改操作 (RTM_NEWROUTE/RTM_DELROUTE), 等待内核确认.
	static bool nl_change(int fd, struct nlmsghdr* n, std::string& err)
	{
		n->nlmsg_seq = nl_next_seq();
		if (!nl_send_request(fd, n))
		{
			err = std::strerror(errno);
			return false;
		}

		char buf[8192];
		for (;;)
		{
			ssize_t len = ::recv(fd, buf, sizeof(buf), 0);
			if (len < 0)
			{
				if (errno == EINTR)
					continue;
				err = std::strerror(errno);
				return false;
			}

			for (struct nlmsghdr* h = reinterpret_cast<struct nlmsghdr*>(buf);
				NLMSG_OK(h, len); h = NLMSG_NEXT(h, len))
			{
				if (h->nlmsg_seq != n->nlmsg_seq)
					continue;
				if (h->nlmsg_type == NLMSG_ERROR)
				{
					struct nlmsgerr* e =
						reinterpret_cast<struct nlmsgerr*>(NLMSG_DATA(h));
					if (e->error == 0)
						return true;
					err = std::strerror(-e->error);
					return false;
				}
			}
		}
	}

	// 追加路由属性.
#if defined(__GNUC__) && !defined(__clang__)
	// GCC 无法理解 RTA_DATA 基于 NLMSG_ALIGN 的对齐偏移, 对 netlink
	// 惯用法误报 -Wstringop-overflow (属性实际写入 req.buf, 未越界).
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstringop-overflow"
#endif
	static void addattr_l(struct nlmsghdr* n, unsigned int maxlen, int type,
		const void* data, int alen)
	{
		int len = RTA_LENGTH(alen);
		if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > maxlen)
			return;

		struct rtattr* rta = reinterpret_cast<struct rtattr*>(
			reinterpret_cast<char*>(n) + NLMSG_ALIGN(n->nlmsg_len));
		rta->rta_type = type;
		rta->rta_len = len;
		if (alen)
			std::memcpy(RTA_DATA(rta), data, alen);
		n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);
	}
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif

	// 构造路由请求 (RTM_NEWROUTE/RTM_DELROUTE).
	static void build_route_request(struct nlmsghdr* n, int type,
		const nl_route_entry& rt)
	{
		n->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
		n->nlmsg_type = type;
		n->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
		if (type == RTM_NEWROUTE)
			n->nlmsg_flags |= NLM_F_CREATE | NLM_F_REPLACE;

		struct rtmsg* r = reinterpret_cast<struct rtmsg*>(NLMSG_DATA(n));
		std::memset(r, 0, sizeof(*r));
		r->rtm_family = static_cast<unsigned char>(rt.family);
		r->rtm_dst_len = static_cast<unsigned char>(rt.prefix);
		r->rtm_table = RT_TABLE_MAIN;
		r->rtm_protocol = RTPROT_BOOT;
		r->rtm_scope = rt.scope ?
			static_cast<unsigned char>(rt.scope) :
			static_cast<unsigned char>(rt.gateway.empty() ?
				RT_SCOPE_LINK : RT_SCOPE_UNIVERSE);
		r->rtm_type = RTN_UNICAST;

		if (!rt.dst.empty())
		{
			if (rt.family == AF_INET)
			{
				struct in_addr addr;
				if (::inet_pton(AF_INET, rt.dst.c_str(), &addr) == 1)
					addattr_l(n, 512, RTA_DST, &addr, sizeof(addr));
			}
			else if (rt.family == AF_INET6)
			{
				struct in6_addr addr;
				if (::inet_pton(AF_INET6, rt.dst.c_str(), &addr) == 1)
					addattr_l(n, 512, RTA_DST, &addr, sizeof(addr));
			}
		}
		if (!rt.gateway.empty())
		{
			if (rt.family == AF_INET)
			{
				struct in_addr addr;
				if (::inet_pton(AF_INET, rt.gateway.c_str(), &addr) == 1)
					addattr_l(n, 512, RTA_GATEWAY, &addr, sizeof(addr));
			}
			else if (rt.family == AF_INET6)
			{
				struct in6_addr addr;
				if (::inet_pton(AF_INET6, rt.gateway.c_str(), &addr) == 1)
					addattr_l(n, 512, RTA_GATEWAY, &addr, sizeof(addr));
			}
		}
		if (!rt.ifname.empty())
		{
			unsigned int idx = ::if_nametoindex(rt.ifname.c_str());
			if (idx)
				addattr_l(n, 512, RTA_OIF, &idx, sizeof(idx));
		}
		if (rt.metric >= 0)
		{
			unsigned int metric = static_cast<unsigned int>(rt.metric);
			addattr_l(n, 512, RTA_PRIORITY, &metric, sizeof(metric));
		}
	}

	// 解析 netlink 消息中的路由表项.
	static bool parse_route(struct nlmsghdr* h, nl_route_entry& out)
	{
		struct rtmsg* r = reinterpret_cast<struct rtmsg*>(NLMSG_DATA(h));
		int len = static_cast<int>(h->nlmsg_len) -
			static_cast<int>(NLMSG_LENGTH(sizeof(struct rtmsg)));

		out.family = r->rtm_family;
		out.prefix = r->rtm_dst_len;
		out.scope = r->rtm_scope;
		out.metric = -1;

		struct rtattr* tb[RTA_MAX + 1];
		std::memset(tb, 0, sizeof(tb));

		for (struct rtattr* a = reinterpret_cast<struct rtattr*>(
				reinterpret_cast<char*>(r) +
				NLMSG_ALIGN(sizeof(struct rtmsg)));
			RTA_OK(a, len); a = RTA_NEXT(a, len))
		{
			if (a->rta_type <= RTA_MAX)
				tb[a->rta_type] = a;
		}

		char buf[INET6_ADDRSTRLEN];
		if (tb[RTA_DST])
		{
			if (r->rtm_family == AF_INET && RTA_PAYLOAD(tb[RTA_DST]) >= 4 &&
				::inet_ntop(AF_INET, RTA_DATA(tb[RTA_DST]), buf, sizeof(buf)))
				out.dst = buf;
			else if (r->rtm_family == AF_INET6 &&
				RTA_PAYLOAD(tb[RTA_DST]) >= 16 &&
				::inet_ntop(AF_INET6, RTA_DATA(tb[RTA_DST]), buf, sizeof(buf)))
				out.dst = buf;
		}
		if (tb[RTA_GATEWAY])
		{
			if (r->rtm_family == AF_INET && RTA_PAYLOAD(tb[RTA_GATEWAY]) >= 4 &&
				::inet_ntop(AF_INET, RTA_DATA(tb[RTA_GATEWAY]), buf, sizeof(buf)))
				out.gateway = buf;
			else if (r->rtm_family == AF_INET6 &&
				RTA_PAYLOAD(tb[RTA_GATEWAY]) >= 16 &&
				::inet_ntop(AF_INET6, RTA_DATA(tb[RTA_GATEWAY]), buf, sizeof(buf)))
				out.gateway = buf;
		}
		if (tb[RTA_OIF] && RTA_PAYLOAD(tb[RTA_OIF]) >= sizeof(unsigned int))
		{
			unsigned int idx = 0;
			std::memcpy(&idx, RTA_DATA(tb[RTA_OIF]), sizeof(idx));
			char ifname[IFNAMSIZ];
			if (::if_indextoname(idx, ifname))
				out.ifname = ifname;
		}
		if (tb[RTA_PRIORITY] && RTA_PAYLOAD(tb[RTA_PRIORITY]) >= sizeof(unsigned int))
		{
			unsigned int metric = 0;
			std::memcpy(&metric, RTA_DATA(tb[RTA_PRIORITY]), sizeof(metric));
			out.metric = static_cast<int>(metric);
		}
		return true;
	}

} // namespace

	bool nl_route_replace(const nl_route_entry& rt, std::string& err)
	{
		int fd = nl_open();
		if (fd < 0)
		{
			err = std::strerror(errno);
			return false;
		}

		struct { struct nlmsghdr n; struct rtmsg r; char buf[512]; } req;
		std::memset(&req, 0, sizeof(req));
		build_route_request(&req.n, RTM_NEWROUTE, rt);

		bool ok = nl_change(fd, &req.n, err);
		::close(fd);
		return ok;
	}

	bool nl_route_delete(const nl_route_entry& rt, std::string& err)
	{
		int fd = nl_open();
		if (fd < 0)
		{
			err = std::strerror(errno);
			return false;
		}

		struct { struct nlmsghdr n; struct rtmsg r; char buf[512]; } req;
		std::memset(&req, 0, sizeof(req));
		build_route_request(&req.n, RTM_DELROUTE, rt);

		bool ok = nl_change(fd, &req.n, err);
		::close(fd);
		return ok;
	}

	bool nl_route_dump_default(std::vector<nl_route_entry>& out, std::string& err)
	{
		int fd = nl_open();
		if (fd < 0)
		{
			err = std::strerror(errno);
			return false;
		}

		struct { struct nlmsghdr n; struct rtmsg r; } req;
		std::memset(&req, 0, sizeof(req));
		req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
		req.n.nlmsg_type = RTM_GETROUTE;
		req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
		req.n.nlmsg_seq = nl_next_seq();
		req.r.rtm_family = AF_INET;
		req.r.rtm_table = RT_TABLE_MAIN;

		if (!nl_send_request(fd, &req.n))
		{
			err = std::strerror(errno);
			::close(fd);
			return false;
		}

		char buf[32768];
		out.clear();
		for (;;)
		{
			ssize_t len = ::recv(fd, buf, sizeof(buf), 0);
			if (len < 0)
			{
				if (errno == EINTR)
					continue;
				err = std::strerror(errno);
				::close(fd);
				return false;
			}

			for (struct nlmsghdr* h = reinterpret_cast<struct nlmsghdr*>(buf);
				NLMSG_OK(h, len); h = NLMSG_NEXT(h, len))
			{
				if (h->nlmsg_seq != req.n.nlmsg_seq)
					continue;
				if (h->nlmsg_type == NLMSG_DONE)
				{
					::close(fd);
					return true;
				}
				if (h->nlmsg_type == NLMSG_ERROR)
				{
					struct nlmsgerr* e =
						reinterpret_cast<struct nlmsgerr*>(NLMSG_DATA(h));
					err = e->error ? std::strerror(-e->error) : "netlink error";
					::close(fd);
					return false;
				}
				if (h->nlmsg_type != RTM_NEWROUTE)
					continue;

				const struct rtmsg* r =
					reinterpret_cast<const struct rtmsg*>(NLMSG_DATA(h));
				if (r->rtm_dst_len != 0 || r->rtm_table != RT_TABLE_MAIN)
					continue;

				nl_route_entry entry;
				parse_route(h, entry);
				out.push_back(entry);
			}
		}
	}

	std::string nl_route_to_string(const nl_route_entry& rt)
	{
		std::string s;
		if (rt.prefix == 0)
			s = "default";
		else if (!rt.dst.empty())
			s = rt.dst + "/" + std::to_string(rt.prefix);
		else
			s = "route";

		if (!rt.gateway.empty())
			s += " via " + rt.gateway;
		if (!rt.ifname.empty())
			s += " dev " + rt.ifname;
		if (rt.metric >= 0)
			s += " metric " + std::to_string(rt.metric);
		return s;
	}

} // namespace libavpn

#else // !defined(__linux__)

namespace libavpn {

	bool nl_route_replace(const nl_route_entry& rt, std::string& err)
	{
		(void)rt;
		err = "netlink route not supported on this platform";
		return false;
	}

	bool nl_route_delete(const nl_route_entry& rt, std::string& err)
	{
		(void)rt;
		err = "netlink route not supported on this platform";
		return false;
	}

	bool nl_route_dump_default(std::vector<nl_route_entry>& out, std::string& err)
	{
		(void)out;
		err = "netlink route not supported on this platform";
		return false;
	}

	std::string nl_route_to_string(const nl_route_entry& rt)
	{
		std::string s;
		if (rt.prefix == 0)
			s = "default";
		else if (!rt.dst.empty())
			s = rt.dst + "/" + std::to_string(rt.prefix);
		else
			s = "route";
		if (!rt.gateway.empty())
			s += " via " + rt.gateway;
		if (!rt.ifname.empty())
			s += " dev " + rt.ifname;
		if (rt.metric >= 0)
			s += " metric " + std::to_string(rt.metric);
		return s;
	}

} // namespace libavpn

#endif // defined(__linux__)
