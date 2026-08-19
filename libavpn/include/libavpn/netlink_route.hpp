//
// netlink_route.hpp
// ~~~~~~~~~~~~~~~~~
//
// Copyright (C) 2026 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#ifndef INCLUDE__2026_08_19__NETLINK_ROUTE_HPP
#define INCLUDE__2026_08_19__NETLINK_ROUTE_HPP

#include <string>
#include <vector>

namespace libavpn {

	// Linux 平台下基于 Netlink 套接字的路由表操作 (类似 iproute2 的实现方式).
	// 在非 Linux 平台上这些接口保持可用, 但操作返回 false.
	struct nl_route_entry
	{
		int family{ 0 };          // AF_INET / AF_INET6.
		std::string dst;          // 目的地址, 空表示未指定.
		int prefix{ 0 };          // 前缀长度.
		std::string gateway;      // 下一跳地址, 空表示直连.
		std::string ifname;       // 出接口名, 空表示未指定.
		int metric{ -1 };         // 路由优先级 (RTA_PRIORITY), -1 表示未指定.
		int scope{ 0 };           // 路由 scope, 0 表示按 gateway 自动选择.
	};

	// 添加或替换路由 (RTM_NEWROUTE + NLM_F_CREATE|NLM_F_REPLACE, 等同 ip route replace).
	bool nl_route_replace(const nl_route_entry& rt, std::string& err);

	// 删除路由 (RTM_DELROUTE, 等同 ip route del).
	bool nl_route_delete(const nl_route_entry& rt, std::string& err);

	// 转储主表 (RT_TABLE_MAIN) 中的默认路由 (dst_len == 0, 等同 ip route show default).
	bool nl_route_dump_default(std::vector<nl_route_entry>& out, std::string& err);

	// 将路由表项格式化为类似 "default via 192.168.1.1 dev eth0 metric 100" 的文本.
	std::string nl_route_to_string(const nl_route_entry& rt);

} // namespace libavpn

#endif // INCLUDE__2026_08_19__NETLINK_ROUTE_HPP
