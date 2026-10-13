//
// resolv_conf.hpp
// ~~~~~~~~~~~~~~~
//
// Copyright (C) 2026 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#ifndef INCLUDE__2026_10_14__RESOLV_CONF_HPP
#define INCLUDE__2026_10_14__RESOLV_CONF_HPP

#include <string>
#include <string_view>

namespace libavpn {

	// 系统解析器配置 (/etc/resolv.conf) 的读写.
	//
	// 客户端接上网关推送的 DNS 后, 把推送地址放到 nameserver 列表最前面, 原来的
	// nameserver 原样留在后面当后备; 会话结束再恢复成原样.

	// 默认的解析器配置路径.
	inline constexpr std::string_view resolv_conf_default_path = "/etc/resolv.conf";

	// 把 dns 插到 nameserver 列表最前面: 同样的地址出现在别处就从原位拿掉, 其余
	// 行 (search / options 等) 原样保留. 已经排在第一位时原样返回.
	std::string resolv_conf_merge(std::string_view original, std::string_view dns);

	// /etc/resolv.conf 是否由 systemd-resolved 托管 (它是指向 /run/systemd/resolve/
	// 下文件的符号链接). 这种情况下直接改文件会被守护进程立刻盖掉, 得走 resolvectl
	// 改链路级 DNS.
	bool resolv_conf_is_systemd_managed();

	// 用 resolvectl 把链路 dev 的 DNS 指到 dns, 并把它的搜索域设成 "~.": 不设
	// 路由域的话, systemd-resolved 仍会优先用物理链路的 DNS.
	bool resolved_set_dns(std::string_view dev, std::string_view dns, std::string& err);

	// 用 resolvectl 撤销链路 dev 的 DNS 设置 (链路本来也会随 tun 一起消失).
	bool resolved_revert(std::string_view dev, std::string& err);

	// 读取文件全文, 失败时 err 给出原因.
	bool resolv_conf_read(std::string_view path, std::string& out, std::string& err);

	// 就地写回文件 (保留符号链接: /etc/resolv.conf 常指向 systemd-resolved 的
	// stub 文件, 换 inode 会把链接换掉), 失败时 err 给出原因.
	bool resolv_conf_write(std::string_view path, std::string_view text, std::string& err);

} // namespace libavpn

#endif // INCLUDE__2026_10_14__RESOLV_CONF_HPP
