//
// nat_rule.hpp
// ~~~~~~~~~~~~
//
// Copyright (C) 2026 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#ifndef INCLUDE__2026_08_20__NAT_RULE_HPP
#define INCLUDE__2026_08_20__NAT_RULE_HPP

#include <string>

namespace libavpn {

	// 添加 MASQUERADE 规则 (POSTROUTING -o <dev> -j MASQUERADE).
	// 自动探测可用防火墙后端 (iptables 优先, 回退 nft), 幂等添加.
	// 失败时返回 false, err 给出具体原因; 在非 Linux 平台返回 false.
	bool nat_rule_add_masquerade(const std::string& dev, std::string& err);

	// 删除 MASQUERADE 规则. 规则不存在时视为成功 (返回 true).
	// 失败时返回 false, err 给出具体原因; 在非 Linux 平台返回 false.
	bool nat_rule_del_masquerade(const std::string& dev, std::string& err);

} // namespace libavpn

#endif // INCLUDE__2026_08_20__NAT_RULE_HPP
