//
// nat_rule.cpp
// ~~~~~~~~~~~~
//
// Copyright (C) 2026 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#include "libavpn/nat_rule.hpp"

#if defined(__linux__)

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

namespace libavpn {
namespace {

	// 可用的 NAT 操作后端.
	enum class nat_backend { unknown, iptables, nft, none };

	nat_backend g_backend = nat_backend::unknown;

	// 执行命令并捕获输出, 返回 wait status (与 system 一致), 失败返回 -1.
	int run_cmd_capture(const std::string& cmd, std::string& output)
	{
		output.clear();
		FILE* pipe = ::popen((cmd + " 2>&1").c_str(), "r");
		if (!pipe)
			return -1;

		char buf[512];
		std::size_t n;
		while ((n = std::fread(buf, 1, sizeof(buf), pipe)) > 0)
			output.append(buf, n);
		return ::pclose(pipe);
	}

	// 探测可用后端并缓存. iptables 兼容层 (iptables-nft) 在现代系统普遍
	// 可用且支持 -C 幂等检查; 仅当 iptables 不可用时回退 nft.
	nat_backend detect_backend()
	{
		if (g_backend != nat_backend::unknown)
			return g_backend;

		std::string out;
		if (run_cmd_capture("iptables -V", out) == 0)
			g_backend = nat_backend::iptables;
		else if (run_cmd_capture("nft --version", out) == 0)
			g_backend = nat_backend::nft;
		else
			g_backend = nat_backend::none;
		return g_backend;
	}

} // namespace

	bool nat_rule_add_masquerade(const std::string& dev, std::string& err)
	{
		auto backend = detect_backend();
		std::string out;
		int ret = -1;

		if (backend == nat_backend::iptables)
		{
			// -C 检查存在, 不存在则 -A 添加; 幂等且不影响已有规则.
			std::string cmd = "iptables -t nat -C POSTROUTING -o " + dev +
				" -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o " +
				dev + " -j MASQUERADE";
			ret = run_cmd_capture(cmd, out);
		}
		else if (backend == nat_backend::nft)
		{
			// 确保 nat 表与 postrouting 链存在.
			run_cmd_capture("nft list table ip nat >/dev/null 2>&1 || "
				"nft add table ip nat", out);
			run_cmd_capture("nft list chain ip nat postrouting >/dev/null 2>&1 || "
				"nft add chain ip nat postrouting "
				"'{ type nat hook postrouting priority 100 ; }'", out);

			// 规则已存在则直接成功.
			ret = run_cmd_capture(
				"nft list chain ip nat postrouting | grep -q "
				"'oifname \"" + dev + "\" masquerade' && echo EXISTS || echo MISSING", out);
			if (ret == 0 && out.find("EXISTS") != std::string::npos)
				return true;

			ret = run_cmd_capture(
				"nft add rule ip nat postrouting oifname \"" + dev +
				"\" masquerade", out);
		}
		else
		{
			err = "no usable firewall backend (iptables/nft not found)";
			return false;
		}

		if (ret != 0)
		{
			err = out.empty() ? "command failed" : out;
			return false;
		}
		return true;
	}

	bool nat_rule_del_masquerade(const std::string& dev, std::string& err)
	{
		auto backend = detect_backend();
		std::string out;
		int ret = -1;

		if (backend == nat_backend::iptables)
		{
			// -D 删除, 规则不存在时返回非零, 视为成功.
			ret = run_cmd_capture("iptables -t nat -D POSTROUTING -o " + dev +
				" -j MASQUERADE 2>/dev/null", out);
			return ret == 0 || ret == 256;
		}
		else if (backend == nat_backend::nft)
		{
			// 删除所有匹配规则 (按 handle), 链不存在或无匹配视为成功.
			ret = run_cmd_capture(
				"for h in $(nft -a list chain ip nat postrouting 2>/dev/null | "
				"awk '/oifname \"" + dev + "\" masquerade/{print $NF}'); do "
				"nft delete rule ip nat postrouting handle $h; done", out);
			return true;
		}

		err = "no usable firewall backend (iptables/nft not found)";
		return false;
	}

} // namespace libavpn

#else // !defined(__linux__)

namespace libavpn {

	bool nat_rule_add_masquerade(const std::string& dev, std::string& err)
	{
		(void)dev;
		err = "MASQUERADE is only supported on Linux";
		return false;
	}

	bool nat_rule_del_masquerade(const std::string& dev, std::string& err)
	{
		(void)dev;
		err = "MASQUERADE is only supported on Linux";
		return false;
	}

} // namespace libavpn

#endif // defined(__linux__)
