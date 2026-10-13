//
// resolv_conf.cpp
// ~~~~~~~~~~~~~~~
//
// Copyright (C) 2026 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#include "libavpn/resolv_conf.hpp"

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <vector>

#if defined(__linux__)
#	include <limits.h>
#	include <unistd.h>
#endif

namespace libavpn {

	namespace {

		// 取一行里 "nameserver <地址>" 的地址部分; 不是 nameserver 行返回空.
		std::string_view nameserver_of(std::string_view line)
		{
			constexpr std::string_view key = "nameserver";

			// 行首允许空白, 关键字与地址之间也允许连续空白.
			std::size_t i = 0;
			while (i < line.size() && (line[i] == ' ' || line[i] == '\t'))
				i++;
			if (line.compare(i, key.size(), key) != 0)
				return {};
			i += key.size();
			if (i >= line.size() || (line[i] != ' ' && line[i] != '\t'))
				return {};
			while (i < line.size() && (line[i] == ' ' || line[i] == '\t'))
				i++;

			std::size_t end = i;
			while (end < line.size() && line[end] != ' ' && line[end] != '\t')
				end++;
			return line.substr(i, end - i);
		}

		// 按行切开 (丢掉结尾换行, 重建时统一补 '\n').
		std::vector<std::string> split_lines(std::string_view text)
		{
			std::vector<std::string> lines;
			for (std::size_t pos = 0; pos < text.size(); )
			{
				const std::size_t nl = text.find('\n', pos);
				std::string_view line = nl == std::string_view::npos
					? text.substr(pos) : text.substr(pos, nl - pos);
				if (!line.empty() && line.back() == '\r')
					line.remove_suffix(1);
				lines.emplace_back(line);
				if (nl == std::string_view::npos)
					break;
				pos = nl + 1;
			}
			return lines;
		}

		// 跑一条 shell 命令, 退出状态为零才算成功.
		// 参数里的链路名一律用单引号包住, 免得配置里的怪名字被当成命令.
		bool run_cmd(const std::string& cmd)
		{
			return std::system((cmd + " >/dev/null 2>&1").c_str()) == 0;
		}

	} // namespace

	bool resolv_conf_is_systemd_managed()
	{
#if defined(__linux__)
		char buf[PATH_MAX] = {};
		const ssize_t n = ::readlink("/etc/resolv.conf", buf,
			sizeof(buf) - 1);
		if (n <= 0)
			return false;

		const std::string_view target(buf, static_cast<std::size_t>(n));
		return target.rfind("/run/systemd/resolve/", 0) == 0;
#else
		return false;
#endif
	}

	bool resolved_set_dns(std::string_view dev, std::string_view dns,
		std::string& err)
	{
		const std::string link = "'" + std::string(dev) + "'";
		if (!run_cmd("resolvectl dns " + link + " " + std::string(dns)) ||
			!run_cmd("resolvectl domain " + link + " '~.'"))
		{
			err = "resolvectl set dns on " + link + " failed";
			return false;
		}
		return true;
	}

	bool resolved_revert(std::string_view dev, std::string& err)
	{
		const std::string link = "'" + std::string(dev) + "'";
		if (!run_cmd("resolvectl revert " + link))
		{
			err = "resolvectl revert " + link + " failed";
			return false;
		}
		return true;
	}

	std::string resolv_conf_merge(std::string_view original, std::string_view dns)
	{
		if (dns.empty())
			return std::string(original);

		auto lines = split_lines(original);

		// 已经排在第一位: 文件不用动.
		for (const auto& line : lines)
		{
			const auto addr = nameserver_of(line);
			if (addr.empty())
				continue;
			if (addr == dns)
				return std::string(original);
			break;
		}

		// 插到第一个 nameserver 之前; 原位置的同地址项丢掉, 其余行原样保留.
		std::vector<std::string> out;
		out.reserve(lines.size() + 1);
		bool inserted = false;
		for (auto& line : lines)
		{
			const auto addr = nameserver_of(line);
			if (!addr.empty() && addr == dns)
				continue;
			if (!inserted && !addr.empty())
			{
				out.push_back("nameserver " + std::string(dns));
				inserted = true;
			}
			out.push_back(std::move(line));
		}
		if (!inserted)
			out.push_back("nameserver " + std::string(dns));

		std::string text;
		for (const auto& line : out)
		{
			text += line;
			text += '\n';
		}
		return text;
	}

	bool resolv_conf_read(std::string_view path, std::string& out, std::string& err)
	{
		std::ifstream in(std::string(path), std::ios::binary);
		if (!in)
		{
			err = "open " + std::string(path) + " failed: " + std::strerror(errno);
			return false;
		}

		std::ostringstream buf;
		buf << in.rdbuf();
		if (in.bad())
		{
			err = "read " + std::string(path) + " failed: " + std::strerror(errno);
			return false;
		}

		out = buf.str();
		return true;
	}

	bool resolv_conf_write(std::string_view path, std::string_view text, std::string& err)
	{
		std::ofstream out(std::string(path),
			std::ios::binary | std::ios::trunc);
		if (!out)
		{
			err = "open " + std::string(path) + " failed: " + std::strerror(errno);
			return false;
		}

		out.write(text.data(), static_cast<std::streamsize>(text.size()));
		out.flush();
		if (!out)
		{
			err = "write " + std::string(path) + " failed: " + std::strerror(errno);
			return false;
		}
		return true;
	}

} // namespace libavpn
