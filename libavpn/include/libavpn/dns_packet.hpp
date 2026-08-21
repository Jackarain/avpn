//
// dns_packet.hpp
// ~~~~~~~~~~~~~~
//
// Copyright (c) 2026 Jack (jack dot wgm at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// DNS 拦截用 IP/UDP/DNS 报文解析与重组 (纯函数, 无 IO 依赖, 便于单元测试).
//

#ifndef INCLUDE__2026_08_22__DNS_PACKET_HPP
#define INCLUDE__2026_08_22__DNS_PACKET_HPP

#include <algorithm>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>
#include <vector>

namespace libavpn {
namespace dns_packet {

	// Internet 校验和 (1's complement), sum 为前序伪头累加和.
	inline uint16_t internet_checksum(const uint8_t* data,
		std::size_t len, uint32_t sum = 0)
	{
		while (len > 1)
		{
			sum += (static_cast<uint32_t>(data[0]) << 8) | data[1];
			data += 2;
			len -= 2;
		}
		if (len)
			sum += static_cast<uint32_t>(data[0]) << 8;
		while (sum >> 16)
			sum = (sum & 0xffff) + (sum >> 16);
		return static_cast<uint16_t>(~sum);
	}

	// 从 DNS 消息解析第一个查询的 QNAME (小写, 不带末尾点), 支持压缩指针.
	// 返回 false 表示消息过短或格式不合法.
	inline bool parse_qname(const uint8_t* msg, std::size_t len,
		std::string& out)
	{
		std::size_t pos = 12;
		if (pos + 4 > len)
			return false;
		out.clear();
		for (int i = 0; i < 128; i++)
		{
			if (pos >= len)
				return false;
			uint8_t b = msg[pos];
			if (b == 0)
			{
				pos++;
				break;
			}
			if ((b & 0xc0) == 0xc0)
			{
				// 压缩指针: 域名结束.
				pos += 2;
				break;
			}
			if ((b & 0xc0) != 0)
				return false;
			if (pos + 1 + b > len)
				return false;
			if (!out.empty())
				out.push_back('.');
			for (uint8_t j = 0; j < b; j++)
			{
				char c = static_cast<char>(msg[pos + 1 + j]);
				if (c >= 'A' && c <= 'Z')
					c = static_cast<char>(c - 'A' + 'a');
				out.push_back(c);
			}
			pos += 1 + b;
		}
		return !out.empty();
	}

	// 定位 IP 包中的 UDP/53 DNS 消息, 成功返回 true 并输出 DNS 消息位置.
	// 仅处理无分片的 UDP 包; IPv6 仅处理无扩展头 (next header 直接为 UDP) 的包.
	inline bool locate_udp53(const std::vector<uint8_t>& pkt,
		const uint8_t*& dns, std::size_t& dns_len)
	{
		if (pkt.size() < 28)
			return false;
		const uint8_t* ip = pkt.data();
		std::size_t size = pkt.size();
		std::size_t udp_off = 0;

		if (((ip[0] >> 4) & 0x0f) == 4)
		{
			udp_off = (ip[0] & 0x0f) * 4;
			if (udp_off < 20 || size < udp_off + 8 + 12)
				return false;
			if (ip[9] != 17) // UDP
				return false;
			// 分片包不处理.
			uint16_t frag = (static_cast<uint16_t>(ip[6] & 0x1f) << 8) | ip[7];
			if (frag != 0 || (ip[6] & 0x20) != 0)
				return false;
		}
		else if (((ip[0] >> 4) & 0x0f) == 6)
		{
			if (size < 40 + 8 + 12)
				return false;
			if (ip[6] != 17) // 仅支持无扩展头的 UDP.
				return false;
			udp_off = 40;
		}
		else
			return false;

		const uint8_t* udp = ip + udp_off;
		uint16_t dst_port = (static_cast<uint16_t>(udp[2]) << 8) | udp[3];
		if (dst_port != 53)
			return false;

		dns = udp + 8;
		dns_len = size - udp_off - 8;
		return dns_len >= 12;
	}

	// 将 DNS 回复重组为 IP 包: 互换源/目的地址与 UDP 端口, 替换 DNS 消息,
	// 更新长度并重算 IP/UDP 校验和. 成功返回 true, out 为新 IP 包.
	inline bool build_reply(const std::vector<uint8_t>& req,
		const uint8_t* dns_msg, std::size_t dns_len,
		std::vector<uint8_t>& out)
	{
		if (req.size() < 28)
			return false;

		out = req;
		const uint8_t* ip = out.data();
		std::size_t udp_off = 0;
		bool is_v6 = false;

		if (((ip[0] >> 4) & 0x0f) == 4)
		{
			udp_off = (ip[0] & 0x0f) * 4;
			if (udp_off < 20)
				return false;
		}
		else if (((ip[0] >> 4) & 0x0f) == 6)
		{
			udp_off = 40;
			is_v6 = true;
		}
		else
			return false;

		if (out.size() < udp_off + 8)
			return false;

		// 互换源/目的 IP.
		if (is_v6)
			std::swap_ranges(out.begin() + 8, out.begin() + 24,
				out.begin() + 24);
		else
			std::swap_ranges(out.begin() + 12, out.begin() + 16,
				out.begin() + 16);

		// 计算新包总长并扩容 (先扩容, 避免后续指针失效).
		std::size_t new_total = udp_off + 8 + dns_len;
		if (new_total > 65535)
			return false;
		out.resize(new_total);
		uint16_t udp_len = static_cast<uint16_t>(8 + dns_len);

		// 互换 UDP 端口, 更新长度并清零校验和.
		uint8_t* udp = out.data() + udp_off;
		uint16_t src_port = (static_cast<uint16_t>(udp[0]) << 8) | udp[1];
		uint16_t dst_port = (static_cast<uint16_t>(udp[2]) << 8) | udp[3];
		udp[0] = static_cast<uint8_t>(dst_port >> 8);
		udp[1] = static_cast<uint8_t>(dst_port & 0xff);
		udp[2] = static_cast<uint8_t>(src_port >> 8);
		udp[3] = static_cast<uint8_t>(src_port & 0xff);
		udp[4] = static_cast<uint8_t>(udp_len >> 8);
		udp[5] = static_cast<uint8_t>(udp_len & 0xff);
		udp[6] = 0;
		udp[7] = 0;

		// 写入 DNS 回复消息.
		std::memcpy(out.data() + udp_off + 8, dns_msg, dns_len);

		if (is_v6)
		{
			// 更新 payload length.
			uint16_t payload = static_cast<uint16_t>(8 + dns_len);
			out[4] = static_cast<uint8_t>(payload >> 8);
			out[5] = static_cast<uint8_t>(payload & 0xff);
			// IPv6 UDP 校验和必须计算: 伪头 + UDP + 数据.
			uint32_t sum = 0;
			const uint8_t* src = out.data() + 8;
			const uint8_t* dst = out.data() + 24;
			for (int i = 0; i < 16; i += 2)
				sum += (static_cast<uint32_t>(src[i]) << 8) | src[i + 1];
			for (int i = 0; i < 16; i += 2)
				sum += (static_cast<uint32_t>(dst[i]) << 8) | dst[i + 1];
			sum += udp_len;
			sum += 17; // next header = UDP.
			uint16_t csum = internet_checksum(out.data() + udp_off,
				8 + dns_len, sum);
			udp[6] = static_cast<uint8_t>(csum >> 8);
			udp[7] = static_cast<uint8_t>(csum & 0xff);
			if (csum == 0)
			{
				udp[6] = 0xff;
				udp[7] = 0xff;
			}
		}
		else
		{
			// IPv4: 更新 total length 并重算 IP 头校验和.
			uint16_t total = static_cast<uint16_t>(new_total);
			out[2] = static_cast<uint8_t>(total >> 8);
			out[3] = static_cast<uint8_t>(total & 0xff);
			out[10] = 0;
			out[11] = 0;
			uint16_t csum = internet_checksum(out.data(), udp_off, 0);
			out[10] = static_cast<uint8_t>(csum >> 8);
			out[11] = static_cast<uint8_t>(csum & 0xff);
			// 重算 UDP 校验和 (伪头).
			uint32_t sum = 0;
			const uint8_t* src = out.data() + 12;
			const uint8_t* dst = out.data() + 16;
			sum += (static_cast<uint32_t>(src[0]) << 8) | src[1];
			sum += (static_cast<uint32_t>(src[2]) << 8) | src[3];
			sum += (static_cast<uint32_t>(dst[0]) << 8) | dst[1];
			sum += (static_cast<uint32_t>(dst[2]) << 8) | dst[3];
			sum += 17;
			sum += udp_len;
			uint16_t ucsum = internet_checksum(out.data() + udp_off,
				8 + dns_len, sum);
			udp[6] = static_cast<uint8_t>(ucsum >> 8);
			udp[7] = static_cast<uint8_t>(ucsum & 0xff);
		}

		return true;
	}

} // namespace dns_packet
} // namespace libavpn

#endif // INCLUDE__2026_08_22__DNS_PACKET_HPP
