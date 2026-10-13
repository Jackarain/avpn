//
// avpn_frame.cpp
// ~~~~~~~~~~~~~~
//
// Copyright (C) 2025 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#include "libavpn/avpn_frame.hpp"
#include "libavpn/avpn_crypto.hpp"

#include <algorithm>
#include <cstring>

namespace libavpn {

	namespace {

		// 小端读写.
		inline void put_u16(std::string& out, uint16_t v)
		{
			out.push_back(static_cast<char>(v & 0xff));
			out.push_back(static_cast<char>((v >> 8) & 0xff));
		}

		inline void put_u32(std::string& out, uint32_t v)
		{
			for (int i = 0; i < 4; i++)
				out.push_back(static_cast<char>((v >> (i * 8)) & 0xff));
		}

		inline uint16_t get_u16(const uint8_t* p)
		{
			return static_cast<uint16_t>(p[0] | (p[1] << 8));
		}

		// IP 头里的长度字段是网络字节序 (大端).
		inline uint16_t get_be16(const uint8_t* p)
		{
			return static_cast<uint16_t>((p[0] << 8) | p[1]);
		}

		inline uint32_t get_u32(const uint8_t* p)
		{
			return static_cast<uint32_t>(p[0]) |
				(static_cast<uint32_t>(p[1]) << 8) |
				(static_cast<uint32_t>(p[2]) << 16) |
				(static_cast<uint32_t>(p[3]) << 24);
		}

		inline const uint8_t* bytes_of(std::string_view s)
		{
			return reinterpret_cast<const uint8_t*>(s.data());
		}

		// 会话参数号 (见 doc/protocol_v2.md §2.2).
		namespace param_id {
			constexpr uint8_t version = 0x01;
			constexpr uint8_t tag_len = 0x02;
			constexpr uint8_t fec = 0x03;
			constexpr uint8_t keepalive = 0x04;
			constexpr uint8_t abandon = 0x05;
			constexpr uint8_t cache = 0x06;
			constexpr uint8_t early_close = 0x07;
			constexpr uint8_t mtu = 0x08;
			constexpr uint8_t vaddr = 0x09;
			constexpr uint8_t v6 = 0x0a;
			constexpr uint8_t routes = 0x0b;
			constexpr uint8_t compress = 0x0c;
			constexpr uint8_t obfuscate = 0x0d;
			constexpr uint8_t roam_cookie = 0x0e;
			constexpr uint8_t cookie_beacon = 0x0f;
			constexpr uint8_t transport = 0x10;
			constexpr uint8_t pushdns = 0x11;
			constexpr uint8_t passbyvpn = 0x12;
			constexpr uint8_t obfuscate_key_hash = 0x13;
		} // namespace param_id

		void append_param(std::string& out, uint8_t id,
			std::string_view body)
		{
			out.push_back(static_cast<char>(id));
			put_u16(out, static_cast<uint16_t>(body.size()));
			out.append(body.data(), body.size());
		}

	} // namespace

	bool valid_control_code(uint8_t code)
	{
		if (code == container_marker)
			return false;
		// 与 IP 版本号冲突的取值不能作消息码.
		if ((code >> 4) == 4 || (code >> 4) == 6)
			return false;
		return true;
	}

	compress_type negotiate_compress(compress_type wish, compress_type have)
	{
		if (wish != have)
			return compress_type::none;

		// 只有 deflate 有实现, 其余算法谈成了也压不了.
		if (wish == compress_type::deflate)
			return compress_type::deflate;
		return compress_type::none;
	}

	frame_kind classify_payload(std::string_view plaintext)
	{
		if (plaintext.empty())
			return frame_kind::control;

		const uint8_t first = static_cast<uint8_t>(plaintext[0]);
		const uint8_t version = static_cast<uint8_t>(first >> 4);
		if (version == 4 || version == 6)
			return frame_kind::ip;
		if (first == container_marker)
			return frame_kind::container;
		return frame_kind::control;
	}

	std::size_t ip_packet_size(const uint8_t* data, std::size_t size)
	{
		if (size < 20)
			return 0;

		const uint8_t version = static_cast<uint8_t>(data[0] >> 4);
		if (version == 4)
		{
			const std::size_t total = get_be16(data + 2);
			if (total < 20 || total > size)
				return 0;
			return total;
		}

		if (version == 6)
		{
			if (size < 40)
				return 0;
			const std::size_t payload = get_be16(data + 4);
			const std::size_t total = 40 + payload;
			if (total > size)
				return 0;
			return total;
		}

		return 0;
	}

	void append_control_message(std::string& out, uint8_t code,
		std::string_view body)
	{
		out.push_back(static_cast<char>(code));
		put_u16(out, static_cast<uint16_t>(body.size()));
		out.append(body.data(), body.size());
	}

	bool parse_control_message(std::string_view plaintext, uint8_t& code,
		std::string_view& body)
	{
		if (plaintext.size() < control_header_size)
			return false;

		code = static_cast<uint8_t>(plaintext[0]);
		if (!valid_control_code(code))
			return false;

		const uint16_t len = get_u16(bytes_of(plaintext.data()) + 1);
		if (len != plaintext.size() - control_header_size)
			return false;

		body = plaintext.substr(control_header_size, len);
		return true;
	}

	void append_container(std::string& out,
		const std::vector<std::string_view>& entries)
	{
		append_container(out, entries, 0, entries.size());
	}

	void append_container(std::string& out,
		const std::vector<std::string_view>& entries, std::size_t from,
		std::size_t count)
	{
		out.push_back(static_cast<char>(container_marker));
		out.push_back(static_cast<char>(count & 0xff));
		for (std::size_t i = from; i < from + count; i++)
			out.append(entries[i].data(), entries[i].size());
	}

	std::size_t pack_packets(const std::vector<std::string_view>& packets,
		std::size_t from, std::size_t payload_limit, std::string& out)
	{
		out.clear();
		if (from >= packets.size() ||
			payload_limit < container_header_size)
			return 0;

		// 先看能连着装几个: 一个包时不加容器头, 两个以上才按容器算长度.
		std::size_t used = 0;
		std::size_t body = 0;
		while (from + used < packets.size() &&
			used < container_max_entries)
		{
			const std::size_t size = packets[from + used].size();
			if (used == 0)
			{
				if (size > payload_limit)
					break;
			}
			else if (container_header_size + body + size > payload_limit)
			{
				break;
			}
			body += size;
			used++;
		}

		// 只装得下一个 (或第一个就超过一片): 不做容器封装, 原样交出去;
		// 超过一片的包由上层按老路径丢掉.
		if (used <= 1)
		{
			out.assign(packets[from].data(), packets[from].size());
			return 1;
		}

		append_container(out, packets, from, used);
		return used;
	}

	namespace {

		// 走一遍容器里的条目: entries 非空就收下每个条目, total 非空就给出
		// 容器真正占用的字节数 (末尾多余的字节是补零, 不算在内).
		// 任何一处不合法都返回 false.
		bool walk_container(std::string_view plaintext,
			std::vector<std::string_view>* entries, std::size_t* total)
		{
			if (entries)
				entries->clear();
			if (plaintext.size() < 2)
				return false;
			if (static_cast<uint8_t>(plaintext[0]) != container_marker)
				return false;

			const std::size_t count = static_cast<uint8_t>(plaintext[1]);
			std::size_t pos = 2;
			if (entries)
				entries->reserve(count);

			for (std::size_t i = 0; i < count; i++)
			{
				const std::size_t remain = plaintext.size() - pos;
				if (remain == 0)
					return false;

				const uint8_t first = static_cast<uint8_t>(plaintext[pos]);
				const uint8_t version = static_cast<uint8_t>(first >> 4);
				std::size_t len = 0;
				if (version == 4 || version == 6)
				{
					len = ip_packet_size(
						bytes_of(plaintext.data() + pos), remain);
					if (len == 0)
						return false;
				}
				else
				{
					// 其余按控制条目解析; 剩余不足或长度越界都判整帧丢弃.
					if (remain < control_header_size)
						return false;
					if (!valid_control_code(first))
						return false;
					const uint16_t body =
						get_u16(bytes_of(plaintext.data() + pos) + 1);
					if (control_header_size + body > remain)
						return false;
					len = control_header_size + body;
				}

				if (entries)
					entries->push_back(plaintext.substr(pos, len));
				pos += len;
			}

			if (total)
				*total = pos;
			return true;
		}

	} // namespace

	bool parse_container(std::string_view plaintext,
		std::vector<std::string_view>& entries)
	{
		return walk_container(plaintext, &entries, nullptr);
	}

	std::size_t container_size(std::string_view plaintext)
	{
		std::size_t total = 0;
		if (!walk_container(plaintext, nullptr, &total))
			return 0;
		return total;
	}

	bool session_params::valid() const
	{
		if (tag_len != 12 && tag_len != 16)
			return false;

		if (fec_total != 1 && fec_total != 2 && fec_total != 4 &&
			fec_total != 8 && fec_total != 16)
			return false;
		if (fec_total == 1)
		{
			if (fec_data != 1)
				return false;
		}
		else if (fec_data < 1 || fec_data >= fec_total)
			return false;

		if (keepalive_sec == 0)
			return false;
		if (compress > 3)
			return false;
		if (transport > 1)
			return false;
		if (prefix_len > 32 || v6_prefix > 128)
			return false;

		// 内层 MTU 得保证一个满长包放得进一片. 这里只按不含混淆开销的上限
		// 粗校验取值范围: 客户端报的是"想要多大的 MTU", 开不开混淆要等应答
		// 方按协商结果定, 最终值由应答方收到片长上限里 (见 shard_limit).
		if (mtu < 576 || mtu > wire_payload_limit(tag_len, false))
			return false;

		return true;
	}

	void append_params(std::string& out, const session_params& p)
	{
		std::string body;

		body.resize(2);
		body[0] = static_cast<char>(p.version & 0xff);
		body[1] = static_cast<char>((p.version >> 8) & 0xff);
		append_param(out, param_id::version, body);

		body.assign(1, static_cast<char>(p.tag_len));
		append_param(out, param_id::tag_len, body);

		body.assign(2, '\0');
		body[0] = static_cast<char>(p.fec_total);
		body[1] = static_cast<char>(p.fec_data);
		append_param(out, param_id::fec, body);

		body.clear();
		put_u16(body, p.keepalive_sec);
		append_param(out, param_id::keepalive, body);

		body.clear();
		put_u16(body, p.group_abandon_ms);
		append_param(out, param_id::abandon, body);

		body.clear();
		put_u16(body, p.group_cache_ms);
		append_param(out, param_id::cache, body);

		body.clear();
		put_u16(body, p.early_close_ms);
		append_param(out, param_id::early_close, body);

		body.clear();
		put_u16(body, p.mtu);
		append_param(out, param_id::mtu, body);

		body.clear();
		put_u32(body, p.vaddr);
		body.push_back(static_cast<char>(p.prefix_len));
		append_param(out, param_id::vaddr, body);

		body.clear();
		body.push_back(static_cast<char>(p.v6_prefix));
		auto v6 = p.v6_net.to_bytes();
		body.append(reinterpret_cast<const char*>(v6.data()), v6.size());
		append_param(out, param_id::v6, body);

		body.clear();
		body.push_back(static_cast<char>(p.routes.size() & 0xff));
		for (auto& r : p.routes)
		{
			body.push_back(static_cast<char>(r.size() & 0xff));
			body.append(r);
		}
		append_param(out, param_id::routes, body);

		body.assign(1, static_cast<char>(p.compress));
		append_param(out, param_id::compress, body);

		body.assign(1, static_cast<char>(p.obfuscate ? 1 : 0));
		append_param(out, param_id::obfuscate, body);

		body.assign(reinterpret_cast<const char*>(p.roam_cookie.data()),
			p.roam_cookie.size());
		append_param(out, param_id::roam_cookie, body);

		body.clear();
		put_u16(body, p.cookie_beacon_k);
		append_param(out, param_id::cookie_beacon, body);

		body.assign(1, static_cast<char>(p.transport));
		append_param(out, param_id::transport, body);

		body.clear();
		put_u32(body, p.pushdns);
		append_param(out, param_id::pushdns, body);

		body.assign(1, static_cast<char>(p.passbyvpn ? 1 : 0));
		append_param(out, param_id::passbyvpn, body);

		body.clear();
		put_u32(body, p.obfuscate_key_hash);
		append_param(out, param_id::obfuscate_key_hash, body);
	}

	bool parse_params(std::string_view data, session_params& p)
	{
		session_params out;
		std::array<bool, 0x13> seen{};

		std::size_t pos = 0;
		while (pos < data.size())
		{
			if (pos + 3 > data.size())
				return false;

			const uint8_t id = static_cast<uint8_t>(data[pos]);
			const uint16_t len = get_u16(bytes_of(data.data() + pos) + 1);
			pos += 3;
			if (len > data.size() - pos)
				return false;
			const std::string_view body = data.substr(pos, len);
			pos += len;

			// 不认识的参数按长度跳过; 重复出现的参数判握手失败.
			if (id < seen.size())
			{
				if (seen[id])
					return false;
				seen[id] = true;
			}

			const uint8_t* bp = bytes_of(body.data());
			switch (id)
			{
			case param_id::version:
				if (len != 2)
					return false;
				out.version = get_u16(bp);
				break;
			case param_id::tag_len:
				if (len != 1)
					return false;
				out.tag_len = bp[0];
				break;
			case param_id::fec:
				if (len != 2)
					return false;
				out.fec_total = bp[0];
				out.fec_data = bp[1];
				break;
			case param_id::keepalive:
				if (len != 2)
					return false;
				out.keepalive_sec = get_u16(bp);
				break;
			case param_id::abandon:
				if (len != 2)
					return false;
				out.group_abandon_ms = get_u16(bp);
				break;
			case param_id::cache:
				if (len != 2)
					return false;
				out.group_cache_ms = get_u16(bp);
				break;
			case param_id::early_close:
				if (len != 2)
					return false;
				out.early_close_ms = get_u16(bp);
				break;
			case param_id::mtu:
				if (len != 2)
					return false;
				out.mtu = get_u16(bp);
				break;
			case param_id::vaddr:
				if (len != 5)
					return false;
				out.vaddr = get_u32(bp);
				out.prefix_len = bp[4];
				break;
			case param_id::v6:
			{
				if (len != 17)
					return false;
				out.v6_prefix = bp[0];
				net::ip::address_v6::bytes_type addr{};
				std::memcpy(addr.data(), bp + 1, addr.size());
				out.v6_net = net::ip::address_v6(addr);
				break;
			}
			case param_id::routes:
			{
				if (len < 1)
					return false;
				const std::size_t count = bp[0];
				std::size_t rp = 1;
				out.routes.clear();
				out.routes.reserve(count);
				for (std::size_t i = 0; i < count; i++)
				{
					if (rp + 1 > len)
						return false;
					const std::size_t rlen = bp[rp];
					rp += 1;
					if (rp + rlen > len)
						return false;
					out.routes.emplace_back(
						reinterpret_cast<const char*>(bp + rp), rlen);
					rp += rlen;
				}
				if (rp != len)
					return false;
				break;
			}
			case param_id::compress:
				if (len != 1)
					return false;
				out.compress = bp[0];
				break;
			case param_id::obfuscate:
				if (len != 1)
					return false;
				out.obfuscate = bp[0] != 0;
				break;
			case param_id::roam_cookie:
				if (len != out.roam_cookie.size())
					return false;
				std::memcpy(out.roam_cookie.data(), bp, len);
				break;
			case param_id::cookie_beacon:
				if (len != 2)
					return false;
				out.cookie_beacon_k = get_u16(bp);
				break;
			case param_id::transport:
				if (len != 1)
					return false;
				out.transport = bp[0];
				break;
			case param_id::pushdns:
				if (len != 4)
					return false;
				out.pushdns = get_u32(bp);
				break;
			case param_id::passbyvpn:
				if (len != 1)
					return false;
				out.passbyvpn = bp[0] != 0;
				break;
			case param_id::obfuscate_key_hash:
				if (len != 4)
					return false;
				out.obfuscate_key_hash = get_u32(bp);
				break;
			default:
				break;
			}
		}

		if (!out.valid())
			return false;

		p = std::move(out);
		return true;
	}

	std::string handshake_req::serialize() const
	{
		std::string params;
		append_params(params, this->params);
		if (params.size() > 0xffff)
			return {};

		std::string out;
		out.reserve(handshake_req_fixed_size + 2 + params.size());

		put_u16(out, version);
		out.append(reinterpret_cast<const char*>(ephemeral_pub.data()),
			ephemeral_pub.size());
		for (int i = 0; i < 8; i++)
			out.push_back(static_cast<char>((timestamp >> (i * 8)) & 0xff));
		out.append(reinterpret_cast<const char*>(client_id.data()),
			client_id.size());
		put_u32(out, requested_vaddr);
		put_u16(out, static_cast<uint16_t>(params.size()));
		out.append(params);

		return out;
	}

	std::array<uint8_t, handshake_hint_size> make_handshake_hint(
		std::string_view static_pub)
	{
		std::array<uint8_t, handshake_hint_size> hint{};
		if (static_pub.size() != crypto::x25519_key_size)
			return hint;

		// 单向派生: 由静态公钥得到一个不会反推出公钥的短标识.
		const std::string h = crypto::hkdf_sha256(static_pub,
			std::string_view(), "avpn-hint-v2", handshake_hint_size);
		if (h.size() != handshake_hint_size)
			return hint;

		std::memcpy(hint.data(), h.data(), hint.size());
		return hint;
	}

	bool parse_handshake_req(std::string_view data, handshake_req& req)
	{
		if (data.size() < handshake_req_fixed_size + 2)
			return false;

		handshake_req out;
		std::size_t pos = 0;
		const uint8_t* p = bytes_of(data.data());

		out.version = get_u16(p + pos);
		pos += 2;
		std::memcpy(out.ephemeral_pub.data(), p + pos,
			out.ephemeral_pub.size());
		pos += out.ephemeral_pub.size();

		out.timestamp = 0;
		for (int i = 0; i < 8; i++)
			out.timestamp |= static_cast<uint64_t>(p[pos + i]) << (i * 8);
		pos += 8;

		std::memcpy(out.client_id.data(), p + pos, out.client_id.size());
		pos += out.client_id.size();

		out.requested_vaddr = get_u32(p + pos);
		pos += 4;

		const uint16_t params_len = get_u16(p + pos);
		pos += 2;
		if (params_len != data.size() - pos)
			return false;

		if (!parse_params(data.substr(pos, params_len), out.params))
			return false;

		req = std::move(out);
		return true;
	}

	std::string handshake_resp::serialize() const
	{
		std::string params;
		append_params(params, this->params);
		if (params.size() > 0xffff)
			return {};

		std::string out;
		out.reserve(handshake_resp_fixed_size + 2 + params.size());
		out.append(reinterpret_cast<const char*>(ephemeral_pub.data()),
			ephemeral_pub.size());
		put_u16(out, static_cast<uint16_t>(params.size()));
		out.append(params);
		return out;
	}

	bool parse_handshake_resp(std::string_view data, handshake_resp& resp)
	{
		if (data.size() < handshake_resp_fixed_size + 2)
			return false;

		handshake_resp out;
		std::memcpy(out.ephemeral_pub.data(), data.data(),
			out.ephemeral_pub.size());

		const std::size_t pos = handshake_resp_fixed_size;
		const uint16_t params_len =
			get_u16(bytes_of(data.data() + pos));
		if (params_len != data.size() - pos - 2)
			return false;

		if (!parse_params(data.substr(pos + 2, params_len), out.params))
			return false;

		resp = std::move(out);
		return true;
	}

} // namespace libavpn
