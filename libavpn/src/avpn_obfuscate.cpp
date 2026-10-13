//
// avpn_obfuscate.cpp
// ~~~~~~~~~~~~~~~~~~
//
// Copyright (C) 2025 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#include "libavpn/avpn_obfuscate.hpp"
#include "libavpn/avpn_crypto.hpp"

// xxhash 以头文件方式内联进本翻译单元 (和 libavpn 的编译开关一致).
#if !defined(XXH_INLINE_ALL)
#define XXH_INLINE_ALL
#endif
#include "libavpn/xxhash.hpp"

namespace libavpn {

	uint16_t obfuscate_mask(std::string_view key, std::string_view salt)
	{
		// 先把密钥串做成种子, 再拿 salt 算一次: 每包一个掩码, 但只有知道
		// 密钥串的两端算得出来.
		const XXH64_hash_t seed = XXH64(key.data(), key.size(), 0);
		return static_cast<uint16_t>(
			XXH64(salt.data(), salt.size(), seed) & 0xffff);
	}

	uint32_t obfuscate_key_hash(std::string_view key)
	{
		if (key.empty())
			return 0;

		// 只用来核对两端配的是不是同一把密钥, 不是加密用途.
		return static_cast<uint32_t>(
			XXH64(key.data(), key.size(), 0) & 0xffffffff);
	}

	void obfuscate_rand::seed(std::string_view seed)
	{
		// 把种子的字节搅进状态里 (FNV-1a 那一手), 再补一个非零值.
		uint64_t h = 0xcbf29ce484222325ull;
		for (char c : seed)
		{
			h ^= static_cast<uint8_t>(c);
			h *= 0x100000001b3ull;
		}
		m_state = h != 0 ? h : 0x9e3779b97f4a7c15ull;
	}

	uint64_t obfuscate_rand::next()
	{
		// xorshift64*: 很快, 输出看着随机, 填垃圾字节够用.
		uint64_t x = m_state;
		x ^= x >> 12;
		x ^= x << 25;
		x ^= x >> 27;
		m_state = x;
		return x * 0x2545f4914f6cdd1dull;
	}

	void obfuscate_rand::fill(char* out, std::size_t len)
	{
		std::size_t i = 0;
		while (i < len)
		{
			const uint64_t v = next();
			const std::size_t n = std::min<std::size_t>(8, len - i);
			for (std::size_t k = 0; k < n; k++)
				out[i + k] = static_cast<char>((v >> (k * 8)) & 0xff);
			i += n;
		}
	}

	std::size_t obfuscate_padding_for(std::size_t frame_size)
	{
		constexpr std::size_t span =
			obfuscate_max_padding - obfuscate_min_padding + 1;
		// 把帧长搅一下, 免得垃圾长度看着就是帧长本身.
		const uint64_t mixed =
			(static_cast<uint64_t>(frame_size) * 0x9e3779b97f4a7c15ull) >> 32;
		return obfuscate_min_padding +
			static_cast<std::size_t>(mixed % span);
	}

	std::string obfuscate_frame(obfuscate_rand& rand, std::string_view key,
		std::string_view frame)
	{
		if (key.empty() || frame.empty())
			return {};

		const std::size_t padding = obfuscate_padding_for(frame.size());

		// 一次取到 salt 和垃圾数据本身.
		char random[obfuscate_salt_size + obfuscate_max_padding];
		rand.fill(random, sizeof(random));

		const std::string_view salt(random, obfuscate_salt_size);

		const uint16_t len_enc =
			static_cast<uint16_t>(padding) ^ obfuscate_mask(key, salt);

		std::string out;
		out.reserve(obfuscate_fixed_overhead + padding + frame.size());
		out.append(salt.data(), salt.size());
		out.push_back(static_cast<char>(len_enc & 0xff));
		out.push_back(static_cast<char>((len_enc >> 8) & 0xff));
		out.append(random + obfuscate_salt_size, padding);
		out.append(frame.data(), frame.size());
		return out;
	}

	bool deobfuscate_frame(std::string_view key, std::string_view wire,
		std::string_view& frame)
	{
		frame = std::string_view();
		if (key.empty() ||
			wire.size() < obfuscate_fixed_overhead + obfuscate_min_padding)
		{
			return false;
		}

		const std::string_view salt(wire.data(), obfuscate_salt_size);
		const uint16_t len_enc = static_cast<uint16_t>(
			static_cast<uint8_t>(wire[obfuscate_salt_size]) |
			(static_cast<uint16_t>(static_cast<uint8_t>(
				wire[obfuscate_salt_size + 1])) << 8));
		const std::size_t padding =
			static_cast<std::size_t>(len_enc ^ obfuscate_mask(key, salt));

		if (padding < obfuscate_min_padding || padding > obfuscate_max_padding)
			return false;
		if (wire.size() < obfuscate_fixed_overhead + padding)
			return false;

		frame = wire.substr(obfuscate_fixed_overhead + padding);
		return true;
	}

} // namespace libavpn
