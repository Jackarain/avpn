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
#include "libavpn/xxhash.hpp"

#include <cstring>
#include <algorithm>

namespace libavpn {

	uint16_t obfuscate_mask(std::string_view key, std::string_view salt)
	{
		// 以密钥派生 XXH64 种子, 再对 salt 计算, 取低 16 位作为掩码.
		// 每个数据包 salt 不同, 掩码也随之变化.
		XXH64_hash_t seed = XXH64(key.data(), key.size(), 0);
		return static_cast<uint16_t>(
			XXH64(salt.data(), salt.size(), seed) & 0xffff);
	}

	bool make_obfuscate_head(std::string_view key, obfuscate_head& head)
	{
		if (key.empty())
			return false;

		// 一次随机调用同时生成 salt 与垃圾数据.
		std::string randbuf = crypto::random_bytes(
			obfuscate_salt_size + obfuscate_max_padding);
		if (randbuf.size() != obfuscate_salt_size + obfuscate_max_padding)
			return false;

		std::memcpy(head.salt.data(), randbuf.data(), obfuscate_salt_size);

		std::size_t padding = obfuscate_min_padding +
			(static_cast<uint8_t>(randbuf[obfuscate_salt_size]) %
				(obfuscate_max_padding - obfuscate_min_padding + 1));

		uint16_t mask = obfuscate_mask(key, std::string_view(
			reinterpret_cast<const char*>(head.salt.data()), head.salt.size()));
		uint16_t len_enc = static_cast<uint16_t>(padding) ^ mask;

		head.len_field[0] = static_cast<uint8_t>(len_enc & 0xff);
		head.len_field[1] = static_cast<uint8_t>((len_enc >> 8) & 0xff);
		head.garbage.assign(randbuf.data() + obfuscate_salt_size, padding);

		return true;
	}

	bool deobfuscate_packet(std::string_view key, std::string_view wire,
		std::string_view& payload, std::string_view& len_field)
	{
		if (key.empty())
			return false;
		if (wire.size() < obfuscate_fixed_overhead + obfuscate_min_padding)
			return false;

		std::string_view salt(wire.data(), obfuscate_salt_size);
		len_field = wire.substr(obfuscate_salt_size, obfuscate_len_field_size);

		uint16_t len_enc = static_cast<uint16_t>(
			static_cast<uint16_t>(static_cast<uint8_t>(len_field[0])) |
			(static_cast<uint16_t>(static_cast<uint8_t>(len_field[1])) << 8));

		uint16_t mask = obfuscate_mask(key, salt);
		std::size_t padding = static_cast<std::size_t>(len_enc ^ mask);

		if (padding < obfuscate_min_padding || padding > obfuscate_max_padding)
			return false;
		if (wire.size() < obfuscate_fixed_overhead + padding)
			return false;

		payload = wire.substr(obfuscate_fixed_overhead + padding);
		return true;
	}

} // namespace libavpn
