//
// avpn_keys.cpp
// ~~~~~~~~~~~~~
//
// Copyright (C) 2025 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#include "libavpn/avpn_keys.hpp"
#include "libavpn/avpn_crypto.hpp"

#include <algorithm>

namespace libavpn {

	namespace {

		// 用途标签.
		constexpr std::string_view kdf_master_info = "avpn-master-v2";
		constexpr std::string_view kdf_temp_info = "avpn-hs-temp-v2";
		constexpr std::string_view kdf_resp_info = "avpn-hs-resp-v2";
		constexpr std::string_view kdf_datakey_info = "avpn-datakey-v2";

		// 缓存的次代密钥条目上限 (收发各自最多两个次代在飞).
		constexpr std::size_t epoch_key_cache_capacity = 8;

		inline std::string hkdf(std::string_view ikm, std::string_view salt,
			std::string_view info)
		{
			return crypto::hkdf_sha256(ikm, salt, info, crypto::x25519_key_size);
		}

	} // namespace

	bool derive_master_key(std::string_view local_static_priv,
		std::string_view local_eph_priv,
		std::string_view peer_static_pub,
		std::string_view peer_eph_pub,
		std::string& out)
	{
		// 静态 x 静态 作为盐, 其余三个按字典序排序后拼接作为输入.
		auto salt = crypto::x25519_ecdh(local_static_priv, peer_static_pub);
		if (salt.size() != crypto::x25519_key_size)
			return false;

		std::array<std::string, 3> secrets;
		secrets[0] = crypto::x25519_ecdh(local_static_priv, peer_eph_pub);
		secrets[1] = crypto::x25519_ecdh(local_eph_priv, peer_static_pub);
		secrets[2] = crypto::x25519_ecdh(local_eph_priv, peer_eph_pub);
		for (auto& s : secrets)
		{
			if (s.size() != crypto::x25519_key_size)
				return false;
		}

		std::sort(secrets.begin(), secrets.end());

		std::string ikm;
		ikm.reserve(crypto::x25519_key_size * secrets.size());
		for (auto& s : secrets)
			ikm.append(s);

		auto master = hkdf(ikm, salt, kdf_master_info);
		if (master.size() != crypto::x25519_key_size)
			return false;

		out = std::move(master);
		return true;
	}

	bool derive_handshake_key(std::string_view shared_secret, bool is_temp,
		std::string& out)
	{
		if (shared_secret.size() != crypto::x25519_key_size)
			return false;

		auto key = hkdf(shared_secret, std::string_view(),
			is_temp ? kdf_temp_info : kdf_resp_info);
		if (key.size() != crypto::x25519_key_size)
			return false;

		out = std::move(key);
		return true;
	}

	bool derive_epoch_key(std::string_view master, uint32_t epoch, bool c2s,
		std::string& out)
	{
		if (master.size() != crypto::x25519_key_size)
			return false;

		// 盐 = 次代号 (8 字节小端), info = 用途标签 + 方向.
		std::string salt(8, '\0');
		for (int i = 0; i < 8; i++)
			salt[i] = static_cast<char>((static_cast<uint64_t>(epoch) >>
				(i * 8)) & 0xff);

		std::string info(kdf_datakey_info);
		info.append(c2s ? "c2s" : "s2c");

		auto key = hkdf(master, salt, info);
		if (key.size() != crypto::x25519_key_size)
			return false;

		out = std::move(key);
		return true;
	}

	std::array<uint8_t, frame_nonce_size> make_frame_nonce(uint32_t counter)
	{
		std::array<uint8_t, frame_nonce_size> nonce{};
		for (int i = 0; i < 4; i++)
			nonce[i] = static_cast<uint8_t>((counter >> (i * 8)) & 0xff);
		return nonce;
	}

	void epoch_key_cache::set_master(std::string master)
	{
		m_master = std::move(master);
		m_keys.clear();
	}

	void epoch_key_cache::clear()
	{
		m_master.clear();
		m_keys.clear();
	}

	const std::string& epoch_key_cache::key(uint32_t epoch, bool c2s)
	{
		static const std::string empty;

		if (!ready())
			return empty;

		const uint64_t id = (static_cast<uint64_t>(epoch) << 1) |
			(c2s ? 1 : 0);
		auto it = m_keys.find(id);
		if (it != m_keys.end())
			return it->second;

		std::string derived;
		if (!derive_epoch_key(m_master, epoch, c2s, derived))
			return empty;

		auto& slot = m_keys[id];
		slot = std::move(derived);

		while (m_keys.size() > epoch_key_cache_capacity)
			m_keys.erase(m_keys.begin());

		return slot;
	}

} // namespace libavpn
