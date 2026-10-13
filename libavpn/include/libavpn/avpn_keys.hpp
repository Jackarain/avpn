//
// avpn_keys.hpp
// ~~~~~~~~~~~~~
//
// v2 的密钥派生:
//   * 四次 X25519 派生的会话主密钥.
//   * 握手请求/回复用的两把一次性密钥.
//   * 按次代派生的数据密钥, 以及帧 nonce 的构造.
//
// Copyright (C) 2025 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#ifndef INCLUDE__2026_10_14__AVPN_KEYS_HPP
#define INCLUDE__2026_10_14__AVPN_KEYS_HPP

#include "libavpn/avpn_frame.hpp"

#include <cstdint>
#include <array>
#include <map>
#include <string>
#include <string_view>

namespace libavpn {

	// 派生会话主密钥 (四次 X25519).
	// local_* 为本端密钥, peer_* 为对端公钥; 成功返回 true 并输出 32 字节.
	bool derive_master_key(std::string_view local_static_priv,
		std::string_view local_eph_priv,
		std::string_view peer_static_pub,
		std::string_view peer_eph_pub,
		std::string& out);

	// 派生握手请求密钥 (is_temp = true) 或回复密钥 (is_temp = false).
	// shared_secret 为 "客户端临时私钥 x 网关静态公钥" 的共享秘密.
	bool derive_handshake_key(std::string_view shared_secret, bool is_temp,
		std::string& out);

	// 派生第 epoch 个次代的数据密钥.
	bool derive_epoch_key(std::string_view master, uint32_t epoch, bool c2s,
		std::string& out);

	// 帧 nonce: 计数器(4, 小端) 后面补 8 个 0.
	std::array<uint8_t, frame_nonce_size> make_frame_nonce(uint32_t counter);

	// 按次代缓存数据密钥, 避免每帧重复派生.
	class epoch_key_cache
	{
	public:
		void set_master(std::string master);
		void clear();

		bool ready() const { return m_master.size() == 32; }

		// 取第 epoch 个次代的数据密钥; 不可用返回空串.
		const std::string& key(uint32_t epoch, bool c2s);

	private:
		std::string m_master;
		std::map<uint64_t, std::string> m_keys;
	};

} // namespace libavpn

#endif // INCLUDE__2026_10_14__AVPN_KEYS_HPP
