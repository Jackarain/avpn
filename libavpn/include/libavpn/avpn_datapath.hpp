//
// avpn_datapath.hpp
// ~~~~~~~~~~~~~~~~~
//
// v2 的数据面 (见 doc/protocol_v2.md 第 2、3、4 章):
//   * 封包: 明文 -> 线上帧; 纠错模式下凑够数据片就补上冗余片.
//   * 收包: 线上帧 -> 明文; 解密、判次代、挡重放、纠错还原.
//   * 漫游帧: 最前面多 8 字节 cookie, 并把 cookie 作为 AAD.
//
// Copyright (C) 2025 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#ifndef INCLUDE__2026_10_14__AVPN_DATAPATH_HPP
#define INCLUDE__2026_10_14__AVPN_DATAPATH_HPP

#include "libavpn/avpn_frame.hpp"
#include "libavpn/avpn_keys.hpp"
#include "libavpn/avpn_replay.hpp"
#include "libavpn/avpn_fec_v2.hpp"
#include "libavpn/avpn_crypto.hpp"

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace libavpn {

	// 一个会话的数据面: 本端往外发的方向加上收进来的那个方向.
	class datapath
	{
	public:
		datapath();
		~datapath();

		datapath(const datapath&) = delete;
		datapath& operator=(const datapath&) = delete;

		// master: 32 字节会话主密钥.
		// local_is_client: 本端是客户端 (发的走 c2s, 收的走 s2c) 还是网关.
		void configure(std::string master, const session_params& params,
			bool local_is_client);

		// 会话建立时下发的漫游凭证; 全 0 表示不带漫游帧.
		void set_roam_cookie(const std::array<uint8_t, 8>& cookie);
		bool has_roam_cookie() const { return m_roam; }

		// 封一个明文: 整帧模式返回一帧, 纠错模式返回它自己那片, 凑够时再跟
		// 上冗余片. 攒不下 (超过单片上限) 返回空.
		std::vector<std::string> seal(std::string_view plaintext,
			uint64_t now_ms, bool roam = false);

		// 收一个线上帧, 返回这次能投递的明文 (可能是 0 个或者多个).
		// 内容不合法、重放、解不开都返回空.
		std::vector<std::string> on_frame(std::string_view frame,
			uint64_t now_ms);

		// 计时: 纠错留组的超时收尾 (可能要发提前关组的冗余片).
		std::vector<std::string> tick(uint64_t now_ms);

		// 下一个要用的计数器和当前次代 (调试 / 测试用).
		uint32_t send_counter() const;
		uint32_t send_epoch() const { return m_tx_epoch; }
		// 最近一次收包确定的次代 (还没有收过时是 0).
		uint32_t recv_epoch() const { return m_rx_epoch; }

		// 调试 / 测试用: 把发送方向直接摆到某个次代的某个计数器上.
		bool set_send_position(uint32_t epoch, uint32_t counter);

		// 帧头大小与 nonce 大小 (调用方算 MTU 预算时用).
		static constexpr std::size_t header_size = frame_header_size;
		static constexpr std::size_t nonce_size = frame_nonce_size;

	private:
		// 按次代拿发方向密钥并重设 AEAD 上下文; 失败返回 false.
		bool ensure_send_key(uint32_t epoch);
		bool ensure_recv_key(uint32_t epoch);

		// 用第 epoch 个次代的密钥解一帧; 成功返回 true.
		bool decrypt_with(uint32_t epoch, uint32_t counter,
			std::string_view body, std::string_view aad,
			std::string& plaintext);
		std::string encrypt_with(std::string_view plaintext,
			uint32_t counter, std::string_view aad);

		// 本端发 / 收方向的密钥标签.
		bool send_c2s() const { return m_local_is_client; }
		bool recv_c2s() const { return !m_local_is_client; }

		session_params m_params;
		bool m_local_is_client{ true };
		bool m_ready{ false };

		// 漫游凭证.
		bool m_roam{ false };
		std::array<uint8_t, 8> m_cookie{};

		// 密钥.
		epoch_key_cache m_keys;
		crypto::aead_cipher m_tx_aead;
		crypto::aead_cipher m_rx_aead;
		bool m_tx_aead_epoch_valid{ false };
		uint32_t m_tx_aead_epoch{ 0 };
		bool m_rx_aead_epoch_valid{ false };
		uint32_t m_rx_aead_epoch{ 0 };

		// 发送方向: 当前次代与上一个用掉的计数器 (用来发现回绕).
		uint32_t m_tx_epoch{ 0 };
		uint32_t m_tx_last{ 0 };
		bool m_tx_has_last{ false };

		// 接收方向: 最近一次解密成功时的次代与该次代里见过的最大计数器.
		uint32_t m_rx_epoch{ 0 };
		uint32_t m_rx_h_last{ 0 };
		bool m_rx_has_last{ false };

		// 防重放 (全局序号) 与纠错.
		seq_window m_replay;
		fec_sender m_fec_tx;
		fec_receiver m_fec_rx;

		// 复用缓冲, 免得每包都开一块.
		std::string m_tx_scratch;
		std::vector<char> m_rx_scratch;
		std::string m_rx_plain;
	};

} // namespace libavpn

#endif // INCLUDE__2026_10_14__AVPN_DATAPATH_HPP
