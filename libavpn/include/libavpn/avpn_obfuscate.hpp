//
// avpn_obfuscate.hpp
// ~~~~~~~~~~~~~~~~~~
//
// v2 的混淆层 (见 doc/protocol_v2.md 2.6): 在加密帧外面再套一层随机数据,
// 把包长和帧在报文里的位置打乱, 旁观者不容易从"包有多大、包长怎么分布"
// 认出这是隧道流量.
//
// 线格式 (只套在数据帧外面):
//
//   [ salt(4) ][ len_enc(2) ][ 垃圾(16~64) ][ 原来的帧 ]
//
//   * salt     每个包现取的 4 字节随机数.
//   * len_enc  垃圾长度按 16 位掩码异或后的值; 掩码 = XXH64(密钥串, salt)
//              的低 16 位, 只有配了同一个密钥串的两端能算出真实长度.
//   * 垃圾     16~64 个随机字节, 用来打乱包长 (多长只跟帧长走, 见
//              obfuscate_padding_for).
//
// 掩码和 salt 绑在一起: 第三方改了 salt 或 len_enc, 算出来的垃圾长度就跟着
// 变, 帧的起点也就错位; 帧本身还有 AEAD 认证, 解不开就丢.
//
// 握手报文和带漫游凭证的帧不套这层: 握手时正是要谈"开不开混淆", 而漫游帧
// 要网关先看到最前面的 8 字节凭证才能认出是哪个会话.
//
// Copyright (C) 2025 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#ifndef INCLUDE__2026_10_14__AVPN_OBFUSCATE_HPP
#define INCLUDE__2026_10_14__AVPN_OBFUSCATE_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace libavpn {

	// 线上 salt 长度.
	inline constexpr std::size_t obfuscate_salt_size = 4;

	// 垃圾长度字段长度.
	inline constexpr std::size_t obfuscate_len_field_size = 2;

	// 垃圾数据长度范围.
	inline constexpr std::size_t obfuscate_min_padding = 16;
	inline constexpr std::size_t obfuscate_max_padding = 64;

	// 固定开销 / 最大开销.
	inline constexpr std::size_t obfuscate_fixed_overhead =
		obfuscate_salt_size + obfuscate_len_field_size;
	inline constexpr std::size_t obfuscate_max_overhead =
		obfuscate_fixed_overhead + obfuscate_max_padding;

	// 由密钥串与 salt 派生垃圾长度用的 16 位掩码 (测试可见).
	uint16_t obfuscate_mask(std::string_view key, std::string_view salt);

	// 密钥串的指纹 (4 字节), 握手时用来核对两端配的是不是同一把密钥;
	// 密钥串为空时返回 0.
	uint32_t obfuscate_key_hash(std::string_view key);

	// 混淆层用的随机数发生器.
	//
	// 每个包要 20~65 字节随机数, 每包都去调一次加密随机数接口太贵 (一次几微秒,
	// 包速率一上去就把 CPU 吃满). 安全性靠的是密钥串: 垃圾只是用来打乱包长,
	// 不必不可预测, 所以这里用一个小发生器, 会话开始时用加密随机数播一次种.
	class obfuscate_rand
	{
	public:
		// 用一段种子 (建议加密随机数) 播种; 空种子也能用.
		void seed(std::string_view seed);

		// 填 len 个随机字节.
		void fill(char* out, std::size_t len);

	private:
		uint64_t next();

		uint64_t m_state{ 0x9e3779b97f4a7c15ull };
	};

	// 帧长对应的垃圾长度, 落在 [obfuscate_min_padding, obfuscate_max_padding]
	// 内.
	//
	// 垃圾长度只跟帧长走, 不随机: 等长的帧套出来还是等长, 内核的合并优化
	// (收方向的 GRO、发方向的 GSO) 才认得出来 (见 doc/protocol_v2.md 6).
	std::size_t obfuscate_padding_for(std::size_t frame_size);

	// 给一个帧套上混淆层; 密钥串为空或帧为空时返回空串.
	std::string obfuscate_frame(obfuscate_rand& rand, std::string_view key,
		std::string_view frame);

	// 剥掉混淆层, frame 指向包装里面那一段 (生命周期跟 wire 走);
	// 长度非法或数据不完整时返回 false.
	bool deobfuscate_frame(std::string_view key, std::string_view wire,
		std::string_view& frame);

} // namespace libavpn

#endif // INCLUDE__2026_10_14__AVPN_OBFUSCATE_HPP
