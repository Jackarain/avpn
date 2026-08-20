//
// avpn_obfuscate.hpp
// ~~~~~~~~~~~~~~~~~~
//
// Copyright (C) 2025 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#ifndef INCLUDE__2025_11_20__AVPN_OBFUSCATE_HPP
#define INCLUDE__2025_11_20__AVPN_OBFUSCATE_HPP

#include <cstddef>
#include <cstdint>
#include <array>
#include <string>
#include <string_view>

namespace libavpn {

	// 数据特征混淆 (traffic obfuscation).
	//
	// 在线路上的数据帧外层追加随机垃圾数据, 打乱包长分布, 使观测者无法从
	// 数据包长度推断真实载荷特征. 混淆发生在 AEAD 加密之后, 不会影响加密
	// 语义, 也不会泄漏任何明文信息.
	//
	// 混淆后的线格式 (每个数据包独立):
	//
	//   [salt(4)][len_enc(2)][garbage(16~64)][counter(4)][ciphertext]
	//
	// - salt: 每包随机, 由 CSPRNG 生成.
	// - len_enc: 垃圾长度的加密字段, len_enc = garbage_len ^ mask,
	//   mask 由会话数据密钥与 salt 经 XXH64 派生 (取低 16 位), 每包不同.
	// - garbage: 随机垃圾数据, 长度 16~64 字节, 用于打乱包长.
	// - 其余部分为原始加密帧 [counter][ciphertext].
	//
	// len_enc 的 2 字节同时作为 AEAD 的 AAD 输入, 收发两侧使用线上原始字节,
	// 任何对长度字段的篡改都会导致 AEAD 认证失败而被丢弃.

	// 线上 salt 长度.
	inline constexpr std::size_t obfuscate_salt_size = 4;

	// 加密后的垃圾长度字段长度.
	inline constexpr std::size_t obfuscate_len_field_size = 2;

	// 垃圾数据长度范围.
	inline constexpr std::size_t obfuscate_min_padding = 16;
	inline constexpr std::size_t obfuscate_max_padding = 64;

	// 固定开销与最大开销.
	inline constexpr std::size_t obfuscate_fixed_overhead =
		obfuscate_salt_size + obfuscate_len_field_size;
	inline constexpr std::size_t obfuscate_max_overhead =
		obfuscate_fixed_overhead + obfuscate_max_padding;

	// 混淆头, 由 make_obfuscate_head 填充.
	struct obfuscate_head
	{
		std::array<uint8_t, obfuscate_salt_size> salt{};
		std::array<uint8_t, obfuscate_len_field_size> len_field{};
		std::string garbage;
	};

	// 生成当前数据包的混淆头: 随机 salt 与垃圾数据, 并计算加密后的长度字段.
	// key 为预共享混淆密钥串 (两端配置一致, 非空), 失败返回 false.
	// 注意: len_field 必须作为 AEAD 的 AAD 传给加密/解密两侧.
	bool make_obfuscate_head(std::string_view key, obfuscate_head& head);

	// 剥离混淆头, 返回原始加密帧 [counter][ciphertext] 与 AAD 长度字段.
	// 长度非法或数据不完整时返回 false. 认证由上层 AEAD 解密完成.
	bool deobfuscate_packet(std::string_view key, std::string_view wire,
		std::string_view& payload, std::string_view& len_field);

	// 由混淆密钥串与 salt 派生 16 位掩码 (测试可见).
	uint16_t obfuscate_mask(std::string_view key, std::string_view salt);

} // namespace libavpn

#endif // INCLUDE__2025_11_20__AVPN_OBFUSCATE_HPP
