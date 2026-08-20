//
// avpn_crypto.hpp
// ~~~~~~~~~~~~~~~~
//
// Copyright (C) 2025 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#ifndef INCLUDE__2025_11_20__AVPN_CRYPTO_HPP
#define INCLUDE__2025_11_20__AVPN_CRYPTO_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>

namespace libavpn {

	// 加密相关常量与工具函数.
	// 基于 OpenSSL 的 X25519(Curve25519) ECDH、ChaCha20-Poly1305 AEAD
	// 以及 HKDF-SHA256 密钥派生.
	namespace crypto {

		// X25519 密钥大小(字节).
		inline constexpr std::size_t x25519_key_size = 32;

		// AEAD nonce 由 8 字节会话盐 + 4 字节计数器组成.
		inline constexpr std::size_t aead_nonce_size = 12;

		// 会话盐部分 (握手时派生, 不走网络).
		inline constexpr std::size_t aead_nonce_salt_size = 8;

		// 计数器部分 (每包递增, 线上仅传输该部分).
		inline constexpr std::size_t aead_counter_size = 4;

		// AEAD 认证标签大小.
		inline constexpr std::size_t aead_tag_size = 16;

		// 会话密钥大小(64 字节, 前 32 字节为 client->server 方向,
		// 后 32 字节为 server->client 方向).
		inline constexpr std::size_t session_key_size = 64;

		// 生成 n 字节密码学安全随机数.
		std::string random_bytes(std::size_t n);

		// base64 编码/解码.
		std::string base64_encode(std::string_view data);
		std::string base64_decode(std::string_view data);

		// 生成一对 X25519 密钥对, 返回 {private_key, public_key}.
		std::pair<std::string, std::string> x25519_generate_keypair();

		// 由私钥计算公钥, 失败返回空字符串.
		std::string x25519_public_key(std::string_view private_key);

		// X25519 ECDH, 使用 private_key 与 peer_public_key 计算共享密钥,
		// 失败返回空字符串.
		std::string x25519_ecdh(std::string_view private_key,
			std::string_view peer_public_key);

		// HKDF-SHA256 密钥派生, 输出 out_len 字节.
		std::string hkdf_sha256(std::string_view ikm, std::string_view salt,
			std::string_view info, std::size_t out_len);

		// ChaCha20-Poly1305 AEAD 加密.
		// key 必须为 32 字节, nonce 必须为 aead_nonce_size 字节.
		// 返回 密文+tag, 失败返回空字符串.
		std::string aead_encrypt(std::string_view key, std::string_view nonce,
			std::string_view plaintext, std::string_view aad = {});

		// ChaCha20-Poly1305 AEAD 解密.
		// 输入为 密文+tag, 成功返回明文, 认证失败返回空字符串.
		std::string aead_decrypt(std::string_view key, std::string_view nonce,
			std::string_view ciphertext, std::string_view aad = {});
	}

} // namespace libavpn

#endif // INCLUDE__2025_11_20__AVPN_CRYPTO_HPP
