//
// avpn_crypto.cpp
// ~~~~~~~~~~~~~~~~
//
// Copyright (C) 2025 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#include "libavpn/avpn_crypto.hpp"
#include "libavpn/logging.hpp"

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#if defined(OPENSSL_IS_BORINGSSL)
#include <openssl/aead.h>
#endif

#include <memory>
#include <vector>
#include <cstring>

namespace libavpn::crypto {

	namespace detail {

		// RAII 封装 EVP_PKEY_CTX.
		struct pkey_ctx_free
		{
			void operator()(EVP_PKEY_CTX* p) const
			{
				if (p)
					EVP_PKEY_CTX_free(p);
			}
		};

		using pkey_ctx_ptr = std::unique_ptr<EVP_PKEY_CTX, pkey_ctx_free>;

		// RAII 封装 EVP_PKEY.
		struct pkey_free
		{
			void operator()(EVP_PKEY* p) const
			{
				if (p)
					EVP_PKEY_free(p);
			}
		};

		using pkey_ptr = std::unique_ptr<EVP_PKEY, pkey_free>;

		// RAII 封装 EVP_CIPHER_CTX.
		struct cipher_ctx_free
		{
			void operator()(EVP_CIPHER_CTX* p) const
			{
				if (p)
					EVP_CIPHER_CTX_free(p);
			}
		};

		using cipher_ctx_ptr = std::unique_ptr<EVP_CIPHER_CTX, cipher_ctx_free>;

#if defined(OPENSSL_IS_BORINGSSL)
		// RAII 封装 EVP_AEAD_CTX (BoringSSL 专用).
		struct aead_ctx_free
		{
			void operator()(EVP_AEAD_CTX* p) const
			{
				if (p)
					EVP_AEAD_CTX_free(p);
			}
		};

		using aead_ctx_ptr = std::unique_ptr<EVP_AEAD_CTX, aead_ctx_free>;
#endif

	} // namespace detail

	std::string random_bytes(std::size_t n)
	{
		std::string ret(n, 0);
		if (n == 0)
			return ret;
		if (RAND_bytes(reinterpret_cast<unsigned char*>(ret.data()),
				static_cast<int>(n)) != 1)
			return {};
		return ret;
	}

	std::string base64_encode(std::string_view data)
	{
		if (data.empty())
			return {};

		// 计算 base64 编码后大小 (含结尾填充).
		std::size_t out_len = 4 * ((data.size() + 2) / 3);
		std::string out(out_len + 1, 0);

		int len = EVP_EncodeBlock(
			reinterpret_cast<unsigned char*>(out.data()),
			reinterpret_cast<const unsigned char*>(data.data()),
			static_cast<int>(data.size()));
		if (len < 0)
			return {};

		out.resize(static_cast<std::size_t>(len));
		return out;
	}

	std::string base64_decode(std::string_view data)
	{
		if (data.empty())
			return {};

		// base64 解码, 每 4 个字符解码为 3 字节.
		std::size_t max_len = (data.size() / 4) * 3 + 3;
		std::string out(max_len, 0);

		int len = EVP_DecodeBlock(
			reinterpret_cast<unsigned char*>(out.data()),
			reinterpret_cast<const unsigned char*>(data.data()),
			static_cast<int>(data.size()));
		if (len < 0)
			return {};

		// 去除填充字符 '=' 对应的大小.
		std::size_t padding = 0;
		if (!data.empty() && data.back() == '=')
			padding++;
		if (data.size() > 1 && data[data.size() - 2] == '=')
			padding++;

		out.resize(static_cast<std::size_t>(len) - padding);
		return out;
	}

	std::pair<std::string, std::string> x25519_generate_keypair()
	{
		std::pair<std::string, std::string> ret;
		ret.first.resize(x25519_key_size);
		ret.second.resize(x25519_key_size);

		// 直接使用 RAND_bytes 生成私钥, 然后通过公钥计算函数得到公钥.
		if (RAND_bytes(reinterpret_cast<unsigned char*>(ret.first.data()),
				x25519_key_size) != 1)
			return {};

		auto pub = x25519_public_key(ret.first);
		if (pub.empty())
			return {};

		ret.second = std::move(pub);
		return ret;
	}

	std::string x25519_public_key(std::string_view private_key)
	{
		if (private_key.size() != x25519_key_size)
			return {};

		detail::pkey_ptr pkey(EVP_PKEY_new_raw_private_key(
			EVP_PKEY_X25519, nullptr,
			reinterpret_cast<const unsigned char*>(private_key.data()),
			x25519_key_size));
		if (!pkey)
			return {};

		std::string pub(x25519_key_size, 0);
		std::size_t len = x25519_key_size;
		if (EVP_PKEY_get_raw_public_key(pkey.get(),
				reinterpret_cast<unsigned char*>(pub.data()), &len) != 1)
			return {};

		pub.resize(len);
		return pub;
	}

	std::string x25519_ecdh(std::string_view private_key,
		std::string_view peer_public_key)
	{
		if (private_key.size() != x25519_key_size ||
			peer_public_key.size() != x25519_key_size)
			return {};

		detail::pkey_ptr pkey(EVP_PKEY_new_raw_private_key(
			EVP_PKEY_X25519, nullptr,
			reinterpret_cast<const unsigned char*>(private_key.data()),
			x25519_key_size));
		if (!pkey)
			return {};

		detail::pkey_ptr peer(EVP_PKEY_new_raw_public_key(
			EVP_PKEY_X25519, nullptr,
			reinterpret_cast<const unsigned char*>(peer_public_key.data()),
			x25519_key_size));
		if (!peer)
			return {};

		detail::pkey_ctx_ptr ctx(EVP_PKEY_CTX_new(pkey.get(), nullptr));
		if (!ctx)
			return {};

		if (EVP_PKEY_derive_init(ctx.get()) <= 0)
			return {};

		if (EVP_PKEY_derive_set_peer(ctx.get(), peer.get()) <= 0)
			return {};

		std::size_t len = 0;
		if (EVP_PKEY_derive(ctx.get(), nullptr, &len) <= 0)
			return {};
		if (len != x25519_key_size)
			return {};

		std::string shared(x25519_key_size, 0);
		if (EVP_PKEY_derive(ctx.get(),
				reinterpret_cast<unsigned char*>(shared.data()), &len) <= 0)
			return {};

		shared.resize(len);
		return shared;
	}

	std::string hkdf_sha256(std::string_view ikm, std::string_view salt,
		std::string_view info, std::size_t out_len)
	{
		if (ikm.empty() || out_len == 0)
			return {};

		detail::pkey_ctx_ptr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr));
		if (!ctx)
			return {};

		if (EVP_PKEY_derive_init(ctx.get()) <= 0)
			return {};

		if (EVP_PKEY_CTX_set_hkdf_md(ctx.get(), EVP_sha256()) <= 0)
			return {};

		if (EVP_PKEY_CTX_set1_hkdf_key(ctx.get(),
				reinterpret_cast<const unsigned char*>(ikm.data()),
				static_cast<int>(ikm.size())) <= 0)
			return {};

		if (!salt.empty())
		{
			if (EVP_PKEY_CTX_set1_hkdf_salt(ctx.get(),
					reinterpret_cast<const unsigned char*>(salt.data()),
					static_cast<int>(salt.size())) <= 0)
				return {};
		}

		if (!info.empty())
		{
			if (EVP_PKEY_CTX_add1_hkdf_info(ctx.get(),
					reinterpret_cast<const unsigned char*>(info.data()),
					static_cast<int>(info.size())) <= 0)
				return {};
		}

		std::string out(out_len, 0);
		std::size_t len = out_len;
		if (EVP_PKEY_derive(ctx.get(),
				reinterpret_cast<unsigned char*>(out.data()), &len) <= 0)
			return {};

		out.resize(len);
		return out;
	}

	std::string aead_encrypt(std::string_view key, std::string_view nonce,
		std::string_view plaintext, std::string_view aad)
	{
		if (key.size() != x25519_key_size ||
			nonce.size() != aead_nonce_size)
			return {};

#if defined(OPENSSL_IS_BORINGSSL)
		// BoringSSL 不提供 EVP_chacha20_poly1305 (EVP_CIPHER), 使用 EVP_AEAD 接口.
		detail::aead_ctx_ptr aead(EVP_AEAD_CTX_new(EVP_aead_chacha20_poly1305(),
			reinterpret_cast<const unsigned char*>(key.data()), key.size(),
			aead_tag_size));
		if (!aead)
			return {};

		// 一次调用完成 ChaCha20-Poly1305 加密并输出密文+认证标签.
		std::string out(plaintext.size() + aead_tag_size, 0);
		std::size_t out_len = 0;
		if (EVP_AEAD_CTX_seal(aead.get(),
				reinterpret_cast<unsigned char*>(out.data()), &out_len, out.size(),
				reinterpret_cast<const unsigned char*>(nonce.data()), nonce.size(),
				reinterpret_cast<const unsigned char*>(plaintext.data()),
				plaintext.size(),
				reinterpret_cast<const unsigned char*>(aad.data()), aad.size()) != 1)
			return {};

		out.resize(out_len);
		return out;
#else
		detail::cipher_ctx_ptr ctx(EVP_CIPHER_CTX_new());
		if (!ctx)
			return {};

		// 初始化加密上下文, 使用 ChaCha20-Poly1305.
		if (EVP_EncryptInit_ex(ctx.get(), EVP_chacha20_poly1305(),
				nullptr, nullptr, nullptr) != 1)
			return {};

		// 设置 nonce 长度.
		if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN,
				static_cast<int>(aead_nonce_size), nullptr) != 1)
			return {};

		// 设置 key 与 nonce.
		if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr,
				reinterpret_cast<const unsigned char*>(key.data()),
				reinterpret_cast<const unsigned char*>(nonce.data())) != 1)
			return {};

		// 设置附加认证数据 (aad).
		int out_len = 0;
		if (!aad.empty())
		{
			if (EVP_EncryptUpdate(ctx.get(), nullptr, &out_len,
					reinterpret_cast<const unsigned char*>(aad.data()),
					static_cast<int>(aad.size())) != 1)
				return {};
		}

		// 加密数据.
		std::string out(plaintext.size() + aead_tag_size, 0);
		if (!plaintext.empty())
		{
			if (EVP_EncryptUpdate(ctx.get(),
					reinterpret_cast<unsigned char*>(out.data()), &out_len,
					reinterpret_cast<const unsigned char*>(plaintext.data()),
					static_cast<int>(plaintext.size())) != 1)
				return {};
		}

		int final_len = 0;
		if (EVP_EncryptFinal_ex(ctx.get(),
				reinterpret_cast<unsigned char*>(out.data()) + out_len,
				&final_len) != 1)
			return {};

		out_len += final_len;

		// 获取认证标签.
		unsigned char tag[aead_tag_size]{};
		if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_GET_TAG,
				aead_tag_size, tag) != 1)
			return {};

		std::memcpy(out.data() + out_len, tag, aead_tag_size);
		out.resize(out_len + aead_tag_size);
		return out;
#endif
	}

	std::string aead_decrypt(std::string_view key, std::string_view nonce,
		std::string_view ciphertext, std::string_view aad)
	{
		if (key.size() != x25519_key_size ||
			nonce.size() != aead_nonce_size ||
			ciphertext.size() < aead_tag_size)
			return {};

		std::size_t cipher_len = ciphertext.size() - aead_tag_size;

#if defined(OPENSSL_IS_BORINGSSL)
		detail::aead_ctx_ptr aead(EVP_AEAD_CTX_new(EVP_aead_chacha20_poly1305(),
			reinterpret_cast<const unsigned char*>(key.data()), key.size(),
			aead_tag_size));
		if (!aead)
			return {};

		// 一次调用完成认证与解密, 输入为密文+认证标签.
		std::string out(ciphertext.size(), 0);
		std::size_t out_len = 0;
		if (EVP_AEAD_CTX_open(aead.get(),
				reinterpret_cast<unsigned char*>(out.data()), &out_len, out.size(),
				reinterpret_cast<const unsigned char*>(nonce.data()), nonce.size(),
				reinterpret_cast<const unsigned char*>(ciphertext.data()),
				ciphertext.size(),
				reinterpret_cast<const unsigned char*>(aad.data()), aad.size()) != 1)
			return {};

		out.resize(out_len);
		return out;
#else
		detail::cipher_ctx_ptr ctx(EVP_CIPHER_CTX_new());
		if (!ctx)
			return {};

		if (EVP_DecryptInit_ex(ctx.get(), EVP_chacha20_poly1305(),
				nullptr, nullptr, nullptr) != 1)
			return {};

		if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN,
				static_cast<int>(aead_nonce_size), nullptr) != 1)
			return {};

		if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr,
				reinterpret_cast<const unsigned char*>(key.data()),
				reinterpret_cast<const unsigned char*>(nonce.data())) != 1)
			return {};

		// 设置认证标签.
		if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_TAG,
				aead_tag_size,
				const_cast<unsigned char*>(
					reinterpret_cast<const unsigned char*>(
						ciphertext.data() + cipher_len))) != 1)
			return {};

		// 验证附加认证数据 (aad).
		int out_len = 0;
		if (!aad.empty())
		{
			if (EVP_DecryptUpdate(ctx.get(), nullptr, &out_len,
					reinterpret_cast<const unsigned char*>(aad.data()),
					static_cast<int>(aad.size())) != 1)
				return {};
		}

		// 解密数据.
		std::string out(cipher_len, 0);
		if (cipher_len > 0)
		{
			if (EVP_DecryptUpdate(ctx.get(),
					reinterpret_cast<unsigned char*>(out.data()), &out_len,
					reinterpret_cast<const unsigned char*>(ciphertext.data()),
					static_cast<int>(cipher_len)) != 1)
				return {};
		}

		int final_len = 0;
		if (EVP_DecryptFinal_ex(ctx.get(),
				reinterpret_cast<unsigned char*>(out.data()) + out_len,
				&final_len) != 1)
		{
			// 认证失败.
			return {};
		}

		out_len += final_len;
		out.resize(out_len);
		return out;
#endif
	}

	aead_cipher::aead_cipher() = default;

	aead_cipher::~aead_cipher()
	{
#if defined(OPENSSL_IS_BORINGSSL)
		if (m_ctx)
			EVP_AEAD_CTX_free(static_cast<EVP_AEAD_CTX*>(m_ctx));
#else
		if (m_ctx)
			EVP_CIPHER_CTX_free(static_cast<EVP_CIPHER_CTX*>(m_ctx));
#endif
	}

	bool aead_cipher::init(std::string_view key)
	{
		if (key.size() != x25519_key_size)
			return false;

#if defined(OPENSSL_IS_BORINGSSL)
		auto* ctx = EVP_AEAD_CTX_new(EVP_aead_chacha20_poly1305(),
			reinterpret_cast<const unsigned char*>(key.data()), key.size(),
			aead_tag_size);
		if (!ctx)
			return false;

		if (m_ctx)
			EVP_AEAD_CTX_free(static_cast<EVP_AEAD_CTX*>(m_ctx));

		m_ctx = ctx;
#else
		detail::cipher_ctx_ptr ctx(EVP_CIPHER_CTX_new());
		if (!ctx)
			return false;

		if (EVP_EncryptInit_ex(ctx.get(), EVP_chacha20_poly1305(),
				nullptr, nullptr, nullptr) != 1)
			return false;

		if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN,
				static_cast<int>(aead_nonce_size), nullptr) != 1)
			return false;

		// 仅设置密钥, nonce 在每次加解密时单独设置.
		if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr,
				reinterpret_cast<const unsigned char*>(key.data()),
				nullptr) != 1)
			return false;

		if (m_ctx)
			EVP_CIPHER_CTX_free(static_cast<EVP_CIPHER_CTX*>(m_ctx));

		m_ctx = ctx.release();
#endif
		return true;
	}

	bool aead_cipher::encrypt(std::string_view nonce, std::string_view plaintext,
		std::string_view aad, uint8_t* out, std::size_t out_size,
		std::size_t& out_len)
	{
		out_len = 0;

		if (!m_ctx || nonce.size() != aead_nonce_size || !out ||
			out_size < plaintext.size() + aead_tag_size)
			return false;

#if defined(OPENSSL_IS_BORINGSSL)
		std::size_t len = 0;
		if (EVP_AEAD_CTX_seal(static_cast<EVP_AEAD_CTX*>(m_ctx), out, &len,
				out_size,
				reinterpret_cast<const unsigned char*>(nonce.data()),
				nonce.size(),
				reinterpret_cast<const unsigned char*>(plaintext.data()),
				plaintext.size(),
				reinterpret_cast<const unsigned char*>(aad.data()),
				aad.size()) != 1)
			return false;

		out_len = len;
		return true;
#else
		auto* ctx = static_cast<EVP_CIPHER_CTX*>(m_ctx);

		// 复用已设置好的密钥, 每包只更新 nonce.
		if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, nullptr,
				reinterpret_cast<const unsigned char*>(nonce.data())) != 1)
			return false;

		int len = 0;
		if (!aad.empty() && EVP_EncryptUpdate(ctx, nullptr, &len,
				reinterpret_cast<const unsigned char*>(aad.data()),
				static_cast<int>(aad.size())) != 1)
			return false;

		int total = 0;
		if (!plaintext.empty() && EVP_EncryptUpdate(ctx, out, &len,
				reinterpret_cast<const unsigned char*>(plaintext.data()),
				static_cast<int>(plaintext.size())) != 1)
			return false;
		total = len;

		int final_len = 0;
		if (EVP_EncryptFinal_ex(ctx, out + total, &final_len) != 1)
			return false;
		total += final_len;

		if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, aead_tag_size,
				out + total) != 1)
			return false;

		out_len = static_cast<std::size_t>(total) + aead_tag_size;
		return true;
#endif
	}

	bool aead_cipher::decrypt(std::string_view nonce, std::string_view ciphertext,
		std::string_view aad, uint8_t* out, std::size_t out_size,
		std::size_t& out_len)
	{
		out_len = 0;

		if (!m_ctx || nonce.size() != aead_nonce_size ||
			ciphertext.size() < aead_tag_size || !out)
			return false;

		const std::size_t cipher_len = ciphertext.size() - aead_tag_size;
		if (out_size < cipher_len)
			return false;

#if defined(OPENSSL_IS_BORINGSSL)
		std::size_t len = 0;
		if (EVP_AEAD_CTX_open(static_cast<EVP_AEAD_CTX*>(m_ctx), out, &len,
				out_size,
				reinterpret_cast<const unsigned char*>(nonce.data()),
				nonce.size(),
				reinterpret_cast<const unsigned char*>(ciphertext.data()),
				ciphertext.size(),
				reinterpret_cast<const unsigned char*>(aad.data()),
				aad.size()) != 1)
			return false;

		out_len = len;
		return true;
#else
		auto* ctx = static_cast<EVP_CIPHER_CTX*>(m_ctx);

		if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, nullptr,
				reinterpret_cast<const unsigned char*>(nonce.data())) != 1)
			return false;

		// 设置认证标签 (原地解密时标签位于输入缓冲区尾部).
		if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
				aead_tag_size,
				const_cast<unsigned char*>(
					reinterpret_cast<const unsigned char*>(
						ciphertext.data() + cipher_len))) != 1)
			return false;

		int len = 0;
		if (!aad.empty() && EVP_DecryptUpdate(ctx, nullptr, &len,
				reinterpret_cast<const unsigned char*>(aad.data()),
				static_cast<int>(aad.size())) != 1)
			return false;

		int total = 0;
		if (cipher_len > 0 && EVP_DecryptUpdate(ctx, out, &len,
				reinterpret_cast<const unsigned char*>(ciphertext.data()),
				static_cast<int>(cipher_len)) != 1)
			return false;
		total = len;

		int final_len = 0;
		if (EVP_DecryptFinal_ex(ctx, out + total, &final_len) != 1)
			return false;

		out_len = static_cast<std::size_t>(total + final_len);
		return true;
#endif
	}

} // namespace libavpn::crypto
