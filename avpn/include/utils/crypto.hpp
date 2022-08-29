//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#pragma once

#include <cstddef>
#include <string>
#include <string_view>
#include <random>
#include <span>
#include <limits>
#include <memory>


namespace crypto_util {

	std::string ecdh_keygen();
	std::string ecdh_public(const std::string& pkey);

	struct keyexchange_member;
	class keyexchange
	{
		keyexchange(const keyexchange&) = delete;
		keyexchange& operator=(const keyexchange&) = delete;

	public:
		keyexchange(std::string_view static_private_key = {},
			std::string_view static_public_key = {},
			bool use_curve25519 = true);
		~keyexchange() = default;

	public:
		// DH或ECDH相关.
		std::string_view StaticPublicKey();
		std::string_view StaticPrivateKey();

		std::string_view GenerateSharedKey(std::string_view otherPubKey);

		// DH2相关.
		std::string_view EphemeralPublicKey();
		std::string_view GenerateSharedKey(std::string_view otherStaticPubKey,
			std::string_view otherEphemeralPubKey);

	private:
		std::shared_ptr<keyexchange_member> m_member;
	};

	class stream_crypto
	{
		stream_crypto(const stream_crypto&) = delete;
		stream_crypto& operator=(const stream_crypto&) = delete;

		class CSPRNG
		{
			CSPRNG(const CSPRNG&) = delete;
			CSPRNG& operator=(const CSPRNG&) = delete;

		public:
			using result_type = uint32_t;

			CSPRNG(std::mt19937& mt);
			~CSPRNG() = default;

			result_type operator()();

			static constexpr result_type min();
			static constexpr result_type max();

		private:
			std::mt19937& mt_;
		};

	public:
		explicit stream_crypto(std::string_view passwd);
		~stream_crypto() = default;

		void perform(std::span<std::byte> content);

		uint32_t aead_encrypt(std::span<std::byte> content);
		bool aead_decrypt(std::span<std::byte> content, uint32_t hash);

	private:
		std::seed_seq m_seed;
		std::mt19937 m_mt19937;
		std::string m_passwd;
	};

}
