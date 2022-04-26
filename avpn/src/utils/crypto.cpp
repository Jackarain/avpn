//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#include "utils/crypto.hpp"

#ifndef XXH_INLINE_ALL
#	define XXH_INLINE_ALL
#endif // !XXH_INLINE_ALL

#include "utils/xxhash.hpp"

#include <cryptopp/dh.h>
#include <cryptopp/dh2.h>
#include <cryptopp/osrng.h>
#include <cryptopp/xed25519.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/base64.h>


namespace crypto_util {

	struct keyexchange_member
	{
		keyexchange_member()
			: p_("0xB10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C6"
				"9A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C0"
				"13ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD70"
				"98488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0"
				"A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708"
				"DF1FB2BC2E4A4371")
			, g_("0xA4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507F"
				"D6406CFF14266D31266FEA1E5C41564B777E690F5504F213"
				"160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1"
				"909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A"
				"D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24"
				"855E6EEB22B3B2E5")
			, q_("0xF518AA8781A8DF278ABA4E7D64B7CB9D49462353")
			, dh2_(dh_)
		{}

		CryptoPP::Integer p_;
		CryptoPP::Integer g_;
		CryptoPP::Integer q_;

		CryptoPP::DH dh_;
		CryptoPP::DH2 dh2_;


		CryptoPP::SecByteBlock staticPrivateKey_;
		CryptoPP::SecByteBlock staticPublicKey_;

		CryptoPP::SecByteBlock ephemeralPublicKey_;
		CryptoPP::SecByteBlock ephemeralPrivateKey_;

		CryptoPP::SecByteBlock shared_;

		std::unique_ptr<CryptoPP::x25519> x25519_;
	};

	keyexchange::keyexchange(std::string_view static_private_key /*= {}*/,
		std::string_view static_public_key /*= {}*/, bool use_curve25519/* = true*/)
		: m_member(new keyexchange_member)
	{
		CryptoPP::AutoSeededRandomPool prng;
		auto& member = *m_member;

		if (use_curve25519)
		{
			if (!static_private_key.empty())
			{
				CryptoPP::Base64Decoder decoder;
				decoder.Put((CryptoPP::byte*)static_private_key.data(), static_private_key.size());
				decoder.MessageEnd();

				auto size = decoder.MaxRetrievable();
				if (size && size <= SIZE_MAX)
				{
					member.staticPrivateKey_.resize(size);
					decoder.Get(member.staticPrivateKey_, size);
				}
			}
			else
			{
				member.staticPrivateKey_.resize(CryptoPP::x25519::SECRET_KEYLENGTH);

				CryptoPP::x25519 ecdh;
				ecdh.GeneratePrivateKey(prng, member.staticPrivateKey_);
			}

			member.x25519_ = std::make_unique<CryptoPP::x25519>(member.staticPrivateKey_);
			member.staticPublicKey_.resize(member.x25519_->PublicKeyLength());
			member.x25519_->GeneratePublicKey(prng, member.staticPrivateKey_, member.staticPublicKey_);
		}
		else
		{
			member.dh_.AccessGroupParameters().Initialize(member.p_, member.q_, member.g_);
			member.dh_.GetGroupParameters().ValidateGroup(prng, 3);

			CryptoPP::DH2& dh2 = member.dh2_;

			if (static_private_key.empty() || static_public_key.empty())
			{
				member.staticPrivateKey_.resize(dh2.StaticPrivateKeyLength());
				member.staticPublicKey_.resize(dh2.StaticPublicKeyLength());

				dh2.GenerateStaticKeyPair(prng, member.staticPrivateKey_, member.staticPublicKey_);
			}
			else
			{
				member.staticPrivateKey_ = CryptoPP::SecByteBlock(reinterpret_cast<const CryptoPP::byte*>(
					static_private_key.data()), static_private_key.size());
				member.staticPublicKey_ = CryptoPP::SecByteBlock(reinterpret_cast<const CryptoPP::byte*>(
					static_public_key.data()), static_public_key.size());
			}

			member.ephemeralPrivateKey_.resize(dh2.EphemeralPrivateKeyLength());
			member.ephemeralPublicKey_.resize(dh2.EphemeralPublicKeyLength());

			dh2.GenerateEphemeralKeyPair(prng, member.ephemeralPrivateKey_, member.ephemeralPublicKey_);
		}
	}



	//////////////////////////////////////////////////////////////////////////

	std::string base64_encode(std::string_view input)
	{
		std::string result;

		CryptoPP::Base64Encoder encoder;
		encoder.Put((CryptoPP::byte*)input.data(), input.size());
		encoder.MessageEnd();

		auto size = encoder.MaxRetrievable();
		if (size && size <= SIZE_MAX)
		{
			result.resize(size);
			encoder.Get((CryptoPP::byte*)&result[0], result.size());
		}

		return result;
	}

	//////////////////////////////////////////////////////////////////////////

	std::string_view keyexchange::StaticPublicKey()
	{
		auto& member = *m_member;
		return { (char*)member.staticPublicKey_.data(), member.staticPublicKey_.size() };
	}

	std::string_view keyexchange::EphemeralPublicKey()
	{
		auto& member = *m_member;
		if (member.x25519_)
			return {};
		return { (char*)member.ephemeralPublicKey_.data(), member.ephemeralPublicKey_.size() };
	}

	std::string_view keyexchange::GenerateSharedKey(std::string_view otherPubKey)
	{
		CryptoPP::SecByteBlock pubKey(
			reinterpret_cast<const CryptoPP::byte*>(otherPubKey.data()), otherPubKey.size());

		auto& member = *m_member;
		if (member.x25519_)
		{
			member.shared_.resize(member.x25519_->AgreedValueLength());
			if (!member.x25519_->Agree(member.shared_, member.staticPrivateKey_, pubKey))
				return {};
		}
		else
		{
			member.shared_.resize(member.dh_.AgreedValueLength());
			if (!member.dh_.Agree(member.shared_, member.ephemeralPrivateKey_, pubKey))
				return {};
		}

		return { (char*)member.shared_.data(), member.shared_.size() };
	}

	std::string_view keyexchange::GenerateSharedKey(std::string_view otherStaticPubKey, std::string_view otherEphemeralPubKey)
	{
		auto& member = *m_member;

		if (member.x25519_)
			return {};

		member.shared_.resize(member.dh2_.AgreedValueLength());

		CryptoPP::SecByteBlock spubKey(
			reinterpret_cast<const CryptoPP::byte*>(otherStaticPubKey.data()), otherStaticPubKey.size());
		CryptoPP::SecByteBlock epubKey(
			reinterpret_cast<const CryptoPP::byte*>(otherEphemeralPubKey.data()), otherEphemeralPubKey.size());

		if (!member.dh2_.Agree(member.shared_, member.staticPrivateKey_, member.ephemeralPrivateKey_, spubKey, epubKey))
			return {};

		return { (char*)member.shared_.data(), member.shared_.size() };
	}





	//////////////////////////////////////////////////////////////////////////

	stream_crypto::CSPRNG::CSPRNG(std::mt19937& mt)
		: mt_(mt)
	{}

	stream_crypto::CSPRNG::result_type stream_crypto::CSPRNG::operator()()
	{
		auto result = mt_();
		const char* p = reinterpret_cast<const char*>(&result);
		return (result_type)XXH32(p, 4, 0) % 256;
	}

	constexpr stream_crypto::CSPRNG::result_type stream_crypto::CSPRNG::min()
	{
		return std::numeric_limits<result_type>::min();
	}

	constexpr crypto_util::stream_crypto::CSPRNG::result_type stream_crypto::CSPRNG::max()
	{
		return std::numeric_limits<result_type>::max();
	}


	stream_crypto::stream_crypto(std::string_view passwd)
		: m_seed(passwd.begin(), passwd.end())
		, m_mt19937(m_seed)
	{}

	void stream_crypto::perform(std::span<std::byte> content)
	{
		CSPRNG rng(m_mt19937);
		for (auto& c : content)
			c = c ^ static_cast<std::byte>(rng());
	}

	uint32_t stream_crypto::aead_encrypt(std::span<std::byte> content)
	{
		const char* p = reinterpret_cast<const char*>(content.data());
		uint32_t hash = XXH32(p, content.size_bytes(), 0);

		CSPRNG rng(m_mt19937);
		for (auto& c : content)
			c = c ^ static_cast<std::byte>(rng());

		return hash;
	}

	bool stream_crypto::aead_decrypt(std::span<std::byte> content, uint32_t hash)
	{
		CSPRNG rng(m_mt19937);
		for (auto& c : content)
			c = c ^ static_cast<std::byte>(rng());

		const char* p = reinterpret_cast<const char*>(content.data());
		uint32_t h = XXH32(p, content.size_bytes(), 0);

		if (hash != h)
			return false;

		return true;
	}

	std::mt19937& stream_crypto::mt19937()
	{
		return m_mt19937;
	}

}
