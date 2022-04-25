//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#pragma once

#include "utils/xxhash.hpp"

#include <cryptopp/dh.h>
#include <cryptopp/dh2.h>
#include <cryptopp/osrng.h>

#include <cstddef>
#include <string>
#include <string_view>
#include <random>
#include <span>
#include <limits>


namespace crypto_util {

class dh_keyexchange
{
public:
    dh_keyexchange()
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
	{
		CryptoPP::AutoSeededRandomPool prng;

		dh_.AccessGroupParameters().Initialize(p_, q_, g_);
		dh_.AccessGroupParameters().ValidateGroup(prng, 3);

		privateKey_.resize(dh_.PrivateKeyLength());
		publicKey_.resize(dh_.PublicKeyLength());

		dh_.GenerateKeyPair(prng, privateKey_, publicKey_);
	}
    ~dh_keyexchange() = default;

public:
	std::string_view PublicKey()
	{
		return { (char*)publicKey_.data(), publicKey_.size() };
	}

	std::string_view GenerateSharedKey(std::string_view otherPubKey)
	{
		CryptoPP::SecByteBlock pubKey(
			reinterpret_cast<const CryptoPP::byte*>(otherPubKey.data()), otherPubKey.size());

		shared_.resize(dh_.AgreedValueLength());
		if (!dh_.Agree(shared_, privateKey_, pubKey))
			return {};

		return { (char*)shared_.data(), shared_.size() };
	}

private:
	CryptoPP::Integer p_;
	CryptoPP::Integer g_;
	CryptoPP::Integer q_;
	CryptoPP::DH dh_;
	CryptoPP::SecByteBlock privateKey_;
	CryptoPP::SecByteBlock publicKey_;
	CryptoPP::SecByteBlock shared_;
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
        using result_type = uint64_t;

        CSPRNG(std::mt19937& mt)
            : mt_(mt)
        {}
        ~CSPRNG() = default;

        result_type operator()()
        {
            auto result = mt_();
            const char* p = reinterpret_cast<const char*>(&result);
            return xxh::xxhash3<64>((const void*)p, sizeof(result));
        }

        static constexpr result_type min()
        {
            return std::numeric_limits<result_type>::min();
        }

        static constexpr result_type max()
        {
            return std::numeric_limits<result_type>::max();
        }

    private:
        std::mt19937& mt_;
    };

public:
    explicit stream_crypto(std::string_view passwd)
        : m_seed(passwd.begin(), passwd.end())
        , m_mt19937(m_seed)
        , m_distribution(0, 255)
    {}
    ~stream_crypto() = default;

    void perform(std::span<std::byte> content)
    {
        CSPRNG rng(m_mt19937);
        for (auto& c : content)
            c = c ^ static_cast<std::byte>(m_distribution(rng));
    }

private:
    std::seed_seq m_seed;
    std::mt19937 m_mt19937;
    std::uniform_int_distribution<int> m_distribution;
};

}
