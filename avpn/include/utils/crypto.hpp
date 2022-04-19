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

#include "utils/xxhash.hpp"


namespace crypto_util {

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
    std::uniform_int_distribution<uint8_t> m_distribution;
};

}
