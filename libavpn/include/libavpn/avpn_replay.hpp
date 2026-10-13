//
// avpn_replay.hpp
// ~~~~~~~~~~~~~~~
//
// 64 位全局序号 (次代 x 2^32 + 计数器) 的重放窗口.
//
// Copyright (C) 2025 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#ifndef INCLUDE__2026_10_14__AVPN_REPLAY_HPP
#define INCLUDE__2026_10_14__AVPN_REPLAY_HPP

#include <cstdint>
#include <cstddef>
#include <vector>
#include <algorithm>

namespace libavpn {

	// 接受单调递增且位于滑动窗口内的序号, 拒绝重放与窗口外旧包.
	//
	// 窗口用 64 位字位图表示, 位 i 表示序号 (m_max - i) 已收到.
	// 序号跨次代连续递增, 所以不存在回绕带来的歧义.
	class seq_window
	{
	public:
		explicit seq_window(std::size_t window_size = 1024)
			: m_window_size(std::max<std::size_t>(1, window_size))
			, m_words((m_window_size + 63) / 64, 0)
		{}

		seq_window(const seq_window&) = delete;
		seq_window& operator=(const seq_window&) = delete;

		// 检查 seq 是否可接受, 接受则更新窗口并返回 true.
		bool check_and_update(uint64_t seq)
		{
			if (!m_init)
			{
				m_init = true;
				m_max = seq;
				std::fill(m_words.begin(), m_words.end(), uint64_t{ 0 });
				set_bit(0);
				return true;
			}

			if (seq > m_max)
			{
				shift_bits(seq - m_max);
				m_max = seq;
				set_bit(0);
				return true;
			}

			const uint64_t offset = m_max - seq;
			if (offset >= m_window_size || get_bit(static_cast<std::size_t>(offset)))
				return false;
			set_bit(static_cast<std::size_t>(offset));
			return true;
		}

		void reset()
		{
			m_max = 0;
			m_init = false;
			std::fill(m_words.begin(), m_words.end(), uint64_t{ 0 });
		}

	private:
		void set_bit(std::size_t i)
		{
			m_words[i >> 6] |= (uint64_t{ 1 } << (i & 63));
		}

		bool get_bit(std::size_t i) const
		{
			return ((m_words[i >> 6] >> (i & 63)) & 1) != 0;
		}

		// 全部位向高位偏移 shift (旧序号对应的偏移量随之增大).
		void shift_bits(uint64_t shift)
		{
			if (shift >= m_window_size)
			{
				std::fill(m_words.begin(), m_words.end(), uint64_t{ 0 });
				return;
			}

			const std::size_t word_shift = static_cast<std::size_t>(shift >> 6);
			const unsigned bit_shift = static_cast<unsigned>(shift & 63);

			for (std::size_t i = m_words.size(); i-- > 0;)
			{
				uint64_t v = 0;
				if (i >= word_shift)
				{
					v = m_words[i - word_shift] << bit_shift;
					if (bit_shift != 0 && i > word_shift)
						v |= m_words[i - word_shift - 1] >> (64 - bit_shift);
				}
				m_words[i] = v;
			}

			const std::size_t rem = m_window_size & 63;
			if (rem != 0)
				m_words.back() &= (uint64_t{ 1 } << rem) - 1;
		}

		std::size_t m_window_size{ 1024 };
		uint64_t m_max{ 0 };
		std::vector<uint64_t> m_words;
		bool m_init{ false };
	};

} // namespace libavpn

#endif // INCLUDE__2026_10_14__AVPN_REPLAY_HPP
