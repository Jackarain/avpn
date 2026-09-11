//
// replay_window.hpp
// ~~~~~~~~~~~~~~~~~
//
// Copyright (C) 2025 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#ifndef INCLUDE__2026_08_20__REPLAY_WINDOW_HPP
#define INCLUDE__2026_08_20__REPLAY_WINDOW_HPP

#include <cstdint>
#include <cstddef>
#include <vector>
#include <algorithm>

namespace libavpn {

	// AEAD 计数器接收重放窗口.
	// 接受单调递增且位于滑动窗口内的计数器, 拒绝重放与窗口外旧包.
	//
	// 窗口用 64 位字位图表示, 位 i 表示计数器 (m_counter_max - i) 已收到.
	// 新计数器到达时整窗口按位移移动, 逐包开销为常数次字操作.
	class replay_window
	{
	public:
		explicit replay_window(std::size_t window_size = 1024)
			: m_window_size(std::max<std::size_t>(1, window_size))
			, m_words((m_window_size + 63) / 64, 0)
		{}

		replay_window(const replay_window&) = delete;
		replay_window& operator=(const replay_window&) = delete;

		// 检查 counter 是否可接受, 接受则更新窗口并返回 true.
		bool check_and_update(uint32_t counter)
		{
			if (!m_init)
			{
				m_init = true;
				m_counter_max = counter;
				std::fill(m_words.begin(), m_words.end(), uint64_t{ 0 });
				set_bit(0);
				return true;
			}

			if (counter > m_counter_max)
			{
				shift_bits(static_cast<std::size_t>(
					static_cast<uint64_t>(counter) - m_counter_max));
				m_counter_max = counter;
				set_bit(0);
				return true;
			}

			std::size_t offset = static_cast<std::size_t>(
				static_cast<uint64_t>(m_counter_max) - counter);
			if (offset >= m_window_size || get_bit(offset))
				return false;
			set_bit(offset);
			return true;
		}

		// 重置窗口 (新会话).
		void reset()
		{
			m_counter_max = 0;
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

		// 全部位向高位偏移 shift (旧计数器对应的偏移量随之增大).
		void shift_bits(std::size_t shift)
		{
			if (shift >= m_window_size)
			{
				std::fill(m_words.begin(), m_words.end(), uint64_t{ 0 });
				return;
			}

			const std::size_t word_shift = shift >> 6;
			const unsigned bit_shift = static_cast<unsigned>(shift & 63);

			for (std::size_t i = m_words.size(); i-- > 0;)
			{
				uint64_t v = 0;
				if (i >= word_shift)
				{
					v = m_words[i - word_shift] << bit_shift;
					if (bit_shift != 0 && i > word_shift)
						v |= m_words[i - word_shift - 1] >>
							(64 - bit_shift);
				}
				m_words[i] = v;
			}

			// 清除窗口之外的残留位.
			const std::size_t rem = m_window_size & 63;
			if (rem != 0)
				m_words.back() &= (uint64_t{ 1 } << rem) - 1;
		}

		std::size_t m_window_size{ 1024 };
		uint32_t m_counter_max{ 0 };
		std::vector<uint64_t> m_words;
		bool m_init{ false };
	};

} // namespace libavpn

#endif // INCLUDE__2026_08_20__REPLAY_WINDOW_HPP
