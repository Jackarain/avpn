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
	class replay_window
	{
	public:
		explicit replay_window(std::size_t window_size = 1024)
			: m_window_size(std::max<std::size_t>(1, window_size))
			, m_window(m_window_size, false)
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
				m_window.assign(m_window_size, false);
				m_window[0] = true;
				return true;
			}

			if (counter > m_counter_max)
			{
				uint64_t shift = static_cast<uint64_t>(counter) -
					m_counter_max;
				if (shift >= m_window_size)
				{
					m_window.assign(m_window_size, false);
				}
				else
				{
					std::vector<bool> shifted(m_window_size, false);
					for (std::size_t i = 0;
						i + shift < m_window_size; i++)
						shifted[i + shift] = m_window[i];
					m_window.swap(shifted);
				}
				m_counter_max = counter;
				m_window[0] = true;
				return true;
			}

			std::size_t offset = static_cast<std::size_t>(
				static_cast<uint64_t>(m_counter_max) - counter);
			if (offset >= m_window_size)
				return false;
			if (m_window[offset])
				return false;
			m_window[offset] = true;
			return true;
		}

		// 重置窗口 (新会话).
		void reset()
		{
			m_counter_max = 0;
			m_init = false;
			std::fill(m_window.begin(), m_window.end(), false);
		}

	private:
		std::size_t m_window_size{ 1024 };
		uint32_t m_counter_max{ 0 };
		std::vector<bool> m_window;
		bool m_init{ false };
	};

} // namespace libavpn

#endif // INCLUDE__2026_08_20__REPLAY_WINDOW_HPP
