//
// avpn_roam_cookie.hpp
// ~~~~~~~~~~~~~~~~~~~~
//
// 漫游凭证的轮换窗口: 一个会话同时只有一把正在用的凭证, 但换网重新绑定之后
// 需要一小段重叠期, 让轮换之前发出去的帧仍然认得出来.
//
// Copyright (C) 2025 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#ifndef INCLUDE__2026_10_14__AVPN_ROAM_COOKIE_HPP
#define INCLUDE__2026_10_14__AVPN_ROAM_COOKIE_HPP

#include <array>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string_view>

namespace libavpn {

	// 漫游凭证长度 (字节).
	inline constexpr std::size_t roam_cookie_size = 8;

	// 轮换之后旧凭证还能用多久 (毫秒). 轮换通知走隧道, 一个单程之内客户端就
	// 换上了新的; 留这段重叠只为兜住在途的旧帧, 太长会拖长"抢认领"的窗口.
	inline constexpr uint64_t roam_cookie_grace_ms = 10000;

	// 会话的漫游凭证: 当前那把, 加上一把限时有效的旧凭证.
	class roam_cookie_window
	{
	public:
		// 全 0 表示没有凭证 (TCP 传输就是这样).
		void clear()
		{
			m_current.fill(0);
			m_previous.fill(0);
			m_previous_expire_ms = 0;
		}

		// 握手谈定的凭证, 同时丢掉上一把.
		void set(const std::array<uint8_t, roam_cookie_size>& cookie)
		{
			m_current = cookie;
			m_previous.fill(0);
			m_previous_expire_ms = 0;
		}

		// 轮换到 next: 当前那把降为旧凭证 (从 now_ms 起 roam_cookie_grace_ms
		// 内仍然认), 返回被顶出窗口的那把, 给调用方清理索引.
		std::array<uint8_t, roam_cookie_size> rotate(
			const std::array<uint8_t, roam_cookie_size>& next, uint64_t now_ms)
		{
			const auto dropped = m_previous;
			m_previous = m_current;
			m_previous_expire_ms = now_ms + roam_cookie_grace_ms;
			m_current = next;
			return dropped;
		}

		bool empty() const { return is_zero(m_current); }

		const std::array<uint8_t, roam_cookie_size>& current() const
		{
			return m_current;
		}

		// frame 开头是当前凭证, 或者还在重叠期内的旧凭证, 都算带凭证.
		bool accepts(std::string_view frame, uint64_t now_ms) const
		{
			if (starts_with(frame, m_current))
				return true;
			return now_ms < m_previous_expire_ms &&
				starts_with(frame, m_previous);
		}

	private:
		static bool is_zero(const std::array<uint8_t, roam_cookie_size>& cookie)
		{
			for (auto b : cookie)
			{
				if (b != 0)
					return false;
			}
			return true;
		}

		static bool starts_with(std::string_view frame,
			const std::array<uint8_t, roam_cookie_size>& cookie)
		{
			return !is_zero(cookie) && frame.size() >= cookie.size() &&
				std::memcmp(frame.data(), cookie.data(), cookie.size()) == 0;
		}

		std::array<uint8_t, roam_cookie_size> m_current{};
		std::array<uint8_t, roam_cookie_size> m_previous{};
		uint64_t m_previous_expire_ms{ 0 };
	};

} // namespace libavpn

#endif // INCLUDE__2026_10_14__AVPN_ROAM_COOKIE_HPP
