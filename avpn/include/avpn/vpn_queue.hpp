//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#pragma once

#include "avpn/vpn_packet.hpp"

#include <atomic>
#include <deque>

#include <mutex>
#include <condition_variable>

#include <boost/chrono.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/thread/condition_variable.hpp>
#include <boost/thread/lock_types.hpp>

namespace avpn {
	inline namespace v1 {

#if 0
	using boost::chrono::milliseconds;
	using boost::unique_lock;
	using boost::lock_guard;
	using boost::mutex;
	using boost::condition_variable;
#else
	using std::chrono::milliseconds;
	using std::unique_lock;
	using std::lock_guard;
	using std::mutex;
	using std::condition_variable;
#endif

	template <typename T>
	class vpn_queue
	{
	private:
		vpn_queue(const vpn_queue&) = delete;
		vpn_queue& operator=(const vpn_queue&) = delete;

	public:
		using value_type = T;
		using reference = T&;
		using const_reference = const T&;

		vpn_queue() = default;
		~vpn_queue() = default;

	public:
		inline void submit(T&& pkt) noexcept
		{
			{
				unique_lock lock(m_mutex);
				m_queue.emplace_back(std::move(pkt));
			}

			m_condition_var.notify_one();
		}

		inline std::optional<T> acquire() noexcept
		{
			unique_lock lock(m_mutex);

			while (m_queue.empty())
			{
				if (m_abort)
					return {};

				m_condition_var.wait_for(lock, milliseconds(128));
			}

			auto pkt = std::move(m_queue.front());
			m_queue.pop_front();

			return { std::move(pkt) };
		}

		inline size_t size() const noexcept
		{
			lock_guard lock(m_mutex);
			return m_queue.size();
		}

		inline void close() noexcept
		{
			m_abort = true;
			m_condition_var.notify_one();
		}

	private:
		mutable mutex m_mutex;
		condition_variable m_condition_var;
		std::deque<T> m_queue;
		std::atomic_bool m_abort{ false };
	};
	}
}
