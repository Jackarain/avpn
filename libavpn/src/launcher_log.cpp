//
// launcher_log.cpp
// ~~~~~~~~~~~~~~~~
//
// Copyright (c) 2023 Jack (jack dot wgm at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// 日志转发到 launcher 控制通道的队列实现。
//
// 日志经 logging.hpp 的 logger_tag 钩子转发到 log_hook_forward, 在其中写入
// 本队列 (可能来自多个线程, logger_writer__ 内部已有全局锁, 此处再加互斥保证
// 队列安全), 由 vpn_launcher 控制通道上报时调用 launcher_log_drain 批量取出
// 并通过 RPC notify "log" 发送给 launcher。
//

#include "libavpn/launcher_log.hpp"
#include "libavpn/logging.hpp"

#include <atomic>
#include <deque>
#include <mutex>

namespace libavpn {
namespace detail {

namespace {

// 仅在启用控制通道时采集, 避免独立运行时无谓加锁.
std::atomic_bool g_launcher_log_enabled{ false };
std::mutex g_launcher_log_mutex;
std::deque<std::string> g_launcher_log_lines;
inline constexpr std::size_t k_launcher_log_max = 2000;

} // namespace

void launcher_log_set_enabled(bool enable)
{
	g_launcher_log_enabled.store(enable, std::memory_order_relaxed);
}

void launcher_log_enqueue(int64_t time, const int& level,
	const std::string& message)
{
	if (!g_launcher_log_enabled.load(std::memory_order_relaxed))
		return;
	char ts[64] = { 0 };
	xlogger::logger_aux__::time_to_string(ts, time);
	std::string line(ts);
	line += xlogger::logger_level_string__(
		static_cast<xlogger::logger_level__>(level));
	line += message;
	std::lock_guard<std::mutex> lock(g_launcher_log_mutex);
	if (g_launcher_log_lines.size() >= k_launcher_log_max)
		g_launcher_log_lines.pop_front();
	g_launcher_log_lines.push_back(std::move(line));
}

std::deque<std::string> launcher_log_drain()
{
	std::lock_guard<std::mutex> lock(g_launcher_log_mutex);
	std::deque<std::string> out;
	out.swap(g_launcher_log_lines);
	return out;
}

} // namespace detail
} // namespace libavpn
