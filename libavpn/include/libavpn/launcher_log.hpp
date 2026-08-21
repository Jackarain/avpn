//
// launcher_log.hpp
// ~~~~~~~~~~~~~~~~
//
// Copyright (c) 2023 Jack (jack dot wgm at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// 日志转发到 launcher 控制通道的队列入口声明。
//
// logging.hpp 的 logger_tag 自定义点（logger_writer__ 在输出到 console/文件
// 之前调用）经 ADL 调用 tag_invoke 钩子, 钩子实现转发到 log_hook_forward,
// 在其中同时将日志写入本队列 (见 src/logging.cpp)。采集到的日志由
// launcher_log.cpp 中实现的队列缓存, 控制通道上报时批量发送 (RPC notify "log")。
// 钩子返回 false 不拦截原有输出（launcher 管理下 console 已关闭, 独立运行
// 不受影响）。
//

#ifndef INCLUDE__2026_08_21__LAUNCHER_LOG_HPP
#define INCLUDE__2026_08_21__LAUNCHER_LOG_HPP

#include <cstdint>
#include <deque>
#include <string>

namespace libavpn {
namespace detail {

// 日志转发队列入口（实现于 src/launcher_log.cpp）.
void launcher_log_enqueue(int64_t time, const int& level,
	const std::string& message);

// 启用/停用日志采集（控制通道启用时由 vpn_controller 调用）.
void launcher_log_set_enabled(bool enable);

// 取出积压日志（控制通道上报时调用）.
std::deque<std::string> launcher_log_drain();

}
}

#endif // INCLUDE__2026_08_21__LAUNCHER_LOG_HPP
