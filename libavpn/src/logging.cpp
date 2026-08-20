#include "libavpn/logging.hpp"

#include <atomic>
#include <mutex>

namespace xlogger {

namespace {

std::mutex g_log_callback_mutex;
log_callback_fn g_log_callback = nullptr;
std::atomic_bool g_log_callback_enabled{ false };

} // namespace

void set_log_callback(log_callback_fn callback)
{
	std::lock_guard<std::mutex> lock(g_log_callback_mutex);
	g_log_callback = callback;
	g_log_callback_enabled.store(callback != nullptr, std::memory_order_relaxed);
}

void log_hook_forward(int64_t time, const int& level, const std::string& message) noexcept
{
	if (!g_log_callback_enabled.load(std::memory_order_relaxed))
		return;

	log_callback_fn cb;
	{
		std::lock_guard<std::mutex> lock(g_log_callback_mutex);
		cb = g_log_callback;
	}
	if (cb)
		cb(time, level, message);
}

} // namespace xlogger
