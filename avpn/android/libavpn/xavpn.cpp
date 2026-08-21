#include "xavpn.hpp"

#include "libavpn/avpn.hpp"
#include "libavpn/logging.hpp"

#include <boost/json.hpp>

#include <algorithm>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

namespace xavpn {

namespace {

// 当前运行的 io_context 池与 avpn 服务实例.
std::unique_ptr<libavpn::io_context_pool> g_io_pool;
std::shared_ptr<libavpn::avpn_service> g_service;
std::thread g_io_thread;
// 保护 g_service/g_io_pool/g_io_thread: start/stop/status 可能来自
// 不同线程 (Android 上 status 常由 UI 线程调用, 启停在工作线程).
std::mutex g_service_mutex;
std::mutex g_log_callback_mutex;
std::shared_ptr<log_callback> g_log_callback;
std::mutex g_protect_callback_mutex;
std::shared_ptr<protect_callback> g_protect_callback;

// xlogger 日志回调: 转发到注册的 log_callback.
void android_log_hook(int64_t time, int level, const std::string& message)
{
	// 仅转发 debug/info/warn/error, 过滤内部 file 级别日志.
	if (level < static_cast<int>(log_level::debug) ||
		level > static_cast<int>(log_level::error))
		return;

	std::shared_ptr<log_callback> cb;
	{
		std::lock_guard<std::mutex> lock(g_log_callback_mutex);
		cb = g_log_callback;
	}
	if (cb)
		cb->on_log(time, static_cast<log_level>(level), message);
}

// 停止并释放服务实例; 调用方须持有 g_service_mutex.
void stop_locked()
{
	if (g_service)
		g_service->stop();
	if (g_io_pool)
		g_io_pool->stop();

	if (g_io_thread.joinable())
		g_io_thread.join();

	g_service.reset();
	g_io_pool.reset();
}

} // namespace

void set_log_callback(std::shared_ptr<log_callback> callback)
{
	{
		std::lock_guard<std::mutex> lock(g_log_callback_mutex);
		g_log_callback = std::move(callback);
	}
	xlogger::set_log_callback(g_log_callback ? android_log_hook : nullptr);
}

void set_protect_callback(std::shared_ptr<protect_callback> callback)
{
	std::shared_ptr<protect_callback> cb;
	{
		std::lock_guard<std::mutex> lock(g_protect_callback_mutex);
		g_protect_callback = std::move(callback);
		cb = g_protect_callback;
	}

	if (cb)
	{
		libavpn::set_socket_protect_handler(
			[cb](int fd) -> bool { return cb->on_protect(fd); });
	}
	else
	{
		libavpn::set_socket_protect_handler(nullptr);
	}
}

std::string min_sdk_version()
{
	return "minSdkVersion: " + std::to_string(__ANDROID_MIN_SDK_VERSION__);
}

int start(const std::string& config)
{
	std::lock_guard<std::mutex> lock(g_service_mutex);

	// 已有实例先停止, 保证同一时刻只有一个 avpn 服务.
	if (g_service)
		stop_locked();

	try {
		auto cfg = libavpn::config_from_json(config);

		g_io_pool = std::make_unique<libavpn::io_context_pool>(
			std::max<std::size_t>(2, std::thread::hardware_concurrency()));
		g_service = libavpn::avpn_service::create_service(*g_io_pool, cfg);
		if (!g_service || !g_service->start()) {
			stop_locked();
			return -1;
		}
	} catch (...) {
		stop_locked();
		return -1;
	}

	// 在后台线程中运行 io_context 池.
	g_io_thread = std::thread([] {
		if (g_io_pool)
			g_io_pool->run();
	});

	return 0;
}

void stop()
{
	std::lock_guard<std::mutex> lock(g_service_mutex);
	stop_locked();
}

std::string status()
{
	std::lock_guard<std::mutex> lock(g_service_mutex);
	if (!g_service)
		return "{}";
	return boost::json::serialize(g_service->status_json());
}

} // namespace xavpn
