#include "xavpn.hpp"

#include "libavpn/avpn.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#ifndef VERSION_GIT
# define VERSION_GIT ""
#endif

namespace xavpn {

namespace {

// 当前运行的 io_context 池与 avpn 服务实例.
std::unique_ptr<libavpn::io_context_pool> g_io_pool;
std::shared_ptr<libavpn::avpn_service> g_service;
std::thread g_io_thread;
// 保护 g_service/g_io_pool/g_io_thread: start/stop/status 可能来自
// 不同线程 (Android 上 status 常由 UI 线程调用, 启停在工作线程).
std::mutex g_service_mutex;

// 当前 io 线程的完成标志: 有界等待的依据 (joinable() 在 join 前恒为 true,
// 不能据此判断线程是否已退出 run()). 每次启动新建, 使各代次互不干扰.
std::shared_ptr<std::atomic<bool>> g_io_finished;

// io 线程因 io_context 卡死被 detach 后, 其仍在访问的池与服务对象不能随
// 引用释放, 移交僵尸列表保活; 仅发生在异常路径, 数量极少, 进程退出时随
// OS 回收.
std::vector<std::unique_ptr<libavpn::io_context_pool>> g_zombie_pools;
std::vector<std::shared_ptr<libavpn::avpn_service>> g_zombie_services;

// 退役对象回收: io_context 停线程后, 其对象中可能仍残留停止时挂起的协程
// 帧 (如控制通道的 ws 读/关闭协程), 析构 io_context 需逐个销毁这些帧,
// 实测可能耗时数百毫秒到数秒. 若在停止线程同步析构, 会阻塞后续启停
// (界面表现为点停止卡顿). 退役对象移入队列, 由独立回收线程异步析构:
// 停止线程只做同步必须项 (停止服务与 io 线程), 用户立即点开始即可创建
// 新实例, 互不影响. 编译期开关 XAVPN_SYNC_DESTROY 关闭回收线程, 改为
// 停止线程同步析构, 用于对比验证. 默认不定义, 即启用回收线程.
#ifndef XAVPN_SYNC_DESTROY
struct retired_objects
{
	std::unique_ptr<libavpn::io_context_pool> pool;
	std::shared_ptr<libavpn::avpn_service> service;
};

std::mutex g_retire_mutex;
std::condition_variable g_retire_cv;
std::deque<retired_objects> g_retired;
std::atomic<bool> g_retire_done{ false };

void retire_objects(std::unique_ptr<libavpn::io_context_pool> pool,
	std::shared_ptr<libavpn::avpn_service> service)
{
	{
		std::lock_guard<std::mutex> lk(g_retire_mutex);
		g_retired.emplace_back(
			retired_objects{ std::move(pool), std::move(service) });
	}
	g_retire_cv.notify_one();
}

void reaper_main()
{
	for (;;)
	{
		retired_objects objs;
		{
			std::unique_lock<std::mutex> lk(g_retire_mutex);
			g_retire_cv.wait(lk, []()
				{
					return !g_retired.empty() || g_retire_done.load();
				});
			if (g_retired.empty())
				return;
			objs = std::move(g_retired.front());
			g_retired.pop_front();
		}
		// 析构在本线程执行: 可能耗时 (清理残留协程帧/慢析构成员), 不影响
		// 停止与下一次启动. 先释放服务再释放池: 服务持有池的引用.
		objs.service.reset();
		objs.pool.reset();
	}
}

std::once_flag g_reaper_once;

void ensure_reaper()
{
	std::call_once(g_reaper_once, []()
		{
			// 进程退出时随 OS 回收, 无需 join.
			std::thread(reaper_main).detach();
		});
}
#endif // !XAVPN_SYNC_DESTROY

// 有界等待 io 线程结束; 返回 false 表示超时 (io_context 可能已卡死).
bool wait_io_finished(const std::shared_ptr<std::atomic<bool>>& flag,
	std::chrono::milliseconds timeout)
{
	if (!flag)
		return true;
	const auto deadline = std::chrono::steady_clock::now() + timeout;
	while (!flag->load(std::memory_order_acquire) &&
		std::chrono::steady_clock::now() < deadline)
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
	return flag->load(std::memory_order_acquire);
}

// 停止并释放服务实例; 调用方须持有 g_service_mutex.
void stop_locked()
{
	if (g_service)
		g_service->stop();
	if (g_io_pool)
		g_io_pool->stop();

	bool detached = false;
	if (g_io_thread.joinable() &&
		g_io_thread.get_id() != std::this_thread::get_id())
	{
		// io_context 可能被卡死的协程占住无法退出, 此时 join() 会永久阻塞
		// (且仍持有 g_service_mutex), 后续所有启停全部失败, 表现为界面永远
		// 等待控制通道, 只能重启应用. 这里只做有限等待, 超时则分离线程并
		// 把池与服务移交僵尸列表保活 (分离线程仍可能访问其成员).
		constexpr auto k_join_timeout = std::chrono::milliseconds(4000);
		if (wait_io_finished(g_io_finished, k_join_timeout))
		{
			g_io_thread.join();
		}
		else
		{
			g_io_thread.detach();
			detached = true;
		}
	}

	if (detached)
	{
		if (g_io_pool)
			g_zombie_pools.push_back(std::move(g_io_pool));
		if (g_service)
			g_zombie_services.push_back(std::move(g_service));
	}
	else if (g_io_pool || g_service)
	{
#ifdef XAVPN_SYNC_DESTROY
		// 开关模式: 对象析构 (io_context 清理残留协程帧等) 在本线程
		// 同步执行, 正常路径下残留帧极少, 用于对比验证.
		g_service.reset();
		g_io_pool.reset();
#else
		// 正常路径: 对象析构 (io_context 清理残留协程帧等) 可能耗时,
		// 移到后台回收线程执行, 停止线程不被阻塞, 也不影响下一次启动.
		ensure_reaper();
		retire_objects(std::move(g_io_pool), std::move(g_service));
#endif
	}
	g_io_finished.reset();
}

} // namespace

std::string min_sdk_version()
{
	return "minSdkVersion: " + std::to_string(__ANDROID_MIN_SDK_VERSION__);
}

std::string build_version()
{
	// VERSION_GIT 形如 "abc1234 (2026-08-08 10:00:00)", 取 hash 前 6 位.
	std::string v = VERSION_GIT;
	auto pos = v.find(' ');
	if (pos != std::string::npos)
		v = v.substr(0, pos);
	if (v.size() > 6)
		v = v.substr(0, 6);
	return v;
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
	//
	// 捕获池指针而非在闭包里读全局: io_context 卡死被 detach 时 g_io_pool
	// 会移交僵尸列表保活并将全局置空, 线程再读全局会拿到空指针而提前返回.
	auto* pool = g_io_pool.get();
	auto finished = std::make_shared<std::atomic<bool>>(false);
	g_io_finished = finished;
	g_io_thread = std::thread([pool, finished] {
		if (pool)
			pool->run();
		finished->store(true, std::memory_order_release);
	});

	return 0;
}

void stop()
{
	std::lock_guard<std::mutex> lock(g_service_mutex);
	stop_locked();
}

} // namespace xavpn
