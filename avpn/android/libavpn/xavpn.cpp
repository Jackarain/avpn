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
#include <vector>

namespace xavpn {

namespace {

// 当前运行的 io_context 池与 avpn 服务实例.
std::unique_ptr<libavpn::io_context_pool> g_io_pool;
std::shared_ptr<libavpn::avpn_service> g_service;
std::thread g_io_thread;
std::mutex g_log_callback_mutex;
std::shared_ptr<log_callback> g_log_callback;

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

// 取配置中的 stringlist.
std::vector<std::string> config_list(const boost::json::object& cfg, const char* key)
{
	std::vector<std::string> out;
	auto it = cfg.find(key);
	if (it == cfg.end())
		return out;
	const auto& v = it->value();
	if (v.is_array()) {
		for (const auto& item : v.as_array()) {
			if (item.is_string())
				out.emplace_back(item.as_string());
		}
	} else if (v.is_string()) {
		out.emplace_back(v.as_string());
	}
	return out;
}

// 取配置中的字符串.
std::string config_string(const boost::json::object& cfg, const char* key)
{
	auto it = cfg.find(key);
	if (it == cfg.end() || !it->value().is_string())
		return {};
	return std::string(it->value().as_string());
}

// 取配置中的整数.
int config_int(const boost::json::object& cfg, const char* key, int def)
{
	auto it = cfg.find(key);
	if (it == cfg.end())
		return def;
	const auto& v = it->value();
	if (v.is_int64())
		return static_cast<int>(v.as_int64());
	if (v.is_uint64())
		return static_cast<int>(v.as_uint64());
	if (v.is_double())
		return static_cast<int>(v.as_double());
	if (v.is_bool())
		return v.as_bool() ? 1 : 0;
	return def;
}

// 取配置中的布尔值.
bool config_bool(const boost::json::object& cfg, const char* key, bool def)
{
	auto it = cfg.find(key);
	if (it == cfg.end())
		return def;
	const auto& v = it->value();
	if (v.is_bool())
		return v.as_bool();
	if (v.is_int64())
		return v.as_int64() != 0;
	if (v.is_string()) {
		const auto& s = v.as_string();
		return s == "true" || s == "1";
	}
	return def;
}

// JSON 配置转 service_config.
libavpn::service_config config_from_json(const std::string& config)
{
	libavpn::service_config cfg{};
	boost::system::error_code ec;
	auto value = boost::json::parse(config, ec);
	if (ec || !value.is_object())
		return cfg;

	const auto& obj = value.as_object();
	cfg.ifdev_ = config_string(obj, "ifdev");
	cfg.ptun_fd_ = config_int(obj, "ptun_fd", -1);
	cfg.utun_fd_ = config_int(obj, "utun_fd", -1);
	cfg.controller_ = config_string(obj, "controller");
	cfg.nexthop_ = config_string(obj, "nexthop");
	cfg.tcp_listens_ = config_list(obj, "tcp_listen");
	cfg.udp_listens_ = config_list(obj, "udp_listen");
	cfg.private_key_ = config_string(obj, "private_key");
	cfg.public_key_ = config_string(obj, "public_key");
	cfg.pkl_ = config_list(obj, "pkl");
	cfg.mtu_size_ = config_int(obj, "mtu_size", 1450);
	cfg.keepalive_ = config_int(obj, "keepalive", 60);
	cfg.pushroutes_ = config_list(obj, "pushroutes");
	cfg.pushdns_ = static_cast<uint32_t>(config_int(obj, "pushdns", 0));
	cfg.passbyvpn_ = config_bool(obj, "passbyvpn", false);
	cfg.bypassroutes_ = config_list(obj, "bypassroutes");
	cfg.ignore_push_ = config_bool(obj, "ignore_push", false);
	cfg.c2c_ = config_bool(obj, "c2c", false);
	cfg.subnet_ = config_string(obj, "subnet");
	cfg.v6_subnet_ = config_string(obj, "v6_subnet");
	cfg.data_shards_ = config_int(obj, "data_shards", 0);
	cfg.parity_shards_ = config_int(obj, "parity_shards", 0);
	cfg.compress_ = config_string(obj, "compress");
	cfg.obfuscate_key_ = config_string(obj, "obfuscate_key");
	cfg.pre_up_ = config_string(obj, "pre_up");
	cfg.post_up_ = config_string(obj, "post_up");
	cfg.pre_down_ = config_string(obj, "pre_down");
	cfg.post_down_ = config_string(obj, "post_down");

	return cfg;
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

std::string min_sdk_version()
{
	return "minSdkVersion: " + std::to_string(__ANDROID_MIN_SDK_VERSION__);
}

int start(const std::string& config)
{
	if (g_service)
		stop();

	try {
		auto cfg = config_from_json(config);

		g_io_pool = std::make_unique<libavpn::io_context_pool>(
			std::max<std::size_t>(2, std::thread::hardware_concurrency()));
		g_service = libavpn::avpn_service::create_service(*g_io_pool, cfg);
		if (!g_service || !g_service->start()) {
			stop();
			return -1;
		}
	} catch (...) {
		stop();
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
	if (g_service)
		g_service->stop();
	if (g_io_pool)
		g_io_pool->stop();

	if (g_io_thread.joinable())
		g_io_thread.join();

	g_service.reset();
	g_io_pool.reset();
}

std::string status()
{
	if (!g_service)
		return "{}";
	return boost::json::serialize(g_service->status_json());
}

} // namespace xavpn
