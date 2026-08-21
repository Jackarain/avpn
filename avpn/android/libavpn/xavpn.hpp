#ifndef INCLUDE__2026_08_21__XAVPN_HPP
#define INCLUDE__2026_08_21__XAVPN_HPP

#include <cstdint>
#include <memory>
#include <string>

namespace xavpn {

	// 日志级别 (对应 xlogger 的 debug/info/warn/error, 不含内部 file 级别).
	enum class log_level
	{
		debug = 0,
		info = 1,
		warn = 2,
		error = 3,
	};

	// 日志回调接口: 通过 set_log_callback 注册, 日志输出时回调.
	class log_callback
	{
	public:
		virtual ~log_callback() = default;

		// time 为 Unix 毫秒时间戳, level 为日志级别, message 为日志内容
		// (不含时间戳与级别前缀).
		// 回调在日志线程中执行, 应尽快返回, 避免阻塞日志输出.
		virtual void on_log(int64_t time, log_level level,
			const std::string& message) = 0;
	};

	// 设置日志回调, 传入空 shared_ptr 取消; 线程安全.
	void set_log_callback(std::shared_ptr<log_callback> callback);

	// socket 保护回调接口: 当 avpn 创建对外连接 (nexthop) 的 socket 时回调,
	// 用于 Android VpnService.protect 放行, 避免流量回环进 tun.
	class protect_callback
	{
	public:
		virtual ~protect_callback() = default;

		// fd 为对外 socket 的文件描述符, 返回 true 表示保护成功.
		virtual bool on_protect(int fd) = 0;
	};

	// 设置 socket 保护回调, 传入空 shared_ptr 取消; 线程安全.
	void set_protect_callback(std::shared_ptr<protect_callback> callback);

	// 返回当前编译环境最低支持的 Android SDK 版本.
	std::string min_sdk_version();

	// 以 JSON 配置启动 avpn 服务, 成功返回 0, 失败返回非 0 值.
	int start(const std::string& config);

	// 停止 avpn 服务.
	void stop();

	// 获取当前服务运行状态, 返回 JSON 字符串.
	std::string status();
}

#endif // INCLUDE__2026_08_21__XAVPN_HPP
