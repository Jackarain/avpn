#ifndef INCLUDE__2026_08_21__XAVPN_HPP
#define INCLUDE__2026_08_21__XAVPN_HPP

#include <string>
#include <memory>

namespace xavpn {

	// 日志回调接口: 通过 set_log_callback 注册, 在日志输出时回调.
	class log_callback
	{
	public:
		virtual ~log_callback() = default;

		// level: 0=debug, 1=info, 2=warn, 3=error, 4=file.
		// message 为日志内容(不含时间戳与级别前缀).
		// 回调在日志线程中执行, 应尽快返回.
		virtual void on_log(int level, const std::string& message) = 0;
	};

	// 设置日志回调, 传入空 shared_ptr 取消; 线程安全.
	void set_log_callback(std::shared_ptr<log_callback> callback);

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
