#ifndef INCLUDE__2026_08_21__XAVPN_HPP
#define INCLUDE__2026_08_21__XAVPN_HPP

#include <string>

namespace xavpn {

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
