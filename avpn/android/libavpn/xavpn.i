%module xavpn
%{
#include "xavpn.hpp"
%}

%include <std_string.i>
%include <std_shared_ptr.i>
%include <stdint.i>

%feature("director") xavpn::log_callback;
%shared_ptr(xavpn::log_callback)

// Java 命名风格.
%rename(LogCallback) xavpn::log_callback;
%rename(onLog) xavpn::log_callback::on_log;
%rename(setLogCallback) xavpn::set_log_callback;
%rename(LogLevel) xavpn::log_level;
%rename(DEBUG) xavpn::log_level::debug;
%rename(INFO) xavpn::log_level::info;
%rename(WARN) xavpn::log_level::warn;
%rename(ERROR) xavpn::log_level::error;

// Java 便捷封装: 函数式接口 + 适配器, 支持 Java lambda / Kotlin SAM 注册日志回调.
%pragma(java) modulecode = %{
    /** 日志回调函数式接口, 可用 Java lambda 或 Kotlin SAM 转换注册. */
    public interface LogCallbackHandler {
        void onLog(long time, LogLevel level, String message);
    }

    private static final class LogCallbackAdapter extends LogCallback {
        private final LogCallbackHandler handler;
        LogCallbackAdapter(LogCallbackHandler handler) {
            this.handler = handler;
        }
        @Override
        public void onLog(long time, LogLevel level, String message) {
            handler.onLog(time, level, message);
        }
    }

    /** 以函数式接口注册日志回调, 传 null 取消; 等价于 setLogCallback(LogCallback). */
    public static void setLogCallback(LogCallbackHandler handler) {
        setLogCallback(handler == null ? null : new LogCallbackAdapter(handler));
    }
%}

namespace xavpn {

	enum class log_level
	{
		debug = 0,
		info = 1,
		warn = 2,
		error = 3,
	};

	class log_callback
	{
	public:
		virtual ~log_callback() = default;
		virtual void on_log(int64_t time, log_level level,
			const std::string& message) = 0;
	};

	void set_log_callback(std::shared_ptr<log_callback> callback);

	std::string min_sdk_version();

	int start(const std::string& config);
	void stop();

	std::string status();
}
