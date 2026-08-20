%module xavpn
%{
#include "xavpn.hpp"
%}

%include <std_string.i>
%include <std_shared_ptr.i>

%feature("director") xavpn::log_callback;
%shared_ptr(xavpn::log_callback)

namespace xavpn {

	class log_callback
	{
	public:
		virtual ~log_callback() = default;
		virtual void on_log(int level, const std::string& message) = 0;
	};

	void set_log_callback(std::shared_ptr<log_callback> callback);

	std::string min_sdk_version();

	int start(const std::string& config);
	void stop();

	std::string status();
}
