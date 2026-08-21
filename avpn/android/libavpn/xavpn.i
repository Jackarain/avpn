%module xavpn
%{
#include "xavpn.hpp"
%}

%include <std_string.i>
%include <std_shared_ptr.i>
%include <stdint.i>

namespace xavpn {

	std::string min_sdk_version();

	int start(const std::string& config);
	void stop();
}
