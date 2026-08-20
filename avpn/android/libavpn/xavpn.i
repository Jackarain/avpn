%module xavpn
%{
#include "xavpn.hpp"
%}

%include <std_string.i>

namespace xavpn {

	std::string min_sdk_version();

	int start(const std::string& config);
	void stop();

	std::string status();
}
