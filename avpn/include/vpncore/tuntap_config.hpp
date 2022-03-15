//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#pragma once
#include <string>

namespace avpn {

	struct device_tuntap
	{
		std::string name_;			// utf8 encode.
		std::string guid_;
	};

	struct dev_config
	{
		std::string local_;
		std::string mask_;
		std::string gateway_;
		std::string dhcp_;
		std::string guid_;
		std::string dev_name_;

		bool ifconfig_setup_;
	};

}
