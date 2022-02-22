//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#pragma once
#include <string>

namespace avpn {

	enum dev_type {
		dev_tap,
		dev_tun,
	};

	struct device_tuntap
	{
		std::string name_;			// utf8 encode.
		std::string guid_;
		dev_type	dev_type_;
	};

	struct dev_config
	{
		std::string local_;
		std::string mask_;
		std::string gateway_;
		std::string dhcp_;
		std::string guid_;
		std::string dev_name_;

		// use for linux tun dev.
		int tun_fd_{ -1 };

		// true is tap, false is tun.
		dev_type dev_type_{ avpn::dev_tun };

		bool ifconfig_setup_;
	};

}
