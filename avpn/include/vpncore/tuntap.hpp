//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#pragma once

#if defined(AVPN_WINDOWS)
#	include "vpncore/tuntap_windows_service.hpp"
#elif defined(AVPN_LINUX)
#	include "vpncore/tuntap_fd_service.hpp"
#elif defined(AVPN_APPLE)
#	include "vpncore/tuntap_fd_service.hpp"
#else
#	error unsupported platform
#endif



#include "vpncore/basic_tuntap.hpp"

namespace avpn {

	// 定义不同平台的tuntap实现.
#if defined(AVPN_WINDOWS)
	using tuntap = basic_tuntap<tuntap_windows_service>;
#elif defined(AVPN_LINUX)
	using tuntap = basic_tuntap<tuntap_fd_service>;
#elif defined(AVPN_APPLE)
	using tuntap = basic_tuntap<tuntap_fd_service>;
#endif

}
