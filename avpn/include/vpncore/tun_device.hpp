//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#pragma once

#if defined(AVPN_WINDOWS)
#ifdef AVPN_USE_WINTUN
#	include "vpncore/wintun_windows_service.hpp"
#else
#	include "vpncore/tuntap_windows_service.hpp"
#endif
#elif defined(AVPN_LINUX)
#	include "vpncore/tundev_linux_service.hpp"
#elif defined(AVPN_APPLE)
#	include "vpncore/tundev_macos_service.hpp"
#elif defined(AVPN_ANDROID)
#	include "vpncore/tundev_android_service.hpp"
#else
#	error unsupported platform
#endif

#include "vpncore/basic_tun_service.hpp"

namespace avpn {

	// 定义不同平台的tuntap实现.
#if defined(AVPN_WINDOWS)
#ifdef AVPN_USE_WINTUN
	using tun_device = basic_tun_service<wintun_windows_service>;
#else
	using tun_device = basic_tun_service<tuntap_windows_service>;
#endif // AVPN_USE_WINTUN
#elif defined(AVPN_LINUX)
	using tun_device = basic_tun_service<tundev_linux_service>;
#elif defined(AVPN_APPLE)
	using tun_device = basic_tun_service<tundev_macos_service>;
#elif defined(AVPN_ANDROID)
	using tun_device = basic_tun_service<tundev_android_service>;
#endif

}
