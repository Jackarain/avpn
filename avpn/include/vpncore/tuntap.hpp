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
#	include "vpncore/tuntap_linux_service.hpp"
#elif defined(AVPN_APPLE)
#	include "vpncore/tuntap_macos_service.hpp"
#elif defined(AVPN_ANDROID)
#	include "vpncore/tuntap_android_service.hpp"
#else
#	error unsupported platform
#endif

#include "vpncore/basic_tuntap.hpp"

namespace avpn {

	// 定义不同平台的tuntap实现.
#if defined(AVPN_WINDOWS)
#ifdef AVPN_USE_WINTUN
	using tuntap = basic_tuntap<wintun_windows_service>;
#else
	using tuntap = basic_tuntap<tuntap_windows_service>;
#endif // AVPN_USE_WINTUN
#elif defined(AVPN_LINUX)
	using tuntap = basic_tuntap<tuntap_linux_service>;
#elif defined(AVPN_APPLE)
	using tuntap = basic_tuntap<tuntap_macos_service>;
#elif defined(AVPN_ANDROID)
	using tuntap = basic_tuntap<tuntap_android_service>;
#endif

}
