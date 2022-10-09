//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#pragma once

#include <boost/asio/ip/network_v4.hpp>

#include <string>
#include <vector>
#include <memory>
#include <tuple>

namespace net = boost::asio;

namespace avpn
{
	namespace common
	{
		std::tuple<net::ip::network_v4, std::string> default_gateway();

#ifdef _WIN32
		DWORD get_interface_index(const wchar_t* guid);
		void windows_set_mtu(
			const int iface_index, const short family, const int mtu);
#endif
	}
}
