//
// Copyright (C) 2022 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#include "avpn/vpn_tcp_stream.hpp"

namespace avpn {

	vpn_tcp_stream::vpn_tcp_stream(net::io_context& ioc)
		: m_io_context(ioc)
	{
	}

	vpn_tcp_stream::~vpn_tcp_stream()
	{
	}

}
