//
// Copyright (C) 2022 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#include "avpn/vpn_conntrack.hpp"

namespace avpn {

	vpn_conntrack::vpn_conntrack(net::io_context& ioc,
		std::weak_ptr<avpn_service> service)
		: m_io_context(ioc)
		, m_serivce(service)
	{
	}

	vpn_conntrack::~vpn_conntrack()
	{
	}

}
