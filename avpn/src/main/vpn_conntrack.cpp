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

	void vpn_conntrack::forward_ip(vpn_packet pkt, const endpoint_pair& endp)
	{
		boost::ignore_unused(pkt);
		auto stream = lookup_stream(endp);
		if (!stream)
		{
			// 1, start connect to target.
			// 2, accept tcp.
			// 3, splice data.
		}

		// splice data.
	}


	vpn_tcp_stream* vpn_conntrack::lookup_stream(const endpoint_pair& endp)
	{
		boost::ignore_unused(endp);
		return nullptr;
	}

}
