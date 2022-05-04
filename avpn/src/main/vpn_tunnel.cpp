//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#include "avpn/vpn_tunnel.hpp"
#include "avpn/avpn.hpp"

namespace avpn {

	vpn_tunnel::vpn_tunnel(net::io_context& ioc, const service_config& cfg)
		: m_io_context(ioc)
		, m_config(cfg)
		, m_remote_tcp(ioc)
	{}

	std::shared_ptr<vpn_tunnel>
	vpn_tunnel::make_tunnel(net::io_context& ioc, const service_config& cfg)
	{
		return std::shared_ptr<vpn_tunnel>(new vpn_tunnel(ioc, cfg));
	}

	tcp::socket& vpn_tunnel::tcp_socket()
	{
		return m_remote_tcp;
	}

}
