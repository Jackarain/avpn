//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#include "avpn/vpn_tunnel.hpp"
#include "avpn/avpn.hpp"

namespace avpn {

	vpn_tunnel::vpn_tunnel(net::io_context& ioc,
		std::shared_ptr<avpn_service>& vpn,
		const service_config& cfg,
		std::string pubkey, std::string passphrase)
		: m_io_context(ioc)
		, m_vpn_serivce(vpn)
		, m_config(cfg)
		, m_pubkey(pubkey)
		, m_remote_tcp(ioc)
		, m_keyexchange(passphrase)
		, m_shared_key(m_keyexchange.GenerateSharedKey(pubkey))
	{}

	std::shared_ptr<vpn_tunnel>
	vpn_tunnel::make_tunnel(net::io_context& ioc,
		std::shared_ptr<avpn_service>& vpn,
		const service_config& cfg,
		std::string pubkey, std::string passphrase)
	{
		return std::shared_ptr<vpn_tunnel>(new
			vpn_tunnel(ioc, vpn, cfg, pubkey, passphrase));
	}

	void vpn_tunnel::start_tcp_loop()
	{

	}

	tcp::socket& vpn_tunnel::tcp_socket()
	{
		return m_remote_tcp;
	}

	std::string vpn_tunnel::shared_key() const
	{
		return m_shared_key;
	}

	net::ip::network_v4 vpn_tunnel::vnet_addr() const
	{
		return m_vaddr;
	}

	void vpn_tunnel::vnet_addr(const net::ip::network_v4& vaddr)
	{
		m_vaddr = vaddr;
	}

	udp::endpoint vpn_tunnel::remote_endpoint() const
	{
		return m_remote_endpoint;
	}

	void vpn_tunnel::remote_endpoint(const udp::endpoint& endp)
	{
		m_remote_endpoint = endp;
	}

}
