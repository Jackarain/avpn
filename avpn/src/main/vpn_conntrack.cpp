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

	void vpn_conntrack::forward_ip(vpn_packet pkt, endpoint_pair endp)
	{
		auto stream = lookup_stream(endp);
		if (!stream)
		{
			stream = make_tcp_stream();
			m_conntrack[endp] = stream;
		}

		stream->process_tcp_stack(std::move(pkt), std::move(endp));
	}

	tcp_stream_ptr vpn_conntrack::make_tcp_stream()
	{
		auto stream = std::make_shared<vpn_tcp_stream>(m_io_context, m_serivce);

		stream->set_accept_handler(
			[this, stream](auto arg) mutable
			{
				handle_accept(stream, arg);
			});

		stream->set_closed_handler(
			[this, stream](auto arg) mutable
			{
				handle_closed(stream, arg);
			});

		return stream;
	}

	tcp_stream_ptr vpn_conntrack::lookup_stream(const endpoint_pair& endp)
	{
		auto it = m_conntrack.find(endp);
		if (it == m_conntrack.end())
			return nullptr;
		return it->second;
	}

	void vpn_conntrack::handle_accept(
		tcp_stream_ptr stream, const boost::system::error_code& ec)
	{
		if (ec)
		{
			XLOG_DBG << "stream: " << stream.get()
				<< " accept error: " << ec.message();
			return;
		}
	}

	void vpn_conntrack::handle_closed(
		tcp_stream_ptr stream, const boost::system::error_code& ec)
	{
		if (ec)
		{
			XLOG_DBG << "stream: " << stream.get()
				<< " closed error: " << ec.message();
			return;
		}
	}

}
