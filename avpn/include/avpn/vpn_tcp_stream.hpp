//
// Copyright (C) 2022 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#include "avpn/avpn.hpp"

namespace avpn {

	class vpn_tcp_stream
	{
		// c++11 noncopyable.
		vpn_tcp_stream(const vpn_tcp_stream&) = delete;
		vpn_tcp_stream& operator=(const vpn_tcp_stream&) = delete;
	public:
		vpn_tcp_stream(net::io_context& ioc);
		~vpn_tcp_stream();

	private:
		// 用于当前vpn_conntrack业务调度.
		net::io_context& m_io_context;

		// 连接接受状态.
		bool m_accepted{ false };

		// 中止tcp状态机.
		bool m_abort;
	};
}
