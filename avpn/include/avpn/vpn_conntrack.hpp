//
// Copyright (C) 2022 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#include "avpn/avpn.hpp"


namespace avpn {

	class vpn_conntrack
	{
		// c++11 noncopyable.
		vpn_conntrack(const vpn_conntrack&) = delete;
		vpn_conntrack& operator=(const vpn_conntrack&) = delete;
	public:
		vpn_conntrack(net::io_context& ioc, std::weak_ptr<avpn_service> service);
		~vpn_conntrack();

	private:
		// 用于当前vpn_conntrack业务调度.
		net::io_context& m_io_context;

		// service 对象引用.
		std::weak_ptr<avpn_service> m_serivce;
	};

}
