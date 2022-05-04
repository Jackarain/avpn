//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#pragma once

#include "utils/io_context_pool.hpp"
#include "utils/scoped_exit.hpp"
#include "utils/bitfield.hpp"
#include "utils/url_parser.hpp"
#include "utils/async_connect.hpp"
#include "utils/io.hpp"
#include "utils/logging.hpp"
#include "utils/misc.hpp"
#include "utils/crypto.hpp"
#include "utils/uawaitable.hpp"

#include "avpn/endpoint_pair.hpp"

#include "avpn/reedsolomon.hpp"
#include "avpn/fec_cache.hpp"
#include "avpn/avpn.hpp"


namespace avpn {

	class vpn_tunnel : public std::enable_shared_from_this<vpn_tunnel>
	{
		// c++11 noncopyable.
		vpn_tunnel(const vpn_tunnel&) = delete;
		vpn_tunnel& operator=(const vpn_tunnel&) = delete;

		// avoid direct call construct object...
		vpn_tunnel() = delete;
		vpn_tunnel(net::io_context&, service_config);

	public:
		static std::shared_ptr<vpn_tunnel> make_tunnel(
			net::io_context&, service_config);
		~vpn_tunnel() = default;

	public:
		tcp::socket& tcp_socket();

	private:
		// 用于当前tunnel业务调度.
		net::io_context& m_io_context;

		// vpn相关配置.
		service_config m_config;

		// 与remote通信的tcp socket.
		tcp::socket m_remote_tcp;
	};
}
