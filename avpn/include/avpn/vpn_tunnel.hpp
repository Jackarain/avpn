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
		vpn_tunnel(net::io_context&, std::shared_ptr<avpn_service>&,
			const service_config&, std::string, std::string);

	public:
		static std::shared_ptr<vpn_tunnel> make_tunnel(
			net::io_context&, std::shared_ptr<avpn_service>&,
				const service_config&, std::string, std::string);
		~vpn_tunnel() = default;

	public:
		// 开始处理tcp协议.
		void start_tcp_loop();

		// 返回该tunnel的tcp socket引用.
		tcp::socket& tcp_socket();

		// 返回协商的密钥.
		std::string shared_key() const;

		// 返回server分配的vnet addr.
		net::ip::network_v4 vnet_addr() const;
		// 设置vnet addr.
		void vnet_addr(const net::ip::network_v4& vaddr);

		// 返回远端udp的endpoint.
		udp::endpoint remote_endpoint() const;
		// 设置远端udp的endpoint.
		void remote_endpoint(const udp::endpoint& endp);

	private:
		// 用于当前tunnel业务调度.
		net::io_context& m_io_context;

		// service 对象引用.
		std::weak_ptr<avpn_service> m_vpn_serivce;

		// vpn相关配置.
		service_config m_config;

		// 对方的pubkey.
		std::string m_pubkey;

		// 与remote通信的tcp socket.
		tcp::socket m_remote_tcp;

		// 用于密钥交换.
		crypto_util::keyexchange m_keyexchange;

		// 密钥.
		std::string m_shared_key;

		// 分配的vaddr.
		net::ip::network_v4 m_vaddr;

		// 对方udp的endpoint.
		udp::endpoint m_remote_endpoint;
	};
}
