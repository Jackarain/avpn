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
		static std::shared_ptr<vpn_tunnel> make(
			net::io_context&, std::shared_ptr<avpn_service>&,
				const service_config&, std::string, std::string);
		~vpn_tunnel();

	public:
		// 开始tunnel工作.
		void start_tunnel(uint8_t ds, uint8_t ps);

		// 关闭tunnel.
		void close_tunnel();

		// tcp消息循环.
		net::awaitable<void> tcp_loop();

		// 设置/返回该tunnel的tcp socket引用.
		tcp::socket& tcp_socket();
		void tcp_socket(tcp::socket&& s, size_t id);

		// forward tun packet to network.
		net::awaitable<void>
		tun_forward(vpn_packet_ptr pkt, endpoint_pair endp);

		// forward udp packet from network.
		net::awaitable<void>
		udp_forward(vpn_packet_ptr pkt, udp::endpoint remote);

		// 通过udp/tcp协议发送数据包.
		void udp_write_packet(vpn_packet_ptr& pkt);
		void tcp_write_packet(vpn_packet_ptr& pkt);

		// 设置/返回client的id.
		std::string client_id() const;
		void client_id(const std::string& id);

		// 返回协商的密钥.
		std::string shared_key() const;

		// 设置/返回server分配的vnet addr.
		net::ip::network_v4 vnet_addr() const;
		void vnet_addr(const net::ip::network_v4& vaddr);

		// 设置/返回远端udp的endpoint.
		udp::endpoint remote_endpoint() const;
		void remote_endpoint(const udp::endpoint& endp);

		// 设置/返回tunnel最后活跃时间.
		time_point last_see() const;
		void last_see(const time_point& now);

		// Obtains the executor associated with the io_context.
		net::any_io_executor get_executor();

	private:
		// 定时任务处理, 如keepalive等相关处理.
		net::awaitable<void> tick();

		// 在tcp连接上读/写一个vpn_packet消息.
		net::awaitable<int> tcp_read_packet(
			tcp::socket& stream, vpn_packet& pkt);
		net::awaitable<void> tcp_write_packet(
			tcp::socket& stream, vpn_packet_ptr& pkt);

		// 处理tcp/udp协议.
		net::awaitable<bool> process_tcp_packet(vpn_packet_ptr pkt);
		net::awaitable<void> process_udp_packet(vpn_packet_ptr pkt);

		// 作为server时, 接收到keepalive消息.
		net::awaitable<void> on_vpn_keepalive();

		// 接收到transfer/compress消息.
		net::awaitable<void> on_vpn_transfer(vpn_packet_ptr pkt);
		net::awaitable<void> on_vpn_transfer_compress(vpn_packet_ptr pkt);

	private:
		// 用于当前tunnel业务调度.
		net::io_context& m_io_context;

		// service 对象引用.
		std::weak_ptr<avpn_service> m_serivce;

		// vpn相关配置.
		service_config m_config;

		// 当前vpn的身份.
		Identity m_identity;

		// 对方的pubkey.
		std::string m_pubkey;

		// 客户端的client id.
		std::string m_client_id;

		// 对方fec编码使用的ds, ps.
		// 本端解码时需要使用对方的ds,ps来进行fec解码.
		uint8_t m_data_shards{ 0 };
		uint8_t m_parity_shards{ 0 };

		// fec纠错相关统计信息.
		int m_num_corrected{ 0 };
		int m_num_incorrect{ 0 };

		// 与remote通信的tcp socket及tcp socket id.
		tcp::socket m_tcp_socket;
		size_t m_tcp_socket_id{ 0 };

		// 用于密钥交换.
		crypto_util::keyexchange m_keyexchange;

		// 密钥.
		std::string m_shared_key;

		// 分配的vaddr.
		net::ip::network_v4 m_vaddr;

		// 对方udp的endpoint.
		udp::endpoint m_remote_endpoint;

		// 最后活跃时间.
		time_point m_last_see{ steady_clock::now() };

		// timer, 处理本tunnel相关定时工作.
		// 如: keepalive等工作.
		asio_timer m_tick_timer;

		// fec解码器.
		fec_recover m_recover;

		// fec编码器.
		fec_encode_group m_feg;

		// 退出标志.
		boost::tribool m_abort{ boost::indeterminate };
	};
}
