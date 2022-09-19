//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#pragma once

#include <cinttypes>
#include <memory>

#include "avpn/endpoint_pair.hpp"

namespace avpn {

	//////////////////////////////////////////////////////////////////////////
	// transfer 中的IP包数据在消息中偏移.
	const inline int avpn_payload_header_size = 14;
	// packet的header大小.
	const inline int avpn_pkt_header_size = 5;
	// 正常mtu大小定义.
	const inline int avpn_normal_mtu = 1500;
	// PPPoE header大小.
	const inline int avpn_normal_pppoe = 8;
	// ipv6 header大小.
	const inline int avpn_normal_ipv6_header_size = 40;
	// ipv4 header大小.
	const inline int avpn_normal_ipv4_header_size = 20;

	// 上层协议空间.
	inline int avpn_upper_layer_additional_size = 0;
	// UDP header大小.
	inline int avpn_normal_udp_header = avpn_normal_ipv4_header_size + 8;

	// avpn数据包最大定义(传输在udp网络中的最大可用size).
	inline int avpn_packet_size = avpn_normal_mtu
		- avpn_normal_pppoe
		- avpn_normal_udp_header
		- avpn_upper_layer_additional_size;

	// avpn数据包中IP包大小定义, 即网卡的mtu.
	inline int avpn_static_mtu =
		avpn_packet_size - avpn_payload_header_size;

	//////////////////////////////////////////////////////////////////////////
	// vpn数据包定义.
	enum vpn_packet_t
	{
		pkt_tcp = 0x06,
		pkt_udp = 0x11,
		pkt_icmp = 0x01,
	};

	struct packet_free
	{
		void operator()(void* p);
	};

	struct vpn_packet
	{
	private:
		vpn_packet(const vpn_packet&) = delete;
		vpn_packet& operator=(const vpn_packet&) = delete;

	public:
		vpn_packet();
		vpn_packet(vpn_packet&&);
		vpn_packet& operator=(vpn_packet&&);
		~vpn_packet();

		// pkt的数据指针.
		uint8_t* data();
		const uint8_t* data() const;

		// 整个pkt有效数据大小.
		uint16_t size();
		void resize(size_t count);

		// payload 表示ip数据包的内容.
		uint8_t* payload();

		// 设置或获取payload的大小.
		uint16_t payload_size();
		void payload_size(size_t count);

		// 数据包类型.
		vpn_packet_t type() const;
		void type(vpn_packet_t t);

		// 释放数据指针, 手工管理内存, 使用free释放.
		void* release();

	public:
		std::unique_ptr<uint8_t, packet_free> data_;
		uint16_t size_{ 0 };
		uint16_t payload_size_{ 0 };

		uint32_t gid_{ 0 };
		uint8_t pid_{ 0 };

		vpn_packet_t type_;
		int debug_flag_{ -1 };
	};

	// avpn数据包整个占用内存大小.
	inline int avpn_packet_memory_size =
		avpn_packet_size + sizeof(vpn_packet);

	// 重新计算mtut等参数的大小, 返回false则表示设置了不
	// 合适的值, avpn将自动计算合适的值.
	inline bool recompute_mtu(int mtu = 0, bool v6 = true)
	{
		avpn_normal_udp_header =
			(v6 ? avpn_normal_ipv6_header_size : avpn_normal_ipv4_header_size)
			+ 8;

		avpn_packet_size = avpn_normal_mtu
			- avpn_normal_pppoe
			- avpn_normal_udp_header;

		if (mtu > avpn_packet_size)
			return false;

		if (mtu <= 0)
			avpn_upper_layer_additional_size = 0;
		else
			avpn_upper_layer_additional_size = avpn_packet_size
			- mtu
			- avpn_payload_header_size;

		avpn_packet_size = avpn_normal_mtu
			- avpn_normal_pppoe
			- avpn_normal_udp_header
			- avpn_upper_layer_additional_size;

		avpn_static_mtu =
			avpn_packet_size - avpn_payload_header_size;

		avpn_packet_memory_size =
			avpn_packet_size + sizeof(vpn_packet);

		return true;
	}

	using vpn_packet_ptr = std::shared_ptr<vpn_packet>;
	using vpn_packet_weak_ptr = std::weak_ptr<vpn_packet>;

	vpn_packet_ptr dup_vpn_packet_ptr(const vpn_packet_ptr& p);
	vpn_packet_ptr dup_vpn_packet_ptr(const vpn_packet& p);

	vpn_packet dup_vpn_packet(const vpn_packet_ptr& p);
	vpn_packet dup_vpn_packet(const vpn_packet& p);

	//////////////////////////////////////////////////////////////////////////

	struct vpn_tun_packet
	{
	private:
		vpn_tun_packet(const vpn_tun_packet&) = delete;
		vpn_tun_packet& operator=(const vpn_tun_packet&) = delete;

	public:
		vpn_tun_packet(vpn_packet pkt, endpoint_pair endp);
		~vpn_tun_packet() = default;

		vpn_tun_packet(vpn_tun_packet&&);
		vpn_tun_packet& operator=(vpn_tun_packet&&);

	public:
		vpn_packet pkt_;
		endpoint_pair endp_;
	};
}
