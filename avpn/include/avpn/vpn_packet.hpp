//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#pragma once

#include <cinttypes>
#include <memory>

namespace avpn {

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

	public:
		std::unique_ptr<uint8_t, packet_free> data_;
		uint16_t size_{ 0 };
		uint16_t payload_size_{ 0 };

		uint32_t gid_{ 0 };
		uint8_t pid_{ 0 };

		vpn_packet_t type_;
	};

	using vpn_packet_ptr = std::shared_ptr<vpn_packet>;
	using vpn_packet_weak_ptr = std::weak_ptr<vpn_packet>;

}
