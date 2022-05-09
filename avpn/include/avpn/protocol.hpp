//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#pragma once

#include "avpn/fec_cache.hpp"

namespace avpn {

	const static int normal_mtu = 1500;
	const static int static_mtu = 1450;
	const static uint16_t avpn_protocol_version = 1;

	// 整体协议格式

	// encrypt(1)	0表示未加密, 1表示加密.
	// has_src(1)	0表示未附带源地址, 1表示附带源地址.
	// type(6)		消息类型.
	// [src](32)	源地址, 可选项, 由has_src指示是否存在.
	// body(N)		N个字节的消息体, 如果encrypt为01, 则
	//				这个body为加密体.

	enum {
		vpt_handshake_request = 1,
		vpt_handshake_response = 2,

		vpt_keepalive = 3,
	};

	vpn_packet make_common_header(
		bool enc, bool has_src, uint8_t type, uint32_t src);

	int unwrap_common_header(vpn_packet& pkt,
		bool& enc, bool& has_src, uint8_t& type, uint32_t& src);

	// 构造握手认证消息, c -> s.
	// 协议格式
	// id_len(8)
	// id(id_len)
	// pubkey_len(8)
	// pubkey(pubkey_len)
	// additional_len(8)
	// additional(additional_len)
	vpn_packet make_handshake_request(uint32_t src,
		std::string_view id, std::string_view pubkey,
		std::string_view additional = {});

	int unwrap_handshake_request(vpn_packet& pkt,
		uint32_t& src, std::string& id, std::string& pubkey,
		std::string& additional);

	// 构造握手认证回复消息, s -> c.
	// 协议格式
	// id_len(8)
	// id(id_len)
	// vaddr(number)
	// prefix_length(number)
	// passbyvpn(number)
	// pushdns(number)
	// routes(number)
	// {size(u8), string[size]}[routes]
	vpn_packet make_handshake_response(std::string_view id,
		uint32_t addr, uint8_t prefix_length,
		bool passbyvpn, uint32_t pushdns,
		std::vector<std::string> routes);

	int unwrap_handshake_response(vpn_packet& pkt,
		std::string& id, uint32_t& addr, uint8_t& prefix_length,
		bool& passbyvpn, uint32_t& pushdns,
		std::vector<std::string>& routes);
}
