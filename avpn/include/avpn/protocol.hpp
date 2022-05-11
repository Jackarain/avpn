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

	//////////////////////////////////////////////////////////////////////////

	// 整体协议格式

	// encrypt(1)	0表示未加密, 1表示加密.
	// rsv(1)       保留位.
	// type(6)		消息类型.
	// src(32)	    源地址, 由has_src指示是否存有效.
	// body(N)		N个字节的消息体, 如果encrypt为01, 则
	//				这个body为加密体.

	enum {
		vpt_handshake = 1,
		vpt_handshake_reply = 2,

		vpt_keepalive = 3,
		vpt_keepalive_reply = 4,

		vpt_transfer = 5,
		vpt_transfer_compress = 6,
	};

	// transfer 中的IP包数据在消息中偏移.
	const static int payload_off = 13;
	const static int header_size = 5;

	//////////////////////////////////////////////////////////////////////////

	vpn_packet make_common_header(
		bool enc, uint8_t type, uint32_t src);

	void make_common_header(vpn_packet& pkt,
		bool enc, uint8_t type, uint32_t src);

	int unwrap_common_header(vpn_packet& pkt,
		bool& enc, uint8_t& type, uint32_t& src);

	// 构造握手认证消息, c -> s.
	// 协议格式
	// id_len(8)
	// id(id_len)
	// pubkey_len(8)
	// pubkey(pubkey_len)
	// ds(8)
	// ps(8)
	vpn_packet make_handshake(uint32_t src,
		std::string_view id, std::string_view pubkey,
		uint8_t ds, uint8_t ps);

	int unwrap_handshake(vpn_packet& pkt,
		uint32_t& src, std::string& id, std::string& pubkey,
		uint8_t& ds, uint8_t& ps);

	//////////////////////////////////////////////////////////////////////////

	// 构造握手认证回复消息, s -> c.
	// 协议格式
	// id_len(8)
	// id(id_len)
	// ds(8)
	// ps(8)
	// vaddr(number)
	// prefix_length(number)
	// passbyvpn(number)
	// pushdns(number)
	// routes(number)
	// {size(u8), string[size]}[routes]
	vpn_packet make_handshake_reply(std::string_view id,
		uint8_t ds, uint8_t ps,
		uint32_t addr, uint8_t prefix_length,
		bool passbyvpn, uint32_t pushdns,
		std::vector<std::string> routes);

	int unwrap_handshake_reply(vpn_packet& pkt,
		std::string& id,
		uint8_t& ds, uint8_t& ps,
		uint32_t& addr, uint8_t& prefix_length,
		bool& passbyvpn, uint32_t& pushdns,
		std::vector<std::string>& routes);

	//////////////////////////////////////////////////////////////////////////

	// 传输数据消息, c <-> s.
	// 协议格式
	// gid(32)
	// pid(8)
	// rsv(8)
	// data_len(16)
	// data(data_len)
	vpn_packet make_transfer(uint32_t src,
		uint32_t gid, uint8_t pid, std::string_view data);

	void make_transfer(vpn_packet& pkt,
		uint32_t src, uint32_t gid, uint8_t pid,
		std::string_view data);

	int unwrap_transfer(vpn_packet& pkt,
		uint32_t& src, uint32_t& gid, uint8_t& pid);

	//////////////////////////////////////////////////////////////////////////

	// 传输数据消息, c <-> s.
	// 协议格式
	// gid(32)
	// pid(8)
	// compress_type(8)
	// data_len(16)
	// data(data_len)
	vpn_packet make_transfer_compress(uint32_t src,
		uint32_t gid, uint8_t pid,
		uint8_t ctype, std::string_view data);

	void make_transfer_compress(vpn_packet& pkt,
		uint32_t src, uint32_t gid, uint8_t pid,
		uint8_t ctype, std::string_view data);

	int unwrap_transfer_compress(vpn_packet& pkt, uint32_t& src,
		uint32_t& gid, uint8_t& pid, uint8_t& ctype);

}
