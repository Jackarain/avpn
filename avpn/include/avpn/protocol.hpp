//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#pragma once

#include "avpn/fec_cache.hpp"


namespace avpn {


	//////////////////////////////////////////////////////////////////////////

	// 整体协议格式

	// encrypt(1)	0表示未加密, 1表示加密.
	// rsv(1)       保留位.
	// type(6)		消息类型.
	// src(32)	    ip包发起端的虚拟源地址, 当server收到pkt时, 通过
	//				src索引到具体的tunnel, 对于client来说用不到.
	// body(N)		N个字节的消息体, 如果encrypt为01, 则
	//				这个body为加密体.

	enum {
		vpt_handshake = 1,
		vpt_handshake_reply = 2,

		vpt_keepalive = 3,
		vpt_keepalive_reply = 4,

		vpt_transfer = 5,
		vpt_transfer_compress = 6,

		vpt_transfer_ack = 7,

		vpt_error = 8,
	};

	enum
	{
		compress_zstd = 1,
		compress_lz4,
		compress_deflate,
	};

	const static uint16_t avpn_protocol_version = 1;


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
	// vaddr(32)
	// prefix_length(8)
	// passbyvpn(8)
	// pushdns(32)
	// routes(8)
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

	// 构造keepalive消息, c -> s.
	// 协议格式
	// id_len(8)
	// id(id_len)
	// rx(32)
	// tx(32)
	vpn_packet make_keepalive(uint32_t src,
		std::string_view id,
		uint32_t rx, uint32_t tx,
		uint64_t timestamp = 0);

	int unwrap_keepalive(vpn_packet& pkt,
		uint32_t& src,
		std::string& id,
		uint32_t& rx, uint32_t& tx,
		uint64_t& timestamp);


	//////////////////////////////////////////////////////////////////////////

	// 构造keepalive_reply消息, s -> c.
	// 协议格式
	// id_len(8)
	// id(id_len)
	// rx(32)
	// tx(32)
	vpn_packet make_keepalive_reply(uint32_t src,
		std::string_view id,
		uint32_t rx, uint32_t tx,
		uint64_t timestamp = 0);

	int unwrap_keepalive_reply(vpn_packet& pkt,
		uint32_t& src,
		std::string& id,
		uint32_t& rx, uint32_t& tx,
		uint64_t& timestamp);


	//////////////////////////////////////////////////////////////////////////

	// 传输数据消息, c <-> s.
	// 协议格式
	// gid(32)
	// pid(8)
	// rsv(8)
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
	// rsv(8)
	// data_len(16)
	// data(data_len)
	vpn_packet make_transfer_compress(uint32_t src,
		uint32_t gid, uint8_t pid,
		uint8_t ctype, std::string_view data);

	void make_transfer_compress(vpn_packet& pkt,
		uint32_t src, uint32_t gid, uint8_t pid,
		uint8_t ctype, std::string_view data);

	vpn_packet_ptr unwrap_transfer_compress(vpn_packet& pkt, uint32_t& src,
		uint32_t& gid, uint8_t& pid, uint8_t& ctype);


	//////////////////////////////////////////////////////////////////////////

	// ack消息, s <-> c.
	// 协议格式
	// gid(32)
	// pid(8)
	// rsv(16)
	// rsv(8)

	vpn_packet make_transfer_ack(uint32_t src,
		uint32_t gid, uint8_t pid);

	int unwrap_transfer_ack(vpn_packet& pkt,
		uint32_t& src, uint32_t& gid, uint8_t& pid);
}
