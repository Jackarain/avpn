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
		vpt_handshake_reply,

		vpt_tun2socks,
		vpt_tun2socks_reply,

		vpt_keepalive,
		vpt_keepalive_reply,

		vpt_transfer,
		vpt_transfer_compress,

		vpt_transfer_ack,

		vpt_error,
	};

	enum
	{
		compress_zstd = 1,
		compress_lz4,
		compress_deflate,
	};

	const inline uint16_t avpn_protocol_version = 2;


	//////////////////////////////////////////////////////////////////////////

	// 公共协议头, 共5字节.
	// 协议格式
	// enc  (1b)
	// rsv  (1b)
	// type (6b)
	// src  (1)

	vpn_packet make_common_header(
		bool enc, uint8_t type, uint32_t src);

	void make_common_header(vpn_packet& pkt,
		bool enc, uint8_t type, uint32_t src);

	int unwrap_common_header(vpn_packet& pkt,
		bool& enc, uint8_t& type, uint32_t& src);


	//////////////////////////////////////////////////////////////////////////

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

	// 构造tun2socks协议.
	// 协议格式
	// target_len(8)
	// target(target_len)
	// port(16)
	// pubkey_len(8)
	// pubkey(pubkey_len)

	vpn_packet make_tun2socks(
		std::string_view target, uint16_t port,
		std::string_view pubkey);

	int unwarp_tun2socks(vpn_packet& pkt,
		std::string& target, uint16_t& port,
		std::string& pubkey);


	//////////////////////////////////////////////////////////////////////////

	// 构造tun2socks_reply协议.
	// 协议格式
	// status(8)
	// reason_len(8)
	// reason(reason_len)

	vpn_packet make_tun2socks_reply(
		uint8_t status, std::string_view reason);

	int unwarp_tun2socks_reply(vpn_packet& pkt,
		uint8_t& status, std::string& reason);


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
	// index(64)
	// rsv(8)
	// data(payload_size)

	vpn_packet make_transfer(uint32_t src,
		uint64_t index, std::string_view data);

	void make_transfer(vpn_packet& pkt,
		uint32_t src, uint64_t index, std::string_view data);

	int unwrap_transfer(vpn_packet& pkt, uint32_t& src, uint64_t& index);


	//////////////////////////////////////////////////////////////////////////

	// 传输数据消息, c <-> s.
	// 协议格式
	// index(64)
	// compress_type(8)
	// data(payload_size)

	vpn_packet make_transfer_compress(uint32_t src,
		uint64_t index,
		uint8_t ctype, std::string_view data);

	void make_transfer_compress(vpn_packet& pkt,
		uint32_t src,
		uint64_t index,
		uint8_t ctype, std::string_view data);

	vpn_packet_ptr unwrap_transfer_compress(
		vpn_packet& pkt, uint32_t& src,
		uint64_t& index, uint8_t& ctype);


	//////////////////////////////////////////////////////////////////////////

	// ack消息, s <-> c.
	// 协议格式
	// index(64)

	vpn_packet make_transfer_ack(uint32_t src,
		uint64_t index);

	int unwrap_transfer_ack(vpn_packet& pkt,
		uint32_t& src, uint64_t& index);
}
