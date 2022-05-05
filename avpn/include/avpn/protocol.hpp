//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#pragma once

#include "avpn/fec_cache.hpp"

namespace avpn {

	// 整体协议格式

	// encrypt(1)	0表示未加密, 1表示加密.
	// has_src(1)	0表示未附带源地址, 1表示附带源地址.
	// type(6)		消息类型.
	// [src](32)	源地址, 可选项, 由has_src指示是否存在.
	// body(N)		N个字节的消息体, 如果encrypt为01, 则
	//				这个body为加密体.

	enum {
		vpt_auth_request = 0,
		vpt_auth_response = 1,
	};

	vpn_packet make_common_header(
		bool enc, bool has_src, uint8_t type, uint32_t src);

	int unwrap_common_header(vpn_packet& pkt,
		bool& enc, bool& has_src, uint8_t& type, uint32_t& src);

	// 构造认证消息.
	// 协议格式
	// id_len(16)
	// id(id_len)
	// pubkey_len(16)
	// pubkey(pubkey_len)
	// additional_len(16)
	// additional(additional_len)
	vpn_packet make_auth_request(uint32_t src,
		std::string_view id, std::string_view pubkey,
		std::string_view additional = {});

	int unwrap_auth_request(vpn_packet& pkt,
		uint32_t& src, std::string& id, std::string& pubkey,
		std::string& additional);
}
