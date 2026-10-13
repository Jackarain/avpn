//
// avpn_protocol.hpp
// ~~~~~~~~~~~~~~~~~
//
// Copyright (C) 2025 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#ifndef INCLUDE__2025_11_20__AVPN_PROTOCOL_HPP
#define INCLUDE__2025_11_20__AVPN_PROTOCOL_HPP

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>

#include <boost/asio/ip/udp.hpp>
#include <boost/asio/ip/tcp.hpp>

namespace libavpn {

	namespace net = boost::asio;

	// 最大 tun mtu.
	inline constexpr std::size_t avpn_max_mtu = 1500;

	// 最大网络数据包大小(含加密与协议开销).
	inline constexpr std::size_t avpn_max_packet_size = 2048;

	// 压缩算法.
	enum class compress_type : uint8_t
	{
		none = 0,
		deflate = 1,
		lz4 = 2,
		zstd = 3,
	};

	// 将压缩算法字符串转换为 compress_type.
	compress_type compress_type_from_string(std::string_view name);
	std::string_view compress_type_to_string(compress_type type);

	// 解析 "ip:port" 形式的地址为 udp/tcp endpoint.
	bool parse_endpoint(std::string_view addr, net::ip::udp::endpoint& ep);
	bool parse_endpoint(std::string_view addr, net::ip::tcp::endpoint& ep);

	// 将 endpoint 转换为字符串.
	std::string endpoint_to_string(const net::ip::udp::endpoint& ep);
	std::string endpoint_to_string(const net::ip::tcp::endpoint& ep);

} // namespace libavpn

#endif // INCLUDE__2025_11_20__AVPN_PROTOCOL_HPP
