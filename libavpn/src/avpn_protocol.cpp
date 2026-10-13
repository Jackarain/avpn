//
// avpn_protocol.cpp
// ~~~~~~~~~~~~~~~~~
//
// Copyright (C) 2025 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#include "libavpn/avpn_protocol.hpp"

#include <boost/asio/ip/address.hpp>
#include <boost/algorithm/string.hpp>

namespace libavpn {

	namespace
	{
		// 解析 "host:port", 供 udp/tcp endpoint 共用.
		bool parse_host_port(std::string_view addr, net::ip::address& ip, uint16_t& port)
		{
			boost::system::error_code ec;
			auto pos = addr.rfind(':');
			if (pos == std::string_view::npos)
				return false;

			auto host = addr.substr(0, pos);
			auto port_str = addr.substr(pos + 1);

			int value = 0;
			try
			{
				value = std::stoi(std::string(port_str));
			}
			catch (...)
			{
				return false;
			}
			if (value < 0 || value > 65535)
				return false;

			ip = net::ip::make_address(std::string(host), ec);
			if (ec)
				return false;

			port = static_cast<uint16_t>(value);
			return true;
		}

		template <typename Endpoint>
		std::string endpoint_string(const Endpoint& ep)
		{
			return ep.address().to_string() + ":" + std::to_string(ep.port());
		}
	} // namespace

	compress_type compress_type_from_string(std::string_view name)
	{
		if (boost::iequals(name, "deflate"))
			return compress_type::deflate;
		if (boost::iequals(name, "lz4"))
			return compress_type::lz4;
		if (boost::iequals(name, "zstd"))
			return compress_type::zstd;
		return compress_type::none;
	}

	std::string_view compress_type_to_string(compress_type type)
	{
		switch (type)
		{
		case compress_type::deflate:
			return "deflate";
		case compress_type::lz4:
			return "lz4";
		case compress_type::zstd:
			return "zstd";
		default:
			return "none";
		}
	}

	bool parse_ipv4(std::string_view text, uint32_t& out)
	{
		if (text.empty())
			return false;

		boost::system::error_code ec;
		auto addr = net::ip::make_address_v4(std::string(text), ec);
		if (!ec)
		{
			out = addr.to_uint();
			return true;
		}

		// 也认十进制整数写法 (与 JSON 配置、老命令兼容).
		if (text.find_first_not_of("0123456789") != std::string_view::npos)
			return false;

		unsigned long long v = 0;
		for (char c : text)
		{
			v = v * 10 + static_cast<unsigned>(c - '0');
			if (v > 0xffffffffull)
				return false;
		}
		out = static_cast<uint32_t>(v);
		return true;
	}

	bool parse_endpoint(std::string_view addr, net::ip::udp::endpoint& ep)
	{
		net::ip::address ip;
		uint16_t port = 0;
		if (!parse_host_port(addr, ip, port))
			return false;

		ep = net::ip::udp::endpoint(ip, port);
		return true;
	}

	bool parse_endpoint(std::string_view addr, net::ip::tcp::endpoint& ep)
	{
		net::ip::address ip;
		uint16_t port = 0;
		if (!parse_host_port(addr, ip, port))
			return false;

		ep = net::ip::tcp::endpoint(ip, port);
		return true;
	}

	std::string endpoint_to_string(const net::ip::udp::endpoint& ep)
	{
		return endpoint_string(ep);
	}

	std::string endpoint_to_string(const net::ip::tcp::endpoint& ep)
	{
		return endpoint_string(ep);
	}

} // namespace libavpn
