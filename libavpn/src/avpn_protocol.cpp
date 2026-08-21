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
#include "libavpn/avpn.hpp"

#include <boost/asio/ip/address.hpp>
#include <boost/algorithm/string.hpp>

namespace libavpn {

	using namespace byteorder;

	std::string serialize_handshake_msg1(const handshake_msg1& msg)
	{
		std::string out;
		out.reserve(avpn_handshake_packet_size - 12 - 16);

		// [TPubC(32)]
		out.append(reinterpret_cast<const char*>(msg.ephemeral_pub.data()),
			msg.ephemeral_pub.size());
		// [timestamp(8)]
		put_u64(out, msg.timestamp);
		// [client_id(32)]
		out.append(reinterpret_cast<const char*>(msg.client_id.data()),
			msg.client_id.size());
		// [requested_vaddr(4)]
		put_u32(out, msg.requested_vaddr);

		return out;
	}

	bool deserialize_handshake_msg1(std::string_view data, handshake_msg1& msg)
	{
		std::size_t pos = 0;

		// 兼容老版本 (无 requested_vaddr) 与新版本载荷.
		const std::size_t base = avpn_ephemeral_key_size + 8 + avpn_client_id_size;
		if (data.size() != base && data.size() != base + 4)
			return false;

		std::memcpy(msg.ephemeral_pub.data(), data.data() + pos,
			msg.ephemeral_pub.size());
		pos += msg.ephemeral_pub.size();

		if (!get_u64(data, pos, msg.timestamp))
			return false;

		std::memcpy(msg.client_id.data(), data.data() + pos,
			msg.client_id.size());
		pos += msg.client_id.size();

		msg.requested_vaddr = 0;
		if (pos + 4 == data.size())
		{
			if (!get_u32(data, pos, msg.requested_vaddr))
				return false;
		}

		return pos == data.size();
	}

	std::string serialize_handshake_msg2(const handshake_msg2& msg)
	{
		std::string out;
		out.reserve(64 + 32 + 32);

		// [TPubS(32)]
		out.append(reinterpret_cast<const char*>(msg.ephemeral_pub.data()),
			msg.ephemeral_pub.size());

		const auto& c = msg.config;

		// [compress(1)]
		out.push_back(static_cast<char>(c.compress));
		// [data_shards(1)]
		out.push_back(static_cast<char>(c.data_shards));
		// [parity_shards(1)]
		out.push_back(static_cast<char>(c.parity_shards));
		// [keepalive(2)]
		put_u16(out, c.keepalive);
		// [mtu(2)]
		put_u16(out, c.mtu);
		// [vaddr(4)]
		put_u32(out, c.vaddr);
		// [prefix_length(1)]
		out.push_back(static_cast<char>(c.prefix_length));
		// [v6_prefix(1)]
		out.push_back(static_cast<char>(c.v6_prefix));
		// [v6_net(16)]
		out.append(reinterpret_cast<const char*>(c.v6_net.to_bytes().data()),
			16);
		// [passbyvpn(1)]
		out.push_back(c.passbyvpn ? 1 : 0);
		// [pushdns(4)]
		put_u32(out, c.pushdns);
		// [routes_count(1)]
		out.push_back(static_cast<char>(c.routes.size()));
		// {[len(1)][route]}
		for (auto& r : c.routes)
		{
			if (r.size() > 255)
				return {};
			out.push_back(static_cast<char>(r.size()));
			out.append(r);
		}
		// [obfuscate(1)] 可选字段, 老版本对端无此字节.
		out.push_back(c.obfuscate ? 1 : 0);

		return out;
	}

	bool deserialize_handshake_msg2(std::string_view data, handshake_msg2& msg)
	{
		std::size_t pos = 0;

		if (data.size() < avpn_ephemeral_key_size + 35)
			return false;

		std::memcpy(msg.ephemeral_pub.data(), data.data() + pos,
			msg.ephemeral_pub.size());
		pos += msg.ephemeral_pub.size();

		auto& c = msg.config;

		uint8_t v8 = 0;
		if (!get_u8(data, pos, v8))
			return false;
		c.compress = static_cast<compress_type>(v8);

		if (!get_u8(data, pos, c.data_shards))
			return false;
		if (!get_u8(data, pos, c.parity_shards))
			return false;
		if (!get_u16(data, pos, c.keepalive))
			return false;
		if (!get_u16(data, pos, c.mtu))
			return false;
		if (!get_u32(data, pos, c.vaddr))
			return false;
		if (!get_u8(data, pos, c.prefix_length))
			return false;
		if (!get_u8(data, pos, c.v6_prefix))
			return false;
		if (pos + 16 > data.size())
			return false;
		net::ip::address_v6::bytes_type v6_bytes{};
		std::memcpy(v6_bytes.data(), data.data() + pos, 16);
		c.v6_net = net::ip::address_v6(v6_bytes);
		pos += 16;
		if (!get_u8(data, pos, v8))
			return false;
		c.passbyvpn = v8 != 0;
		if (!get_u32(data, pos, c.pushdns))
			return false;

		if (!get_u8(data, pos, v8))
			return false;

		c.routes.clear();
		c.routes.reserve(v8);
		for (int i = 0; i < v8; i++)
		{
			uint8_t len = 0;
			if (!get_u8(data, pos, len))
				return false;
			if (pos + len > data.size())
				return false;
			c.routes.emplace_back(data.substr(pos, len));
			pos += len;
		}

		// 可选字段: obfuscate, 老版本对端握手包无此字节时保持默认关闭.
		c.obfuscate = false;
		if (pos < data.size())
		{
			if (!get_u8(data, pos, v8))
				return false;
			c.obfuscate = v8 != 0;
		}

		return pos == data.size();
	}

	session_config make_session_config(const service_config& config,
		uint32_t vaddr, uint8_t prefix_length)
	{
		session_config cfg;

		// 解析 IPv6 内网子网, 默认 fd00:8888::/64.
		boost::system::error_code ec;
		auto slash = config.v6_subnet_.find('/');
		auto v6_net_str = slash == std::string::npos ?
			config.v6_subnet_ : config.v6_subnet_.substr(0, slash);
		auto v6 = net::ip::make_address_v6(v6_net_str, ec);
		if (!ec)
		{
			cfg.v6_net = v6;
			if (slash != std::string::npos)
			{
				try
				{
					cfg.v6_prefix = static_cast<uint8_t>(
						std::stoi(config.v6_subnet_.substr(slash + 1)));
				}
				catch (...)
				{
					cfg.v6_prefix = 64;
				}
			}
		}
		else
		{
			cfg.v6_net = net::ip::make_address_v6("fd00:8888::");
			cfg.v6_prefix = 64;
		}
		// 低 32 位作为虚拟地址主机位, 前缀必须 <= 96.
		if (cfg.v6_prefix > 96)
			cfg.v6_prefix = 96;

		cfg.compress = compress_type_from_string(config.compress_);
		cfg.data_shards = static_cast<uint8_t>(
			std::max(1, config.data_shards_));
		cfg.parity_shards = static_cast<uint8_t>(
			std::max(0, config.parity_shards_));
		cfg.keepalive = static_cast<uint16_t>(
			std::max(1, config.keepalive_));
		cfg.mtu = static_cast<uint16_t>(
			std::clamp(config.mtu_size_ > 0 ? config.mtu_size_ : 1450,
				576, static_cast<int>(avpn_max_mtu)));
		cfg.vaddr = vaddr;
		cfg.prefix_length = prefix_length;
		cfg.passbyvpn = config.passbyvpn_;
		cfg.pushdns = config.pushdns_;
		cfg.routes = config.pushroutes_;
		cfg.obfuscate = !config.obfuscate_key_.empty();

		return cfg;
	}

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

	bool parse_endpoint(std::string_view addr, net::ip::udp::endpoint& ep)
	{
		boost::system::error_code ec;
		auto pos = addr.rfind(':');
		if (pos == std::string_view::npos)
			return false;

		auto host = addr.substr(0, pos);
		auto port_str = addr.substr(pos + 1);

		int port = 0;
		try
		{
			port = std::stoi(std::string(port_str));
		}
		catch (...)
		{
			return false;
		}
		if (port < 0 || port > 65535)
			return false;

		auto ip = net::ip::make_address(std::string(host), ec);
		if (ec)
			return false;

		ep = net::ip::udp::endpoint(ip, static_cast<uint16_t>(port));
		return true;
	}

	bool parse_endpoint(std::string_view addr, net::ip::tcp::endpoint& ep)
	{
		boost::system::error_code ec;
		auto pos = addr.rfind(':');
		if (pos == std::string_view::npos)
			return false;

		auto host = addr.substr(0, pos);
		auto port_str = addr.substr(pos + 1);

		int port = 0;
		try
		{
			port = std::stoi(std::string(port_str));
		}
		catch (...)
		{
			return false;
		}
		if (port < 0 || port > 65535)
			return false;

		auto ip = net::ip::make_address(std::string(host), ec);
		if (ec)
			return false;

		ep = net::ip::tcp::endpoint(ip, static_cast<uint16_t>(port));
		return true;
	}

	std::string endpoint_to_string(const net::ip::udp::endpoint& ep)
	{
		return ep.address().to_string() + ":" + std::to_string(ep.port());
	}

	std::string endpoint_to_string(const net::ip::tcp::endpoint& ep)
	{
		return ep.address().to_string() + ":" + std::to_string(ep.port());
	}

} // namespace libavpn
