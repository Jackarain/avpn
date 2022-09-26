//
// endpoint_pair.hpp
// ~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2019 Jack (jack dot wgm at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#pragma once

#include "utils/logging.hpp"

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/container_hash/hash.hpp>

#include <iostream>

#if defined(__cpp_lib_format)
#	include <format>
#endif

#if !defined(__cpp_lib_format)
#ifdef _MSC_VER
#	pragma warning(push)
#	pragma warning(disable: 4244 4127)
#endif // _MSC_VER

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wexpansion-to-defined"
#endif

#include <fmt/ostream.h>
#include <fmt/printf.h>
#include <fmt/format.h>

namespace std {
	using ::fmt::format;
	using ::fmt::format_to;
}

#ifdef __clang__
#pragma clang diagnostic pop
#endif

#ifdef _MSC_VER
#	pragma warning(pop)
#endif
#endif

namespace avpn {

	// see this:
	// https://www.iana.org/assignments/protocol-numbers/protocol-numbers.txt
	enum ip_type
	{
		ip_tcp = 0x06,
		ip_udp = 0x11,
		ip_icmp = 0x01,
	};

	// 定义一个源地址和目标地址的结构.
	struct endpoint_pair
	{
		net::ip::tcp::endpoint src_;
		net::ip::tcp::endpoint dst_;

		int type_{ -1 };
		int size_{ -1 };
		uint16_t id_{ 0 };

		endpoint_pair()
		{}

		// ipv4地址传入构造endpoint pair.
		endpoint_pair(uint32_t src_ip, uint16_t src_port,
			uint32_t dst_ip, uint16_t dst_port)
		{
			src_.address(net::ip::address_v4(ntohl(src_ip)));
			src_.port(ntohs(src_port));
			dst_.address(net::ip::address_v4(ntohl(dst_ip)));
			dst_.port(ntohs(dst_port));
		}

		// ipv4地址传入构造endpoint pair.
		endpoint_pair(net::ip::address_v6 src_ip, uint16_t src_port,
			net::ip::address_v6 dst_ip, uint16_t dst_port)
		{
			src_.address(src_ip);
			src_.port(ntohs(src_port));
			dst_.address(dst_ip);
			dst_.port(ntohs(dst_port));
		}

		endpoint_pair(endpoint_pair&& endp)
			: src_(std::move(endp.src_))
			, dst_(std::move(endp.dst_))
			, type_(endp.type_)
			, size_(endp.size_)
			, id_(endp.id_)
		{
			endp.type_ = -1;
			endp.size_ = -1;
			endp.id_ = 0;
		}

		endpoint_pair& operator=(endpoint_pair&& endp)
		{
			src_ = std::move(endp.src_);
			dst_ = std::move(endp.dst_);

			type_ = endp.type_;
			size_ = endp.size_;
			id_ = endp.id_;

			endp.type_ = -1;
			endp.size_ = -1;
			endp.id_ = 0;

			return *this;
		}

		endpoint_pair(const endpoint_pair& endp)
			: src_(endp.src_)
			, dst_(endp.dst_)
			, type_(endp.type_)
			, size_(endp.size_)
			, id_(endp.id_)
		{
		}

		bool empty() const
		{
			return type_ < 0;
		}

		endpoint_pair& reserve()
		{
			auto tmp = src_;
			src_ = dst_;
			dst_ = tmp;
			return *this;
		}

		std::string to_string() const
		{
			return std::format("{}:{} - {}:{}",
				src_.address().to_string(), src_.port(),
				dst_.address().to_string(), dst_.port());
		}
	};

	inline bool operator==(const endpoint_pair& lh, const endpoint_pair& rh)
	{
		if (lh.src_ == rh.src_ && lh.dst_ == rh.dst_)
			return true;
		return false;
	}

	inline bool operator!=(const endpoint_pair& lh, const endpoint_pair& rh)
	{
		if (lh.src_ != rh.src_ || lh.dst_ != rh.dst_)
			return true;
		return false;
	}

	inline bool operator<(const endpoint_pair& lh, const endpoint_pair& rh)
	{
		if (lh.src_ < rh.src_)
			return true;

		if (lh.src_ != rh.src_)
			return false;

		if (lh.dst_ < rh.dst_)
			return true;

		return false;
	}

	inline bool operator>(const endpoint_pair& lh, const endpoint_pair& rh)
	{
		if (rh < lh)
			return true;
		if (lh == rh)
			return false;
		return true;
	}

	inline endpoint_pair parser_endpoint(const uint8_t* buf, std::size_t len)
	{
		if (buf[0] != 0x45)
			return {};

		static std::tuple<uint32_t, uint32_t> fd_test;

		uint8_t version = (buf[0] & 0xf0) >> 4;
		if (version == 4)
		{
			int ihl = ((*(const uint8_t*)(buf)) & 0x0f) * 4;
			if (len < (size_t)ihl + 4)
				return {};

			uint16_t total = ntohs(*(uint16_t*)(buf + 2));
			uint16_t id = ntohs(*(uint16_t*)(buf + 4));
			uint8_t type = *(uint8_t*)(buf + 9);
			uint32_t src_ip = (*(uint32_t*)(buf + 12));
			uint32_t dst_ip = (*(uint32_t*)(buf + 16));

			if (type == ip_tcp)		// only tcp
			{
				auto p = buf + ihl;

				uint16_t src_port = (*(uint16_t*)(p + 0));
				uint16_t dst_port = (*(uint16_t*)(p + 2));

				endpoint_pair endp(src_ip, src_port, dst_ip, dst_port);
				endp.type_ = type;
				endp.size_ = total;
				endp.id_ = id;

				return endp;
			}
			else if (type == ip_udp)
			{
				auto p = buf + 4;

				p = buf + ihl;

				uint16_t src_port;
				uint16_t dst_port;

				auto [last_id, port] = fd_test;
				if (last_id != id)
				{
					src_port = (*(uint16_t*)(p + 0));
					dst_port = (*(uint16_t*)(p + 2));

					fd_test = std::make_tuple(id, (*(uint32_t*)(p + 0)));
				}
				else
				{
					src_port = (*(uint16_t*)(((uint8_t*)&port) + 0));
					dst_port = (*(uint16_t*)(((uint8_t*)&port) + 2));
				}

				// auto udp_len = *(uint16_t*)(p + 4);
				// auto chksum = *(uint16_t*)(p + 6);	// skip chksum.

				endpoint_pair endp(src_ip, src_port, dst_ip, dst_port);
				endp.type_ = type;
				endp.size_ = total;
				endp.id_ = id;

				return endp;
			}
			else if (type == ip_icmp)
			{
				endpoint_pair endp(src_ip, 0, dst_ip, 0);
				endp.type_ = type;
				endp.size_ = total;
				endp.id_ = id;

				return endp;
			}
		}
		return {};
	}
}

namespace std
{
	template<> struct hash<net::ip::tcp::endpoint>
	{
		typedef net::ip::tcp::endpoint argument_type;
		typedef std::size_t result_type;
		inline result_type operator()(argument_type const& s) const
		{
			std::string temp = s.address().to_string();
			std::size_t seed = 0;
			boost::hash_combine(seed, temp);
			boost::hash_combine(seed, s.port());
			return seed;
		}
	};

	template<> struct hash<avpn::endpoint_pair>
	{
		typedef avpn::endpoint_pair argument_type;
		typedef std::size_t result_type;
		inline result_type operator()(argument_type const& s) const
		{
			result_type const h1(std::hash<net::ip::tcp::endpoint>{}(s.src_));
			result_type const h2(std::hash<net::ip::tcp::endpoint>{}(s.dst_));
			std::size_t seed = 0;
			boost::hash_combine(seed, h1);
			boost::hash_combine(seed, h2);
			return seed;
		}
	};
}

namespace util {

	inline logger___&
	operator<<(logger___& log, const avpn::endpoint_pair& endp)
	{
		log << endp.to_string();
		return log;
	}

	inline logger___&
	operator<<(logger___&& log, const avpn::endpoint_pair& endp)
	{
		log << endp.to_string();
		return log;
	}
}