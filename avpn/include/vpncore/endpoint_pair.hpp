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
#include <iostream>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>

#include <fmt/ostream.h>
#include <fmt/printf.h>
#include <fmt/format.h>

#include "utils/logging.hpp"

namespace avpn {

	// see https://www.iana.org/assignments/protocol-numbers/protocol-numbers.txt
	enum ip_type
	{
		ip_tcp = 0x06,
		ip_udp = 0x11,
		ip_icmp = 0x01,
	};

	// 定义一个源地址和目标地址的结构.
	struct endpoint_pair
	{
		boost::asio::ip::tcp::endpoint src_;
		boost::asio::ip::tcp::endpoint dst_;

		int type_;

		endpoint_pair()
			: type_(-1)
		{}

		// ipv4地址传入构造endpoint pair.
		endpoint_pair(uint32_t src_ip, uint16_t src_port,
			uint32_t dst_ip, uint16_t dst_port)
			: type_(-1)
		{
			src_.address(boost::asio::ip::address_v4(ntohl(src_ip)));
			src_.port(ntohs(src_port));
			dst_.address(boost::asio::ip::address_v4(ntohl(dst_ip)));
			dst_.port(ntohs(dst_port));
		}

		// ipv4地址传入构造endpoint pair.
		endpoint_pair(boost::asio::ip::address_v6 src_ip, uint16_t src_port,
			boost::asio::ip::address_v6 dst_ip, uint16_t dst_port)
			: type_(-1)
		{
			src_.address(src_ip);
			src_.port(ntohs(src_port));
			dst_.address(dst_ip);
			dst_.port(ntohs(dst_port));
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
			return fmt::format("{}:{} - {}:{}",
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

	inline endpoint_pair lookup_endpoint_pair(const uint8_t* buf, std::size_t len)
	{
		uint8_t version = (buf[0] & 0xf0) >> 4;

		static std::tuple<uint32_t, uint32_t> fd_test;

		if (version == 4) {

			int ihl = ((*(const uint8_t*)(buf)) & 0x0f) * 4;
			if (len < (size_t)ihl + 4)
				return {};

			[[maybe_unused]] uint16_t total = ntohs(*(uint16_t*)(buf + 2));
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

				return endp;
			}
			else if (type == ip_udp)
			{
				auto p = buf + 4;
				uint16_t id = (*(uint16_t*)(p + 0));

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

				return endp;
			}
			else if (type == ip_icmp)
			{
				endpoint_pair endp(src_ip, 0, dst_ip, 0);
				endp.type_ = type;

				return endp;
			}
		}
		return {};
	}
}

namespace std
{
	template<> struct hash<boost::asio::ip::tcp::endpoint>
	{
		typedef boost::asio::ip::tcp::endpoint argument_type;
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
			result_type const h1(std::hash<boost::asio::ip::tcp::endpoint>{}(s.src_));
			result_type const h2(std::hash<boost::asio::ip::tcp::endpoint>{}(s.dst_));
			std::size_t seed = 0;
			boost::hash_combine(seed, h1);
			boost::hash_combine(seed, h2);
			return seed;
		}
	};
}

namespace util {

	inline logger& operator<<(logger& log, const boost::asio::ip::udp::endpoint& endp)
	{
		log << endp.address().to_string() << ":" << endp.port();
		return log;
	}

	inline logger& operator<<(logger&& log, const boost::asio::ip::udp::endpoint& endp)
	{
		log << endp.address().to_string() << ":" << endp.port();
		return log;
	}


	inline logger& operator<<(logger& log, const boost::asio::ip::tcp::endpoint& endp)
	{
		log << endp.address().to_string() << ":" << endp.port();
		return log;
	}

	inline logger& operator<<(logger& log, const avpn::endpoint_pair& endp)
	{
		log << endp.to_string();
		return log;
	}

	inline logger& operator<<(logger&& log, const boost::asio::ip::tcp::endpoint& endp)
	{
		log << endp.address().to_string() << ":" << endp.port();
		return log;
	}

	inline logger& operator<<(logger&& log, const avpn::endpoint_pair& endp)
	{
		log << endp.to_string();
		return log;
	}
}