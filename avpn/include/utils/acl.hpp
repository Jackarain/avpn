//
// acl.hpp
// ~~~~~~~
//
// Copyright (c) 2019 Jack (jack dot wgm at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include <memory>
#include <type_traits>

#include <boost/asio/ip/address.hpp>

#include <boost/asio/ip/network_v4.hpp>
#include <boost/asio/ip/network_v6.hpp>

namespace acl_util {

	namespace net = boost::asio;

	struct lpm;
	using lpm_tag = void*;

	class lpm_table
	{
		// c++11 noncopyable.
		lpm_table(const lpm_table&) = delete;
		lpm_table& operator=(const lpm_table&) = delete;

	public:
		lpm_table();
		~lpm_table();

	public:

		template<typename AddrType>
		bool insert(const AddrType& addr, lpm_tag target)
		{
			constexpr bool _always_false = true;

			using at = std::decay_t<AddrType>;
			if constexpr (std::is_same_v<at, net::ip::network_v4>)
				return v4_insert(addr, target);
			else if constexpr (std::is_same_v<at, net::ip::network_v6>)
				return v6_insert(addr, target);
			else
				static_assert(_always_false, "address type invalid");
		}

		lpm_tag lookup(const net::ip::address& addr);

	private:
		bool v4_insert(const net::ip::network_v4& addr, lpm_tag target);
		bool v6_insert(const net::ip::network_v6& addr, lpm_tag target);

	private:
		std::unique_ptr<lpm> m_lpm;
	};
}
