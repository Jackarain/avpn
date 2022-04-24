#define BOOST_TEST_MAIN

#ifdef USE_MIMALLOC

#ifdef MI_OVERRIDE
#	include <mimalloc.h>
#else
#	include <mimalloc-new-delete.h>
#endif

#ifdef _WIN32
#	include <mimalloc-new-delete.h>
#endif

#endif // USE_MIMALLOC

#include <boost/test/included/unit_test.hpp>
#include <boost/algorithm/string/regex.hpp>
#include <boost/algorithm/string.hpp>

#include <cstdlib>
#include <ctime>
#include <vector>
#include <string>
#include <string_view>

#include "utils/acl.hpp"
#include "CN-ip-cidr.txt.hpp"
#include "chnroute.txt.hpp"

std::vector<boost::asio::ip::network_v4> load_cn_ip()
{
	std::vector<boost::asio::ip::network_v4> result;
	std::vector<std::string_view> lines;

	std::string_view sv((char*)&chnroute_txt[0], chnroute_txt_len);
	boost::split(lines, sv, boost::is_any_of("\n"));

	for (auto& s : lines)
	{
		if (!s.empty())
			result.emplace_back(boost::asio::ip::make_network_v4(s));
	}

	return result;
}

BOOST_AUTO_TEST_CASE(acl_test)
{
		acl_util::lpm_table table;
		acl_util::lpm_tag tag((void*)0xa);

		{
			auto nets = load_cn_ip();
			for (auto& net : nets)
				table.insert(net, tag);
		}

		auto addr = boost::asio::ip::address_v4::from_string("36.129.0.0");
		auto target = table.lookup(addr);
		BOOST_TEST(target == tag);

		addr = boost::asio::ip::address_v4::from_string("10.0.0.2");
		target = table.lookup(addr);
		BOOST_TEST(target == (void*)0);

		auto v6addr = boost::asio::ip::address_v6::from_string("abcd::");
		boost::asio::ip::network_v6 v6net(v6addr, 16);

		tag = (acl_util::lpm_tag)0xb;
		table.insert(v6net, tag);

		v6addr = boost::asio::ip::address_v6::from_string("abcd:0000::abcd");
		target = table.lookup(v6addr);
		BOOST_TEST(target == (void*)0xb);
}
