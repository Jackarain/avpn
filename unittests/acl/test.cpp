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
#include <cstdlib>
#include <ctime>

#include "utils/acl.hpp"

BOOST_AUTO_TEST_CASE(acl_test)
{
		auto addr = boost::asio::ip::address_v4::from_string("36.128.0.0");
		boost::asio::ip::network_v4 net(addr, 10);
		acl_util::lpm_table table;
		acl_util::lpm_tag tag((void*)0xa);

		table.insert(net, tag);

		addr = boost::asio::ip::address_v4::from_string("36.129.0.0");
		auto target = table.lookup(addr);
		BOOST_TEST(target == (void*)0xa);

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
