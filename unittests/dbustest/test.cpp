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
#include <boost/asio.hpp>

bool SetLinkDNSv4(int if_index, std::vector<boost::asio::ip::address_v4> dns_addrs);

BOOST_AUTO_TEST_CASE(dbus_test)
{
	bool ok = SetLinkDNSv4(5, { boost::asio::ip::address_v4::from_string("192.168.18.1")});
	std::string test = ok ? "dns set ok" : "dns set failed";
	BOOST_TEST_MESSAGE(test);
}
