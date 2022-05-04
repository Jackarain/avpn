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

#include "avpn/protocol.hpp"


BOOST_AUTO_TEST_CASE(test_make_auth_request)
{
	std::string id = "lljj";
	std::string pubkey = "ljljjjdsldf";
	auto pkt = avpn::make_auth_request(167772225, id, pubkey);
}
