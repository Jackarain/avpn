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

#include "utils/misc.hpp"
#include "utils/crypto.hpp"
#include "avpn/protocol.hpp"

BOOST_AUTO_TEST_CASE(test_auth_request)
{
	const std::string privateKey = "ICBmoiZBqo7pyHZVK+vM2I3LF9PePa18DVjkcbLl/XM=";
	crypto_util::keyexchange ke(privateKey);

	const std::string const_id = gen_unique_string(32);
	const std::string const_pubkey = std::string(ke.StaticPublicKey());

	std::string id = const_id;
	std::string pubkey = const_pubkey;
	uint32_t src = 167772225;
	auto pkt = avpn::make_handshake(src, id, pubkey);

	src = 0;
	id.resize(0);
	pubkey.resize(0);
	std::string additional;
	auto bytes = avpn::unwrap_handshake(pkt, src, id, pubkey, additional);

	BOOST_TEST(src == (uint32_t)167772225);
	BOOST_TEST(id == const_id);
	BOOST_TEST(pubkey == const_pubkey);

	int len = (int)pubkey.size() + 2 + (int)id.size() + 2;
	len += (1 + 4);
	len += 2 + (int)additional.size();
	BOOST_TEST(len == bytes);
}
