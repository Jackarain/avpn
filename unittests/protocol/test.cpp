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

BOOST_AUTO_TEST_CASE(test_handshake)
{
	const std::string privateKey = "ICBmoiZBqo7pyHZVK+vM2I3LF9PePa18DVjkcbLl/XM=";
	crypto_util::keyexchange ke(privateKey);

	const std::string const_id = gen_unique_string(32);
	const std::string const_pubkey = std::string(ke.StaticPublicKey());

	std::string id = const_id;
	std::string pubkey = const_pubkey;
	uint32_t src = 167772225;
	auto pkt = avpn::make_handshake(src, id, pubkey, 8, 4);

	src = 0;
	id.resize(0);
	pubkey.resize(0);
	uint8_t ds, ps;
	auto bytes = avpn::unwrap_handshake(pkt, src, id, pubkey, ds, ps);

	BOOST_TEST(src == (uint32_t)167772225);
	BOOST_TEST(id == const_id);
	BOOST_TEST(pubkey == const_pubkey);
	BOOST_TEST(ds == 8);
	BOOST_TEST(ps == 4);

	int len = (int)pubkey.size() + 1 + (int)id.size() + 1;
	len += (1 + 4);
	len += 2;
	BOOST_TEST(len == bytes);
}

BOOST_AUTO_TEST_CASE(test_transfer)
{
	uint32_t src = 167772225;
	uint32_t gid = 12;
	uint8_t pid = 23;
	std::string data = "hello";

	auto pkt = avpn::make_transfer(src, gid, pid, data);

	src = 0;
	gid = 0;
	pid = 0;

	auto bytes = avpn::unwrap_transfer(pkt, src, gid, pid);
	(void)bytes;

	BOOST_TEST(bytes == 18);
	BOOST_TEST(src == (uint32_t)167772225);
	BOOST_TEST(gid == (uint32_t)12);
	BOOST_TEST(pid == (uint8_t)23);

	std::string_view sv((char*)pkt.content(), pkt.content_size());
	BOOST_TEST(sv == data);
}
