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
#include "avpn/vpn_packet.hpp"
#include "avpn/fec_cache.hpp"
#include "avpn/reedsolomon.hpp"


BOOST_AUTO_TEST_CASE(fec_cache2_test1)
{
	avpn::vpn_packet pkt1;
	pkt1.size_ = 100;

	avpn::vpn_packet pkt2 = std::move(pkt1);

	BOOST_TEST(pkt1.size_ == 0);
	BOOST_TEST(pkt2.size_ == 100);

	for (int i = 0; i < 100; i++)
	{
		avpn::vpn_packet p;
		p.size_ = 100;
	}

	avpn::vpn_packet pkt3;
	avpn::vpn_packet pkt4;
}

BOOST_AUTO_TEST_CASE(fec_cache2_test2)
{
	avpn::fec_decode_group gop(8, 4);
	avpn::vpn_packet pkt;

	avpn::vpn_packet_ptr ptr =
		std::make_shared<avpn::vpn_packet>(std::move(pkt));

	gop.update(1, 0, ptr);

	BOOST_TEST(ptr->size() == avpn::avpn_packet_size);
	BOOST_TEST(gop.total_ == avpn::avpn_packet_size);
}
