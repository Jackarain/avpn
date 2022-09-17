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
#include "avpn/vpn_queue.hpp"

BOOST_AUTO_TEST_CASE(fec_queue_test)
{
	using util::logger_aux__::gettime;
	const int count = 10000000;

	for (int i = 0; i < 400000; i++)
	{
		ASYNC_LOGFILE << "test start...";
	}

#if 1
	{
	avpn::vpn_queue<avpn::vpn_packet> qe;

	std::thread pth1 = std::thread([&]() mutable {
		LOG_DBG << "p thread start";
		auto t1 = gettime();
		for (int i = 0; i < count; i++)
		{
			avpn::vpn_packet pkt;
			qe.submit(std::move(pkt));
		}
		auto t2 = gettime();
		printf("p thread: %lld\n", t2 - t1);
		LOG_DBG << "p thread: " << t2 - t1;
		});
	std::thread cth2 = std::thread([&]() mutable {
		auto t1 = gettime();
		for (int i = 0; i < count; i++)
		{
			auto ret = qe.acquire();
			if (!ret)
				break;
		}
		auto t2 = gettime();
		printf("c thread: %lld\n", t2 - t1);
		});

	pth1.join();
	cth2.join();

	}

// #else

	{

	std::deque<avpn::vpn_packet> queue;
	net::io_context ioc(BOOST_ASIO_CONCURRENCY_HINT_UNSAFE_IO);
	net::io_context::work* w = new net::io_context::work(ioc);
	int n = 0;

	std::thread pth1 = std::thread([&]() mutable {
		auto t1 = gettime();
		for (int i = 0; i < count; i++)
		{
			avpn::vpn_packet pkt;
			net::post(ioc, [pkt = std::move(pkt), &n]() mutable {
				n++;
			});
		}
		auto t2 = gettime();
		delete w;
		printf("p thread: %lld, count: %d\n", t2 - t1, n);
		});

	std::thread cth1 = std::thread([&]() mutable {
		auto t1 = gettime();
		ioc.run();
		auto t2 = gettime();
		printf("c thread: %lld, count: %d\n", t2 - t1, n);
		});

	pth1.join();
	cth1.join();

	printf("main thread count: %d\n", n);

	}
#endif

	LOG_DBG << "test completed...";
}

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
