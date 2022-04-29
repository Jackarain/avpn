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
#include "avpn/fec_cache.hpp"
#include "avpn/reedsolomon.hpp"

#if 0
BOOST_AUTO_TEST_CASE(reedsolomon_test)
{
	int data_shards = 8;
	int parity_shards = 2;
	int total_shards = data_shards + parity_shards;

	fec::reedsolomon rs_enc(data_shards, parity_shards);

	std::string content = gen_unique_string(1450);
	BOOST_TEST(content.size() == (size_t)1450);

	auto pershard_size = rs_enc.estimate_pershard_size((int)content.size());

	content.resize(pershard_size * total_shards);

	std::vector<std::string_view> shards;
	shards.resize(total_shards);
	for (size_t i = 0; i < (size_t)total_shards; i++)
		shards[i] = { (char*)content.data() + (i * pershard_size), pershard_size };

	rs_enc.encode(shards);

	std::srand((unsigned int)std::time(0));
	for (int b = 0; b < 2; b++)
	{
		int broke = std::rand() % total_shards;
		BOOST_TEST_MESSAGE("broke: " << broke);
		shards[broke] = {};
	}

	std::vector<fec::vpn_packet> data;
	for (int b = 0; b < total_shards; b++)
	{
		auto s = shards[b];
		fec::vpn_packet pkt;

		if (!s.empty())
			std::memcpy(pkt.data(), s.data(), s.size());
		else
			BOOST_TEST_MESSAGE("got broke: " << b);

		data.push_back(item);
	}

	fec::reedsolomon rs_dec(data_shards, parity_shards);
	rs_dec.decode(data);

	std::string output;
	for (auto& d : data)
		output.append((const char*)d.data(), d.size());
	output.resize(1450);
	content.resize(1450);

	BOOST_TEST_MESSAGE(content);
	BOOST_TEST_MESSAGE(output);

	BOOST_TEST(output == content);
}
#else
BOOST_AUTO_TEST_CASE(reedsolomon_test)
{}
#endif
