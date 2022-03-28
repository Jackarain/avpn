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

BOOST_AUTO_TEST_CASE(fec_cache_test)
{
	fec::fec_cache fc;

	int data_shards = 8;
	int parity_shards = 2;
	int total_shards = data_shards + parity_shards;

	// 构造编8/2码器.
	fec::reedsolomon rs_enc(data_shards, parity_shards);

	// 生成1450字节的测试内容.
	std::string content = gen_unique_string(1450);
	BOOST_TEST(content.size() == (size_t)1450);
	std::string origin_content = content;

	// 估算每个分片大小.
	auto pershard_size = rs_enc.estimate_pershard_size((int)content.size());
	content.resize(pershard_size * total_shards);

	// rs编码.
	std::vector<std::string_view> shards;
	shards.resize(total_shards);

	for (size_t i = 0; i < (size_t)total_shards; i++)
		shards[i] = { (char*)content.data() + (i * pershard_size), pershard_size };
	rs_enc.encode(shards);

	std::srand((unsigned int)std::time(0));

	int drop_cnt_total = 0;
	int broker_pkt = 0;
	int broker_gop_size = 0;
	int got_pkt_total = 0;
	int got_gop_total = 0;
	int clean_garbage_total = 0;

	const int max_test_number = 1000000;

	// 生成10000个group模拟接收情况测试.
	for (int gid = 0; gid < max_test_number; gid++)
	{
		// 每一组随机丢1到3个数据包.
		int drop = std::rand() % 3 + 1;
		int drop_cnt = 0;

		for (int pid = 0; pid < total_shards; pid++)
		{
			auto s = shards[pid];

			// 随机模拟丢数据.
			if (std::rand() % 3 == 0 && drop > 0)
			{
				drop_cnt_total++;
				drop--;
				drop_cnt++;
				continue;
			}

			// 模拟接收到数据.
			fc.update(gid, pid, data_shards, parity_shards, 1450, (uint8_t*)s.data(), s.size());

			// 先清理一下垃圾.
			clean_garbage_total += fc.garbage_clean();

			// 模拟处理数据, 从fc缓冲区处拿出待解码的数据.
			auto gop = fc.acquire();
			if (!gop.empty())
				got_gop_total++;

			// 解码已经可以解码的数据.
			for (auto& p : gop)
			{
				fec::reedsolomon fec_dec(p.ds_, p.ps_);

				// fec解码.
				fec_dec.decode(p.pkts_);

				std::string output;
				for (auto& d : p.pkts_)
					output.append((const char*)d.data(), d.size());
				output.resize(1450);

				BOOST_TEST(output == origin_content);
				got_pkt_total++;
			}
		}

		// 统计破坏且不可恢复的数据包数量.
		if (drop_cnt > 2)
		{
			broker_gop_size += drop_cnt;
			broker_pkt++;
		}
	}

	auto remainder = (broker_pkt * pershard_size * 10 - broker_gop_size * pershard_size) - clean_garbage_total;

	BOOST_TEST(got_gop_total + broker_pkt == max_test_number);
	BOOST_TEST_MESSAGE("got_gop_total: " << got_gop_total);
	BOOST_TEST_MESSAGE("broker_pkt: " << broker_pkt);
	BOOST_TEST_MESSAGE("total_cache_size: " << fc.total_cache_size_);
	BOOST_TEST_MESSAGE("clean_garbage_total: " << clean_garbage_total);

	BOOST_TEST(remainder == fc.total_cache_size_);
}
