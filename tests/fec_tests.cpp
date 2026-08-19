#define BOOST_TEST_MODULE avpn_fec_tests
#include <boost/test/unit_test.hpp>

// 直接包含 FEC 实现, 以访问内部 gf/fec_cache 及全部 FEC 组件.
#include "../libavpn/src/avpn_fec.cpp"

#include <cstring>
#include <random>
#include <thread>

using namespace libavpn;

namespace {

	// 独立 GF(2^8) 参考乘法 (按位运算, 模 0x11d), 用于校验查表实现.
	inline uint8_t gf_mul_ref(uint8_t a, uint8_t b)
	{
		uint8_t r = 0;
		for (int i = 0; i < 8; i++)
		{
			if (b & 1)
				r ^= a;
			uint8_t hi = a & 0x80;
			a = static_cast<uint8_t>(a << 1);
			if (hi)
				a ^= 0x1d;
			b >>= 1;
		}
		return r;
	}

	std::vector<uint8_t> random_bytes(std::size_t n, std::mt19937& rng)
	{
		std::vector<uint8_t> v(n);
		for (auto& b : v)
			b = static_cast<uint8_t>(rng() & 0xff);
		return v;
	}

	std::vector<int> missing_indices(int mask, int total)
	{
		std::vector<int> missing;
		for (int i = 0; i < total; i++)
		{
			if (mask & (1 << i))
				missing.push_back(i);
		}
		return missing;
	}

	// 参考 parity: 独立构造系统化编码矩阵
	// (冗余行 = Vandermonde 行右乘 V0^{-1}) 后计算.
	std::vector<std::vector<uint8_t>> ref_parity(
		const std::vector<std::vector<uint8_t>>& data, int P)
	{
		const int D = static_cast<int>(data.size());
		const std::size_t sz = data[0].size();

		// 构造 N x D Vandermonde 矩阵.
		std::vector<std::vector<uint8_t>> vm(D + P,
			std::vector<uint8_t>(D, 0));
		for (int r = 0; r < D + P; r++)
		{
			vm[r][0] = 1;
			for (int c = 1; c < D; c++)
				vm[r][c] = gf_mul_ref(vm[r][c - 1],
					static_cast<uint8_t>(r));
		}

		// V0 为前 D 行, 求逆.
		std::vector<std::vector<uint8_t>> v0(vm.begin(), vm.begin() + D);
		std::vector<std::vector<uint8_t>> inv0;
		if (!gf::invert(v0, inv0))
			return {};

		std::vector<std::vector<uint8_t>> par(P, std::vector<uint8_t>(sz, 0));
		for (int p = 0; p < P; p++)
		{
			const int row = D + p;
			// 变换后的冗余行系数: vm[row] * inv0.
			std::vector<uint8_t> coef(D, 0);
			for (int c = 0; c < D; c++)
			{
				for (int k = 0; k < D; k++)
					coef[c] ^= gf_mul_ref(vm[row][k], inv0[k][c]);
			}
			for (std::size_t c = 0; c < sz; c++)
			{
				uint8_t sum = 0;
				for (int d = 0; d < D; d++)
					sum ^= gf_mul_ref(coef[d], data[d][c]);
				par[p][c] = sum;
			}
		}
		return par;
	}

} // namespace

//////////////////////////////////////////////////////////////////////////
// GF(2^8) 域运算性质

BOOST_AUTO_TEST_SUITE(gf_arithmetic)

BOOST_AUTO_TEST_CASE(mul_commutative)
{
	std::mt19937 rng(1);
	for (int i = 0; i < 1000; i++)
	{
		uint8_t a = static_cast<uint8_t>(rng() & 0xff);
		uint8_t b = static_cast<uint8_t>(rng() & 0xff);
		BOOST_CHECK_EQUAL(gf::mul(a, b), gf::mul(b, a));
	}
}

BOOST_AUTO_TEST_CASE(mul_associative)
{
	std::mt19937 rng(2);
	for (int i = 0; i < 1000; i++)
	{
		uint8_t a = static_cast<uint8_t>(rng() & 0xff);
		uint8_t b = static_cast<uint8_t>(rng() & 0xff);
		uint8_t c = static_cast<uint8_t>(rng() & 0xff);
		BOOST_CHECK_EQUAL(gf::mul(gf::mul(a, b), c),
			gf::mul(a, gf::mul(b, c)));
	}
}

BOOST_AUTO_TEST_CASE(mul_distributive)
{
	std::mt19937 rng(3);
	for (int i = 0; i < 1000; i++)
	{
		uint8_t a = static_cast<uint8_t>(rng() & 0xff);
		uint8_t b = static_cast<uint8_t>(rng() & 0xff);
		uint8_t c = static_cast<uint8_t>(rng() & 0xff);
		BOOST_CHECK_EQUAL(gf::mul(a, b ^ c),
			gf::mul(a, b) ^ gf::mul(a, c));
	}
}

BOOST_AUTO_TEST_CASE(identity_and_zero)
{
	std::mt19937 rng(4);
	for (int i = 0; i < 256; i++)
	{
		uint8_t a = static_cast<uint8_t>(i);
		BOOST_CHECK_EQUAL(gf::mul(a, 1), a);
		BOOST_CHECK_EQUAL(gf::mul(1, a), a);
		BOOST_CHECK_EQUAL(gf::mul(a, 0), 0);
		BOOST_CHECK_EQUAL(gf::mul(0, a), 0);
	}
}

BOOST_AUTO_TEST_CASE(inverse_exists)
{
	// 每个非零元素都有乘法逆元.
	for (int a = 1; a < 256; a++)
	{
		uint8_t inv = gf::div(1, static_cast<uint8_t>(a));
		BOOST_CHECK_EQUAL(gf::mul(static_cast<uint8_t>(a), inv), 1);
		BOOST_CHECK_EQUAL(gf::div(static_cast<uint8_t>(a),
			static_cast<uint8_t>(a)), 1);
	}
}

BOOST_AUTO_TEST_CASE(div_properties)
{
	std::mt19937 rng(5);
	for (int i = 0; i < 1000; i++)
	{
		uint8_t a = static_cast<uint8_t>(rng() & 0xff);
		uint8_t b = static_cast<uint8_t>(rng() & 0xff);
		if (b == 0)
			continue;
		BOOST_CHECK_EQUAL(gf::mul(gf::div(a, b), b), a);
		BOOST_CHECK_EQUAL(gf::div(a, 1), a);
	}
	BOOST_CHECK_EQUAL(gf::div(0, 0x5a), 0);
	BOOST_CHECK_EQUAL(gf::div(0x5a, 0), 0);
}

BOOST_AUTO_TEST_CASE(pow_properties)
{
	std::mt19937 rng(6);
	for (int i = 0; i < 100; i++)
	{
		uint8_t a = static_cast<uint8_t>(rng() & 0xff);
		BOOST_CHECK_EQUAL(gf::pow(a, 0), 1);
		BOOST_CHECK_EQUAL(gf::pow(a, 1), a);
		BOOST_CHECK_EQUAL(gf::pow(a, 2), gf::mul(a, a));
		int n = 3 + static_cast<int>(rng() % 10);
		int m = 1 + static_cast<int>(rng() % 10);
		BOOST_CHECK_EQUAL(gf::pow(a, n + m),
			gf::mul(gf::pow(a, n), gf::pow(a, m)));
	}
	// 非零元素满足 a^255 == 1.
	for (int a = 1; a < 256; a++)
		BOOST_CHECK_EQUAL(gf::pow(static_cast<uint8_t>(a), 255), 1);
	BOOST_CHECK_EQUAL(gf::pow(0, 0), 1);
	BOOST_CHECK_EQUAL(gf::pow(0, 5), 0);
}

BOOST_AUTO_TEST_CASE(exp_log_consistency)
{
	for (int i = 1; i < 255; i++)
	{
		uint8_t a = gf::exp_table[i];
		BOOST_CHECK_EQUAL(gf::log_table[a], static_cast<uint8_t>(i));
	}
	for (int a = 1; a < 256; a++)
		BOOST_CHECK_EQUAL(
			gf::exp_table[gf::log_table[a]], static_cast<uint8_t>(a));
}

BOOST_AUTO_TEST_CASE(log_additivity)
{
	// 非零元素的 log 相加对应域乘法.
	for (int a = 1; a < 256; a++)
	{
		for (int b = 1; b < 256; b++)
		{
			uint8_t expect = gf::mul(static_cast<uint8_t>(a),
				static_cast<uint8_t>(b));
			uint8_t got = gf::exp_table[
				(gf::log_table[a] + gf::log_table[b]) % 255];
			BOOST_CHECK_EQUAL(got, expect);
		}
	}
}

BOOST_AUTO_TEST_CASE(generator_order)
{
	// 生成元 2 的阶为 255, 指数表两个周期一致.
	BOOST_CHECK_EQUAL(gf::exp_table[0], 1);
	BOOST_CHECK_EQUAL(gf::exp_table[255], 1);
	BOOST_CHECK_EQUAL(gf::exp_table[510], 1);
	for (int i = 0; i < 255; i++)
		BOOST_CHECK_EQUAL(gf::exp_table[i], gf::exp_table[i + 255]);
	// 0x11d 为模: 2^8 折叠为 0x1d.
	BOOST_CHECK_EQUAL(gf::exp_table[8], 0x1d);
}

BOOST_AUTO_TEST_SUITE_END()

//////////////////////////////////////////////////////////////////////////
// 表

BOOST_AUTO_TEST_SUITE(gf_tables)

BOOST_AUTO_TEST_CASE(mul_table_matches_reference)
{
	// 全表与独立按位乘法实现一致.
	for (int a = 0; a < 256; a++)
	{
		for (int b = 0; b < 256; b++)
		{
			BOOST_CHECK_EQUAL(gf::mul_table[a][b],
				gf_mul_ref(static_cast<uint8_t>(a), static_cast<uint8_t>(b)));
		}
	}
}

BOOST_AUTO_TEST_CASE(nibble_tables_consistent)
{
	for (int b = 0; b < 256; b++)
	{
		for (int n = 0; n < 16; n++)
		{
			BOOST_CHECK_EQUAL(gf::low_tables[b][n], gf::mul_table[b][n]);
			BOOST_CHECK_EQUAL(gf::high_tables[b][n],
				gf::mul_table[b][n << 4]);
		}
		// 低/高半字节组合还原完整乘法.
		for (int x = 0; x < 256; x++)
		{
			uint8_t got = gf::low_tables[b][x & 0x0f] ^
				gf::high_tables[b][x >> 4];
			BOOST_CHECK_EQUAL(got, gf::mul_table[b][x]);
		}
	}
}

BOOST_AUTO_TEST_CASE(mul_matches_exp_log)
{
	for (int a = 1; a < 256; a++)
	{
		for (int b = 1; b < 256; b++)
		{
			BOOST_CHECK_EQUAL(gf::mul_table[a][b],
				gf::exp_table[gf::log_table[a] + gf::log_table[b]]);
		}
	}
}

BOOST_AUTO_TEST_SUITE_END()

//////////////////////////////////////////////////////////////////////////
// SIMD 批量乘法与标量一致性

BOOST_AUTO_TEST_SUITE(gf_mul_slice)

static void check_slice(uint8_t c, std::size_t len)
{
	std::mt19937 rng(static_cast<unsigned>(c) * 131 + static_cast<unsigned>(len));
	std::vector<uint8_t> in = random_bytes(len, rng);
	std::vector<uint8_t> out(len), ref(len);

	// mul_slice: out = c * in.
	gf::mul_slice(c, in.data(), out.data(), len);
	const uint8_t* row = gf::mul_table[c].data();
	for (std::size_t i = 0; i < len; i++)
		ref[i] = row[in[i]];
	BOOST_CHECK_EQUAL_COLLECTIONS(out.begin(), out.end(),
		ref.begin(), ref.end());

	// mul_slice_xor: out ^= c * in.
	out = random_bytes(len, rng);
	ref = out;
	gf::mul_slice_xor(c, in.data(), out.data(), len);
	for (std::size_t i = 0; i < len; i++)
		ref[i] ^= row[in[i]];
	BOOST_CHECK_EQUAL_COLLECTIONS(out.begin(), out.end(),
		ref.begin(), ref.end());
}

BOOST_AUTO_TEST_CASE(all_coefficients)
{
	const std::size_t len = 1024;
	for (int c = 0; c < 256; c++)
		check_slice(static_cast<uint8_t>(c), len);
}

BOOST_AUTO_TEST_CASE(various_lengths)
{
	// 覆盖 16/32 字节对齐与各种尾部余数.
	const std::size_t lengths[] = {
		0, 1, 2, 3, 15, 16, 17, 31, 32, 33, 63, 64, 65,
		127, 128, 129, 255, 256, 257, 511, 512, 513,
		1023, 1024, 1025, 1450, 4096, 4097
	};
	for (std::size_t len : lengths)
		check_slice(0x5a, len);
}

BOOST_AUTO_TEST_CASE(special_coefficients)
{
	// c==0: 结果为 0 / XOR 不变.
	std::vector<uint8_t> in(100), out(100), ref(100);
	std::mt19937 rng(7);
	in = random_bytes(100, rng);
	gf::mul_slice(0, in.data(), out.data(), 100);
	for (auto& v : out)
		BOOST_CHECK_EQUAL(v, 0);
	ref = random_bytes(100, rng);
	out = ref;
	gf::mul_slice_xor(0, in.data(), out.data(), 100);
	BOOST_CHECK_EQUAL_COLLECTIONS(out.begin(), out.end(),
		ref.begin(), ref.end());

	// c==1: 复制 / XOR.
	gf::mul_slice(1, in.data(), out.data(), 100);
	BOOST_CHECK_EQUAL_COLLECTIONS(out.begin(), out.end(),
		in.begin(), in.end());
	ref = random_bytes(100, rng);
	out = ref;
	gf::mul_slice_xor(1, in.data(), out.data(), 100);
	for (std::size_t i = 0; i < 100; i++)
		BOOST_CHECK_EQUAL(out[i], ref[i] ^ in[i]);
}

BOOST_AUTO_TEST_SUITE_END()

//////////////////////////////////////////////////////////////////////////
// reedsolomon encode

BOOST_AUTO_TEST_SUITE(reedsolomon_encode)

BOOST_AUTO_TEST_CASE(parity_matches_reference)
{
	std::mt19937 rng(8);
	const std::vector<std::pair<int, int>> configs = {
		{1, 1}, {2, 1}, {2, 2}, {4, 2}, {5, 3}, {8, 4}, {16, 8}
	};
	const std::size_t lengths[] = { 1, 2, 16, 17, 100, 1024, 1450 };

	for (auto [D, P] : configs)
	{
		for (std::size_t len : lengths)
		{
			reedsolomon rs(D, P);
			std::vector<std::vector<uint8_t>> data(D);
			for (auto& s : data)
				s = random_bytes(len, rng);

			std::vector<std::vector<uint8_t>> parity;
			BOOST_REQUIRE(rs.encode(data, parity));
			BOOST_CHECK_EQUAL(parity.size(),
				static_cast<std::size_t>(P));
			if (P > 0)
				BOOST_CHECK_EQUAL(parity[0].size(), len);

			auto ref = ref_parity(data, P);
			for (int p = 0; p < P; p++)
				BOOST_CHECK_EQUAL_COLLECTIONS(
					parity[p].begin(), parity[p].end(),
					ref[p].begin(), ref[p].end());
		}
	}
}

BOOST_AUTO_TEST_CASE(encode_rejects_wrong_shard_count)
{
	reedsolomon rs(4, 2);
	std::vector<std::vector<uint8_t>> data(3,
		std::vector<uint8_t>(16, 0));
	std::vector<std::vector<uint8_t>> parity;
	BOOST_CHECK(!rs.encode(data, parity));
}

BOOST_AUTO_TEST_CASE(encode_rejects_mismatched_sizes)
{
	reedsolomon rs(4, 2);
	std::vector<std::vector<uint8_t>> data(4,
		std::vector<uint8_t>(16, 0));
	data[3].resize(17);
	std::vector<std::vector<uint8_t>> parity;
	BOOST_CHECK(!rs.encode(data, parity));
}

BOOST_AUTO_TEST_SUITE_END()

//////////////////////////////////////////////////////////////////////////
// reedsolomon reconstruct

BOOST_AUTO_TEST_SUITE(reedsolomon_reconstruct)

BOOST_AUTO_TEST_CASE(all_loss_patterns_roundtrip)
{
	std::mt19937 rng(9);
	const std::vector<std::pair<int, int>> configs = {
		{1, 1}, {2, 1}, {4, 2}, {5, 3}, {8, 4}
	};
	const std::size_t len = 1024;

	for (auto [D, P] : configs)
	{
		const int total = D + P;
		reedsolomon rs(D, P);
		std::vector<std::vector<uint8_t>> data(D);
		for (auto& s : data)
			s = random_bytes(len, rng);
		std::vector<std::vector<uint8_t>> parity;
		BOOST_REQUIRE(rs.encode(data, parity));

		for (int mask = 0; mask < (1 << total); mask++)
		{
			int missing = static_cast<int>(missing_indices(mask, total).size());
			if (missing > P)
				continue;

			std::vector<std::vector<uint8_t>> shards;
			for (int d = 0; d < D; d++)
				shards.push_back(mask & (1 << d)
					? std::vector<uint8_t>() : data[d]);
			for (int p = 0; p < P; p++)
				shards.push_back(mask & (1 << (D + p))
					? std::vector<uint8_t>() : parity[p]);

			if (!rs.reconstruct(shards, len))
			{
				std::printf("reconstruct FAIL D=%d P=%d mask=0x%x\n",
					D, P, mask);
				BOOST_FAIL("reconstruct failed");
			}
			for (int d = 0; d < D; d++)
				BOOST_CHECK_EQUAL_COLLECTIONS(
					shards[d].begin(), shards[d].end(),
					data[d].begin(), data[d].end());
			for (int p = 0; p < P; p++)
				BOOST_CHECK_EQUAL_COLLECTIONS(
					shards[D + p].begin(), shards[D + p].end(),
					parity[p].begin(), parity[p].end());
		}
	}
}

BOOST_AUTO_TEST_CASE(all_data_present_quick_path)
{
	// 数据分片齐全时直接返回, 内容不变.
	reedsolomon rs(4, 2);
	std::vector<std::vector<uint8_t>> data(4,
		std::vector<uint8_t>(64, 0xab));
	std::vector<std::vector<uint8_t>> parity;
	BOOST_REQUIRE(rs.encode(data, parity));

	std::vector<std::vector<uint8_t>> shards = data;
	shards.push_back(parity[0]);
	shards.push_back(parity[1]);
	BOOST_REQUIRE(rs.reconstruct(shards, 64));
	for (int d = 0; d < 4; d++)
		BOOST_CHECK_EQUAL_COLLECTIONS(
			shards[d].begin(), shards[d].end(),
			data[d].begin(), data[d].end());
}

BOOST_AUTO_TEST_CASE(rejects_too_many_missing)
{
	reedsolomon rs(4, 2);
	std::vector<std::vector<uint8_t>> data(4,
		std::vector<uint8_t>(64, 0x11));
	std::vector<std::vector<uint8_t>> parity;
	BOOST_REQUIRE(rs.encode(data, parity));

	// 缺失 3 片 > 2 片冗余.
	std::vector<std::vector<uint8_t>> shards;
	for (int i = 0; i < 3; i++)
		shards.push_back({});
	shards.push_back(data[3]);
	shards.push_back(parity[0]);
	shards.push_back({});
	BOOST_CHECK(!rs.reconstruct(shards, 64));
}

BOOST_AUTO_TEST_CASE(rejects_wrong_shard_count)
{
	reedsolomon rs(4, 2);
	std::vector<std::vector<uint8_t>> shards(5,
		std::vector<uint8_t>(16, 0));
	BOOST_CHECK(!rs.reconstruct(shards, 16));
}

BOOST_AUTO_TEST_CASE(rejects_all_missing)
{
	reedsolomon rs(4, 2);
	std::vector<std::vector<uint8_t>> shards(6);
	BOOST_CHECK(!rs.reconstruct(shards, 16));
}

BOOST_AUTO_TEST_SUITE_END()

//////////////////////////////////////////////////////////////////////////
// FEC 帧编解码

BOOST_AUTO_TEST_SUITE(fec_frames)

static std::vector<uint8_t> make_packet(std::size_t n, std::mt19937& rng)
{
	return random_bytes(n, rng);
}

static uint32_t read_u32(const std::vector<uint8_t>& v, std::size_t off)
{
	return static_cast<uint32_t>(v[off]) |
		(static_cast<uint32_t>(v[off + 1]) << 8) |
		(static_cast<uint32_t>(v[off + 2]) << 16) |
		(static_cast<uint32_t>(v[off + 3]) << 24);
}

static uint16_t read_u16(const std::vector<uint8_t>& v, std::size_t off)
{
	return static_cast<uint16_t>(v[off]) |
		(static_cast<uint16_t>(v[off + 1]) << 8);
}

BOOST_AUTO_TEST_CASE(encode_group_frame_format)
{
	std::mt19937 rng(10);
	fec_encode_group eg(4, 2);
	std::vector<uint8_t> ip = make_packet(1377, rng);
	std::vector<std::vector<uint8_t>> frames;
	BOOST_REQUIRE(eg.encode(0x12345678, std::string_view(
		reinterpret_cast<const char*>(ip.data()), ip.size()), frames));
	BOOST_CHECK_EQUAL(frames.size(), 6u);

	std::size_t shard_size = (ip.size() + 3) / 4;
	for (std::size_t i = 0; i < frames.size(); i++)
	{
		const auto& f = frames[i];
		BOOST_CHECK_EQUAL(read_u32(f, 0), 0x12345678u);
		BOOST_CHECK_EQUAL(f[4], 6u);
		BOOST_CHECK_EQUAL(f[5], static_cast<uint8_t>(i));
		BOOST_CHECK_EQUAL(read_u16(f, 6), static_cast<uint16_t>(ip.size()));
		BOOST_CHECK_EQUAL(f.size(),
			fec_frame_header_size + shard_size);
	}
}

BOOST_AUTO_TEST_CASE(decode_group_recovers_all_loss_patterns)
{
	std::mt19937 rng(11);
	const std::vector<std::pair<int, int>> configs = {
		{1, 1}, {4, 2}
	};
	const std::vector<std::size_t> lengths = { 1, 2, 100, 1377 };

	for (auto [D, P] : configs)
	{
		const int total = D + P;
		for (std::size_t n : lengths)
		{
			std::vector<uint8_t> ip = make_packet(n, rng);
			fec_encode_group eg(D, P);
			std::vector<std::vector<uint8_t>> frames;
			BOOST_REQUIRE(eg.encode(0xabcdef01, std::string_view(
				reinterpret_cast<const char*>(ip.data()), ip.size()), frames));

			for (int mask = 0; mask < (1 << total); mask++)
			{
				if (static_cast<int>(missing_indices(mask, total).size()) > P)
					continue;

				fec_decode_group dg(D, P);
				std::vector<uint8_t> output;
				bool recovered = false;
				for (int i = 0; i < total; i++)
				{
					if (mask & (1 << i))
						continue; // 模拟丢失.
					const auto& f = frames[i];
					if (dg.add(read_u32(f, 0), f[5], f[4],
						read_u16(f, 6), std::string_view(
							reinterpret_cast<const char*>(f.data()) +
							fec_frame_header_size,
							f.size() - fec_frame_header_size), output))
					{
						recovered = true;
						break;
					}
				}
				BOOST_REQUIRE(recovered);
				BOOST_CHECK_EQUAL_COLLECTIONS(output.begin(), output.end(),
					ip.begin(), ip.end());
			}
		}
	}
}

BOOST_AUTO_TEST_CASE(duplicate_shard_rejected)
{
	fec_decode_group dg(4, 2);
	std::vector<uint8_t> shard(16, 0x77);
	std::vector<uint8_t> output;
	BOOST_REQUIRE(!dg.add(1, 0, 6, 64, std::string_view(
		reinterpret_cast<const char*>(shard.data()), shard.size()), output));
	// 相同 index 重复添加返回 false (去重).
	BOOST_CHECK(!dg.add(1, 0, 6, 64, std::string_view(
		reinterpret_cast<const char*>(shard.data()), shard.size()), output));
	// 同一分组不同 index 正常接收.
	BOOST_REQUIRE(!dg.add(1, 1, 6, 64, std::string_view(
		reinterpret_cast<const char*>(shard.data()), shard.size()), output));
}

BOOST_AUTO_TEST_CASE(invalid_args_rejected)
{
	fec_decode_group dg(2, 1);
	std::vector<uint8_t> shard(16, 0);
	std::vector<uint8_t> output;
	std::string_view s(reinterpret_cast<const char*>(shard.data()),
		shard.size());
	BOOST_CHECK(!dg.add(1, 3, 3, 32, s, output)); // index >= total.
	BOOST_CHECK(!dg.add(1, 0, 9, 32, s, output)); // total 不匹配.
}

BOOST_AUTO_TEST_CASE(purge_expired)
{
	fec_decode_group dg(4, 2, std::chrono::milliseconds(20));
	std::vector<uint8_t> shard(16, 0x42);
	std::vector<uint8_t> output;
	BOOST_REQUIRE(!dg.add(7, 0, 6, 64, std::string_view(
		reinterpret_cast<const char*>(shard.data()), shard.size()), output));
	BOOST_CHECK_EQUAL(dg.purge(), 0u); // 未过期.
	std::this_thread::sleep_for(std::chrono::milliseconds(40));
	BOOST_CHECK_EQUAL(dg.purge(), 1u); // 已过期.
}

BOOST_AUTO_TEST_SUITE_END()

//////////////////////////////////////////////////////////////////////////
// FEC 矩阵缓存

BOOST_AUTO_TEST_SUITE(fec_matrix_cache)

BOOST_AUTO_TEST_CASE(inverse_key_properties)
{
	// 选中顺序无关.
	BOOST_CHECK_EQUAL(fec_cache::inverse_key(4, 2, {0, 1, 2, 3}),
		fec_cache::inverse_key(4, 2, {3, 2, 1, 0}));
	// 不同选中集合位图不同.
	BOOST_CHECK(fec_cache::inverse_key(4, 2, {0, 1, 2, 3}) !=
		fec_cache::inverse_key(4, 2, {0, 1, 2, 4}));
	// 不同 data/parity 配置区分.
	BOOST_CHECK(fec_cache::inverse_key(4, 2, {0}) !=
		fec_cache::inverse_key(4, 3, {0}));
	BOOST_CHECK(fec_cache::inverse_key(4, 2, {0}) !=
		fec_cache::inverse_key(5, 2, {0}));
	// 索引 >= 32 不可缓存.
	BOOST_CHECK_EQUAL(fec_cache::inverse_key(4, 2, {32}), 0u);
	BOOST_CHECK_EQUAL(fec_cache::inverse_key(4, 2, {0, 40}), 0u);
}

BOOST_AUTO_TEST_CASE(encoding_key_distinct)
{
	BOOST_CHECK(fec_cache::encoding_key(4, 2) !=
		fec_cache::encoding_key(2, 4));
	BOOST_CHECK_EQUAL(fec_cache::encoding_key(4, 2),
		fec_cache::encoding_key(4, 2));
}

BOOST_AUTO_TEST_CASE(store_and_find_inverse)
{
	fec_cache::matrix m = { {1, 2, 3}, {4, 5, 6}, {7, 8, 9} };
	uint64_t key = fec_cache::inverse_key(3, 1, {0, 1, 2});
	BOOST_REQUIRE(key != 0);
	fec_cache::store_inverse(key, m);
	fec_cache::matrix out;
	BOOST_REQUIRE(fec_cache::find_inverse(key, out));
	BOOST_CHECK(out == m);

	// 未存储的 key 找不到.
	fec_cache::matrix out2;
	BOOST_CHECK(!fec_cache::find_inverse(
		fec_cache::inverse_key(3, 1, {1, 2, 3}), out2));
}

BOOST_AUTO_TEST_CASE(lru_eviction)
{
	// 超过容量后, 最旧的条目被淘汰.
	const std::size_t cap = fec_cache::inverse_capacity;
	std::vector<uint64_t> keys;
	for (std::size_t i = 0; i <= cap; i++)
	{
		uint64_t key = fec_cache::inverse_key(1,
			static_cast<int>(100 + i), {0});
		BOOST_REQUIRE(key != 0);
		keys.push_back(key);
		fec_cache::store_inverse(key,
			fec_cache::matrix{ { static_cast<uint8_t>(i) } });
	}
	fec_cache::matrix out;
	BOOST_CHECK(!fec_cache::find_inverse(keys[0], out)); // 最旧淘汰.
	for (std::size_t i = 1; i <= cap; i++)
		BOOST_CHECK(fec_cache::find_inverse(keys[i], out));
}

BOOST_AUTO_TEST_SUITE_END()
