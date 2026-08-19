//
// avpn_fec.cpp
// ~~~~~~~~~~~~
//
// Copyright (C) 2025 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#include "libavpn/avpn_fec.hpp"
#include "libavpn/logging.hpp"
#include "libavpn/avpn_protocol.hpp"

#include <algorithm>
#include <cstring>
#include <list>
#include <mutex>
#include <unordered_map>

#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
#include <immintrin.h>
#define AVPN_TARGET_SSSE3 __attribute__((target("ssse3")))
#define AVPN_TARGET_AVX2 __attribute__((target("avx2")))
#elif defined(_M_X64)
// MSVC x64: 无 per-function target attribute, 整个 TU 以 /arch:AVX2 编译,
// 运行时通过 __cpuid 分派, 保证在不支持 AVX2 的 CPU 上回退到 SSSE3/标量.
#include <intrin.h>
#define AVPN_TARGET_SSSE3
#define AVPN_TARGET_AVX2
#elif (defined(__aarch64__) && (defined(__GNUC__) || defined(__clang__))) || \
	defined(_M_ARM64)
#include <arm_neon.h>
#elif defined(_M_ARM64)
#include <arm64_neon.h>
#endif

namespace libavpn {

	//////////////////////////////////////////////////////////////////////////
	// FEC 矩阵缓存.
	//
	// 编码矩阵按 (data_shards, parity_shards) 全局缓存, 避免每个会话重复
	// 生成 Vandermonde 矩阵; 解码逆矩阵按选中分片位图做 LRU 缓存, 避免
	// 每次恢复重复进行矩阵求逆.
	namespace fec_cache {

		using matrix = std::vector<std::vector<uint8_t>>;

		std::mutex& encoding_mutex()
		{
			static std::mutex m;
			return m;
		}

		std::unordered_map<uint32_t, matrix>& encoding_map()
		{
			static std::unordered_map<uint32_t, matrix> cache;
			return cache;
		}

		// 编码矩阵 key: (data_shards << 16) | parity_shards.
		inline uint32_t encoding_key(int data_shards, int parity_shards)
		{
			return (static_cast<uint32_t>(data_shards) << 16) |
				static_cast<uint32_t>(parity_shards);
		}

		// 逆矩阵 LRU 容量.
		constexpr std::size_t inverse_capacity = 64;

		std::mutex& inverse_mutex()
		{
			static std::mutex m;
			return m;
		}

		using inverse_entry = std::pair<uint64_t, matrix>;
		std::list<inverse_entry>& inverse_list()
		{
			static std::list<inverse_entry> l;
			return l;
		}

		std::unordered_map<uint64_t, std::list<inverse_entry>::iterator>&
		inverse_index()
		{
			static std::unordered_map<uint64_t,
				std::list<inverse_entry>::iterator> index;
			return index;
		}

		bool find_encoding(uint32_t key, matrix& out)
		{
			std::lock_guard<std::mutex> lock(encoding_mutex());
			auto it = encoding_map().find(key);
			if (it == encoding_map().end())
				return false;
			out = it->second;
			return true;
		}

		void store_encoding(uint32_t key, const matrix& m)
		{
			std::lock_guard<std::mutex> lock(encoding_mutex());
			encoding_map()[key] = m;
		}

		// 查找逆矩阵, 命中后移到 LRU 前端.
		bool find_inverse(uint64_t key, matrix& out)
		{
			std::lock_guard<std::mutex> lock(inverse_mutex());
			auto it = inverse_index().find(key);
			if (it == inverse_index().end())
				return false;
			out = it->second->second;
			inverse_list().splice(inverse_list().begin(),
				inverse_list(), it->second);
			return true;
		}

		void store_inverse(uint64_t key, const matrix& m)
		{
			std::lock_guard<std::mutex> lock(inverse_mutex());
			if (inverse_index().size() >= inverse_capacity)
			{
				auto last = inverse_list().end();
				--last;
				inverse_index().erase(last->first);
				inverse_list().pop_back();
			}
			inverse_list().emplace_front(key, m);
			inverse_index()[key] = inverse_list().begin();
		}

		// 逆矩阵 key: (data_shards << 8 | parity_shards) << 32 | 选中分片位图.
		// 选中分片索引必须小于 32, 否则返回 0 表示不可缓存.
		inline uint64_t inverse_key(int data_shards, int parity_shards,
			const std::vector<int>& selected)
		{
			uint64_t bitmap = 0;
			for (int idx : selected)
			{
				if (idx >= 32)
					return 0;
				bitmap |= (1ULL << idx);
			}
			return ((static_cast<uint64_t>(data_shards) << 8 |
				static_cast<uint64_t>(parity_shards)) << 32) | bitmap;
		}

	} // namespace fec_cache

	namespace gf {

		// GF(2^8) 对数表 (以本原多项式 0x11d 为模).
		inline constexpr std::array<uint8_t, 256> log_table = {
			0,   0,   1,   25,  2,   50,  26,  198, 3,   223, 51,  238, 27,  104, 199, 75,
			4,   100, 224, 14,  52,  141, 239, 129, 28,  193, 105, 248, 200, 8,   76,  113,
			5,   138, 101, 47,  225, 36,  15,  33,  53,  147, 142, 218, 240, 18,  130, 69,
			29,  181, 194, 125, 106, 39,  249, 185, 201, 154, 9,   120, 77,  228, 114, 166,
			6,   191, 139, 98,  102, 221, 48,  253, 226, 152, 37,  179, 16,  145, 34,  136,
			54,  208, 148, 206, 143, 150, 219, 189, 241, 210, 19,  92,  131, 56,  70,  64,
			30,  66,  182, 163, 195, 72,  126, 110, 107, 58,  40,  84,  250, 133, 186, 61,
			202, 94,  155, 159, 10,  21,  121, 43,  78,  212, 229, 172, 115, 243, 167, 87,
			7,   112, 192, 247, 140, 128, 99,  13,  103, 74,  222, 237, 49,  197, 254, 24,
			227, 165, 153, 119, 38,  184, 180, 124, 17,  68,  146, 217, 35,  32,  137, 46,
			55,  63,  209, 91,  149, 188, 207, 205, 144, 135, 151, 178, 220, 252, 190, 97,
			242, 86,  211, 171, 20,  42,  93,  158, 132, 60,  57,  83,  71,  109, 65,  162,
			31,  45,  67,  216, 183, 123, 164, 118, 196, 23,  73,  236, 127, 12,  111, 246,
			108, 161, 59,  82,  41,  157, 85,  170, 251, 96,  134, 177, 187, 204, 62,  90,
			203, 89,  95,  176, 156, 169, 160, 81,  11,  245, 22,  235, 122, 117, 44,  215,
			79,  174, 213, 233, 230, 231, 173, 232, 116, 214, 244, 234, 168, 80,  88,  175
		};

		// GF(2^8) 指数表 (长度 512, 含两个周期, 避免取模).
		// 以本原多项式 0x11d 生成.
		inline constexpr std::array<uint8_t, 512> make_exp_table()
		{
			std::array<uint8_t, 512> t{};
			uint8_t x = 1;
			for (int i = 0; i < 255; i++)
			{
				t[i] = x;
				t[i + 255] = x;
				// x * 2 在 GF(2^8) 中 (模 0x11d).
				x = static_cast<uint8_t>(
					(x << 1) ^ (x & 0x80 ? 0x1d : 0));
			}
			t[510] = 1;
			t[511] = 2;
			return t;
		}
		inline constexpr std::array<uint8_t, 512> exp_table = make_exp_table();

		// GF(2^8) 乘法表 (256x256), 由对数/指数表生成, 单次查表完成乘法.
		inline constexpr std::array<std::array<uint8_t, 256>, 256> make_mul_table()
		{
			const uint8_t* e = exp_table.data();
			const uint8_t* l = log_table.data();
			std::array<std::array<uint8_t, 256>, 256> t{};
			auto* rows = t.data();
			for (int a = 0; a < 256; a++)
			{
				auto* col = rows[a].data();
				for (int b = 0; b < 256; b++)
				{
					if (a == 0 || b == 0)
						continue;
					col[b] = e[l[a] + l[b]];
				}
			}
			return t;
		}
		inline constexpr std::array<std::array<uint8_t, 256>, 256> mul_table = make_mul_table();

		// 低/高半字节紧凑表: low[b][n] = b*n, high[b][n] = b*(n<<4).
		// 供 SIMD (pshufb/vqtbl1q) 批量查表乘法使用.
		inline constexpr std::array<std::array<uint8_t, 16>, 256> make_low_tables()
		{
			std::array<std::array<uint8_t, 16>, 256> t{};
			auto* rows = mul_table.data();
			for (int b = 0; b < 256; b++)
			{
				const uint8_t* row = rows[b].data();
				auto* col = t[b].data();
				for (int n = 0; n < 16; n++)
					col[n] = row[n];
			}
			return t;
		}
		inline constexpr std::array<std::array<uint8_t, 16>, 256> low_tables = make_low_tables();

		inline constexpr std::array<std::array<uint8_t, 16>, 256> make_high_tables()
		{
			std::array<std::array<uint8_t, 16>, 256> t{};
			auto* rows = mul_table.data();
			for (int b = 0; b < 256; b++)
			{
				const uint8_t* row = rows[b].data();
				auto* col = t[b].data();
				for (int n = 0; n < 16; n++)
					col[n] = row[n << 4];
			}
			return t;
		}
		inline constexpr std::array<std::array<uint8_t, 16>, 256> high_tables = make_high_tables();

		// SIMD 批量 GF(2^8) 乘法: out = c * in / out ^= c * in.
		// x86-64 用 SSSE3/AVX2 pshufb 查表, aarch64 用 NEON vqtbl1q, 其余回退标量.
#if (defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))) || \
	defined(_M_X64)
		AVPN_TARGET_SSSE3 inline void mul_slice_ssse3(
			uint8_t c, const uint8_t* in, uint8_t* out, std::size_t len, bool x)
		{
			__m128i tl = _mm_loadu_si128(
				reinterpret_cast<const __m128i*>(low_tables[c].data()));
			__m128i th = _mm_loadu_si128(
				reinterpret_cast<const __m128i*>(high_tables[c].data()));
			__m128i lo_mask = _mm_set1_epi8(0x0f);
			std::size_t i = 0;
			for (; i + 16 <= len; i += 16)
			{
				__m128i v = _mm_loadu_si128(
					reinterpret_cast<const __m128i*>(in + i));
				__m128i lo = _mm_and_si128(v, lo_mask);
				__m128i hi = _mm_and_si128(_mm_srli_epi64(v, 4), lo_mask);
				__m128i r = _mm_xor_si128(
					_mm_shuffle_epi8(tl, lo), _mm_shuffle_epi8(th, hi));
				if (x)
					r = _mm_xor_si128(r, _mm_loadu_si128(
						reinterpret_cast<const __m128i*>(out + i)));
				_mm_storeu_si128(reinterpret_cast<__m128i*>(out + i), r);
			}
			const uint8_t* row = mul_table[c].data();
			for (; i < len; i++)
				out[i] = x ? out[i] ^ row[in[i]] : row[in[i]];
		}

		AVPN_TARGET_AVX2 inline void mul_slice_avx2(
			uint8_t c, const uint8_t* in, uint8_t* out, std::size_t len, bool x)
		{
			__m256i tl = _mm256_broadcastsi128_si256(_mm_loadu_si128(
				reinterpret_cast<const __m128i*>(low_tables[c].data())));
			__m256i th = _mm256_broadcastsi128_si256(_mm_loadu_si128(
				reinterpret_cast<const __m128i*>(high_tables[c].data())));
			__m256i lo_mask = _mm256_set1_epi8(0x0f);
			std::size_t i = 0;
			for (; i + 32 <= len; i += 32)
			{
				__m256i v = _mm256_loadu_si256(
					reinterpret_cast<const __m256i*>(in + i));
				__m256i lo = _mm256_and_si256(v, lo_mask);
				__m256i hi = _mm256_and_si256(_mm256_srli_epi64(v, 4), lo_mask);
				__m256i r = _mm256_xor_si256(
					_mm256_shuffle_epi8(tl, lo), _mm256_shuffle_epi8(th, hi));
				if (x)
					r = _mm256_xor_si256(r, _mm256_loadu_si256(
						reinterpret_cast<const __m256i*>(out + i)));
				_mm256_storeu_si256(reinterpret_cast<__m256i*>(out + i), r);
			}
			mul_slice_ssse3(c, in + i, out + i, len - i, x);
		}
#elif (defined(__aarch64__) && (defined(__GNUC__) || defined(__clang__))) || \
	defined(_M_ARM64)
		inline void mul_slice_neon(
			uint8_t c, const uint8_t* in, uint8_t* out, std::size_t len, bool x)
		{
			uint8x16_t tl = vld1q_u8(low_tables[c].data());
			uint8x16_t th = vld1q_u8(high_tables[c].data());
			uint8x16_t lo_mask = vdupq_n_u8(0x0f);
			std::size_t i = 0;
			for (; i + 16 <= len; i += 16)
			{
				uint8x16_t v = vld1q_u8(in + i);
				uint8x16_t lo = vandq_u8(v, lo_mask);
				uint8x16_t hi = vshrq_n_u8(v, 4);
				uint8x16_t r = veorq_u8(
					vqtbl1q_u8(tl, lo), vqtbl1q_u8(th, hi));
				if (x)
					r = veorq_u8(r, vld1q_u8(out + i));
				vst1q_u8(out + i, r);
			}
			const uint8_t* row = mul_table[c].data();
			for (; i < len; i++)
				out[i] = x ? out[i] ^ row[in[i]] : row[in[i]];
		}
#endif

		inline bool cpu_has_avx2()
		{
#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
			return __builtin_cpu_supports("avx2");
#elif defined(_M_X64)
			int cpu_info[4] = { 0 };
			__cpuid(cpu_info, 7);
			return (cpu_info[1] & (1 << 5)) != 0; // EBX.AVX2.
#else
			return false;
#endif
		}

		inline bool cpu_has_ssse3()
		{
#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
			return __builtin_cpu_supports("ssse3");
#elif defined(_M_X64)
			int cpu_info[4] = { 0 };
			__cpuid(cpu_info, 1);
			return (cpu_info[2] & (1 << 9)) != 0; // ECX.SSSE3.
#else
			return false;
#endif
		}

		inline uint8_t mul(uint8_t a, uint8_t b)
		{
			return mul_table[a][b];
		}

		inline void mul_slice(uint8_t c, const uint8_t* in, uint8_t* out, std::size_t len)
		{
			if (c == 0)
			{
				std::memset(out, 0, len);
				return;
			}
			if (c == 1)
			{
				std::memcpy(out, in, len);
				return;
			}
#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
			static const bool has_avx2 = cpu_has_avx2();
			if (has_avx2)
			{
				mul_slice_avx2(c, in, out, len, false);
				return;
			}
			static const bool has_ssse3 = cpu_has_ssse3();
			if (has_ssse3)
			{
				mul_slice_ssse3(c, in, out, len, false);
				return;
			}
#elif defined(_M_X64)
			static const bool has_avx2 = cpu_has_avx2();
			if (has_avx2)
			{
				mul_slice_avx2(c, in, out, len, false);
				return;
			}
			static const bool has_ssse3 = cpu_has_ssse3();
			if (has_ssse3)
			{
				mul_slice_ssse3(c, in, out, len, false);
				return;
			}
#elif defined(__aarch64__) && (defined(__GNUC__) || defined(__clang__))
			mul_slice_neon(c, in, out, len, false);
			return;
#elif defined(_M_ARM64)
			mul_slice_neon(c, in, out, len, false);
			return;
#endif
			const uint8_t* row = mul_table[c].data();
			for (std::size_t i = 0; i < len; i++)
				out[i] = row[in[i]];
		}

		inline void mul_slice_xor(uint8_t c, const uint8_t* in, uint8_t* out, std::size_t len)
		{
			if (c == 0)
				return;
			if (c == 1)
			{
				for (std::size_t i = 0; i < len; i++)
					out[i] ^= in[i];
				return;
			}
#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
			static const bool has_avx2 = cpu_has_avx2();
			if (has_avx2)
			{
				mul_slice_avx2(c, in, out, len, true);
				return;
			}
			static const bool has_ssse3 = cpu_has_ssse3();
			if (has_ssse3)
			{
				mul_slice_ssse3(c, in, out, len, true);
				return;
			}
#elif defined(_M_X64)
			static const bool has_avx2 = cpu_has_avx2();
			if (has_avx2)
			{
				mul_slice_avx2(c, in, out, len, true);
				return;
			}
			static const bool has_ssse3 = cpu_has_ssse3();
			if (has_ssse3)
			{
				mul_slice_ssse3(c, in, out, len, true);
				return;
			}
#elif defined(__aarch64__) && (defined(__GNUC__) || defined(__clang__))
			mul_slice_neon(c, in, out, len, true);
			return;
#elif defined(_M_ARM64)
			mul_slice_neon(c, in, out, len, true);
			return;
#endif
			const uint8_t* row = mul_table[c].data();
			for (std::size_t i = 0; i < len; i++)
				out[i] ^= row[in[i]];
		}

		inline uint8_t div(uint8_t a, uint8_t b)
		{
			if (a == 0)
				return 0;
			if (b == 0)
				return 0;
			return exp_table[(log_table[a] + 255 - log_table[b]) % 255];
		}

		inline uint8_t pow(uint8_t a, int n)
		{
			if (n == 0)
				return 1;
			if (a == 0)
				return 0;
			if (n < 0)
				return div(1, pow(a, -n));
			return exp_table[(log_table[a] * n) % 255];
		}

		// 生成 Vandermonde 矩阵.
		inline void vandermonde(int rows, int cols,
			std::vector<std::vector<uint8_t>>& matrix)
		{
			matrix.assign(rows, std::vector<uint8_t>(cols, 0));
			for (int r = 0; r < rows; r++)
			{
				matrix[r][0] = 1;
				for (int c = 1; c < cols; c++)
					matrix[r][c] = mul(matrix[r][c - 1], static_cast<uint8_t>(r));
			}
		}

		// 矩阵求逆 (高斯-约当消元), 成功返回 true.
		inline bool invert(const std::vector<std::vector<uint8_t>>& in,
			std::vector<std::vector<uint8_t>>& out)
		{
			std::size_t n = in.size();
			if (n == 0 || in[0].size() != n)
				return false;

			out.assign(n, std::vector<uint8_t>(n, 0));
			auto aug = in;
			for (std::size_t i = 0; i < n; i++)
				out[i][i] = 1;

			for (std::size_t i = 0; i < n; i++)
			{
				// 找到主元.
				std::size_t pivot = i;
				for (std::size_t j = i + 1; j < n; j++)
				{
					if (aug[j][i] != 0)
					{
						pivot = j;
						break;
					}
				}
				if (aug[pivot][i] == 0)
					return false;

				// 交换行.
				if (pivot != i)
				{
					std::swap(aug[i], aug[pivot]);
					std::swap(out[i], out[pivot]);
				}

				// 归一化主元行.
				uint8_t inv_pivot = gf::div(1, aug[i][i]);
				for (std::size_t j = 0; j < n; j++)
				{
					aug[i][j] = gf::mul(aug[i][j], inv_pivot);
					out[i][j] = gf::mul(out[i][j], inv_pivot);
				}

				// 消去其他行的主元列.
				for (std::size_t j = 0; j < n; j++)
				{
					if (j == i || aug[j][i] == 0)
						continue;
					uint8_t factor = aug[j][i];
					for (std::size_t k = 0; k < n; k++)
					{
						aug[j][k] ^= gf::mul(factor, aug[i][k]);
						out[j][k] ^= gf::mul(factor, out[i][k]);
					}
				}
			}

			return true;
		}

	} // namespace gf

	reedsolomon::reedsolomon(int data_shards, int parity_shards)
		: m_data_shards(std::max(1, data_shards))
		, m_parity_shards(std::max(0, parity_shards))
	{
		int total = m_data_shards + m_parity_shards;
		if (total > 255)
		{
			XLOG_ERR << "Too many shards: " << total;
			m_parity_shards = 0;
			total = m_data_shards;
		}

		// 优先从缓存获取编码矩阵, 避免重复生成 Vandermonde 矩阵.
		uint32_t key = fec_cache::encoding_key(
			m_data_shards, m_parity_shards);
		if (fec_cache::find_encoding(key, m_encoding_matrix))
			return;

		// 生成系统形式的编码矩阵: 前 data_shards 行为单位矩阵,
		// 冗余行 = Vandermonde 行右乘 V0^{-1} (V0 为前 data_shards 行),
		// 保证任意 data_shards 行组合构成的子矩阵可逆.
		std::vector<std::vector<uint8_t>> vm;
		gf::vandermonde(total, m_data_shards, vm);

		std::vector<std::vector<uint8_t>> v0(vm.begin(),
			vm.begin() + m_data_shards);
		std::vector<std::vector<uint8_t>> inv0;
		if (!gf::invert(v0, inv0))
		{
			XLOG_ERR << "vandermonde matrix not invertible";
			m_parity_shards = 0;
			return;
		}

		m_encoding_matrix.assign(total,
			std::vector<uint8_t>(m_data_shards, 0));
		for (int r = 0; r < total; r++)
		{
			if (r < m_data_shards)
			{
				m_encoding_matrix[r][r] = 1;
				continue;
			}

			// 冗余行 = vm[r] * inv0.
			for (int c = 0; c < m_data_shards; c++)
			{
				uint8_t sum = 0;
				for (int k = 0; k < m_data_shards; k++)
					sum ^= gf::mul(vm[r][k], inv0[k][c]);
				m_encoding_matrix[r][c] = sum;
			}
		}

		fec_cache::store_encoding(key, m_encoding_matrix);
	}

	bool reedsolomon::encode(const std::vector<std::vector<uint8_t>>& data,
		std::vector<std::vector<uint8_t>>& parity)
	{
		if (data.size() != static_cast<std::size_t>(m_data_shards))
			return false;

		std::size_t shard_size = data[0].size();
		for (auto& d : data)
		{
			if (d.size() != shard_size)
				return false;
		}

		parity.assign(m_parity_shards,
			std::vector<uint8_t>(shard_size, 0));

		for (int p = 0; p < m_parity_shards; p++)
		{
			int row = m_data_shards + p;
			auto& out = parity[p];
			auto& mrow = m_encoding_matrix[row];

			// 第一个数据分片直接赋值, 其余分片查表累加.
			gf::mul_slice(mrow[0], data[0].data(), out.data(), shard_size);
			for (int d = 1; d < m_data_shards; d++)
				gf::mul_slice_xor(mrow[d], data[d].data(), out.data(), shard_size);
		}

		return true;
	}

	bool reedsolomon::reconstruct(std::vector<std::vector<uint8_t>>& shards,
		std::size_t shard_size)
	{
		if (shards.size() != static_cast<std::size_t>(total_shards()))
			return false;

		// 收集存在与缺失的分片.
		std::vector<int> present_idx;
		std::vector<int> missing_idx;
		for (std::size_t i = 0; i < shards.size(); i++)
		{
			if (!shards[i].empty())
				present_idx.push_back(static_cast<int>(i));
			else
				missing_idx.push_back(static_cast<int>(i));
		}

		// 数据完整, 无需恢复.
		if (missing_idx.empty())
			return true;

		// 需要足够多的分片.
		if (present_idx.size() < static_cast<std::size_t>(m_data_shards))
			return false;

		// 数据分片齐全时无需恢复, 直接使用现有数据分片.
		bool data_complete = std::all_of(shards.begin(),
			shards.begin() + m_data_shards,
			[](const std::vector<uint8_t>& s) { return !s.empty(); });

		std::vector<std::vector<uint8_t>> data;
		if (!data_complete)
		{
			// 取任意 data_shards 个存在分片对应编码矩阵行构成方阵.
			std::vector<int> selected(present_idx.begin(),
				present_idx.begin() + m_data_shards);

			// 相同缺失模式复用缓存的逆矩阵, 避免重复求逆.
			uint64_t inv_key = fec_cache::inverse_key(
				m_data_shards, m_parity_shards, selected);

			std::vector<std::vector<uint8_t>> inv;
			bool have_inv = inv_key != 0 &&
				fec_cache::find_inverse(inv_key, inv);
			if (!have_inv)
			{
				std::vector<std::vector<uint8_t>> sub_matrix;
				sub_matrix.reserve(m_data_shards);
				for (int idx : selected)
					sub_matrix.push_back(m_encoding_matrix[idx]);

				if (!gf::invert(sub_matrix, inv))
					return false;

				if (inv_key != 0)
					fec_cache::store_inverse(inv_key, inv);
			}

			// 恢复原始数据分片: M = D^-1 * P.
			// 先复制选中的分片数据.
			std::vector<std::vector<uint8_t>> present(m_data_shards);
			for (int k = 0; k < m_data_shards; k++)
				present[k] = shards[selected[k]];

			data.assign(m_data_shards,
				std::vector<uint8_t>(shard_size, 0));
			for (int i = 0; i < m_data_shards; i++)
			{
				auto& out = data[i];
				gf::mul_slice(inv[i][0], present[0].data(), out.data(), shard_size);
				for (int k = 1; k < m_data_shards; k++)
					gf::mul_slice_xor(inv[i][k], present[k].data(), out.data(), shard_size);
			}

			// 回填数据分片.
			for (int i = 0; i < m_data_shards; i++)
				shards[i] = data[i];
		}
		else
		{
			data.assign(shards.begin(), shards.begin() + m_data_shards);
		}

		// 重新计算缺失的冗余分片.
		for (int missing : missing_idx)
		{
			if (missing < m_data_shards)
				continue; // 数据分片已恢复.
			auto& row = m_encoding_matrix[missing];
			shards[missing].assign(shard_size, 0);
			gf::mul_slice(row[0], data[0].data(), shards[missing].data(), shard_size);
			for (int d = 1; d < m_data_shards; d++)
				gf::mul_slice_xor(row[d], data[d].data(), shards[missing].data(), shard_size);
		}

		return true;
	}

	//////////////////////////////////////////////////////////////////////////

	fec_encode_group::fec_encode_group(int data_shards, int parity_shards)
		: m_rs(data_shards, parity_shards)
	{}

	bool fec_encode_group::encode(uint32_t fec_id, std::string_view ip_packet,
		std::vector<std::vector<uint8_t>>& frames)
	{
		int ds = m_rs.data_shards();
		int ps = m_rs.parity_shards();
		int total = ds + ps;

		// 计算分片大小 (向上取整).
		std::size_t shard_size = (ip_packet.size() + ds - 1) / ds;
		if (shard_size == 0)
			shard_size = 1;

		// 拆分数据分片.
		std::vector<std::vector<uint8_t>> data_shards(ds,
			std::vector<uint8_t>(shard_size, 0));
		for (int d = 0; d < ds; d++)
		{
			std::size_t offset = static_cast<std::size_t>(d) * shard_size;
			std::size_t len = std::min<std::size_t>(shard_size,
				ip_packet.size() - std::min(offset, ip_packet.size()));
			if (offset < ip_packet.size())
				std::memcpy(data_shards[d].data(), ip_packet.data() + offset, len);
		}

		// 计算冗余分片.
		std::vector<std::vector<uint8_t>> parity_shards;
		if (!m_rs.encode(data_shards, parity_shards))
			return false;

		// 组装所有分片帧.
		frames.clear();
		frames.reserve(total);

		auto make_frame = [&](int index, const std::vector<uint8_t>& shard) {
			std::vector<uint8_t> frame;
			frame.reserve(fec_frame_header_size + shard.size());
			byteorder::put_u32_into(frame, fec_id);
			frame.push_back(static_cast<uint8_t>(total));
			frame.push_back(static_cast<uint8_t>(index));
			byteorder::put_u16_into(frame,
				static_cast<uint16_t>(ip_packet.size()));
			frame.insert(frame.end(), shard.begin(), shard.end());
			return frame;
		};

		for (int d = 0; d < ds; d++)
			frames.push_back(make_frame(d, data_shards[d]));
		for (int p = 0; p < ps; p++)
			frames.push_back(make_frame(ds + p, parity_shards[p]));

		return true;
	}

	//////////////////////////////////////////////////////////////////////////

	fec_decode_group::fec_decode_group(int data_shards, int parity_shards,
		std::chrono::milliseconds max_live_time)
		: m_data_shards(std::max(1, data_shards))
		, m_parity_shards(std::max(0, parity_shards))
		, m_max_live_time(max_live_time)
		, m_rs(m_data_shards, m_parity_shards)
	{}

	bool fec_decode_group::add(uint32_t fec_id, uint8_t index, uint8_t total,
		uint16_t original_len, std::string_view data,
		std::vector<uint8_t>& output)
	{
		if (index >= total)
			return false;
		if (total != m_rs.total_shards())
			return false;

		auto now = std::chrono::steady_clock::now();

		// 周期性清理过期分组, 避免高丢包环境下分组无限累积导致延迟劣化.
		if (++m_add_count % 512 == 0)
			purge();

		// 查找或创建分组.
		group* g = nullptr;
		for (auto& grp : m_groups)
		{
			if (grp.fec_id == fec_id)
			{
				g = &grp;
				break;
			}
		}

		if (!g)
		{
			m_groups.push_back(group{});
			g = &m_groups.back();
			g->fec_id = fec_id;
			g->total = total;
			g->original_len = original_len;
			g->shard_size = data.size();
			g->shards.assign(total, {});
			g->present.assign(total, false);
			g->last_seen = now;
		}
		else
		{
			// 使用该分组携带的原始长度.
			if (g->original_len == 0)
				g->original_len = original_len;
		}

		// 如果 shard_size 不同, 取较大者.
		if (data.size() > g->shard_size)
		{
			g->shard_size = data.size();
			for (auto& s : g->shards)
				s.resize(g->shard_size);
		}

		// 去重.
		if (g->present[index])
			return false;

		g->shards[index].assign(data.begin(), data.end());
		g->shards[index].resize(g->shard_size);
		g->present[index] = true;
		g->received++;
		g->last_seen = now;

		// 达到足够分片, 尝试恢复.
		if (g->received >= static_cast<std::size_t>(m_data_shards))
		{
			if (m_rs.reconstruct(g->shards, g->shard_size))
			{
				// 恢复成功, 拼接所有数据分片, 并按原始长度去除填充.
				output.clear();
				output.reserve(g->shard_size * m_data_shards);
				for (int d = 0; d < m_data_shards; d++)
				{
					auto& s = g->shards[d];
					output.insert(output.end(), s.begin(), s.end());
				}
				if (output.size() > g->original_len)
					output.resize(g->original_len);

				// 移除该分组.
				m_groups.erase(std::remove_if(m_groups.begin(), m_groups.end(),
					[fec_id](const group& grp) { return grp.fec_id == fec_id; }),
					m_groups.end());

				return true;
			}
		}

		return false;
	}

	std::size_t fec_decode_group::purge()
	{
		auto now = std::chrono::steady_clock::now();
		auto before = m_groups.size();
		m_groups.erase(std::remove_if(m_groups.begin(), m_groups.end(),
			[&](const group& grp) {
				return (now - grp.last_seen) > m_max_live_time;
			}), m_groups.end());
		return before - m_groups.size();
	}

} // namespace libavpn
