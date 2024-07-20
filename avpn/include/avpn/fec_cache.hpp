//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#pragma once

#include "utils/scoped_exit.hpp"
#include "utils/io.hpp"
#include "utils/logging.hpp"
#include "utils/misc.hpp"
#include "utils/fileop.hpp"

#include "avpn/reedsolomon.hpp"
#include "avpn/endpoint_pair.hpp"
#include "avpn/vpn_packet.hpp"

#ifdef __clang__
#	pragma clang diagnostic push
#	pragma clang diagnostic ignored "-Wambiguous-reversed-operator"
#endif
#include <boost/lockfree/queue.hpp>
#ifdef __clang__
#	pragma clang diagnostic pop
#endif // __clang__

#include <boost/assert.hpp>

#include <cinttypes>
#include <vector>
#include <algorithm>
#include <limits>
#include <set>
#include <map>
#include <list>
#include <cstdlib>
#include <memory>
#include <atomic>


namespace avpn {


	//////////////////////////////////////////////////////////////////////////
	// 一个带垃圾回收的无锁vpn_packet全局分配器.
	class packet_allocator
	{
		packet_allocator(const packet_allocator&) = delete;
		packet_allocator& operator=(const packet_allocator&) = delete;

	public:
		explicit packet_allocator(std::size_t max_size
			= std::numeric_limits<std::size_t>::max());
		~packet_allocator();

	public:
		uint8_t* alloc_packet();
		void free_packet(uint8_t* p);
		std::size_t race() const;
		std::size_t total_size() const;
		void release();
		void set_max_size(size_t max_size);

	private:
		boost::lockfree::queue<uint8_t*> garbage_pool_;
		std::atomic_int64_t garbage_size_{ 0 };
		std::size_t max_size_;
		std::atomic_int64_t memory_size_{ 0 };
		std::size_t race_{ 0 };
	};

	// 设置分配器大小.
	void set_global_allocator_size(size_t max_size);

	// 返回全局分配器指针.
	packet_allocator* static_packet_allocator();


	//////////////////////////////////////////////////////////////////////////
	// LRU matrix cache.
	class lru_matrix_cache
	{
	private:
		lru_matrix_cache(const lru_matrix_cache&) = delete;
		lru_matrix_cache& operator=(const lru_matrix_cache&) = delete;

		typedef typename std::pair<uint64_t, matrix> key_value;
		typedef typename std::list<key_value>::iterator list_iterator_type;

	public:
		lru_matrix_cache(size_t n = 0)
			: m_max_size(n)
		{}
		~lru_matrix_cache() = default;

		lru_matrix_cache(lru_matrix_cache&&) = default;
		lru_matrix_cache& operator=(lru_matrix_cache&&) = default;

	public:
		void put(uint64_t index, const matrix& val)
		{
			m_list.emplace_front(index, val);

			auto it = m_rmatrixs.find(index);
			if (it != m_rmatrixs.end())
			{
				m_list.erase(it->second);
				m_rmatrixs.erase(it);
			}

			m_rmatrixs[index] = m_list.begin();

			if (m_rmatrixs.size() > m_max_size)
			{
				auto last = m_list.end();
				last--;
				m_rmatrixs.erase(last->first);
				m_list.pop_back();
			}
		}

		std::optional<matrix> get(uint64_t index)
		{
			auto it = m_rmatrixs.find(index);
			if (it == m_rmatrixs.end())
				return {};

			m_list.splice(m_list.begin(), m_list, it->second);
			return it->second->second;
		}

		void set_capacity(int size)
		{
			m_max_size = size;
		}

	private:
		std::list<key_value> m_list;
		std::unordered_map<uint64_t, list_iterator_type> m_rmatrixs;
		size_t m_max_size;
	};

	//////////////////////////////////////////////////////////////////////////
	// fec编码分组.
	struct fec_encode_group
	{
	private:
		fec_encode_group(const fec_encode_group&) = delete;
		fec_encode_group& operator=(const fec_encode_group&) = delete;
		fec_encode_group() = delete;

	public:
		fec_encode_group(int data_shards, int parity_shards);
		fec_encode_group(fec_encode_group&& pg) noexcept;

	public:
		// 判断是否存储已编码的fec数据.
		std::vector<vpn_packet_ptr> acquire();

		// 生成正常fec数据.
		void make_fec_normal(vpn_packet& pkt, uint32_t src);

		// 生成压缩fec数据.
		void make_fec_zstd(vpn_packet& pkt, uint32_t src);

	private:
		std::tuple<uint64_t, uint32_t, uint8_t> fetch_ids();
		bool do_encode();

	public:
		int ds_{ 0 };
		int ps_{ 0 };
		int shards_{ 0 };
		int64_t current_index_{ 0 };
		std::vector<vpn_packet_ptr> pkts_;
		static inline std::map<uint64_t, avpn::matrix> matrix_cache_;
	};


	//////////////////////////////////////////////////////////////////////////
	// fec解码分组
	struct fec_decode_group
	{
	private:
		fec_decode_group(const fec_decode_group&) = delete;
		fec_decode_group& operator=(const fec_decode_group&) = delete;
		fec_decode_group() = delete;

	public:
		fec_decode_group(int data_shards, int parity_shards,
			int matrix_cache = 16);
		fec_decode_group(fec_decode_group&& pg) noexcept;

		// 更新这个gop的数据.
		// gid 表示 group id;
		// pid 表示 packet id, 即在这个group中的index;
		// pkt 实际数据, 作为右值移动到fec_group中存储
		//     以备将来使用;
		void update(uint64_t gid, uint64_t pid, vpn_packet_ptr& pkt);

		// 可用, 只要能完整解码此gop, 则表示可用.
		bool available() const;
		// 丢失的索引, 如果未发生丢失, 则返回空.
		std::vector<int> lost() const;

		// 设置/返回为已经被用过的.
		void set_expired();
		bool expired() const;

		// fec解码数据.
		bool decode();

	public:
		std::vector<vpn_packet_ptr> pkts_;
		uint64_t gid_{ 0 };
		int ds_{ 0 };
		int ps_{ 0 };
		int64_t total_{ 0 };
		asio_timer::time_point time_;
		std::atomic_bool used_{ false };
		static inline std::map<uint64_t, matrix> matrix_cache_;
		static inline lru_matrix_cache rmatrix_cache_;
		// static inline std::list<int> matrix_cb_;
		// static inline std::unordered_map<uint64_t, matrix> rmatrix_cache_;
	};


	//////////////////////////////////////////////////////////////////////////
	// fec 恢复器.
	class fec_recover
	{
	private:
		fec_recover(const fec_recover&) = delete;
		fec_recover& operator=(const fec_recover&) = delete;

	public:
		explicit fec_recover(int matrix_cache, int64_t max_size = 64 * 1024 * 1024);
		~fec_recover() = default;

		void reset();

		// 更新fec恢复缓冲, 返回2个bool
		// 第1个bool表示是这个gop是否完整, 如果已经完整表示fec已经恢复
		// 出已丢的数据包.
		// 第2个bool表示这个index是否过期, 如果过期则可直接跳过.
		std::tuple<bool, bool> update(uint64_t gid, uint64_t pid,
			int ds, int ps, time_point now, vpn_packet& pkt);

		std::vector<vpn_packet_ptr> acquire();

	public:
		int matrix_cache_;
		int64_t cache_size_limit_;
		uint64_t early_packet_index_{ 0 };
		std::map<uint64_t, fec_decode_group> groups_;
		std::vector<vpn_packet_ptr> results_;
	};
}
