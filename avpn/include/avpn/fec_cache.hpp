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
#include <cstdlib>
#include <memory>
#include <atomic>


namespace avpn {

	using namespace util;

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
		fec_decode_group(int data_shards, int parity_shards);
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
		static inline std::map<uint64_t, avpn::matrix> matrix_cache_;
	};


	//////////////////////////////////////////////////////////////////////////
	// fec 恢复器.
	class fec_recover
	{
	private:
		fec_recover(const fec_recover&) = delete;
		fec_recover& operator=(const fec_recover&) = delete;

	public:
		explicit fec_recover(int64_t max_size = 64 * 1024 * 1024);
		~fec_recover() = default;

		void reset();

		std::tuple<bool, bool> update(uint64_t gid, uint64_t pid,
			int ds, int ps, vpn_packet& pkt);

		int64_t garbage_clean();
		std::vector<vpn_packet_ptr> acquire();

	public:
		int64_t cache_size_limit_;
		std::map<uint64_t, fec_decode_group> groups_;
		std::vector<vpn_packet_ptr> results_;
	};
}
