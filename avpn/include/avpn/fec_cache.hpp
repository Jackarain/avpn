//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#pragma once

#include "utils/scoped_exit.hpp"
#include "utils/bitfield.hpp"
#include "utils/io.hpp"
#include "utils/logging.hpp"
#include "utils/misc.hpp"
#include "utils/fileop.hpp"

#include "avpn/reedsolomon.hpp"

#include <boost/lockfree/queue.hpp>

#include <boost/assert.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/beast/core/multi_buffer.hpp>
#include <boost/asio.hpp>

#include <cinttypes>
#include <vector>
#include <algorithm>
#include <limits>
#include <set>
#include <map>
#include <cstdlib>
#include <memory>
#include <atomic>


namespace fec {

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
		std::size_t total_size() const;
		void set_max_size(size_t max_size);

	private:
		boost::lockfree::queue<uint8_t*> garbage_pool_;
		std::atomic_int64_t garbage_size_{ 0 };
		std::size_t max_size_;
		std::atomic_int64_t memory_size_{ 0 };
	};

	// 设置分配器大小.
	void set_global_allocator_size(size_t max_size);

	struct packet_free
	{
		void operator()(void* p);
	};


	//////////////////////////////////////////////////////////////////////////
	// vpn数据包定义.
	enum vpn_packet_type
	{
		pkt_tcp = 0x06,
		pkt_udp = 0x11,
		pkt_icmp = 0x01,
	};
	struct vpn_packet
	{
	private:
		vpn_packet(const vpn_packet&) = delete;
		vpn_packet& operator=(const vpn_packet&) = delete;

	public:
		vpn_packet();
		vpn_packet(vpn_packet&&);
		vpn_packet& operator=(vpn_packet&&);
		~vpn_packet() = default;

		uint8_t* data();

		uint16_t size();
		void resize(size_t count);

		vpn_packet_type type() const;
		void type(vpn_packet_type t);

	public:
		std::unique_ptr<uint8_t, packet_free> data_;
		uint16_t size_;
		vpn_packet_type type_;
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
		// 更新这个gop的数据.
		// gid 表示 group id;
		// pid 表示 packet id, 即在这个group中的index;
		// pkt 实际数据, 作为右值移动到fec_group中存储
		//     以备将来使用;
		void update(uint32_t gid, uint16_t pid, vpn_packet&& pkt);

		// 数据已达到可编码.
		bool available() const;

	public:
		int ds_{ 0 };
		int ps_{ 0 };
		uint32_t gid_{ 0 };
		int64_t total_{ 0 };
		std::vector<vpn_packet> pkts_;
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
		void update(uint32_t gid, uint16_t pid, vpn_packet&& pkt);

		// 完整接收.
		bool full() noexcept;

		// 可用, 只要能完整解码此gop, 则表示可用.
		bool available() const;
		// 丢失的索引, 如果未发生丢失, 则返回空.
		std::vector<int> lost() const;

		// 设置为已经被用过的.
		void set_used();
		// 返回是否被用过.
		bool used() const;

		// fec解码数据.
		bool decode();

	public:
		std::vector<vpn_packet> pkts_;
		uint32_t gid_{ 0 };
		bitfield bs_;
		int ds_{ 0 };
		int ps_{ 0 };
		int64_t total_{ 0 };
		timer::time_point time_;
		std::atomic_bool used_{ false };
		static std::map<uint64_t, fec::matrix> matrix_cache_;
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

		void update(uint32_t gid, uint16_t pid,
			int ds, int ps, vpn_packet&& pkt);

		int64_t garbage_clean();
		std::vector<vpn_packet> acquire();

	public:
		int64_t cache_size_limit_;
		std::map<uint32_t, fec_decode_group> groups_;
		std::vector<vpn_packet> results_;
	};
}
