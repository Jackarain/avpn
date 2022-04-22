//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#pragma once

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

#include "utils/scoped_exit.hpp"
#include "utils/bitfield.hpp"
#include "utils/time_clock.hpp"
#include "utils/io.hpp"
#include "utils/logging.hpp"
#include "utils/misc.hpp"
#include "utils/fileop.hpp"

#include "avpn/reedsolomon.hpp"

namespace fec {

	using namespace util;

	struct fec_group
	{
	private:
		fec_group(const fec_group&) = delete;
		fec_group& operator=(const fec_group&) = delete;

	public:
		const static size_t max_ptk_size = 512 * 1024;

		enum class fec_ip_state {
			ip_start = 0,
			ip_parsing = 1,
		};

		fec_group() = delete;
		fec_group(int data_shards, int parity_shards, int size);

		fec_group(fec_group&& pg) noexcept;

		// 更新这个gop的数据.
		void update(uint32_t gid, uint16_t pid, uint8_t* data, size_t size);

		// 完整接收.
		bool full() noexcept;

		// 接收数据已达到可解码.
		bool accord() const;

		// 总数据量.
		size_t count() const;

		bool parse_impl(std::string& ip,
			uint8_t* data_ptr, int data_size,
			int& left, int& whole, int& ip_size,
			fec_ip_state& state, std::vector<std::string>& result);

		template<class Buf, class DataPtr, class DataSize>
		void group_parse(Buf& buffer, std::vector<std::string>& result,
			DataPtr data_ptr_func, DataSize data_size_func)
		{
			std::string ip;
			int left = 0;
			int ip_size = 0;
			int whole = (int)gsize_;
			fec_ip_state state = fec_ip_state::ip_start;
			bool corrupted = false;

			for (auto i = 0; i < ds_; i++)
			{
				auto& d = buffer[i];
				if (d.size() == 0)
					continue;

				auto data_ptr = (uint8_t*)data_ptr_func(d);
				auto data_size = (int)data_size_func(d);

				bool ret = parse_impl(ip, data_ptr, data_size,
					left, whole, ip_size, state, result);
				if (whole == 0)
					return;

				if (!ret)
				{
					corrupted = true;
					break;
				}
			}

			if (corrupted)
			{
				auto all_size = buffer.size();

				LOG_WARN << "fec corrupted: gsize: " << gsize_ << ", gid: "
					<< gid_ << ", total: " << total_ << ", ds: " << ds_
					<< ", ps: " << ps_ << ", all: " << all_size;

				// dump corrupted data.
				auto params = std::format("gid={},gsize={},total={},ds={},ps={}",
					gid_, gsize_, total_, ds_, ps_);
				fileop::write(std::format("ds{}.param", gid_), params);

				for (size_t i = 0; i < all_size; i++)
				{
					auto& d = buffer[i];
					fileop::write(std::format("ds{}-{}.dat", gid_, i), d);
				}
			}
		}

		// rs解码数据, 返回的vector中每个元素将是一个完整的ip包.
		std::vector<std::string> decode();
		std::vector<std::string> decode(const fec::matrix& m);

	public:
		std::vector<std::vector<uint8_t>> pkts_;
		uint32_t gid_{ 0 };
		bitfield bs_;
		int ps_{ 0 };
		size_t gsize_;
		int ds_{ 0 };
		int64_t total_{ 0 };
		timer::time_point time_;
		static std::map<uint64_t, fec::matrix> matrix_cache_;
	};


	//////////////////////////////////////////////////////////////////////////

	class fec_cache
	{
	private:
		fec_cache(const fec_cache&) = delete;
		fec_cache& operator=(const fec_cache&) = delete;

	public:
		explicit fec_cache(int64_t max_cache_size = 64 * 1024 * 1024);
		~fec_cache() = default;

		void reset();

		void update(uint32_t gid, uint16_t pid,
			int data_shards, int parity_shards, int gsize,
			uint8_t* data, size_t data_size);

		int garbage_clean();
		std::vector<fec_group> acquire();

	public:
		int64_t cache_size_limit_;
		std::map<uint32_t, fec_group> groups_;
		std::set<uint32_t> expired_;
		std::vector<fec_group> result_;
		int64_t total_cache_size_ = 0;
	};

}
