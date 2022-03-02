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

#include "utils/scoped_exit.hpp"
#include "utils/bitfield.hpp"
#include "utils/time_clock.hpp"
#include "utils/io.hpp"
#include "utils/logging.hpp"

namespace avpn {

	using timer = boost::asio::basic_waitable_timer<time_clock::steady_clock>;
	using namespace util;

	struct fec_group
	{
	public:
		const static size_t max_ptk_size = 512 * 1024;
		enum class fec_ip_state {
			ip_start = 0,
			ip_parsing = 1,
		};

		std::vector<boost::beast::multi_buffer> pkts_;
		uint32_t gid_{ 0 };
		bitfield bs_;
		int ps_{ 0 };
		size_t gsize_;
		int ds_{ 0 };
		int64_t total_{ 0 };
		timer::time_point time_;

		fec_group(fec_group&& pg) noexcept
			: pkts_(std::move(pg.pkts_))
			, gid_(pg.gid_)
			, bs_(pg.bs_)
			, ps_(pg.ps_)
			, gsize_(pg.gsize_)
			, ds_(pg.ds_)
			, total_(pg.total_)
			, time_(pg.time_)
		{
			pg.gid_ = 0;
			pg.pkts_.clear();
			pg.bs_.clear_all();
			pg.ds_ = -1;
			pg.ps_ = -1;
			pg.gsize_ = 0;
			pg.total_ = 0;
		}

		fec_group() = delete;
		fec_group(int data_shards, int parity_shards, int size)
		{
			BOOST_ASSERT(data_shards + parity_shards < 256
				&& "dataShards + parityShards >= 255");

			time_ = timer::clock_type::now();

			ds_ = data_shards;
			ps_ = parity_shards;
			gsize_ = (size_t)size;

			auto total = ds_ + ps_;
			bs_.resize(total, false);
			for (int i = 0; i < total; i++)
				pkts_.emplace_back(boost::beast::multi_buffer{ max_ptk_size });
		}

		void update(uint32_t gid, uint16_t pid, uint8_t* data, size_t size)
		{
			gid_ = gid;

			auto& pkt = pkts_[pid];
			auto p = pkt.prepare(size);

			boost::asio::buffer_copy(p, boost::asio::buffer(data, size));
			pkt.commit(size);
			bs_.set_bit(pid);

			// 这个group中接收到的所有字节总计.
			total_ += (int64_t)size;
		}

		// 完整接收.
		bool full() noexcept
		{
			return bs_.count() == (ds_ + ps_);
		}

		// 接收数据已达到可解码.
		bool accord() const
		{
			return bs_.count() >= ds_;
		}

		// 总数据量.
		size_t count() const
		{
			return bs_.count();
		}

		void parse_impl(std::string& ip,
			uint8_t* data_ptr, int data_size,
			int& left, int& whole, int& ip_size,
			fec_ip_state& state, std::vector<std::string>& result)
		{
			while (true)
			{
				uint8_t* bufptr = (uint8_t*)data_ptr + left;
				int bufsize = data_size - left;

				// 没有数据了, 跳向下一个.
				if (bufsize <= 0)
				{
					left = 0;
					break;
				}

				if (whole == 0)
					return;

				BOOST_ASSERT(whole > 0);

				switch (state)
				{
				case fec_ip_state::ip_start:
				{
					if (ip.size() < 4)
					{
						int n = 4 - (int)ip.size();
						n = std::min<int>((int)bufsize, n);

						ip.append((char*)bufptr, n);
						left += n;

						if (ip.size() < 4)
							continue;

						bufptr += n;
						bufsize -= n;
					}

					// 必然等于4.
					BOOST_ASSERT(ip.size() == 4);

					// 获取ip包大小.
					ip_size = ntohs(*(uint16_t*)(ip.data() + 2));
					BOOST_ASSERT(ip_size > 0);

					// 跳过已经拷贝的4字节head.
					ip_size -= 4;

					auto num = std::min<int>(ip_size, bufsize);

					// 如果ip包大小小于已有数据大小, 则直接拷入ip字符串.
					if (num == ip_size)
					{
						ip.append((char*)bufptr, num);
						whole -= (int)ip.size();
						result.emplace_back(std::move(ip));
						left += num;
					}
					else
					{
						// 否则拷入已有的部分ip数据到ip字符串, 然后接着拷.
						ip.append((char*)bufptr, num);
						left += num;
						ip_size -= num;
						state = fec_ip_state::ip_parsing;
					}
				}
				break;
				case fec_ip_state::ip_parsing:
				{
					auto num = std::min<int>(ip_size, bufsize);
					if (num == ip_size)
					{
						ip.append((char*)bufptr, num);
						whole -= (int)ip.size();
						result.emplace_back(std::move(ip));
						left += num;
						state = fec_ip_state::ip_start;
					}
					else
					{
						// 否则拷入已有的部分ip数据到ip字符串, 然后接着拷.
						ip.append((char*)bufptr, num);
						left += num;
						ip_size -= num;
						state = fec_ip_state::ip_parsing;
					}
				}
				break;
				}
			}
		}

		template<class Buf, class DataPtr, class DataSize>
		void group_parse(Buf& buffer, std::vector<std::string>& result,
			DataPtr data_ptr_func, DataSize data_size_func)
		{
			std::string ip;
			int left = 0;
			int ip_size = 0;
			int whole = (int)gsize_;
			fec_ip_state state = fec_ip_state::ip_start;

			for (auto i = 0; i < ds_; i++)
			{
				auto& d = buffer[i];
				if (d.size() == 0)
					continue;

				auto data_ptr = (uint8_t*)data_ptr_func(d);
				auto data_size = (int)data_size_func(d);

				parse_impl(ip, data_ptr, data_size,
					left, whole, ip_size, state, result);

				if (whole == 0)
					return;
			}
		}

		// rs解码数据, 返回的vector中每个元素将是一个完整的ip包.
		std::vector<std::string> decode()
		{
			if (!accord())
				return {};

			std::vector<std::vector<uint8_t>> data;

			fec::reedsolomon fec_dec(ds_, ps_);
			data.resize(ds_ + ps_);

			for (size_t i = 0; i < data.size(); i++)
			{
				auto& d = data[i];
				auto& s = pkts_[i];

				d.resize(s.size());
				boost::asio::buffer_copy(boost::asio::buffer(d), s.data());
			}

			// fec解码.
#if !defined(_DEBUG) && !defined(DEBUG)
			try {
#endif
				fec_dec.decode(data);
#if !defined(_DEBUG) && !defined(DEBUG)
			}
			catch (const std::exception& e) {
				LOG_WARN << "fec decode exception: " << e.what();
				return {};
			}
#endif

			std::vector<std::string> result;

			auto ptr_func = [](std::vector<uint8_t>& buf) -> const uint8_t* {
				return buf.data();
			};

			auto size_func = [](std::vector<uint8_t>& buf) -> size_t {
				return buf.size();
			};

			group_parse(data, result, ptr_func, size_func);

			return result;
		}

	private:
		fec_group(const fec_group&) = delete;
		fec_group& operator=(const fec_group&) = delete;
	};


	//////////////////////////////////////////////////////////////////////////

	class fec_cache
	{
	private:
		fec_cache(const fec_cache&) = delete;
		fec_cache& operator=(const fec_cache&) = delete;

	public:
		explicit fec_cache(int64_t max_cache_size = 64 * 1024 * 1024)
			: cache_size_limit_(max_cache_size)
		{}
		~fec_cache() = default;

		void reset()
		{
			groups_.clear();
			total_cache_size_ = 0;
			start_gid_ = 0;
		}

		void update(uint32_t gid, uint16_t pid,
			int data_shards, int parity_shards, int gsize,
			uint8_t* data, size_t data_size)
		{
			auto it = groups_.find(gid);
			if (it == groups_.end())
			{
				// 如果gid小于start_gid, 则表示数据已经过期
				// 不再需要了, 便可丢了.
				if (gid < start_gid_)
					return;

				// gid回环的时候, 如果接收到的gid小于
				// start_gid, 则由下判断确定丢弃过期数据.
				static auto boundary = std::numeric_limits<uint32_t>::max() - 65535;
				if (gid > boundary && start_gid_ < 65535)
					return;

				fec_group pkt(data_shards, parity_shards, gsize);
				pkt.update(gid, pid, data, data_size);
				groups_.emplace(gid, std::move(pkt));
			}
			else
			{
				auto& pkt = it->second;
				pkt.update(gid, pid, data, data_size);
			}

			total_cache_size_ += data_size;
		}

		int garbage_clean()
		{
			if (total_cache_size_ <= cache_size_limit_)
				return 0;

			int num = 0;
			for (auto it = groups_.begin(); it != groups_.end();)
			{
				auto& [gid, gop] = *it;

				start_gid_ = gid + 1;
				total_cache_size_ -= gop.total_;
				num++;
				groups_.erase(it++);

				if (total_cache_size_ <= cache_size_limit_)
					break;
			}

			return num;
		}

		std::vector<fec_group> acquire()
		{
			std::vector<fec_group> result;
			auto now = timer::clock_type::now();

			for (auto it = groups_.begin(); it != groups_.end();)
			{
				auto& [gid, gop] = *it;

				// 满足fec数量要求, 便取出来用于返回解码.
				if (gop.full() || gop.accord())
				{
					// 增加fec接收的gid, 自此小于start_gid的gop都将丢弃.
					if (start_gid_ == gop.gid_)
						start_gid_ = gop.gid_ + 1;

					// 计算fec cache总大小.
					total_cache_size_ -= gop.total_;
					BOOST_ASSERT(total_cache_size_ >= 0);

					// 返回此gop, 同时从cache中清除.
					result.emplace_back(std::move(gop));
					it = groups_.erase(it);

					continue;
				}
				else
				{
					// 清除严重超时的gop.
					if (now - gop.time_ >= std::chrono::seconds(30))
					{
						if (start_gid_ == gop.gid_)
							start_gid_ = gop.gid_ + 1;

						total_cache_size_ -= gop.total_;
						BOOST_ASSERT(total_cache_size_ >= 0);

						LOG_WARN << "clean timeout gop: " << gop.gid_
							<< ", total size: " << total_cache_size_;

						it = groups_.erase(it);
						continue;
					}
				}

				it++;
			}

			return result;
		}

	public:
		int64_t cache_size_limit_;
		std::map<uint32_t, fec_group> groups_;
		int64_t total_cache_size_ = 0;
		uint32_t start_gid_ = 0;
	};

}
