//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#include "avpn/fec_cache.hpp"

namespace fec
{
	std::map<uint64_t, fec::matrix> fec_group::matrix_cache_;

	fec_group::fec_group(int data_shards, int parity_shards, int size)
	{
		BOOST_ASSERT(data_shards + parity_shards < 256
			&& "dataShards + parityShards >= 255");

		time_ = timer::clock_type::now();

		ds_ = data_shards;
		ps_ = parity_shards;
		gsize_ = (size_t)size;

		auto total = ds_ + ps_;
		bs_.resize(total, false);
		pkts_.resize(total);
	}

	fec_group::fec_group(fec_group&& pg) noexcept
		: pkts_(std::move(pg.pkts_))
		, gid_(pg.gid_)
		, bs_(std::move(pg.bs_))
		, ps_(pg.ps_)
		, gsize_(pg.gsize_)
		, ds_(pg.ds_)
		, total_(pg.total_)
		, time_(pg.time_)
	{
		pg.gid_ = 0;
		pg.pkts_.clear();
		pg.ds_ = -1;
		pg.ps_ = -1;
		pg.gsize_ = 0;
		pg.total_ = 0;
	}

	void fec_group::update(uint32_t gid, uint16_t pid, uint8_t* data, size_t size)
	{
		gid_ = gid;

		// COPY数据到容器.
		auto& pkt = pkts_[pid];
		pkt = std::vector<uint8_t>(data, data + size);
		bs_.set_bit(pid);

		// 这个group中接收到的所有字节总计.
		total_ += (int64_t)size;
	}

	bool fec_group::full() noexcept
	{
		return bs_.count() == (ds_ + ps_);
	}

	bool fec_group::accord() const
	{
		return bs_.count() >= ds_;
	}

	size_t fec_group::count() const
	{
		return bs_.count();
	}

	bool fec_group::parse_impl(std::string& ip, uint8_t* data_ptr,
		int data_size, int& left, int& whole, int& ip_size,
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
				return true;

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

				BOOST_ASSERT(ip.size() == 4);
				// 必然等于4, 如果不是, 则表示此段解析代码有问题.
				if (ip.size() != 4)
					return false;

				// 获取ip包大小.
				ip_size = ntohs(*(uint16_t*)(ip.data() + 2));

				// ip包至少20大小, 如果不是, 则表示数据损坏.
				if (ip_size < 20)
					return false;

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

		return true;
	}

	std::vector<std::string> fec_group::decode()
	{
		if (!accord())
			return {};

		int64_t idx = (ds_ << 16) | ps_;
		auto it = matrix_cache_.find(idx);
		if (it == matrix_cache_.end())
		{
			matrix_cache_[idx] = fec::reedsolomon::build_matrix((size_t)(ds_ + ps_), ds_);
			it = matrix_cache_.find(idx);
		}

		fec::reedsolomon fec_dec(ds_, ps_, it->second);

		// fec解码.
#if !defined(_DEBUG) && !defined(DEBUG)
		try {
#endif
			fec_dec.decode(pkts_);
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

		group_parse(pkts_, result, ptr_func, size_func);

		return result;
	}

	std::vector<std::string> fec_group::decode(const fec::matrix& m)
	{
		if (!accord())
			return {};

		fec::reedsolomon fec_dec(ds_, ps_, m);

		// fec解码.
#if !defined(_DEBUG) && !defined(DEBUG)
		try {
#endif
			fec_dec.decode(pkts_);
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

		group_parse(pkts_, result, ptr_func, size_func);

		return result;
	}


	//////////////////////////////////////////////////////////////////////////

	fec_cache::fec_cache(int64_t max_cache_size /*= 64 * 1024 * 1024*/)
		: cache_size_limit_(max_cache_size)
	{}

	void fec_cache::reset()
	{
		groups_.clear();
		expired_.clear();
		result_.clear();

		total_cache_size_ = 0;
	}

	void fec_cache::update(uint32_t gid, uint16_t pid,
		int data_shards, int parity_shards,
		int gsize, uint8_t* data, size_t data_size)
	{
		auto it = groups_.find(gid);
		if (it == groups_.end())
		{
			if (expired_.contains(gid))
				return;

			fec_group pkt(data_shards, parity_shards, gsize);
			pkt.update(gid, pid, data, data_size);
			groups_.emplace(gid, std::move(pkt));
		}
		else
		{
			auto& pkt = it->second;
			pkt.update(gid, pid, data, data_size);

			// 保存已经可用的pkt.
			if (pkt.accord())
			{
				expired_.insert(gid);
				result_.emplace_back(std::move(pkt));
				groups_.erase(it);
			}
		}

		total_cache_size_ += data_size;
	}

	int fec_cache::garbage_clean()
	{
		if (expired_.size() > 2048)
		{
			int num = 0;
			for (auto it = expired_.begin();
				it != expired_.end() && num <= 1024; num++)
			{
				expired_.erase(it++);
			}
		}

		if (total_cache_size_ <= cache_size_limit_)
			return 0;

		int bytes_num = 0;
		for (auto it = groups_.begin(); it != groups_.end();)
		{
			auto& [gid, gop] = *it;

			total_cache_size_ -= gop.total_;
			bytes_num += (int)gop.total_;
			groups_.erase(it++);

			if (total_cache_size_ <= cache_size_limit_)
				break;
		}

		return bytes_num;
	}

	std::vector<fec::fec_group> fec_cache::acquire()
	{
		for (const auto& gop : result_)
			total_cache_size_ -= gop.total_;

		return std::move(result_);
	}

}
