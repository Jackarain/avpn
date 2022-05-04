//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#include "utils/scoped_exit.hpp"

#include "avpn/fec_cache.hpp"

namespace avpn
{
	std::map<uint64_t, avpn::matrix> fec_decode_group::matrix_cache_;


	//////////////////////////////////////////////////////////////////////////
	packet_allocator::packet_allocator(
		std::size_t max_size /*= std::numeric_limits<std::size_t>::max()*/)
		: garbage_pool_(0)
		, max_size_(max_size)
	{}

	packet_allocator::~packet_allocator()
	{
		while (!garbage_pool_.empty())
		{
			uint8_t* ptr = nullptr;
			while (garbage_pool_.pop(ptr))
			{
				if (ptr)
					delete ptr;
			}
		}
	}

	uint8_t* packet_allocator::alloc_packet()
	{
		uint8_t* p = nullptr;

		if (garbage_size_ > 0)
		{
			// 成功则返回被回收的内存, 在返回前
			// 将内存块清0.
			if (garbage_pool_.pop(p))
			{
				garbage_size_--;
				std::memset(p, 0, 1450);
				return p;
			}
		}

		p = (uint8_t*)std::calloc(1, 1450);
		memory_size_ += 1450;
		return p;
	}

	void packet_allocator::free_packet(uint8_t* p)
	{
		// 如果垃圾大小超出最大设定大小, 则直接释放.
		if ((size_t)memory_size_ >= max_size_)
		{
			std::free((void*)p);
			memory_size_ -= 1450;
			return;
		}

		// 放入垃圾站, 用以重复利用.
		while (!garbage_pool_.push(p))
			;
		garbage_size_++;
	}

	std::size_t packet_allocator::total_size() const
	{
		return memory_size_;
	}

	void packet_allocator::set_max_size(size_t max_size)
	{
		max_size_ = max_size;
	}

	static packet_allocator global_allocator;

	void set_global_allocator_size(size_t max_size)
	{
		global_allocator.set_max_size(max_size);
	}

	void packet_free::operator()(void* p)
	{
		global_allocator.free_packet((uint8_t*)p);
	}


	//////////////////////////////////////////////////////////////////////////

	vpn_packet::vpn_packet()
		: data_(global_allocator.alloc_packet())
		, size_(0)
	{}

	vpn_packet::vpn_packet(vpn_packet&& p)
		: data_(std::move(p.data_))
		, size_(p.size_)
		, type_(p.type_)
	{
		p.size_ = 0;
	}

	vpn_packet& vpn_packet::operator=(vpn_packet&& p)
	{
		data_ = std::move(p.data_);
		size_ = p.size_;
		type_ = p.type_;
		p.size_ = 0;
		return *this;
	}

	uint8_t* vpn_packet::data()
	{
		BOOST_ASSERT(data_);
		return data_.get();
	}

	uint16_t vpn_packet::size()
	{
		return size_;
	}

	void vpn_packet::resize(size_t count)
	{
		size_ = (uint16_t)count;
	}

	vpn_packet_type vpn_packet::type() const
	{
		return type_;
	}

	void vpn_packet::type(vpn_packet_type t)
	{
		type_ = t;
	}

	//////////////////////////////////////////////////////////////////////////

	fec_encode_group::fec_encode_group(int data_shards, int parity_shards)
		: ds_(data_shards)
		, ps_(parity_shards)
		, pkts_(data_shards + parity_shards)
	{
		BOOST_ASSERT((data_shards + parity_shards) < 256 &&
			"fec_encode_group, dataShards + parityShards >= 255");
	}

	fec_encode_group::fec_encode_group(fec_encode_group&& pg) noexcept
		: ds_(pg.ds_)
		, ps_(pg.ps_)
		, gid_(pg.gid_)
		, total_(pg.total_)
		, pkts_(std::move(pg.pkts_))
	{
		pg.ds_ = 0;
		pg.ps_ = 0;
		pg.gid_ = 0;
		pg.total_ = 0;
	}

	void fec_encode_group::update(uint32_t gid, uint16_t pid, vpn_packet&& pkt)
	{
		BOOST_ASSERT(gid == gid_ || gid == 0);

		pkts_[pid] = std::move(pkt);
		gid_ = gid;

		total_++;
	}

	bool fec_encode_group::available() const
	{
		if (total_ == ds_)
			return true;
		return false;
	}


	//////////////////////////////////////////////////////////////////////////

	fec_decode_group::fec_decode_group(int data_shards, int parity_shards)
		: pkts_(data_shards + parity_shards)
		, bs_(data_shards + parity_shards)
		, ds_(data_shards)
		, ps_(parity_shards)
		, time_(asio_timer::clock_type::now())
	{
		BOOST_ASSERT((data_shards + parity_shards) < 256 &&
			"fec_decode_group, dataShards + parityShards >= 255");
	}

	fec_decode_group::fec_decode_group(fec_decode_group&& pg) noexcept
		: pkts_(std::move(pg.pkts_))
		, gid_(pg.gid_)
		, bs_(std::move(pg.bs_))
		, ds_(pg.ds_)
		, ps_(pg.ps_)
		, total_(pg.total_)
		, time_(pg.time_)
	{
		pg.gid_ = 0;
		pg.pkts_.clear();
		pg.ds_ = -1;
		pg.ps_ = -1;
		pg.total_ = 0;
	}

	void fec_decode_group::update(uint32_t gid, uint16_t pid, vpn_packet&& pkt)
	{
		BOOST_ASSERT(gid == gid_ || gid == 0);
		gid_ = gid;

		pkts_[pid] = std::move(pkt);
		bs_.set_bit(pid);

		pkt.resize(1450);
		total_ += 1450;
	}

	bool fec_decode_group::full() noexcept
	{
		return bs_.count() == (ds_ + ps_);
	}

	bool fec_decode_group::available() const
	{
		return bs_.count() >= ds_;
	}

	std::vector<int> fec_decode_group::lost() const
	{
		std::vector<int> result;

		for (auto i = 0; i < ds_; i++)
		{
			if (!bs_[i])
				result.push_back(i);
		}

		return result;
	}

	void fec_decode_group::set_used()
	{
		used_ = true;
		pkts_.clear();
	}

	bool fec_decode_group::used() const
	{
		return used_;
	}

	bool fec_decode_group::decode()
	{
		BOOST_ASSERT(available());

		avpn::matrix* matrix_ptr = nullptr;
		// 找解码缓冲.
		int64_t idx = (ds_ << 16) | ps_;

		auto it = matrix_cache_.find(idx);
		if (it == matrix_cache_.end())
		{
			matrix_cache_[idx] =
				avpn::reedsolomon::build_matrix((size_t)(ds_ + ps_), ds_);
			matrix_ptr = &matrix_cache_[idx];
		}
		else
		{
			matrix_ptr = &it->second;
		}

		avpn::reedsolomon fec_dec(ds_, ps_, *matrix_ptr);

		// fec解码.
		try {
			fec_dec.decode(pkts_);
		}
		catch (const std::exception& e) {
			LOG_WARN << "fec decode exception: " << e.what();
			return false;
		}

		return true;
	}


	//////////////////////////////////////////////////////////////////////////

	fec_recover::fec_recover(int64_t max_size /*= 64 * 1024 * 1024*/)
		: cache_size_limit_(max_size)
	{
		set_global_allocator_size(max_size);
	}

	void fec_recover::reset()
	{
		groups_.clear();
		results_.clear();
	}

	void fec_recover::update(uint32_t gid, uint16_t pid,
		int ds, int ps, vpn_packet&& pkt)
	{
		auto it = groups_.find(gid);
		if (it == groups_.end())
		{
			fec_decode_group gop(ds, ps);
			gop.update(gid, pid, std::move(pkt));

			groups_.emplace(gid, std::move(gop));
		}
		else
		{
			auto& gop = it->second;
			if (gop.used())
				return;

			gop.update(gid, pid, std::move(pkt));
			if (!gop.available())
				return;

			scoped_exit se([&gop]() mutable { gop.set_used(); });

			auto lost_pkts = gop.lost();
			if (lost_pkts.empty())
				return;

			if (!gop.decode())
				return;

			for (auto& index : lost_pkts)
				results_.emplace_back(std::move(gop.pkts_[index]));
		}
	}

	int64_t fec_recover::garbage_clean()
	{
		auto memory_used = [this]()
		{
			return (int64_t)(global_allocator.total_size()
				+ groups_.size() * sizeof(fec_decode_group));
		};

		int64_t total = memory_used();

		if (total <= cache_size_limit_ && groups_.size() < 40000)
			return 0;

		int64_t bytes = 0;
		for (auto it = groups_.begin(); it != groups_.end();)
		{
			groups_.erase(it++);
			bytes = memory_used();

			if (bytes <= cache_size_limit_ && groups_.size() < 40000)
				break;
		}

		return total - bytes;
	}

	std::vector<vpn_packet> fec_recover::acquire()
	{
		return std::move(results_);
	}
}
