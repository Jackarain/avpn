//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#include "utils/scoped_exit.hpp"
#include "avpn/fec_cache.hpp"
#include "avpn/protocol.hpp"

namespace avpn
{
	std::map<uint64_t, avpn::matrix> fec_decode_group::matrix_cache_;
	std::map<uint64_t, avpn::matrix> fec_encode_group::matrix_cache_;


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
				std::memset(p, 0, avpn_packet_size);
				return p;
			}
		}

		p = (uint8_t*)std::calloc(1, avpn_packet_size);
		memory_size_ += avpn_whole_packet_size;
		return p;
	}

	void packet_allocator::free_packet(uint8_t* p)
	{
		// 如果垃圾大小超出最大设定大小, 则直接释放.
		if ((size_t)memory_size_ >= max_size_)
		{
			std::free((void*)p);
			memory_size_ -= avpn_whole_packet_size;
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

	packet_allocator* static_packet_allocator()
	{
		return &global_allocator;
	}

	//////////////////////////////////////////////////////////////////////////

	fec_encode_group::fec_encode_group(int data_shards, int parity_shards)
		: ds_(data_shards)
		, ps_(parity_shards)
		, shards_(ds_ + ps_)
		, pkts_(data_shards + parity_shards)
	{
		BOOST_ASSERT((data_shards + parity_shards) < 256 &&
			"fec_encode_group, dataShards + parityShards >= 255");
	}

	fec_encode_group::fec_encode_group(fec_encode_group&& pg) noexcept
		: ds_(pg.ds_)
		, ps_(pg.ps_)
		, shards_(ds_ + ps_)
		, gid_(pg.gid_)
		, pid_(pg.pid_)
		, pkts_(std::move(pg.pkts_))
	{
		pg.ds_ = 0;
		pg.ps_ = 0;
		pg.shards_ = 0;
		pg.gid_ = 1;
		pg.pid_ = 0;
	}

	void fec_encode_group::make_fec_header(vpn_packet& pkt, uint32_t src)
	{
		// 构造一个sv.
		std::string_view sv((char*)pkt.payload(), pkt.payload_size());

		// 构造transfer数据包.
		BOOST_ASSERT(pid_ < shards_);
		make_transfer(pkt, src, gid_, pid_, sv);
	}

	void fec_encode_group::make_fec_compress_header(
		vpn_packet& pkt, uint32_t src)
	{
		// 构造一个sv.
		std::string_view sv((char*)pkt.payload(), pkt.payload_size());

		// 构造transfer_compress数据包.
		BOOST_ASSERT(pid_ < shards_);
		make_transfer_compress(pkt, src, gid_, pid_, 1, sv);
	}

	bool fec_encode_group::encode(vpn_packet_ptr& pkt, uint32_t src/* = 0 */)
	{
		pkts_[pid_++] = pkt;

		if (pid_ == ds_)
		{
			// 立即编码.
			if (!do_encode())
				return false;

			// 编码完后填充协议头.
			for (; pid_ < shards_; pid_++)
			{
				auto& ptr = pkts_[pid_];
				if (!ptr)
					continue;

				ptr->resize(avpn_packet_size);
				ptr->payload_size(avpn_payload_size);

				make_fec_header(*ptr, src);
			}

			// gop id自增, 开始下一组fec编码.
			gid_++;
			pid_ = 0;

			return true;
		}

		return false;
	}

	bool fec_encode_group::do_encode()
	{
		avpn::matrix* matrix_ptr = nullptr;

		// 找编码缓冲.
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

		avpn::reedsolomon fec_enc(ds_, ps_, *matrix_ptr);

		// fec编码.
		try {
			fec_enc.encode(pkts_);
		}
		catch (const std::exception& e) {
			LOG_WARN << "fec encode exception: " << e.what();
			return false;
		}

		return true;
	}

	//////////////////////////////////////////////////////////////////////////

	fec_decode_group::fec_decode_group(int data_shards, int parity_shards)
		: pkts_(data_shards + parity_shards)
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

	void fec_decode_group::update(
		uint32_t gid, uint16_t pid, vpn_packet_ptr& pkt)
	{
		BOOST_ASSERT(gid > 0);
		gid_ = gid;

		pkts_[pid] = pkt;

		pkt->resize(avpn_packet_size);
		total_ += avpn_packet_size;
	}

	bool fec_decode_group::available() const
	{
		int sum = 0;
		for (auto& p : pkts_)
			if (p) sum++;

		return sum >= ds_;
	}

	std::vector<int> fec_decode_group::lost() const
	{
		std::vector<int> result;

		for (auto i = 0; i < ds_; i++)
		{
			if (!pkts_[i])
				result.push_back(i);
		}

		return result;
	}

	void fec_decode_group::set_expired()
	{
		used_ = true;
		pkts_.clear();
	}

	bool fec_decode_group::expired() const
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
				reedsolomon::build_matrix((size_t)(ds_ + ps_), ds_);
			matrix_ptr = &matrix_cache_[idx];
		}
		else
		{
			matrix_ptr = &it->second;
		}

		reedsolomon fec_dec(ds_, ps_, *matrix_ptr);

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

	fec_decode_group* fec_recover::find(uint32_t gid)
	{
		auto it = groups_.find(gid);
		if (it == groups_.end())
			return nullptr;
		return &it->second;
	}

	void fec_recover::update(fec_decode_group* opt,
		uint32_t gid, uint16_t pid,
		int ds, int ps, vpn_packet_ptr& pkt)
	{
		if (!opt)
		{
			fec_decode_group gop(ds, ps);
			gop.update(gid, pid, pkt);
			groups_.emplace(gid, std::move(gop));
			return;
		}

		auto& gop = *opt;
		if (gop.expired())
			return;

		gop.update(gid, pid, pkt);
		if (!gop.available())
			return;

		scoped_exit se([this, &gop, &gid]() mutable
			{
				gop.set_expired();

				for (auto it = groups_.begin();
					it != groups_.end();)
				{
					auto& [i, g] = *it;

					if (g.gid_ + 64 > gid)
						break;

					it = groups_.erase(it);
				}
			});

		auto lost_pkts = gop.lost();
		if (lost_pkts.empty())
			return;

		// gop解码.
		if (!gop.decode())
			return;

		// 解码后将丢失的pkt放入result容器中.
		for (auto& index : lost_pkts)
		{
			auto& p = gop.pkts_[index];

			p->gid_ = gid;
			p->pid_ = (uint8_t)index;

			results_.emplace_back(std::move(p));
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

	std::vector<vpn_packet_ptr> fec_recover::acquire()
	{
		return std::move(results_);
	}
}
