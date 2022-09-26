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
		memory_size_ += avpn_packet_memory_size;
		return p;
	}

	void packet_allocator::free_packet(uint8_t* p)
	{
		// 如果垃圾大小超出最大设定大小, 则直接释放.
		if ((size_t)memory_size_ >= max_size_)
		{
			std::free((void*)p);
			memory_size_ -= avpn_packet_memory_size;
			return;
		}

		// 放入垃圾站, 用以重复利用.
		while (!garbage_pool_.push(p))
			race_++;
		garbage_size_++;
	}

	std::size_t packet_allocator::race() const
	{
		return race_;
	}

	std::size_t packet_allocator::total_size() const
	{
		return memory_size_;
	}

	void packet_allocator::release()
	{
		memory_size_ -= avpn_packet_memory_size;
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
		, index_(pg.index_)
		, pkts_(std::move(pg.pkts_))
	{
		pg.ds_ = 0;
		pg.ps_ = 0;
		pg.shards_ = 0;
		pg.index_ = 0;
	}

	std::vector<avpn::vpn_packet_ptr> fec_encode_group::acquire()
	{
		std::vector<avpn::vpn_packet_ptr> paritys;

		if (ds_ == 1)
		{
			return paritys;
		}

		for (int i = ds_; i < shards_; i++)
		{
			auto p = std::move(pkts_[i]);
			if (!p)
				break;

			paritys.emplace_back(std::move(p));
		}

		return paritys;
	}

	void fec_encode_group::make_fec_normal(vpn_packet& pkt, uint32_t src)
	{
		// 获取当前fec编码index以及gid,pid值.
		auto [index, gid, pid] = fetch_ids();

		// 获取ip包数据用于计算transfer协议.
		std::string_view sv((char*)pkt.payload(), pkt.payload_size());

		// pid不为0, 倍发模式不再作fec编码, 仅更新pid即可.
		if (ds_ == 1 && pid != 0)
		{
			make_transfer(pkt, src, index, sv);
			pkt.index_ = index;
			return;
		}

		// 构造transfer数据包.
		make_transfer(pkt, src, index, sv);

		// 倍发模式不再作fec编码.
		if (ds_ <= 1)
			return;

		// 保存到fec编码缓冲.
		pkts_[pid] = dup_vpn_packet_ptr(pkt);

		// 判断fec编码是否达到可实施fec编码大小要求.
		// 如果达到, 则直接进行fec编码.
		if (pid + 1 == ds_)
		{
			// 执行fec编码.
			if (!do_encode())
				return;

			// 编码完后, 从编码缓冲中遍历编码出来的fec编码数
			// 据包, 并逐一填充协议头.
			for (pid++; pid < shards_; pid++)
			{
				auto& ptr = pkts_[pid];
				if (!ptr)
					continue;

				ptr->resize(avpn_packet_size);
				ptr->payload_size(avpn_static_mtu);

				auto [findex, fgid, fpid] = fetch_ids();
				ptr->index_ = findex;

				// 更新fec冗余数据包的pid, gid等信息.
				std::string_view fsv(
					(char*)ptr->payload(),
					avpn_static_mtu);

				make_transfer(*ptr, src, findex, fsv);
			}
		}
	}

	void fec_encode_group::make_fec_zstd(vpn_packet& pkt, uint32_t src)
	{
		// 获取当前fec编码index以及gid,pid值.
		auto [index, gid, pid] = fetch_ids();

		// 获取ip包数据用于计算transfer协议.
		std::string_view sv((char*)pkt.payload(), pkt.payload_size());

		// pid不为0, 倍发模式不再作fec编码, 仅更新pid即可.
		if (ds_ == 1 && pid != 0)
		{
			make_transfer(pkt, src, index, sv);
			pkt.index_ = index;
			return;
		}

		// 构造transfer数据包.
		make_transfer_compress(pkt, src, index, compress_zstd, sv);

		// 倍发模式不再作fec编码.
		if (ds_ <= 1)
			return;

		// 保存到fec编码缓冲.
		pkts_[pid] = std::make_shared<vpn_packet>(dup_vpn_packet(pkt));

		// 判断fec编码是否达到可实施fec编码大小要求.
		// 如果达到, 则直接进行fec编码.
		if (pid + 1 == ds_)
		{
			// 执行fec编码.
			if (!do_encode())
				return;

			// 编码完后, 从编码缓冲中遍历编码出来的fec编码数
			// 据包, 并逐一填充协议头.
			for (pid++; pid < shards_; pid++)
			{
				auto& ptr = pkts_[pid];
				if (!ptr)
					continue;

				ptr->resize(avpn_packet_size);
				ptr->payload_size(avpn_static_mtu);

				auto [findex, fgid, fpid] = fetch_ids();
				ptr->index_ = findex;

				// 更新fec冗余数据包的pid, gid等信息.
				std::string_view fsv(
					(char*)ptr->payload(),
					avpn_static_mtu);

				make_transfer_compress(*ptr,
					src, findex, compress_zstd, fsv);
			}
		}
	}

	std::tuple<uint64_t, uint32_t, uint8_t> fec_encode_group::fetch_ids()
	{
		scoped_exit se([this]() { index_++; });

		return {
			index_,
			static_cast<uint32_t>((index_ / shards_) + 1),
			static_cast<uint8_t>(index_ % shards_)
		};
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
		, used_(!!pg.used_)
	{
		pg.gid_ = 0;
		pg.pkts_.clear();
		pg.ds_ = -1;
		pg.ps_ = -1;
		pg.total_ = 0;
		pg.used_ = false;
	}

	void fec_decode_group::update(
		uint64_t gid, uint64_t pid, vpn_packet_ptr& pkt)
	{
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

	std::tuple<bool, bool> fec_recover::update(
		uint64_t gid, uint64_t pid,
		int ds, int ps,
		vpn_packet& pkt)
	{
		if (ds == 1 && ps == 0)
			return {true, false};

		auto ptr = dup_vpn_packet_ptr(pkt);

		auto clean_gops =
		[this](uint64_t& gid) mutable -> void
		{
			// 作gop清理工作, 清理gid大于当前gid + 64的gop.
			for (auto it = groups_.begin();
				it != groups_.end();)
			{
				auto& [i, g] = *it;

				if (g.gid_ + 64 > gid)
					break;

				it = groups_.erase(it);
			}
		};

		// 查找是否已存在创建的gop, 如果不存在则创建新的gop.
		auto it = groups_.find(gid);
		if (it == groups_.end())
		{
			fec_decode_group gop(ds, ps);
			gop.update(gid, pid, ptr);

			scoped_exit se(std::bind(clean_gops, std::ref(gid)));

			// 对方ds为1的时候, 任何pkt返回即过期.
			if (ds == 1)
				gop.set_expired();
			else
				se.cancel();

			groups_.emplace(gid, std::move(gop));

			return { false, false };
		}

		// 如果gop已过期, 直接跳过.
		auto& gop = it->second;
		if (gop.expired())
			return { false, true };

		// 更新gop.
		gop.update(gid, pid, ptr);
		if (!gop.available())
			return { false, false };

		// gop可用后, 标记为过期.
		scoped_exit expired([&gop]() mutable {
			gop.set_expired();
			});

		// 在完成解码后, 清理过期大于64的gop.
		scoped_exit se(std::bind(clean_gops, std::ref(gid)));

		// 是否丢包, 如果没丢包则返回 true 以表示完成.
		auto lost_pkts = gop.lost();
		if (lost_pkts.empty())
			return { true, false };

		// 发送方配置了重复发送模式, 所以这里只要接受到1个数
		// 据包, 便属于未丢包的情况.
		if (ds == 1)
			return { true, false };

		// 将这个gop作fec解码.
		if (!gop.decode())
			return { false, false };

		// 解码出丢失的pkt后, 将其放入result容器中.
		auto shards = ds + ps;
		auto start_index = gop.gid_ * shards;
		for (auto& index : lost_pkts)
		{
			auto& p = gop.pkts_[index];

			p->index_ = start_index + index;

			results_.emplace_back(std::move(p));
		}

		return { true, false };
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
		// 必须调用 std::move 以清空recover的结果
		// 避免被重复获取.
		return std::move(results_);
	}
}
