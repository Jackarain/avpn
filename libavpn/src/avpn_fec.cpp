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

namespace libavpn {

	// 已完成分组的去重窗口大小.
	constexpr std::size_t completed_capacity = 1024;

	//////////////////////////////////////////////////////////////////////////

	namespace {

		// 将载荷均分为 data_shards 片, 计算冗余并按 [数据分片..., 冗余分片...]
		// 输出. 分片不足部分以 0 补齐.
		bool encode_shards(reedsolomon* rs, std::string_view payload,
			std::vector<std::vector<uint8_t>>& shards)
		{
			int ds = rs->data_shards();
			int ps = rs->parity_shards();

			std::size_t shard_size = (payload.size() + ds - 1) / ds;
			if (shard_size == 0)
				shard_size = 1;

			std::vector<std::vector<uint8_t>> data(ds,
				std::vector<uint8_t>(shard_size, 0));
			for (int d = 0; d < ds; d++)
			{
				std::size_t offset = static_cast<std::size_t>(d) * shard_size;
				if (offset >= payload.size())
					break;
				std::size_t len = std::min<std::size_t>(shard_size,
					payload.size() - offset);
				std::memcpy(data[d].data(), payload.data() + offset, len);
			}

			std::vector<std::vector<uint8_t>> parity;
			if (!rs->encode(data, parity))
				return false;

			shards.clear();
			shards.reserve(static_cast<std::size_t>(ds + ps));
			for (auto& d : data)
				shards.push_back(std::move(d));
			for (auto& p : parity)
				shards.push_back(std::move(p));
			shards.resize(static_cast<std::size_t>(ds + ps));
			return true;
		}

	} // namespace

	fec_encode_group::fec_encode_group(int data_shards, int parity_shards)
		: m_rs(data_shards, parity_shards)
	{}

	reedsolomon* fec_encode_group::code(int data_shards, int parity_shards)
	{
		if (data_shards == m_rs.data_shards() &&
			parity_shards == m_rs.parity_shards())
			return &m_rs;

		uint32_t key = (static_cast<uint32_t>(data_shards) << 8) |
			static_cast<uint32_t>(parity_shards);
		auto it = m_codes.find(key);
		if (it != m_codes.end())
			return it->second.get();

		auto rs = std::make_unique<reedsolomon>(data_shards, parity_shards);
		reedsolomon* raw = rs.get();
		m_codes.emplace(key, std::move(rs));
		return raw;
	}

	bool fec_encode_group::encode(uint32_t fec_id, std::string_view ip_packet,
		std::vector<std::vector<uint8_t>>& frames)
	{
		int ds = m_rs.data_shards();
		int ps = m_rs.parity_shards();
		int total = ds + ps;

		std::vector<std::vector<uint8_t>> shards;
		if (!encode_shards(&m_rs, ip_packet, shards))
			return false;

		frames.clear();
		frames.reserve(static_cast<std::size_t>(total));
		for (std::size_t i = 0; i < shards.size(); i++)
		{
			auto& frame = frames.emplace_back();
			frame.reserve(fec_frame_header_size + shards[i].size());
			uint32_t seq = fec_id * static_cast<uint32_t>(total) +
				static_cast<uint32_t>(i);
			byteorder::put_u32_into(frame, seq);
			byteorder::put_u16_into(frame,
				static_cast<uint16_t>(ip_packet.size()));
			frame.insert(frame.end(), shards[i].begin(), shards[i].end());
		}

		return true;
	}

	bool fec_encode_group::encode_variable(uint32_t fec_id, int data_shards,
		int parity_shards, std::string_view ip_packet,
		std::vector<std::vector<uint8_t>>& frames)
	{
		reedsolomon* rs = code(data_shards, parity_shards);
		if (!rs || rs->data_shards() != data_shards ||
			rs->parity_shards() != parity_shards)
			return false;

		std::vector<std::vector<uint8_t>> shards;
		if (!encode_shards(rs, ip_packet, shards))
			return false;

		frames.clear();
		frames.reserve(shards.size());
		for (std::size_t i = 0; i < shards.size(); i++)
		{
			auto& frame = frames.emplace_back();
			frame.reserve(afec_frame_header_size + shards[i].size());
			byteorder::put_u32_into(frame, fec_id);
			frame.push_back(static_cast<uint8_t>(i));
			frame.push_back(static_cast<uint8_t>(data_shards));
			frame.push_back(static_cast<uint8_t>(parity_shards));
			byteorder::put_u16_into(frame,
				static_cast<uint16_t>(ip_packet.size()));
			frame.insert(frame.end(), shards[i].begin(), shards[i].end());
		}

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

	reedsolomon* fec_decode_group::code(int data_shards, int parity_shards)
	{
		data_shards = std::max(1, data_shards);
		parity_shards = std::max(0, parity_shards);
		if (data_shards == m_data_shards &&
			parity_shards == m_parity_shards)
			return &m_rs;

		uint32_t key = (static_cast<uint32_t>(data_shards) << 8) |
			static_cast<uint32_t>(parity_shards);
		auto it = m_codes.find(key);
		if (it != m_codes.end())
			return it->second.get();

		auto rs = std::make_unique<reedsolomon>(data_shards, parity_shards);
		reedsolomon* raw = rs.get();
		m_codes.emplace(key, std::move(rs));
		return raw;
	}

	bool fec_decode_group::add(uint32_t index, uint16_t original_len,
		std::string_view data,
		std::vector<uint8_t>& output)
	{
		int total = m_data_shards + m_parity_shards;
		if (total <= 0)
			return false;

		uint32_t fec_id = index / static_cast<uint32_t>(total);
		uint8_t idx = static_cast<uint8_t>(
			index % static_cast<uint32_t>(total));
		return add_shard(fec_id, idx, m_data_shards, m_parity_shards,
			original_len, data, output);
	}

	bool fec_decode_group::add_adaptive(uint32_t fec_id, uint8_t pid,
		uint8_t data_shards, uint8_t parity_shards, uint16_t original_len,
		std::string_view data,
		std::vector<uint8_t>& output)
	{
		if (data_shards == 0 ||
			static_cast<int>(data_shards) + parity_shards > afec_max_shards ||
			pid >= static_cast<uint8_t>(data_shards + parity_shards))
			return false;

		return add_shard(fec_id, pid, data_shards, parity_shards,
			original_len, data, output);
	}

	bool fec_decode_group::add_shard(uint32_t fec_id, uint8_t pid,
		int data_shards, int parity_shards, uint16_t original_len,
		std::string_view data,
		std::vector<uint8_t>& output)
	{
		const int total = data_shards + parity_shards;
		const auto now = std::chrono::steady_clock::now();

		// 该分组已完成, 迟到的冗余分片直接丢弃 (否则会不断为剩余分片
		// 重新建组, 导致分组表膨胀与线性扫描开销).
		if (m_completed.count(fec_id))
			return false;

		// 周期性清理过期分组, 避免高丢包环境下分组无限累积导致延迟劣化.
		if (++m_add_count % 512 == 0)
			purge();

		// 查找或创建分组 (按 fec_id 哈希索引).
		auto it = m_groups.find(fec_id);
		group* g = nullptr;
		if (it == m_groups.end())
		{
			auto res = m_groups.emplace(fec_id, group{});
			g = &res.first->second;
			g->fec_id = fec_id;
			g->data_shards = static_cast<uint8_t>(data_shards);
			g->parity_shards = static_cast<uint8_t>(parity_shards);
			g->original_len = original_len;
			g->shard_size = data.size();
			g->shards.assign(total, {});
			g->present.assign(total, false);
			g->last_seen = now;
		}
		else
		{
			g = &it->second;
			// 同一分组的分片必须携带一致的分片数, 否则丢弃.
			if (g->data_shards != data_shards ||
				g->parity_shards != parity_shards)
				return false;
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
		if (g->present[pid])
			return false;

		g->shards[pid].assign(data.begin(), data.end());
		g->shards[pid].resize(g->shard_size);
		g->present[pid] = true;
		g->received++;
		g->last_seen = now;

		// 达到足够分片, 尝试恢复.
		if (g->received >= static_cast<std::size_t>(g->data_shards))
		{
			reedsolomon* rs = code(g->data_shards, g->parity_shards);
			if (rs && rs->reconstruct(g->shards, g->shard_size))
			{
				// 恢复成功, 拼接所有数据分片, 并按原始长度去除填充.
				output.clear();
				output.reserve(g->shard_size * g->data_shards);
				for (int d = 0; d < g->data_shards; d++)
				{
					auto& s = g->shards[d];
					output.insert(output.end(), s.begin(), s.end());
				}
				if (output.size() > g->original_len)
					output.resize(g->original_len);

				// 移除该分组并记录, 其迟到分片将被丢弃.
				m_groups.erase(fec_id);
				if (m_completed.size() >= completed_capacity)
				{
					m_completed.erase(m_completed_order.front());
					m_completed_order.pop_front();
				}
				m_completed.insert(fec_id);
				m_completed_order.push_back(fec_id);

				return true;
			}
		}

		return false;
	}

	std::size_t fec_decode_group::purge()
	{
		auto now = std::chrono::steady_clock::now();
		std::size_t before = m_groups.size();
		for (auto it = m_groups.begin(); it != m_groups.end();)
		{
			if ((now - it->second.last_seen) > m_max_live_time)
				it = m_groups.erase(it);
			else
				++it;
		}
		return before - m_groups.size();
	}


} // namespace libavpn
