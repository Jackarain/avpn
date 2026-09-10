//
// avpn_fec.hpp
// ~~~~~~~~~~~~
//
// Copyright (C) 2025 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#ifndef INCLUDE__2025_11_20__AVPN_FEC_HPP
#define INCLUDE__2025_11_20__AVPN_FEC_HPP

#include <cstdint>
#include <deque>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <cstddef>
#include <vector>
#include <array>
#include <string_view>
#include <chrono>

namespace libavpn {

	// Reed-Solomon 纠删码 (GF(2^8), 本原多项式 0x11d).
	// 用于在 UDP 传输时抵抗丢包: 将数据分为 data_shards 片, 计算
	// parity_shards 片冗余, 只要收到任意 data_shards 片即可恢复原始数据.
	class reedsolomon
	{
	public:
		reedsolomon(int data_shards, int parity_shards);
		~reedsolomon() = default;

		reedsolomon(const reedsolomon&) = delete;
		reedsolomon& operator=(const reedsolomon&) = delete;

	public:
		int data_shards() const { return m_data_shards; }
		int parity_shards() const { return m_parity_shards; }
		int total_shards() const { return m_data_shards + m_parity_shards; }

		// 使用 data_shards 片数据计算 parity_shards 片冗余数据.
		// 所有分片长度必须一致, data[i] 指向第 i 片数据.
		// 输出 parity[i] 为第 i 片冗余数据.
		bool encode(const std::vector<std::vector<uint8_t>>& data,
			std::vector<std::vector<uint8_t>>& parity);

		// 从丢失部分分片中恢复数据.
		// shards: 长度为 total_shards, 存在数据的分片非空, 丢失的分片为空.
		// 恢复成功后, 所有分片将被填充.
		bool reconstruct(std::vector<std::vector<uint8_t>>& shards,
			std::size_t shard_size);

	private:
		int m_data_shards{ 1 };
		int m_parity_shards{ 0 };

		// 编码矩阵 (data_shards+parity_shards) x data_shards.
		std::vector<std::vector<uint8_t>> m_encoding_matrix;
	};

	// FEC 数据分片在加密体中的帧头.
	//   [index(4, 小端)]  全局分片序号, gid = index / total, pid = index % total.
	//   [len(2, 小端)]  原始数据包长度, 用于去除分片填充.
	//   [data...]
	inline constexpr std::size_t fec_frame_header_size = 6;

	// 自适应 FEC 分片在加密体中的帧头 (分组大小随载荷变化).
	//   [fec_id(4, 小端)]  分组号.
	//   [pid(1)]  分片在分组内的序号.
	//   [data_shards(1)]  本组数据分片数.
	//   [parity_shards(1)]  本组冗余分片数.
	//   [len(2, 小端)]  原始数据包长度, 用于去除分片填充.
	//   [data...]
	inline constexpr std::size_t afec_frame_header_size = 9;

	// 自适应分组允许的最大分片数 (防御异常帧).
	inline constexpr int afec_max_shards = 255;

	// FEC 探测丢包统计: 按固定窗口结算对端探测包的到达情况, 并给出
	// 链路是否持续干净的结论, 供对端自适应关闭冗余分片.
	//
	// 窗口大小为探测包个数 (探测间隔 100ms, 默认窗口约 1.6s). 只要当前
	// 未结算窗口内出现丢包就立刻报告"不干净", 连续 clean_windows 个窗口
	// 无丢包后才报告"干净", 避免单个干净窗口误判而反复开关冗余.
	class fec_probe_tracker
	{
	public:
		explicit fec_probe_tracker(int window = 16, int clean_windows = 8)
			: m_window(std::max(1, window))
			, m_clean_needed(std::max(1, clean_windows))
		{}

		// 收到一个探测序号; 返回本次是否结算出一个新窗口.
		bool on_probe(uint32_t seq)
		{
			if (m_inited)
			{
				// 迟到/重复的探测不记为丢包.
				if (seq < m_expected)
					return false;
				if (seq > m_expected)
					m_lost += static_cast<int>(seq - m_expected);
			}
			else
			{
				m_inited = true;
			}
			m_expected = seq + 1;

			if (++m_seen < m_window)
				return false;

			m_result = m_lost > 0 ? 1 : 0;
			if (m_result == 0)
				++m_clean_streak;
			else
				m_clean_streak = 0;
			m_seen = 0;
			m_lost = 0;
			return true;
		}

		// 最近一个结算窗口的结果: -1 尚未结算, 0 无丢包, 1 有丢包.
		int last_result() const { return m_result; }

		// 回带给对端的丢包标记: 0=链路持续干净, 1=有丢包或尚未确认.
		// 当前窗口出现丢包时立即回带 1, 使对端尽快恢复冗余.
		uint8_t report() const
		{
			if (m_lost > 0 || m_clean_streak < m_clean_needed)
				return 1;
			return 0;
		}

	private:
		int m_window;
		int m_clean_needed;
		bool m_inited{ false };
		uint32_t m_expected{ 0 };
		int m_seen{ 0 };
		int m_lost{ 0 };
		int m_result{ -1 };
		int m_clean_streak{ 0 };
	};

	// 一个 IP 数据包的 FEC 编码分组.
	class fec_encode_group
	{
	public:
		fec_encode_group(int data_shards, int parity_shards);
		~fec_encode_group() = default;

		// 将 ip 数据包编码为多个分片, 每个分片为:
		//   [index(4)][len(2)][shard_data]
		// fec_id 为分组号, 分片 index = fec_id * total + shard_index.
		// 返回所有分片 (data_shards + parity_shards 个).
		bool encode(uint32_t fec_id, std::string_view ip_packet,
			std::vector<std::vector<uint8_t>>& frames);

		// 使用指定的数据/冗余分片数编码, 分片帧头为 afec_frame_header_size 字节.
		// 用于载荷较小时按需缩小分组, 避免补齐出大量小分片.
		bool encode_variable(uint32_t fec_id, int data_shards,
			int parity_shards, std::string_view ip_packet,
			std::vector<std::vector<uint8_t>>& frames);

	private:
		// 按 (data_shards, parity_shards) 缓存编码器, 避免重复构造.
		reedsolomon* code(int data_shards, int parity_shards);

		reedsolomon m_rs;
		std::unordered_map<uint32_t, std::unique_ptr<reedsolomon>> m_codes;
	};

	// FEC 解码分组, 按 fec_id 收集分片, 达到足够数量后恢复原始数据.
	class fec_decode_group
	{
	public:
		// max_live_time 为分片过期时间.
		fec_decode_group(int data_shards, int parity_shards,
			std::chrono::milliseconds max_live_time = std::chrono::seconds(3));
		~fec_decode_group() = default;

		// 添加一个已解密的分片帧.
		// index 为全局分片序号, 由推导出的分组内序号处理去重.
		// original_len 为原始数据包长度 (用于去除分片填充).
		// 返回 true 表示该分组已恢复出完整数据, 通过 output 返回.
		// 返回 false 表示还需更多分片.
		bool add(uint32_t index, uint16_t original_len,
			std::string_view data,
			std::vector<uint8_t>& output);

		// 添加一个自适应 FEC 分片帧 (分组大小由帧头携带).
		// 返回 true 表示该分组已恢复出完整数据, 通过 output 返回.
		bool add_adaptive(uint32_t fec_id, uint8_t pid, uint8_t data_shards,
			uint8_t parity_shards, uint16_t original_len,
			std::string_view data,
			std::vector<uint8_t>& output);

		// 清理过期分组, 返回被清理的分组数量.
		std::size_t purge();

	private:
		// 一个分组的数据.
		struct group
		{
			uint32_t fec_id{ 0 };
			uint8_t data_shards{ 1 };
			uint8_t parity_shards{ 0 };
			std::size_t original_len{ 0 };
			std::size_t shard_size{ 0 };
			std::vector<std::vector<uint8_t>> shards;
			std::vector<bool> present;
			std::size_t received{ 0 };
			std::chrono::steady_clock::time_point last_seen;
		};

		// 按分组携带的 (data_shards, parity_shards) 取得解码器.
		reedsolomon* code(int data_shards, int parity_shards);

		// 收下一个分片, 达到条件时恢复分组.
		bool add_shard(uint32_t fec_id, uint8_t pid, int data_shards,
			int parity_shards, uint16_t original_len,
			std::string_view data,
			std::vector<uint8_t>& output);

		// 按 fec_id 索引, 避免线性扫描造成的 O(n²) 开销.
		std::unordered_map<uint32_t, group> m_groups;

		// 最近完成的分组 id (丢弃其迟到分片, 避免为剩余冗余分片重复建组).
		std::unordered_set<uint32_t> m_completed;
		std::deque<uint32_t> m_completed_order;

		int m_data_shards{ 1 };
		int m_parity_shards{ 0 };
		std::size_t m_add_count{ 0 };
		std::chrono::milliseconds m_max_live_time;
		reedsolomon m_rs;
		std::unordered_map<uint32_t, std::unique_ptr<reedsolomon>> m_codes;
	};

} // namespace libavpn

#endif // INCLUDE__2025_11_20__AVPN_FEC_HPP
