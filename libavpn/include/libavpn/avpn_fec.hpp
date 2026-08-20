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

	private:
		reedsolomon m_rs;
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

		// 清理过期分组, 返回被清理的分组数量.
		std::size_t purge();

	private:
		// 一个分组的数据.
		struct group
		{
			uint32_t fec_id{ 0 };
			uint8_t total{ 0 };
			std::size_t original_len{ 0 };
			std::size_t shard_size{ 0 };
			std::vector<std::vector<uint8_t>> shards;
			std::vector<bool> present;
			std::size_t received{ 0 };
			std::chrono::steady_clock::time_point last_seen;
		};

		std::vector<group> m_groups;
		int m_data_shards{ 1 };
		int m_parity_shards{ 0 };
		std::size_t m_add_count{ 0 };
		std::chrono::milliseconds m_max_live_time;
		reedsolomon m_rs;
	};

} // namespace libavpn

#endif // INCLUDE__2025_11_20__AVPN_FEC_HPP
