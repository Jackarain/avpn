//
// avpn_rs.hpp
// ~~~~~~~~~~~
//
// Copyright (C) 2025 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#ifndef INCLUDE__2026_10_14__AVPN_RS_HPP
#define INCLUDE__2026_10_14__AVPN_RS_HPP

#include <cstdint>
#include <cstddef>
#include <vector>

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

} // namespace libavpn

#endif // INCLUDE__2026_10_14__AVPN_RS_HPP
