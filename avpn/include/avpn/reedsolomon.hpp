//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#pragma once

#include "avpn/vpn_packet.hpp"

#include <streambuf>
#include <string>
#include <vector>
#include <string_view>
#include <filesystem>
#include <stdexcept>

#include <span> // from c++ 20

#include <boost/algorithm/string/join.hpp>

namespace avpn {

	// rs专用的matrix.
	class matrix
	{
		using internal_matrix = std::vector<std::vector<uint8_t>>;

	public:
		explicit matrix(size_t size = 0);
		matrix(size_t rows, size_t cols);
		~matrix() = default;
		explicit matrix(const matrix& rhs) noexcept;
		matrix(matrix&& rhs) noexcept;
		matrix& operator=(matrix&& rhs) noexcept;

		matrix vandermonde(size_t rows, size_t cols);

		std::vector<uint8_t>& operator[](size_t n);
		const std::vector<uint8_t>& operator[](size_t n) const;

		size_t size() const;

		matrix operator*(const matrix& m) const;
		matrix operator+(const matrix& m) const;
		matrix sub_matrix(size_t rmin, size_t cmin, size_t rmax, size_t cmax) const;

		void swap_rows(size_t r1, size_t r2);
		bool is_square() const;
		matrix invert() const;

		std::string to_string() const;

	private:
		void gaussianElimination();
		uint8_t galMultiply(uint8_t a, uint8_t b) const;
		uint8_t galDivide(uint8_t a, uint8_t b) const;
		uint8_t galExp(int8_t a, int n);

	private:
		internal_matrix m_matrix;
	};

	// 编码器抽象基类, 主要用于统一使用虚基类指针来使用不同优化的派生类.
	class codingloop {
	public:
		virtual ~codingloop() = default;
		virtual void encode(
			const std::vector<std::vector<uint8_t>>&,
			const std::vector<std::string_view>&,
			size_t,
			std::vector<std::span<uint8_t>>&) = 0;
	};

	struct vpn_packet;

	// 基本的(无优化)codingloop实现.
	class io_table_codingloop : public codingloop
	{
	public:
		virtual void encode(
			const std::vector<std::vector<uint8_t>>& parity_rows,
			const std::vector<std::string_view>& inputs,
			size_t data_shard_count,
			std::vector<std::span<uint8_t>>& outputs) override;
	};


	class reedsolomon
	{
	private:
		reedsolomon(const reedsolomon&) = delete;
		reedsolomon& operator=(const reedsolomon&) = delete;

	public:
		reedsolomon(int dataShards, int parityShards);
		reedsolomon(int dataShards, int parityShards, const matrix& m);
		size_t estimate_pershard_size(int total_size, int data_shards = -1);

		void encode(std::vector<vpn_packet_ptr>& shards);
		void decode(std::vector<vpn_packet_ptr>& shards);

		static matrix build_matrix(int shards, int data_shards);

	private:

		template<class T>
		void check_shards(const T& shards, bool nilok = false)
		{
			if (shards.size() != (size_t)m_shards)
				throw std::runtime_error("wrong number of shards");

			size_t shard_length = get_shard_size(shards);
			if (shard_length == 0)
				throw std::runtime_error("wrong shard no data");

#if defined(DEBUG) || defined(_DEBUG)
			for (size_t i = 1; i < shards.size(); i++) {
				if (shards[i].size() != shard_length) {
					if (shards[i].size() != 0 || !nilok) {
						throw std::runtime_error("shards are different sizes");
					}
				}
			}
#endif
		}

	private:
		int m_shards;
		int m_data_shards;
		int m_parity_shards;
		const matrix m_matrix;
		std::vector<std::vector<uint8_t>> m_parity_rows;
		std::unique_ptr<codingloop> m_codingloop = std::make_unique<io_table_codingloop>();
	};
}
