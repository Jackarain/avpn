//
// avpn_compress.cpp
// ~~~~~~~~~~~~~~~~~
//
// Copyright (C) 2025 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#include "libavpn/avpn_compress.hpp"
#include "libavpn/logging.hpp"

#include <zlib.h>

#include <algorithm>
#include <cstring>

namespace libavpn {

	compressor::compressor(compress_type type)
		: m_type(type)
	{}

	compress_type compressor::type() const
	{
		return m_type;
	}

	bool compressor::enabled() const
	{
		return m_type != compress_type::none;
	}

	bool compressor::compress(std::string_view input, std::vector<uint8_t>& output)
	{
		if (input.empty())
			return false;

		switch (m_type)
		{
		case compress_type::deflate:
		{
			// zlib 的 compress2 使用 zlib 格式 (deflate + zlib header).
			uLongf out_len = compressBound(static_cast<uLong>(input.size()));
			output.resize(out_len);

			int ret = ::compress2(
				reinterpret_cast<Bytef*>(output.data()), &out_len,
				reinterpret_cast<const Bytef*>(input.data()),
				static_cast<uLong>(input.size()), Z_BEST_SPEED);

			if (ret != Z_OK)
			{
				XLOG_ERR << "compress2 failed, ret: " << ret;
				return false;
			}

			output.resize(out_len);
			return true;
		}
		case compress_type::lz4:
		case compress_type::zstd:
			// lz4/zstd 未内置于当前构建, 后续可扩展.
			XLOG_WARN << "compress algorithm not supported: "
				<< compress_type_to_string(m_type);
			return false;
		default:
			return false;
		}
	}

	bool compressor::decompress(std::string_view input, std::vector<uint8_t>& output,
		std::size_t max_out)
	{
		if (input.empty())
			return false;

		switch (m_type)
		{
		case compress_type::deflate:
		{
			// 先尝试用输入大小 4 倍的缓冲区解压, 并限制最大不超过 max_out.
			uLongf out_len = static_cast<uLongf>(
				std::min<std::size_t>(max_out, std::max<std::size_t>(input.size() * 4, 2048)));
			output.resize(out_len);

			int ret = ::uncompress(
				reinterpret_cast<Bytef*>(output.data()), &out_len,
				reinterpret_cast<const Bytef*>(input.data()),
				static_cast<uLong>(input.size()));

			if (ret == Z_BUF_ERROR)
			{
				// 缓冲区不够, 按最大允许大小再试一次.
				if (out_len >= max_out)
					return false;
				out_len = static_cast<uLongf>(max_out);
				output.resize(out_len);
				ret = ::uncompress(
					reinterpret_cast<Bytef*>(output.data()), &out_len,
					reinterpret_cast<const Bytef*>(input.data()),
					static_cast<uLong>(input.size()));
			}

			if (ret != Z_OK)
			{
				XLOG_ERR << "uncompress failed, ret: " << ret;
				return false;
			}

			output.resize(out_len);
			return true;
		}
		case compress_type::lz4:
		case compress_type::zstd:
			XLOG_WARN << "decompress algorithm not supported: "
				<< compress_type_to_string(m_type);
			return false;
		default:
			return false;
		}
	}

} // namespace libavpn
