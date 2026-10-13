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

#include <lz4.h>
#include <zlib.h>

#include <limits>

namespace libavpn {

	bool looks_compressible(std::string_view data)
	{
		constexpr std::size_t max_samples = 256;

		if (data.size() < min_compress_size)
			return false;

		// 沿整段数据均匀取样, 用一张 256 位的位图记下出现过哪些字节.
		// 取多少字节就是多少个样本: 随机数据里出现过的字节种类接近样本数的
		// 六成以上, 有结构的载荷 (文本、协议头、成片的相同字节) 一般不到一半,
		// 所以拿"样本数的一半"当界, 两边都留足余量.
		uint8_t seen[32] = {};
		const std::size_t step = data.size() > max_samples
			? data.size() / max_samples : 1;
		std::size_t samples = 0;
		for (std::size_t i = 0; i < data.size(); i += step)
		{
			const uint8_t b = static_cast<uint8_t>(data[i]);
			seen[b >> 3] |= static_cast<uint8_t>(1u << (b & 7));
			samples++;
		}

		std::size_t distinct = 0;
		for (uint8_t byte : seen)
		{
			// 数位图里置上的位 (编译器认得这个写法, 会换成一条指令).
			while (byte != 0)
			{
				byte &= static_cast<uint8_t>(byte - 1);
				distinct++;
			}
		}

		return distinct * 2 < samples;
	}

	compressor::compressor(compress_type type)
		: m_type(type)
	{}

	compressor::~compressor()
	{
		close_streams();
	}

	compress_type compressor::type() const
	{
		return m_type;
	}

	void compressor::set_type(compress_type type)
	{
		if (m_type == type)
			return;

		m_type = type;
		close_streams();
	}

	bool compressor::enabled() const
	{
		return m_type != compress_type::none;
	}

	bool compressor::lz4_compress(std::string_view input,
		std::vector<uint8_t>& output)
	{
		// lz4 块接口的尺寸是 int, 一个 IP 包远到不了这个上限, 超了直接不压.
		if (input.size() > static_cast<std::size_t>(
			std::numeric_limits<int>::max()) ||
			input.size() > static_cast<std::size_t>(LZ4_MAX_INPUT_SIZE))
		{
			return false;
		}

		const int src_size = static_cast<int>(input.size());
		const int bound = ::LZ4_compressBound(src_size);
		if (bound <= 0)
			return false;

		output.resize(static_cast<std::size_t>(bound));
		const int written = ::LZ4_compress_default(input.data(),
			reinterpret_cast<char*>(output.data()), src_size, bound);
		if (written <= 0)
		{
			XLOG_ERR << "lz4 compress failed";
			return false;
		}

		output.resize(static_cast<std::size_t>(written));
		return true;
	}

	bool compressor::lz4_decompress(std::string_view input,
		std::vector<uint8_t>& output, std::size_t max_out)
	{
		if (input.size() > static_cast<std::size_t>(
			std::numeric_limits<int>::max()) ||
			max_out > static_cast<std::size_t>(
				std::numeric_limits<int>::max()))
		{
			return false;
		}

		// 输出缓冲就是上限: 解到这里还没完, 说明不是坏数据就是解压炸弹.
		output.resize(max_out);
		const int written = ::LZ4_decompress_safe(input.data(),
			reinterpret_cast<char*>(output.data()),
			static_cast<int>(input.size()), static_cast<int>(max_out));
		if (written < 0)
			return false;

		output.resize(static_cast<std::size_t>(written));
		return true;
	}

	void compressor::close_streams()
	{
		if (m_deflate != nullptr)
		{
			::deflateEnd(static_cast<z_stream*>(m_deflate));
			delete static_cast<z_stream*>(m_deflate);
			m_deflate = nullptr;
		}
		if (m_inflate != nullptr)
		{
			::inflateEnd(static_cast<z_stream*>(m_inflate));
			delete static_cast<z_stream*>(m_inflate);
			m_inflate = nullptr;
		}
	}

	bool compressor::ensure_streams()
	{
		// lz4 的块接口一次性进出, 没有常驻状态, 直接算可用.
		if (m_type == compress_type::lz4)
			return true;
		if (m_type != compress_type::deflate)
			return false;
		if (m_deflate != nullptr && m_inflate != nullptr)
			return true;

		// 每包一个独立的流, 首尾没有 zlib 头与校验 (报文已经由 AEAD 认证),
		// 所以用原始 deflate: 省下的 10 个字节在小包上很值.
		if (m_deflate == nullptr)
		{
			auto* zs = new z_stream{};
			if (::deflateInit2(zs, Z_BEST_SPEED, Z_DEFLATED,
				-15, 8, Z_DEFAULT_STRATEGY) != Z_OK)
			{
				delete zs;
				return false;
			}
			m_deflate = zs;
		}

		if (m_inflate == nullptr)
		{
			auto* zs = new z_stream{};
			if (::inflateInit2(zs, -15) != Z_OK)
			{
				delete zs;
				return false;
			}
			m_inflate = zs;
		}

		return true;
	}

	bool compressor::compress(std::string_view input, std::vector<uint8_t>& output)
	{
		if (input.empty() || !ensure_streams())
			return false;

		if (m_type == compress_type::lz4)
			return lz4_compress(input, output);

		auto* zs = static_cast<z_stream*>(m_deflate);
		if (::deflateReset(zs) != Z_OK)
		{
			XLOG_ERR << "deflateReset failed";
			return false;
		}

		zs->next_in = reinterpret_cast<Bytef*>(
			const_cast<char*>(input.data()));
		zs->avail_in = static_cast<uInt>(input.size());

		// 压不动时结果会比输入略大, 按 zlib 给的上界留够.
		output.resize(::deflateBound(zs, static_cast<uLong>(input.size())));
		zs->next_out = output.data();
		zs->avail_out = static_cast<uInt>(output.size());

		// 每包一个完整的流, 一次 Z_FINISH 就该结束.
		const int ret = ::deflate(zs, Z_FINISH);
		if (ret != Z_STREAM_END)
		{
			XLOG_ERR << "deflate failed, ret: " << ret;
			return false;
		}

		output.resize(output.size() - zs->avail_out);
		return true;
	}

	bool compressor::decompress(std::string_view input, std::vector<uint8_t>& output,
		std::size_t max_out)
	{
		if (input.empty() || max_out == 0 || !ensure_streams())
			return false;

		if (m_type == compress_type::lz4)
			return lz4_decompress(input, output, max_out);

		auto* zs = static_cast<z_stream*>(m_inflate);
		if (::inflateReset(zs) != Z_OK)
		{
			XLOG_ERR << "inflateReset failed";
			return false;
		}

		zs->next_in = reinterpret_cast<Bytef*>(
			const_cast<char*>(input.data()));
		zs->avail_in = static_cast<uInt>(input.size());

		// 输出缓冲就是上限: 解到这里还没完, 说明不是坏数据就是解压炸弹.
		output.resize(max_out);
		zs->next_out = output.data();
		zs->avail_out = static_cast<uInt>(max_out);

		const int ret = ::inflate(zs, Z_FINISH);
		if (ret != Z_STREAM_END)
			return false;

		output.resize(output.size() - zs->avail_out);
		return true;
	}

} // namespace libavpn
