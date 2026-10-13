//
// avpn_compress.hpp
// ~~~~~~~~~~~~~~~~~
//
// Copyright (C) 2025 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#ifndef INCLUDE__2025_11_20__AVPN_COMPRESS_HPP
#define INCLUDE__2025_11_20__AVPN_COMPRESS_HPP

#include "libavpn/avpn_protocol.hpp"

#include <cstdint>
#include <vector>
#include <string_view>

namespace libavpn {

	// 太短的包压了也不划算 (3 字节条目头就吃掉大半好处).
	inline constexpr std::size_t min_compress_size = 64;

	// 快速看一眼这段数据值不值得压: 采样若干字节, 数出现过的字节种类有多少.
	// 已经加密的载荷、压过的媒体流这类随机数据种类几乎占满, 直接判为不值得压,
	// 免得白交一次 deflate 的钱 (deflate 在随机数据上要几十微秒).
	// 判错的代价只是错过一次压缩机会, 不影响正确性.
	bool looks_compressible(std::string_view data);

	// 压缩器, 用于对 IP 数据包进行压缩.
	// 压缩在握手时协商, 且压缩后仍由对称加密算法加密, 即: 先压缩, 后加密;
	// 接收方需要先解密, 再解压.
	//
	// deflate: 每包是一个独立的 deflate 流; 两条流 (压 / 解) 常驻, 每包只做一次
	// reset, 免得每包重建 zlib 流 (那要几十微秒, 直接吃光包速率的预算).
	// lz4: 用块接口, 一次调用进出, 不需要常驻状态, 速度比 deflate 快得多.
	class compressor
	{
	public:
		explicit compressor(compress_type type = compress_type::none);
		~compressor();

		compressor(const compressor&) = delete;
		compressor& operator=(const compressor&) = delete;

	public:
		// 返回当前压缩算法.
		compress_type type() const;

		// 设置压缩算法; 换了算法会把常驻的流丢掉重建.
		void set_type(compress_type type);

		// 是否启用压缩.
		bool enabled() const;

		// 压缩 input 到 output, 成功返回 true.
		bool compress(std::string_view input, std::vector<uint8_t>& output);

		// 解压 input 到 output, max_out 为解压后最大允许大小(防止解压炸弹),
		// 成功返回 true.
		bool decompress(std::string_view input, std::vector<uint8_t>& output,
			std::size_t max_out);

	private:
		// 按需建流; 算法不支持或建不起来返回 false.
		bool ensure_streams();
		void close_streams();

		// lz4 走块接口, 没有常驻状态.
		bool lz4_compress(std::string_view input, std::vector<uint8_t>& output);
		bool lz4_decompress(std::string_view input, std::vector<uint8_t>& output,
			std::size_t max_out);

		compress_type m_type;

		// z_stream 藏在实现里, 头文件不必带 zlib.
		void* m_deflate{ nullptr };
		void* m_inflate{ nullptr };
	};

} // namespace libavpn

#endif // INCLUDE__2025_11_20__AVPN_COMPRESS_HPP
