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

	// 压缩器, 用于对 IP 数据包进行压缩.
	// 压缩在握手时协商, 且压缩后仍由对称加密算法加密, 即: 先压缩, 后加密;
	// 接收方需要先解密, 再解压.
	class compressor
	{
	public:
		explicit compressor(compress_type type = compress_type::none);
		~compressor() = default;

		compressor(const compressor&) = delete;
		compressor& operator=(const compressor&) = delete;

	public:
		// 返回当前压缩算法.
		compress_type type() const;

		// 设置压缩算法.
		void set_type(compress_type type) { m_type = type; }

		// 是否启用压缩.
		bool enabled() const;

		// 压缩 input 到 output, 成功返回 true.
		bool compress(std::string_view input, std::vector<uint8_t>& output);

		// 解压 input 到 output, max_out 为解压后最大允许大小(防止解压炸弹),
		// 成功返回 true.
		bool decompress(std::string_view input, std::vector<uint8_t>& output,
			std::size_t max_out);

	private:
		compress_type m_type;
	};

} // namespace libavpn

#endif // INCLUDE__2025_11_20__AVPN_COMPRESS_HPP
