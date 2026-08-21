//
// avpn_tun.hpp
// ~~~~~~~~~~~~
//
// Copyright (C) 2025 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#ifndef INCLUDE__2025_11_20__AVPN_TUN_HPP
#define INCLUDE__2025_11_20__AVPN_TUN_HPP

#include "libavpn/avpn.hpp"

#include <boost/asio/io_context.hpp>
#if defined(_WIN32)
#	include "libavpn/avpn_wintun.hpp"
#else
#	include <boost/asio/posix/stream_descriptor.hpp>
#endif

#include <string>

namespace libavpn {

	namespace net = boost::asio;

	// tun 设备封装.
	//
	// 支持:
	//   - Linux: /dev/net/tun.
	//   - macOS: utun 内核控制.
	//   - Windows: wintun 驱动.
	//   - 外部传入 fd (ptun_fd_ / utun_fd_).
	class tun_device
	{
	public:
		explicit tun_device(net::io_context& ioc);
		~tun_device();

		tun_device(const tun_device&) = delete;
		tun_device& operator=(const tun_device&) = delete;

	public:
		// 打开 tun 设备, 依据 service_config 中的 ifdev_/ptun_fd_/utun_fd_.
		bool open(const service_config& config);

		// 关闭 tun 设备.
		void close();

		// 配置 IP 地址/前缀/MTU (需要 root 权限).
		bool configure(uint32_t vaddr, uint8_t prefix, int mtu);

		// 配置 IPv6 内网地址 (<v6_net> + host 低 32 位/prefix, 需要 root 权限).
		bool configure_v6(const net::ip::address_v6& v6_net,
			uint8_t prefix, uint32_t host);

		// 返回设备名.
		const std::string& device_name() const { return m_devname; }

		net::io_context& get_io_context() { return m_ioc; }

		// 异步读取 tun 设备上的 IP 数据包.
		template <typename MutableBufferSequence, typename ReadHandler>
		BOOST_ASIO_INITFN_AUTO_RESULT_TYPE(ReadHandler,
			void(boost::system::error_code, std::size_t))
			async_read_some(const MutableBufferSequence& buffers,
				ReadHandler&& handler)
		{
#if defined(_WIN32)
			return m_wintun.async_read_some(buffers,
				std::forward<ReadHandler>(handler));
#else
			return m_stream.async_read_some(buffers,
				std::forward<ReadHandler>(handler));
#endif
		}

		// 异步写入 IP 数据包到 tun 设备.
		template <typename ConstBufferSequence, typename WriteHandler>
		BOOST_ASIO_INITFN_AUTO_RESULT_TYPE(WriteHandler,
			void(boost::system::error_code, std::size_t))
			async_write_some(const ConstBufferSequence& buffers,
				WriteHandler&& handler)
		{
#if defined(_WIN32)
			return m_wintun.async_write_some(buffers,
				std::forward<WriteHandler>(handler));
#else
			return m_stream.async_write_some(buffers,
				std::forward<WriteHandler>(handler));
#endif
		}

	private:
		net::io_context& m_ioc;
#if defined(_WIN32)
		wintun_tun_device m_wintun;
#else
		net::posix::stream_descriptor m_stream;
#endif
		std::string m_devname;
		bool m_opened{ false };
		// 外部传入的 fd (ptun/utun), 地址/路由由外部负责配置.
		bool m_external_fd{ false };
	};

} // namespace libavpn

#endif // INCLUDE__2025_11_20__AVPN_TUN_HPP
