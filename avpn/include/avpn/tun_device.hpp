//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#pragma once

#if defined(AVPN_WINDOWS)

#	include "avpn/wintun_windows_service.hpp"
#	include "avpn/tuntap_windows_service.hpp"

#elif defined(AVPN_LINUX)
#	include "avpn/tundev_linux_service.hpp"
#elif defined(AVPN_APPLE)
#	include "avpn/tundev_macos_service.hpp"
#elif defined(AVPN_ANDROID)
#	include "avpn/tundev_android_service.hpp"
#else
#	error unsupported platform
#endif

#include "avpn/basic_tun_service.hpp"

#include <variant>

namespace avpn {

	// 定义不同平台的tuntap实现.
#if defined(AVPN_WINDOWS)
#ifdef AVPN_USE_WINTUN
	using tun_device = basic_tun_service<wintun_windows_service>;
#else
	using tun_device = basic_tun_service<tuntap_windows_service>;
#endif // AVPN_USE_WINTUN
#elif defined(AVPN_LINUX)
	using tun_device = basic_tun_service<tundev_linux_service>;
#elif defined(AVPN_APPLE)
	using tun_device = basic_tun_service<tundev_macos_service>;
#elif defined(AVPN_ANDROID)
	using tun_device = basic_tun_service<tundev_android_service>;
#endif

	// 一个适应多态tun_device的抽象类.
	template<typename... T>
	class vtun_device : public std::variant<T...>
	{
	public:
		template <typename S>
		explicit vtun_device(S device)
			: std::variant<T...>(std::move(device))
		{
			static_assert(std::is_move_constructible<S>::value
				, "must be move constructible");
		}
		vtun_device(vtun_device&&) = default;
		~vtun_device() = default;

		vtun_device(const vtun_device&) = delete;
		vtun_device& operator=(vtun_device const&) = delete;
		vtun_device& operator=(vtun_device&&) = default;

		boost::asio::io_context& get_io_context()
		{
			return std::visit([&](auto& t) mutable
				{ return t.get_io_context(); }, *this);
		}

		bool open(const dev_config& cfg)
		{
			return std::visit([&](auto& t) mutable
				{ return t.open(cfg); }, *this);
		}

		void close()
		{
			return std::visit([&](auto& t) mutable
				{ return t.close(); }, *this);
		}

		template <typename MutableBufferSequence, typename ReadHandler>
		BOOST_ASIO_INITFN_AUTO_RESULT_TYPE(ReadHandler,
			void(boost::system::error_code, std::size_t))
		async_read_some(const MutableBufferSequence& buffers, ReadHandler&& handler)
		{
			return std::visit([&](auto& t) mutable
				{ return t.async_read_some(buffers,
					std::forward<ReadHandler>(handler)); }, *this);
		}

		template <typename ConstBufferSequence, typename WriteHandler>
		BOOST_ASIO_INITFN_AUTO_RESULT_TYPE(WriteHandler,
			void(boost::system::error_code, std::size_t))
		async_write_some(const ConstBufferSequence& buffers, WriteHandler&& handler)
		{
			return std::visit([&](auto& t) mutable
				{ return t.async_write_some(buffers,
					std::forward<WriteHandler>(handler)); }, *this);
		}

		std::vector<tun_device_info> take_device_list()
		{
			return std::visit([&](auto& t) mutable
				{ return t.take_device_list(); }, *this);
		}
	};
}
