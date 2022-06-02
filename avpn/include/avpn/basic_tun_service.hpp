//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#pragma once

#include "avpn/tundev_config.hpp"

#include <string>
#include <vector>
#include <memory>

#include <boost/asio.hpp>


namespace avpn {

	template <typename Service>
	class basic_tun_service
	{
		// c++11 noncopyable.
		basic_tun_service(const basic_tun_service&) = delete;
		basic_tun_service& operator=(const basic_tun_service&) = delete;

	public:
		using service_type = Service;

		explicit basic_tun_service(boost::asio::io_context& io_context) noexcept
			: service_(std::make_unique<service_type>(io_context))
		{}

		~basic_tun_service()
		{
			if (service_)
				close();
		}

		basic_tun_service(basic_tun_service&& rv)
			: service_(std::move(rv.service_))
		{}

		boost::asio::io_context& get_io_context()
		{
			return service_->get_io_context();
		}

		// 打开指定的tuntap设备，并按cfg配置.
		bool open(const dev_config& cfg)
		{
			return service_->open(cfg);
		}

		// 关闭已经打开的tuntap设备.
		void close()
		{
			service_->close();
		}

		// 提供异步读取tuntap设备上的数据到buffer.
		// 函数签名同asio的socket.async_read_some
		template <typename MutableBufferSequence, typename ReadHandler>
		BOOST_ASIO_INITFN_AUTO_RESULT_TYPE(ReadHandler,
			void(boost::system::error_code, std::size_t))
			async_read_some(const MutableBufferSequence& buffers, ReadHandler&& handler)
		{
			return service_->async_read_some(buffers, std::forward<ReadHandler>(handler));
		}

		// 提供异步写入tuntap设备上的数据到buffer.
		// 函数签名同asio的socket.async_write_some
		template <typename ConstBufferSequence, typename WriteHandler>
		BOOST_ASIO_INITFN_AUTO_RESULT_TYPE(WriteHandler,
			void(boost::system::error_code, std::size_t))
			async_write_some(const ConstBufferSequence& buffers, WriteHandler&& handler)
		{
			return service_->async_write_some(buffers, std::forward<WriteHandler>(handler));
		}

		// 获取所有tuntap设备列表, 一般在打开tuntap devicep之前
		// 先获取到tuntap, 根据这个列表选择打开指定device.
		std::vector<tun_device_info> take_device_list()
		{
			return service_->take_device_list();
		}

	private:
		std::unique_ptr<service_type> service_;
	};

}
