//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#pragma once

#include <iostream>
#include <string>
#include <vector>
#include <memory>

#include <boost/asio/ip/network_v4.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/local/datagram_protocol.hpp>

#include <boost/smart_ptr/scoped_ptr.hpp>
#include <boost/smart_ptr/local_shared_ptr.hpp>
#include <boost/smart_ptr/make_local_shared.hpp>

namespace net = boost::asio;

#include "utils/logging.hpp"
#include "utils/scoped_exit.hpp"
#include "avpn/tundev_config.hpp"


namespace avpn
{
	using boost::asio::local::datagram_protocol;

	class tundev_ipc_service
		: public net::detail::service_base<tundev_ipc_service>
	{
		// c++11 noncopyable.
		tundev_ipc_service(const tundev_ipc_service &) = delete;
		tundev_ipc_service &operator=(const tundev_ipc_service &) = delete;

	public:
		explicit tundev_ipc_service(net::io_context &io_context)
			: net::detail::service_base<tundev_ipc_service>(io_context)
			, m_ipc_socket(io_context)
		{
		}

		~tundev_ipc_service()
		{}

		bool open(const dev_config &cfg)
		{
			m_ipc_socket.assign(net::local::datagram_protocol(), cfg.fd_);
			return true;
		}

		void close()
		{
			boost::system::error_code ignore_ec;
			m_ipc_socket.close(ignore_ec);
		}

		template <typename MutableBufferSequence, typename ReadHandler>
		BOOST_ASIO_INITFN_AUTO_RESULT_TYPE(ReadHandler,
			void(boost::system::error_code, std::size_t))
		async_read_some(const MutableBufferSequence &buffers, ReadHandler&& handler)
		{
			return m_ipc_socket.async_read_some(buffers, std::forward<ReadHandler>(handler));
		}

		template <typename ConstBufferSequence, typename WriteHandler>
		BOOST_ASIO_INITFN_AUTO_RESULT_TYPE(WriteHandler,
			void(boost::system::error_code, std::size_t))
		async_write_some(const ConstBufferSequence &buffers, WriteHandler&& handler)
		{
			return m_ipc_socket.async_write_some(buffers, std::forward<WriteHandler>(handler));
		}

		std::vector<tun_device_info> take_device_list()
		{
			return m_device_list;
		}

		bool take_mac([[maybe_unused]] char mac[6])
		{
			return false;
		}

		// 获取当前打开的tuntap设备的mtu.
		int take_mtu()
		{
			return -1;
		}

		int get_if_index() const
		{
			return -1;
		}

	private:
		datagram_protocol::socket m_ipc_socket;
		std::vector<tun_device_info> m_device_list;
		dev_config m_config;
		std::vector<uint8_t> m_mac_addr;
	};

}
