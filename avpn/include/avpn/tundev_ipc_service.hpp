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

	inline namespace details
	{
		template <typename ReturnType>
		inline ReturnType error_wrapper(ReturnType return_value,
			boost::system::error_code& ec)
		{
			ec = boost::system::error_code(errno,
				net::error::get_system_category());
			return return_value;
		}

		inline std::tuple<net::ip::network_v4, std::string> default_gateway()
		{
			long Destination, Gateway, Flags, RefCnt, Use, Metric, Mask, MTU, Window, IRTT;
			FILE* file;
			std::string iface;

			file = fopen("/proc/net/route", "r");
			if (!file)
				return {};

			scoped_exit scoped([&file]() mutable { fclose(file); });
			long lowest_metric = std::numeric_limits<long>::max();
			net::ip::network_v4 net;

			char buf[1024] = { 0 };
			memset(buf, 0, sizeof(buf));
			while (fgets(buf, sizeof(buf), file))
			{
				char tmp[512] = { 0 };
				if (sscanf(buf, "%16s %lx %lx %lx %ld %ld %ld %lx %ld %ld %ld",
					tmp, &Destination, &Gateway, &Flags, &RefCnt,
					&Use, &Metric, &Mask, &MTU, &Window, &IRTT) == 11)
				{
					if (Destination == 0 && Mask == 0 && Metric < lowest_metric)
					{
						lowest_metric = Metric;

						net::ip::address_v4 gw{ ntohl(Gateway) };
						net::ip::address_v4 mask{ ntohl(Mask) };

						net = net::ip::network_v4(gw, mask);
						iface = tmp;
					}
				}
			}

			if (lowest_metric == std::numeric_limits<long>::max())
				return {};

			LOG_DBG << "Default gateway: " << net.address().to_string()
				<< ", lowest metric: " << lowest_metric;

			return { net, iface };
		}
	}

	inline std::optional<net::ip::network_v4> get_default_gateway()
	{
		[[maybe_unused]] auto [net, iface] = default_gateway();
		return { net };
	}

	inline std::optional<std::string> get_default_gateway_iface()
	{
		[[maybe_unused]] auto [net, iface] = default_gateway();
		return { iface };
	}

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
