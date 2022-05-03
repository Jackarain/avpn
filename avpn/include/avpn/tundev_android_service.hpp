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

#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_arp.h>

extern "C"
{
#include <linux/if_tun.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
}

#ifndef IFF_TUN
#define IFF_TUN 0x0001
#endif // !IFF_TUN

#ifndef IFF_TAP
#define IFF_TAP 0x0002
#endif // !IFF_TAP

#ifndef IFF_NO_PI
#define IFF_NO_PI 0x1000
#endif // !IFF_NO_PI

static const char drv_name[] = "tun";
#define TUNDEV "/dev/net/tun"


#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/posix/stream_descriptor.hpp>

#include <boost/smart_ptr/scoped_ptr.hpp>
#include <boost/smart_ptr/local_shared_ptr.hpp>
#include <boost/smart_ptr/make_local_shared.hpp>

#include "utils/logging.hpp"
#include "avpn/tundev_config.hpp"

namespace avpn
{
	inline namespace details
	{
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

		template <typename ReturnType>
		inline ReturnType error_wrapper(ReturnType return_value,
			boost::system::error_code& ec)
		{
			ec = boost::system::error_code(errno,
				net::error::get_system_category());
			return return_value;
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

	class tundev_android_service
		: public net::detail::service_base<tundev_android_service>
	{
		// c++11 noncopyable.
		tundev_android_service(const tundev_android_service &) = delete;
		tundev_android_service &operator=(const tundev_android_service &) = delete;

	public:
		explicit tundev_android_service(net::io_context &io_context)
			: net::detail::service_base<tundev_android_service>(io_context)
			, m_stream_descriptor(io_context)
		{}

		~tundev_android_service()
		{}

		bool open(const dev_config &cfg)
		{
			struct ifreq ifr;

			int fd = ::open(TUNDEV, O_RDWR);
			if (fd < 0)
				return false;

			memset(&ifr, 0, sizeof(ifr));
			ifr.ifr_flags = IFF_NO_PI;
			ifr.ifr_flags |= IFF_TUN;

			if (!cfg.dev_name_.empty() && cfg.dev_name_.size() < IFNAMSIZ)
				strncpy(ifr.ifr_name, cfg.dev_name_.data(), IFNAMSIZ);

			if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) //打开虚拟网卡
			{
				::close(fd);
				return false;
			}

			LOG_DBG << "TUN / TAP device " << ifr.ifr_name << " opened";

			m_if_index = if_nametoindex(ifr.ifr_name);

			// open dummy socket for ioctls
			int sock = socket(AF_INET, SOCK_DGRAM, 0);
			if (sock < 0)
			{
				::close(fd);
				return false;
			}

			if (ioctl(sock, SIOCGIFMTU, (void *)&ifr) < 0)
			{
				::close(sock);
				::close(fd);
				return false;
			}

			// hardcode set mtu size.
			m_frame_mtu = ifr.ifr_mtu = 1450;

			if (ioctl(sock, SIOCSIFMTU, (void *)&ifr) < 0)
			{
				::close(sock);
				::close(fd);
				return false;
			}

			if (ioctl(sock, SIOCGIFHWADDR, (void *)&ifr) < 0)
			{
				::close(sock);
				::close(fd);
				return false;
			}
			ifr.ifr_flags |= IFF_UP;
			if (ioctl(sock, SIOCSIFFLAGS, (void *)&ifr) < 0)
			{
				::close(sock);
				::close(fd);
				return false;
			}

			{
				auto addr = net::ip::address_v4::from_string(cfg.local_);
				net::ip::udp::endpoint endp;
				endp.address(addr);
				memcpy(&ifr.ifr_addr, endp.data(), sizeof(struct sockaddr));
				if (ioctl(sock, SIOCSIFADDR, (void *)&ifr) < 0)
				{
					::close(sock);
					::close(fd);
					return false;
				}
			}

			{
				auto addr = net::ip::address_v4::from_string(cfg.mask_);
				net::ip::udp::endpoint endp;
				endp.address(addr);
				memcpy(&ifr.ifr_netmask, endp.data(), sizeof(struct sockaddr));
				if (ioctl(sock, SIOCSIFNETMASK, (void *)&ifr) < 0)
				{
					::close(sock);
					::close(fd);
					return false;
				}
			}

			::close(sock);

			// 复制mac地址.
			m_mac_addr.resize(6);
			memcpy(m_mac_addr.data(), ifr.ifr_hwaddr.sa_data, 6);

			// 设置fd为非阻塞.
			if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0)
			{
				::close(fd);
				return false;
			}

			m_stream_descriptor.assign(fd);

			m_tuntap_fd = fd;

			LOG_DBG << "TUN / TAP device " << ifr.ifr_name << " successd, " << fd;
			return true;
		}

		void close()
		{
			if (m_tuntap_fd != 0)
			{
				boost::system::error_code ignore_ec;
				m_stream_descriptor.cancel(ignore_ec);
				m_stream_descriptor.close(ignore_ec);
				m_tuntap_fd = 0;
			}
		}

		template <typename MutableBufferSequence, typename ReadHandler>
		BOOST_ASIO_INITFN_RESULT_TYPE(ReadHandler,
			void(boost::system::error_code, std::size_t))
		async_read_some(const MutableBufferSequence &buffers, ReadHandler&& handler)
		{
			return m_stream_descriptor.async_read_some(buffers, std::forward<ReadHandler>(handler));
		}

		template <typename ConstBufferSequence, typename WriteHandler>
		BOOST_ASIO_INITFN_RESULT_TYPE(WriteHandler,
			void(boost::system::error_code, std::size_t))
		async_write_some(const ConstBufferSequence &buffers, WriteHandler&& handler)
		{
			return m_stream_descriptor.async_write_some(buffers, std::forward<WriteHandler>(handler));
		}

		std::vector<tun_device> take_device_list()
		{
			return m_device_list;
		}

		bool take_mac(char mac[6])
		{
			if (m_tuntap_fd == 0)
				return false;
			std::memcpy(mac, m_mac_addr.data(), 6);
			return true;
		}

		// 获取当前打开的tuntap设备的mtu.
		int take_mtu()
		{
			return m_frame_mtu;
		}

		int get_if_index() const
		{
			return m_if_index;
		}

	private:
		net::posix::stream_descriptor m_stream_descriptor;
		std::vector<tun_device> m_device_list;
		dev_config m_config;
		int m_frame_mtu{ -1 };
		std::vector<uint8_t> m_mac_addr;
		int m_tuntap_fd{ 0 };
		int m_if_index{ -1 };
	};

}
