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
#include <netinet/in.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <arpa/inet.h>

extern "C"
{
#include <linux/if_tun.h>
#include <asm/types.h>
#include <libnetlink.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

}

// #define ARPHRD_NONE			0xFFFE
// #define ARPHRD_ETHER        1

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

#ifdef AVPN_FREEBSD

#include <net/if_tun.h>
#include <net/if_tap.h>

#endif

#include <boost/asio/ip/network_v4.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/posix/stream_descriptor.hpp>

#include <boost/smart_ptr/scoped_ptr.hpp>
#include <boost/smart_ptr/local_shared_ptr.hpp>
#include <boost/smart_ptr/make_local_shared.hpp>

#include "utils/logging.hpp"
#include "utils/scoped_exit.hpp"
#include "vpncore/tuntap_config.hpp"

inline int rtnl_wilddump_request_old(struct rtnl_handle *rth, int family, int type)
{
	struct
	{
		struct nlmsghdr nlh;
		struct rtgenmsg g;
	} req;
	struct sockaddr_nl nladdr;

	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;

	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = sizeof(req);
	req.nlh.nlmsg_type = type;
	req.nlh.nlmsg_flags = NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST;
	req.nlh.nlmsg_pid = 0;
	req.nlh.nlmsg_seq = rth->dump = ++rth->seq;
	req.g.rtgen_family = family;

	return sendto(rth->fd, (void *)&req, sizeof(req), 0,
				  (struct sockaddr *)&nladdr, sizeof(nladdr));
}


namespace avpn
{
	inline std::optional<boost::asio::ip::network_v4> get_default_gateway()
	{
		long Destination, Gateway, Flags, RefCnt, Use, Metric, Mask, MTU, Window, IRTT;
		char iface[512] = { 0 };
		char buf[1024] = { 0 };
		FILE* file;

		memset(iface, 0, sizeof(iface));
		memset(buf, 0, sizeof(buf));

		file = fopen("/proc/net/route", "r");
		if (!file)
			return {};

		scoped_exit scoped([&file]() mutable { fclose(file); });
		long lowest_metric = std::numeric_limits<long>::max();
		boost::asio::ip::network_v4 net;

		while (fgets(buf, sizeof(buf), file))
		{
			LOG_DBG << buf;

			if (sscanf(buf, "%s %lx %lx %lx %lx %lx %lx %lx %lx %lx %lx",
				iface, &Destination, &Gateway, &Flags, &RefCnt,
				&Use, &Metric, &Mask, &MTU, &Window, &IRTT) == 11)
			{
				if (Destination == 0 && Mask == 0 && Metric < lowest_metric)
				{
					lowest_metric = Metric;

					boost::asio::ip::address_v4 gw{ ntohl(Gateway) };
					boost::asio::ip::address_v4 mask{ ntohl(Mask) };

					net = boost::asio::ip::network_v4(gw, mask);
				}
			}
		}

		if (lowest_metric == std::numeric_limits<long>::max())
			return {};

		LOG_DBG << "Default gateway: " << net.address().to_string()
			<< ", lowest metric: " << lowest_metric;

		return net;
	}

	template <typename ReturnType>
	inline ReturnType error_wrapper(ReturnType return_value,
									boost::system::error_code &ec)
	{
		ec = boost::system::error_code(errno,
									   boost::asio::error::get_system_category());
		return return_value;
	}

	namespace details
	{

		inline int read_tuntap_prop(const char *dev, const char *prop, long *value)
		{
			char fname[128], buf[80], *endp, *nl;
			FILE *fp;
			long result;
			int ret;

			ret = snprintf(fname, sizeof(fname), "/sys/class/net/%s/%s",
						   dev, prop);

			if (ret <= 0 || (size_t)ret >= sizeof(fname))
			{
				LOG_ERR << "could not build pathname for property";
				return -1;
			}

			fp = fopen(fname, "r");
			if (fp == NULL)
			{
				LOG_ERR << "fopen " << fname << " fail";
				return -1;
			}

			if (!fgets(buf, sizeof(buf), fp))
			{
				LOG_ERR << "property '" << prop << "' in file " << fname << "is currently unknown";
				fclose(fp);
				goto out;
			}

			nl = strchr(buf, '\n');
			if (nl)
				*nl = '\0';

			fclose(fp);
			result = strtol(buf, &endp, 0);

			if (*endp || buf == endp)
			{
				LOG_ERR << "value '" << buf << "' in file " << fname << " is not a number";
				goto out;
			}

			*value = result;
			return 0;

		out:
			LOG_ERR << "failed to parse " << fname;
			return -1;
		}
	}

	class tuntap_linux_service
		: public boost::asio::detail::service_base<tuntap_linux_service>
	{
		// c++11 noncopyable.
		tuntap_linux_service(const tuntap_linux_service &) = delete;
		tuntap_linux_service &operator=(const tuntap_linux_service &) = delete;

	public:
		explicit tuntap_linux_service(boost::asio::io_context &io_context)
			: boost::asio::detail::service_base<tuntap_linux_service>(io_context)
			, m_stream_descriptor(io_context)
		{
			// 程序开始时获取tuntap列表.
			fetch_tuntap();
		}

		~tuntap_linux_service()
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
				auto addr = boost::asio::ip::address_v4::from_string(cfg.local_);
				boost::asio::ip::udp::endpoint endp;
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
				auto addr = boost::asio::ip::address_v4::from_string(cfg.mask_);
				boost::asio::ip::udp::endpoint endp;
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
			if (m_tuntap_fd == 0)
				return;

			boost::system::error_code ignore_ec;
			m_stream_descriptor.cancel(ignore_ec);
			m_stream_descriptor.close(ignore_ec);
			m_tuntap_fd = 0;
		}

		template <typename MutableBufferSequence, typename ReadHandler>
		BOOST_ASIO_INITFN_AUTO_RESULT_TYPE(ReadHandler,
			void(boost::system::error_code, std::size_t))
		async_read_some(const MutableBufferSequence &buffers, ReadHandler&& handler)
		{
			return m_stream_descriptor.async_read_some(buffers, std::forward<ReadHandler>(handler));
		}

		template <typename ConstBufferSequence, typename WriteHandler>
		BOOST_ASIO_INITFN_AUTO_RESULT_TYPE(WriteHandler,
			void(boost::system::error_code, std::size_t))
		async_write_some(const ConstBufferSequence &buffers, WriteHandler&& handler)
		{
			return m_stream_descriptor.async_write_some(buffers, std::forward<WriteHandler>(handler));
		}

		std::vector<device_tuntap> take_device_list()
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
		void fetch_tuntap()
		{
			struct rtnl_handle rth;
			if (rtnl_open(&rth, 0) != 0)
				return;
			if (rtnl_wilddump_request_old(&rth, AF_UNSPEC, RTM_GETLINK) < 0)
				return;
			if (rtnl_dump_filter_nc(&rth, list_tuntap_func, (void *)this, 0) < 0)
				return;
			rtnl_close(&rth);
		}

		// friend
		static int list_tuntap_func(struct nlmsghdr *n, void *arg)
		{
			auto pthis = (tuntap_linux_service *)arg;
			return pthis->list_tuntap(n);
		}

		int list_tuntap(struct nlmsghdr *n)
		{
			struct ifinfomsg *ifi = (struct ifinfomsg *)NLMSG_DATA(n);
			struct rtattr *tb[IFLA_MAX + 1];
			struct rtattr *linkinfo[IFLA_INFO_MAX + 1];
			const char *name, *kind;
			long flags /*, owner = -1, group = -1 */;

			if (n->nlmsg_type != RTM_NEWLINK && n->nlmsg_type != RTM_DELLINK)
				return 0;
			if (n->nlmsg_len < NLMSG_LENGTH(sizeof(*ifi)))
				return -1;

			switch (ifi->ifi_type)
			{
			case ARPHRD_NONE:
			case ARPHRD_ETHER:
				break;
			default:
				return 0;
			}

			parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifi), IFLA_PAYLOAD(n));

			if (!tb[IFLA_IFNAME])
				return 0;
			if (!tb[IFLA_LINKINFO])
				return 0;

			parse_rtattr(linkinfo, IFLA_INFO_MAX, (struct rtattr *)RTA_DATA(tb[IFLA_LINKINFO]), RTA_PAYLOAD(tb[IFLA_LINKINFO]));
			// parse_rtattr_nested(linkinfo, IFLA_INFO_MAX, (void*)tb[IFLA_LINKINFO]);
			if (!linkinfo[IFLA_INFO_KIND])
				return 0;

			kind = rta_getattr_str(linkinfo[IFLA_INFO_KIND]);
			if (strcmp(kind, drv_name))
				return 0;

			name = rta_getattr_str(tb[IFLA_IFNAME]);
			if (details::read_tuntap_prop(name, "tun_flags", &flags))
				return 0;

			if (flags & IFF_TUN)
			{
				device_tuntap dev;
				dev.name_ = name;
				m_device_list.push_back(dev);
				LOG_DBG << "iframe: " << name << ", tun type: " << flags;
			}

			if (flags & IFF_TAP)
			{
				device_tuntap dev;
				dev.name_ = name;
				m_device_list.push_back(dev);
				LOG_DBG << "iframe: " << name << ", tap type: " << flags;
			}
			return 0;
		}

	private:
		boost::asio::posix::stream_descriptor m_stream_descriptor;
		std::vector<device_tuntap> m_device_list;
		dev_config m_config;
		int m_frame_mtu{ -1 };
		std::vector<uint8_t> m_mac_addr;
		int m_tuntap_fd{ 0 };
		int m_if_index{ -1 };
	};

}
