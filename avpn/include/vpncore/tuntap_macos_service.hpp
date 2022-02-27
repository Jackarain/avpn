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

#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/kern_control.h>
#include <sys/types.h>
#include <net/route.h>
#include <net/if_utun.h>
#include <net/if_dl.h>
#include <sys/ioctl.h>
#include <sys/kern_event.h>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/address_v4.hpp>
#include <boost/asio/ip/network_v4.hpp>
#include <boost/asio/posix/stream_descriptor.hpp>

#include <boost/smart_ptr/scoped_ptr.hpp>
#include <boost/smart_ptr/local_shared_ptr.hpp>
#include <boost/smart_ptr/make_local_shared.hpp>

#include <boost/algorithm/string.hpp>
#include <boost/regex.hpp>

#include "utils/logging.hpp"
#include "utils/scoped_exit.hpp"
#include "utils/misc.hpp"
#include "vpncore/tuntap_config.hpp"

namespace avpn
{
	inline std::optional<boost::asio::ip::network_v4> get_default_gateway()
	{
		auto [result, ret] = run_command("netstat -rn -f inet");
		if (!ret)
			return {};

		std::vector<std::string> strings;
		boost::split(strings, result, boost::is_any_of("\n"));
		boost::regex expression(R"((default)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S*).*)");

		for (const auto word : strings)
		{
			boost::smatch what;
			if (boost::regex_match(word, what, expression))
			{
				std::string gateway = std::string(what[2]);
				boost::system::error_code ec;
				auto gw = boost::asio::ip::address_v4::from_string(gateway, ec);
				if (ec)
					continue;
				boost::asio::ip::address_v4 mask{ 0 };

				LOG_DBG << "Default gateway: " << gw.to_string();
				return boost::asio::ip::network_v4(gw, mask);
			}
		}

		return {};
	}

	class tuntap_macos_service
		: public boost::asio::detail::service_base<tuntap_macos_service>
	{
		// c++11 noncopyable.
		tuntap_macos_service(const tuntap_macos_service &) = delete;
		tuntap_macos_service &operator=(const tuntap_macos_service &) = delete;

	public:
		explicit tuntap_macos_service(boost::asio::io_context &io_context)
			: boost::asio::detail::service_base<tuntap_macos_service>(io_context)
			, m_stream_descriptor(io_context)
		{}

		~tuntap_macos_service()
		{
		}

		bool open(const dev_config &cfg)
		{
			struct ctl_info ctlInfo = {0};
			strlcpy(ctlInfo.ctl_name, UTUN_CONTROL_NAME, sizeof(ctlInfo.ctl_name));

			int fd;
			fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
			if (fd < 0)
				return false;

			if (ioctl(fd, CTLIOCGINFO, &ctlInfo) == -1)
			{
				LOG_ERR << "ioctl(fd, CTLIOCGINFO, (void *)&ifr)";
				::close(fd);
				return false;
			}

			LOG_DBG << "ctl_info, ctl_id: " << ctlInfo.ctl_id << ", ctl_name: " << ctlInfo.ctl_name;

			struct sockaddr_ctl sc;
			sc.sc_id = ctlInfo.ctl_id;
			sc.sc_len = sizeof(sc);
			sc.sc_family = AF_SYSTEM;
			sc.ss_sysaddr = AF_SYS_CONTROL;
			sc.sc_unit = 0; /* allocate dynamically */
			if (strncmp(cfg.dev_name_.data(), "utun", 4) == 0)
				sc.sc_unit = (int)strtol(cfg.dev_name_.data() + 4, NULL, 10) + 1;

			if (connect(fd, (struct sockaddr *)&sc, sizeof(sc)) < 0)
			{
				perror("connect");
				::close(fd);
				return false;
			}

			socklen_t maxlen = 256;
			char ifname[256] = {0};
			getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, ifname, &maxlen);
			LOG_DBG << "ifname: " << ifname;

			if (1)
			{
				struct ifaliasreq ifaliasreq = {0};
				struct sockaddr_in *in;

				snprintf(ifaliasreq.ifra_name, IFNAMSIZ, "%s", ifname);

				in = (struct sockaddr_in *)&ifaliasreq.ifra_addr;
				in->sin_family = AF_INET;
				in->sin_len = sizeof(ifaliasreq.ifra_addr);
				int err = ::inet_aton(cfg.local_.data(), &in->sin_addr);
				if (err == 0)
				{
					perror("inet_aton local ip");
					LOG_ERR << "inet_aton local ip: " << cfg.local_;
					::close(fd);
					return false;
				}

				in = (struct sockaddr_in *)&ifaliasreq.ifra_mask;
				in->sin_family = AF_INET;
				in->sin_len = sizeof(ifaliasreq.ifra_addr);
				err = ::inet_aton(cfg.mask_.data(), &in->sin_addr);
				if (err == 0)
				{
					perror("inet_aton mask ip");
					LOG_ERR << "inet_aton mask ip: " << cfg.mask_;
					::close(fd);
					return false;
				}

				in = (struct sockaddr_in *)&ifaliasreq.ifra_broadaddr;
				in->sin_family = AF_INET;
				in->sin_len = sizeof(ifaliasreq.ifra_broadaddr);
				in->sin_addr.s_addr = ((struct sockaddr_in *)&ifaliasreq.ifra_addr)->sin_addr.s_addr
					| ~((struct sockaddr_in *)&ifaliasreq.ifra_mask)->sin_addr.s_addr;

				int s = socket(AF_INET, SOCK_STREAM, 0);
				scoped_exit scoped([&s]() mutable { ::close(s); });

				struct ifreq ifr = {0};
				snprintf(ifr.ifr_name, IFNAMSIZ, "%s", ifname);

				ifr.ifr_flags |= IFF_UP;
				ifr.ifr_flags |= IFF_NOARP;
				ifr.ifr_flags |= IFF_PROMISC;
				if (ioctl(s, SIOCSIFFLAGS, (void *)&ifr) < 0)
				{
					perror("SIOCSIFFLAGS");
					LOG_ERR << "ioctl(fd, SIOCSIFFLAGS, (void *)&ifr)";
					::close(fd);
					return false;
				}
				m_frame_mtu = ifr.ifr_mtu = 1450;

				if (ioctl(s, SIOCSIFMTU, (void *)&ifr) < 0)
				{
					perror("SIOCSIFMTU");
					LOG_ERR << "ioctl(fd, SIOCSIFMTU, (void *)&ifr)";
					::close(fd);
					return false;
				}

				if (ioctl(s, SIOCAIFADDR, (void *)&ifaliasreq) < 0)
				{
					perror("ioctl(fd, SIOCAIFADDR, (void *)&ifaliasreq)");
					LOG_ERR << "ioctl(fd, SIOCAIFADDR, (void *)&ifaliasreq): " << cfg.local_ << "/" << cfg.mask_;
					::close(fd);
					return false;
				}

				in = (struct sockaddr_in *)&ifr.ifr_dstaddr;
				in->sin_family = AF_INET;
				in->sin_len = sizeof(ifr.ifr_dstaddr);
				err = ::inet_aton(cfg.gateway_.data(), &in->sin_addr);
				if (err == 0)
				{
					perror("inet_aton gateway ip");
					LOG_ERR << "inet_aton gateway ip: " << cfg.mask_;
					::close(fd);
					return false;
				}

				if (ioctl(s, SIOCSIFDSTADDR, (void *)&ifr) < 0)
				{
					perror("SIOCSIFDSTADDR");
					LOG_ERR << "ioctl(fd, SIOCSIFDSTADDR, (void *)&ifr)";
					::close(fd);
					return false;
				}

				// 如果需要访问整个网段, 需要执行以下命令在OSX上添加路由:
				// sudo route -v delete 10.0.0.1
				// sudo route -v add -net 10.0.0.0/16  -iface utun9
				auto route = "route -v delete " + cfg.gateway_;
				LOG_DBG << route;
				{
					auto [ret, _] = run_command(route);
					LOG_DBG << ret;
				}
				boost::asio::ip::network_v4 net(
					boost::asio::ip::address::from_string(cfg.gateway_).to_v4(),
					boost::asio::ip::address::from_string(cfg.mask_).to_v4()
				);
				route = "route -v add -net "
					+ cfg.gateway_ + "/"
					+ std::to_string(net.prefix_length())
					+ " -iface " + std::string(ifname);
				LOG_DBG << route;
				{
					auto [ret, _] = run_command(route);
					LOG_DBG << ret;
				}
			}

			// 设置fd为非阻塞.
			int flags = fcntl(fd, F_GETFL, 0);
			if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
			{
				perror("fcntl(fd, F_SETFL, flags | O_NONBLOCK)");
				LOG_ERR << "fcntl(fd, F_SETFL, flags | O_NONBLOCK)";
				::close(fd);
				return false;
			}

			m_stream_descriptor.assign(fd);
			m_tuntap_fd = fd;

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
		BOOST_ASIO_INITFN_RESULT_TYPE(ReadHandler,
			void(boost::system::error_code, std::size_t))
		async_read_some(const MutableBufferSequence &buffers, ReadHandler&& handler)
		{
			return boost::asio::async_initiate<ReadHandler, void(boost::system::error_code, std::size_t)>
				([this](auto&& handler, auto buffers) mutable
				{
					m_stream_descriptor.async_read_some(buffers, [this, buffers, handler = std::move(handler)]
					(boost::system::error_code error, std::size_t bytes_transferred) mutable
					{
						boost::system::error_code ec;
						if (error == boost::asio::error::eof)
							ec = error;
						if (bytes_transferred > 4)
						{
							auto ptr = boost::asio::buffer_cast<char*>(buffers);
							bytes_transferred -= 4;
							std::memmove(ptr, ptr + 4, bytes_transferred);
						}
						handler(ec, bytes_transferred);
					});
				}, handler, buffers);
		}

		template <typename ConstBufferSequence, typename WriteHandler>
		BOOST_ASIO_INITFN_AUTO_RESULT_TYPE(WriteHandler,
			void(boost::system::error_code, std::size_t))
		async_write_some(const ConstBufferSequence &buffers, WriteHandler&& handler)
		{
			return boost::asio::async_initiate<WriteHandler, void(boost::system::error_code, std::size_t)>
				([this](auto&& handler, auto buffers) mutable
				{
					// The first byte of data will always be the address family (eg, AF_INET) of
					// the packet. By default, the packet data follows immediately, but if the
					// PREPADDR bit is set, the address to which the packet is to be sent is
					// placed after the address family byte and before the packet data.
					static uint32_t prefix = htonl(AF_INET);

					std::vector<ConstBufferSequence> bufs;
					bufs.push_back(boost::asio::buffer((char*)&prefix, sizeof(prefix)));
					bufs.push_back(buffers);

					m_stream_descriptor.async_write_some(bufs, [this, handler = std::move(handler)]
					(boost::system::error_code error, std::size_t bytes_transferred) mutable
					{
						handler(error, bytes_transferred - sizeof(uint32_t));
					});
				}, handler, buffers);
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
			return -1;
		}

	private:
		boost::asio::posix::stream_descriptor m_stream_descriptor;
		std::vector<device_tuntap> m_device_list;
		dev_config m_config;
		int m_frame_mtu{ -1 };
		std::vector<uint8_t> m_mac_addr;
		int m_tuntap_fd{ 0 };
	};

}
