//
// avpn_tun.cpp
// ~~~~~~~~~~~~
//
// Copyright (C) 2025 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#include "libavpn/avpn_tun.hpp"
#include "libavpn/logging.hpp"

#include <boost/asio/ip/address_v4.hpp>

#if defined(_WIN32)

#include <cstdio>
#include <cstring>
#include <string>

#else

#include <fcntl.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <string>

#endif

#if defined(__linux__)
#	include <linux/if_tun.h>
#	include <net/if.h>
#	include <sys/ioctl.h>
#	include <netinet/in.h>
#	include <arpa/inet.h>
#elif defined(__APPLE__)
#	include <sys/ioctl.h>
#	include <sys/kern_control.h>
#	include <sys/sys_domain.h>
#	include <sys/socket.h>
#	include <net/if.h>
#	include <net/if_utun.h>
#	include <netinet/in.h>
#	include <arpa/inet.h>
#	include <cstdlib>
#endif

namespace libavpn {

#if !defined(_WIN32)
	namespace {
		// 执行命令并捕获标准输出/错误, 避免子进程输出直接上屏.
		// 返回 wait status (与 system 一致), 失败时返回 -1.
		int run_cmd_capture(const std::string& cmd, std::string& output)
		{
			output.clear();
			FILE* pipe = ::popen((cmd + " 2>&1").c_str(), "r");
			if (!pipe)
				return -1;

			char buf[512];
			std::size_t n;
			while ((n = std::fread(buf, 1, sizeof(buf), pipe)) > 0)
				output.append(buf, n);
			return ::pclose(pipe);
		}

		// 平台相关的 tun 打开.
		int platform_open_tun(const std::string& devname,
			std::string& actual_name)
		{
#if defined(__linux__)
			static const char tun_dev[] = "/dev/net/tun";

			int fd = ::open(tun_dev, O_RDWR | O_NONBLOCK);
			if (fd < 0)
			{
				XLOG_ERR << "open " << tun_dev << " failed: "
					<< strerror(errno);
				return -1;
			}

			struct ifreq ifr;
			std::memset(&ifr, 0, sizeof(ifr));
			ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
			if (!devname.empty())
				std::strncpy(ifr.ifr_name, devname.c_str(), IFNAMSIZ - 1);

			if (::ioctl(fd, TUNSETIFF, &ifr) < 0)
			{
				XLOG_ERR << "TUNSETIFF failed: " << strerror(errno);
				::close(fd);
				return -1;
			}

			actual_name = ifr.ifr_name;
			return fd;
#elif defined(__APPLE__)
			// 打开 utun 设备.
			struct ctl_info ctl_info;
			std::memset(&ctl_info, 0, sizeof(ctl_info));
			std::strncpy(ctl_info.ctl_name, UTUN_CONTROL_NAME,
				sizeof(ctl_info.ctl_name));

			int fd = ::socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
			if (fd < 0)
				return -1;

			if (::ioctl(fd, CTLIOCGINFO, &ctl_info) < 0)
			{
				::close(fd);
				return -1;
			}

			struct sockaddr_ctl sc;
			std::memset(&sc, 0, sizeof(sc));
			sc.sc_id = ctl_info.ctl_id;
			sc.sc_len = sizeof(sc);
			sc.sc_family = AF_SYSTEM;
			sc.ss_sysaddr = AF_SYS_CONTROL;
			sc.sc_unit = 0; // 动态分配.

			// 若指定了 utun 名称 (如 "utun5"), 使用对应单元.
			if (devname.compare(0, 4, "utun") == 0 && devname.size() > 4)
				sc.sc_unit = std::atoi(devname.c_str() + 4) + 1;

			if (::connect(fd, reinterpret_cast<struct sockaddr*>(&sc),
					sizeof(sc)) < 0)
			{
				::close(fd);
				return -1;
			}

			char ifname[64] = { 0 };
			socklen_t len = sizeof(ifname);
			if (::getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME,
					ifname, &len) < 0)
			{
				::close(fd);
				return -1;
			}

			// 设置非阻塞.
			int flags = ::fcntl(fd, F_GETFL, 0);
			::fcntl(fd, F_SETFL, flags | O_NONBLOCK);

			actual_name = ifname;
			return fd;
#else
			// 其他平台暂不支持.
			(void)devname;
			(void)actual_name;
			return -1;
#endif
		}
	} // namespace
#endif // !defined(_WIN32)

	tun_device::tun_device(net::io_context& ioc)
		: m_ioc(ioc)
#if defined(_WIN32)
		, m_wintun(ioc)
#else
		, m_stream(ioc)
#endif
	{}

	tun_device::~tun_device()
	{
		close();
	}

	bool tun_device::open(const service_config& config)
	{
#if defined(_WIN32)
		// Windows 使用 wintun.
		if (!m_wintun.open(config))
			return false;
		m_devname = m_wintun.device_name();
		m_opened = true;
		return true;
#else
		boost::system::error_code ec;

		// 外部传入的 tun fd.
		if (config.ptun_fd_ >= 0)
		{
			// Android VpnService 的 tun fd 默认为阻塞模式, 必须改为非阻塞
			// 才能配合 Boost.Asio 异步读写.
			int flags = ::fcntl(config.ptun_fd_, F_GETFL, 0);
			if (flags >= 0)
				::fcntl(config.ptun_fd_, F_SETFL, flags | O_NONBLOCK);

			m_stream.assign(config.ptun_fd_, ec);
			if (ec)
			{
				XLOG_ERR << "assign ptun_fd failed: " << ec.message();
				return false;
			}
			m_devname = "ptun";
			m_opened = true;
			return true;
		}

		// 外部传入的 unix domain socket fd (IPC 方式读写 tun).
		if (config.utun_fd_ >= 0)
		{
			int flags = ::fcntl(config.utun_fd_, F_GETFL, 0);
			if (flags >= 0)
				::fcntl(config.utun_fd_, F_SETFL, flags | O_NONBLOCK);

			m_stream.assign(config.utun_fd_, ec);
			if (ec)
			{
				XLOG_ERR << "assign utun_fd failed: " << ec.message();
				return false;
			}
			m_devname = "utun-ipc";
			m_opened = true;
			return true;
		}

		// 平台原生打开.
		std::string actual_name;
		int fd = platform_open_tun(config.ifdev_, actual_name);
		if (fd < 0)
			return false;

		m_stream.assign(fd, ec);
		if (ec)
		{
			::close(fd);
			XLOG_ERR << "assign tun fd failed: " << ec.message();
			return false;
		}

		m_devname = actual_name;
		m_opened = true;

		XLOG_INFO << "tun device opened: " << m_devname;
		return true;
#endif
	}

	void tun_device::close()
	{
		if (!m_opened)
			return;

#if defined(_WIN32)
		m_wintun.close();
#else
		boost::system::error_code ec;
		m_stream.close(ec);
#endif
		m_opened = false;
	}

	bool tun_device::configure(uint32_t vaddr, uint8_t prefix, int mtu)
	{
		if (!m_opened || m_devname.empty())
			return false;

#if defined(_WIN32)
		return m_wintun.configure(vaddr, prefix, mtu);
#else
		net::ip::address_v4 addr(vaddr);
		uint32_t mask = prefix == 0 ? 0
			: (prefix >= 32 ? 0xffffffffu : (0xffffffffu << (32 - prefix)));

		XLOG_INFO << "configure tun: " << m_devname
			<< ", addr: " << addr.to_string()
			<< ", prefix: " << static_cast<int>(prefix)
			<< ", mtu: " << mtu;

#if defined(__linux__)
		struct ifreq ifr;
		std::memset(&ifr, 0, sizeof(ifr));
		std::strncpy(ifr.ifr_name, m_devname.c_str(), IFNAMSIZ - 1);

		int sock = ::socket(AF_INET, SOCK_DGRAM, 0);
		if (sock < 0)
			return false;

		bool ok = true;

		// 设置 IP.
		struct sockaddr_in* sin =
			reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr);
		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = htonl(vaddr);
		if (::ioctl(sock, SIOCSIFADDR, &ifr) < 0)
		{
			XLOG_ERR << "SIOCSIFADDR failed: " << strerror(errno);
			ok = false;
		}

		// 设置掩码.
		sin = reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_netmask);
		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = htonl(mask);
		if (ok && ::ioctl(sock, SIOCSIFNETMASK, &ifr) < 0)
		{
			XLOG_ERR << "SIOCSIFNETMASK failed: " << strerror(errno);
			ok = false;
		}

		// 设置 MTU.
		if (ok)
		{
			ifr.ifr_mtu = mtu;
			if (::ioctl(sock, SIOCSIFMTU, &ifr) < 0)
			{
				XLOG_ERR << "SIOCSIFMTU failed: " << strerror(errno);
				ok = false;
			}
		}

		// 启用设备.
		if (ok)
		{
			if (::ioctl(sock, SIOCGIFFLAGS, &ifr) < 0)
			{
				XLOG_ERR << "SIOCGIFFLAGS failed: " << strerror(errno);
				ok = false;
			}
			else
			{
				ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
				if (::ioctl(sock, SIOCSIFFLAGS, &ifr) < 0)
				{
					XLOG_ERR << "SIOCSIFFLAGS failed: " << strerror(errno);
					ok = false;
				}
			}
		}

		::close(sock);
		return ok;
#elif defined(__APPLE__)
		// 使用 ioctl 配置 utun (参考 avpn tundev_macos_service, 需要 root).
		// 注意: macOS 的 utun 是点对点接口, 必须同时指定对端地址, 否则
		// ioctl (SIOCAIFADDR) 报 "Destination address required". 这里以
		// 本端地址作为对端地址 (与 WireGuard 等 macOS tun 实现一致).
		struct ifaliasreq ifaliasreq;
		std::memset(&ifaliasreq, 0, sizeof(ifaliasreq));
		std::snprintf(ifaliasreq.ifra_name, IFNAMSIZ, "%s",
			m_devname.c_str());

		// 本端地址.
		struct sockaddr_in* in =
			reinterpret_cast<struct sockaddr_in*>(&ifaliasreq.ifra_addr);
		in->sin_family = AF_INET;
		in->sin_len = sizeof(ifaliasreq.ifra_addr);
		in->sin_addr.s_addr = htonl(vaddr);

		// 掩码.
		in = reinterpret_cast<struct sockaddr_in*>(&ifaliasreq.ifra_mask);
		in->sin_family = AF_INET;
		in->sin_len = sizeof(ifaliasreq.ifra_addr);
		in->sin_addr.s_addr = htonl(mask);

		// 广播地址.
		in = reinterpret_cast<struct sockaddr_in*>(&ifaliasreq.ifra_broadaddr);
		in->sin_family = AF_INET;
		in->sin_len = sizeof(ifaliasreq.ifra_addr);
		in->sin_addr.s_addr = htonl(vaddr) | ~htonl(mask);

		int sock = ::socket(AF_INET, SOCK_DGRAM, 0);
		if (sock < 0)
			return false;

		struct ifreq ifr;
		std::memset(&ifr, 0, sizeof(ifr));
		std::snprintf(ifr.ifr_name, IFNAMSIZ, "%s", m_devname.c_str());

		bool ok = true;

		// 启用接口.
		ifr.ifr_flags |= IFF_UP | IFF_NOARP | IFF_PROMISC;
		if (::ioctl(sock, SIOCSIFFLAGS, &ifr) < 0)
		{
			XLOG_ERR << "SIOCSIFFLAGS failed: " << strerror(errno);
			ok = false;
		}

		// 设置 MTU.
		if (ok)
		{
			ifr.ifr_mtu = mtu;
			if (::ioctl(sock, SIOCSIFMTU, &ifr) < 0)
			{
				XLOG_ERR << "SIOCSIFMTU failed: " << strerror(errno);
				ok = false;
			}
		}

		// 设置地址 (SIOCAIFADDR 通过 ifaliasreq 同时设置地址/掩码/广播).
		if (ok && ::ioctl(sock, SIOCAIFADDR, &ifaliasreq) < 0)
		{
			XLOG_ERR << "SIOCAIFADDR failed: " << strerror(errno);
			ok = false;
		}

		// 设置对端地址 (点对点接口必需).
		if (ok)
		{
			in = reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_dstaddr);
			in->sin_family = AF_INET;
			in->sin_len = sizeof(ifr.ifr_dstaddr);
			in->sin_addr.s_addr = htonl(vaddr);
			if (::ioctl(sock, SIOCSIFDSTADDR, &ifr) < 0)
			{
				XLOG_ERR << "SIOCSIFDSTADDR failed: " << strerror(errno);
				ok = false;
			}
		}

		::close(sock);

		// 自动添加 VPN 子网路由 (参考 avpn), 使本机可通过 tun 访问整个
		// 内网子网; 网关模式配置的是网络地址本身, 重复添加无害.
		if (ok)
		{
			net::ip::address_v4 net_addr(vaddr & mask);
			std::string route = "route -n add " + net_addr.to_string() + "/" +
				std::to_string(static_cast<int>(prefix)) +
				" -interface " + m_devname;
			std::string route_out;
			int ret = run_cmd_capture(route, route_out);
			if (ret != 0)
			{
				// 已存在或不可添加不算致命错误.
				XLOG_DBG << "add route (may already exist): " << route
					<< ", ret: " << ret
					<< (route_out.empty() ? "" : ", " + route_out);
			}
			else
			{
				XLOG_INFO << "Add route: " << net_addr.to_string() << "/"
					<< static_cast<int>(prefix) << " via " << m_devname;
			}
		}

		return ok;
#else
		(void)addr;
		(void)mask;
		(void)mtu;
		return false;
#endif
#endif // !defined(_WIN32)
	}

	bool tun_device::configure_v6(const net::ip::address_v6& v6_net,
		uint8_t prefix, uint32_t host)
	{
		if (!m_opened || m_devname.empty())
			return false;

#if defined(_WIN32)
		return m_wintun.configure_v6(v6_net, prefix, host);
#else
		auto bytes = v6_net.to_bytes();
		bytes[12] = static_cast<uint8_t>((host >> 24) & 0xff);
		bytes[13] = static_cast<uint8_t>((host >> 16) & 0xff);
		bytes[14] = static_cast<uint8_t>((host >> 8) & 0xff);
		bytes[15] = static_cast<uint8_t>(host & 0xff);
		auto addr = net::ip::address_v6(bytes).to_string();

		XLOG_INFO << "configure tun ipv6: " << m_devname
			<< ", addr: " << addr << "/" << static_cast<int>(prefix);

#if defined(__linux__)
		std::string cmd = std::string("ip -6 addr add ") + addr + "/" +
			std::to_string(prefix) + " dev " + m_devname;
		std::string cmd_out;
		int ret = run_cmd_capture(cmd, cmd_out);
		if (ret != 0)
		{
			XLOG_ERR << "ip -6 addr add failed: " << cmd << ", ret: " << ret
				<< (cmd_out.empty() ? "" : ", " + cmd_out);
			return false;
		}
		return true;
#elif defined(__APPLE__)
		std::string cmd = std::string("ifconfig ") + m_devname + " inet6 add " +
			addr + "/" + std::to_string(prefix);
		std::string cmd_out;
		int ret = run_cmd_capture(cmd, cmd_out);
		if (ret != 0)
		{
			XLOG_ERR << "ifconfig failed: " << cmd << ", ret: " << ret
				<< (cmd_out.empty() ? "" : ", " + cmd_out);
			return false;
		}
		return true;
#else
		(void)prefix;
		(void)host;
		(void)v6_net;
		return false;
#endif
#endif // !defined(_WIN32)
	}

} // namespace libavpn
