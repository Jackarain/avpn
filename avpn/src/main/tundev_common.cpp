//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#include "avpn/tundev_common.hpp"
#include "utils/scoped_exit.hpp"
#include "utils/misc.hpp"
#include "utils/logging.hpp"

#include <boost/regex.hpp>
#include <boost/algorithm/string/split.hpp>

#include <limits>
#include <string>
#include <memory>
#include <optional>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef __linux__
#	include <arpa/inet.h>

#elif _WIN32

#	ifndef WIN32_LEAN_AND_MEAN
#		define WIN32_LEAN_AND_MEAN
#	endif // !WIN32_LEAN_AND_MEAN

#	ifndef _WINSOCK_DEPRECATED_NO_WARNINGS
#		define _WINSOCK_DEPRECATED_NO_WARNINGS
#	endif // _WINSOCK_DEPRECATED_NO_WARNINGS

#	include <boost/throw_exception.hpp>
#	include <boost/algorithm/string/trim.hpp>

#	include <tchar.h>
#	include <windows.h>
#	include <winreg.h>
#	include <winioctl.h>
#	include <ws2tcpip.h>
#	include <iphlpapi.h>

#	include <mstcpip.h>
#	include <winternl.h>
#	include <cfgmgr32.h>
#	include <combaseapi.h>

#endif

namespace avpn
{
	namespace common
	{

#if defined(__linux__) || defined(__ANDROID__)
		std::tuple<net::ip::network_v4, std::string> default_gateway()
		{
			long Destination;
			long Gateway;
			long Flags;
			long RefCnt;
			long Use;
			long Metric;
			long Mask;
			long MTU;
			long Window;
			long IRTT;

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
				if (sscanf(buf,
					"%16s %lx %lx %lx %ld %ld %ld %lx %ld %ld %ld",
					tmp,
					&Destination,
					&Gateway,
					&Flags,
					&RefCnt,
					&Use,
					&Metric,
					&Mask,
					&MTU,
					&Window,
					&IRTT) == 11)
				{
					if (Destination == 0 &&
						Mask == 0 &&
						Metric < lowest_metric)
					{
						lowest_metric = Metric;

						net::ip::address_v4 mask(ntohl(Mask));
						net::ip::address_v4 gw(ntohl(Gateway));

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

#elif _WIN32

		DWORD get_interface_index(const wchar_t* guid)
		{
			ULONG index = 0;
			DWORD status;
			std::wstring wstr;

			wstr.reserve(256);
			wstr = L"\\DEVICE\\TCPIP_" + std::wstring(guid);
			if ((status = GetAdapterIndex(
				wstr.data(),
				&index)) != NO_ERROR)
				return (DWORD)~0;
			else
				return index;
		}

		inline auto free_ppft = [](PMIB_IPFORWARDTABLE ppft)
		{
			::free(ppft);
		};

		inline
		std::shared_ptr<MIB_IPFORWARDTABLE>
		get_windows_routing_table()
		{
			ULONG size = 0;
			PMIB_IPFORWARDTABLE rt = nullptr;
			DWORD status;
			std::shared_ptr<MIB_IPFORWARDTABLE> sprt;

			status = GetIpForwardTable(
				NULL,
				&size,
				TRUE);
			if (status == ERROR_INSUFFICIENT_BUFFER)
			{
				rt = (MIB_IPFORWARDTABLE*)::malloc(size);
				sprt.reset(rt, free_ppft);

				status = GetIpForwardTable(
					rt,
					&size,
					TRUE);
				if (status != NO_ERROR)
				{
					LOG_ERR << "NOTE: GetIpForwardTable returned error: "
						<< error_format(status)
						<< "  (code="
						<< status
						<< ")";
					return {};
				}
			}

			return sprt;
		}

		inline
		std::optional<MIB_IPFORWARDROW>
		get_default_gateway_row(const MIB_IPFORWARDTABLE* routes)
		{
			DWORD lowest_metric = MAXDWORD;
			MIB_IPFORWARDROW ret = { 0 };

			if (routes)
			{
				for (DWORD i = 0; i < routes->dwNumEntries; ++i)
				{
					const MIB_IPFORWARDROW* row = &routes->table[i];
					const auto net = ntohl(row->dwForwardDest);
					const auto mask = ntohl(row->dwForwardMask);
					(void)row->dwForwardIfIndex;
					const DWORD metric = row->dwForwardMetric1;

					if (!net &&
						!mask &&
						metric < lowest_metric)
					{
						ret = *row;
						lowest_metric = metric;
					}
				}
			}

			return { ret };
		}

		inline auto free_pai = [](PIP_ADAPTER_INFO pai)
		{
			::free(pai);
		};

		inline
		std::shared_ptr<IP_ADAPTER_INFO>
		get_adapter_info_list()
		{
			ULONG size = 0;
			PIP_ADAPTER_INFO pi = nullptr;
			DWORD status;
			std::shared_ptr<IP_ADAPTER_INFO> spi;

			status = GetAdaptersInfo(
				NULL,
				&size);
			if (status != ERROR_BUFFER_OVERFLOW)
			{
				LOG_ERR << "GetAdaptersInfo #1 failed (status="
					<< status << ") : "
					<< error_format(status);
			}
			else
			{
				pi = (PIP_ADAPTER_INFO)::malloc(size);
				spi.reset(pi, free_pai);

				status = GetAdaptersInfo(
					pi,
					&size);
				if (status != NO_ERROR)
				{
					LOG_ERR << "GetAdaptersInfo #2 failed (status="
						<< status
						<< ") : "
						<< error_format(status);

					return {};
				}
			}

			return spi;
		}

		std::tuple<net::ip::network_v4, std::string> default_gateway()
		{
			auto routes = get_windows_routing_table();
			auto row = get_default_gateway_row(&*routes);

			if (row)
			{
				net::ip::address_v4 gw(ntohl(row->dwForwardNextHop));
				net::ip::address_v4 mask(ntohl(row->dwForwardMask));
				net::ip::network_v4 net(gw, mask);

				LOG_DBG << "Default gateway: "
					<< gw.to_string()
					<< ", lowest metric: "
					<< row->dwForwardMetric1;

				return { net, gw.to_string() };
			}

			return {};
		}

		void windows_set_mtu(
			const int iface_index, const short family, const int mtu)
		{
			DWORD err = 0;
			MIB_IPINTERFACE_ROW ipiface = { 0 };
			InitializeIpInterfaceEntry(&ipiface);

			const char* family_name =
				(family == AF_INET6) ? "IPv6" : "IPv4";
			ipiface.Family = family;
			ipiface.InterfaceIndex = iface_index;
			if (family == AF_INET6 && mtu < 1280)
			{
				LOG_DBG << "NOTE: IPv6 interface MTU < 1280"
					<< " conflicts with IETF standards"
					<< " and might not work";
			}

			err = GetIpInterfaceEntry(&ipiface);
			if (err == NO_ERROR)
			{
				if (family == AF_INET)
					ipiface.SitePrefixLength = 0;

				ipiface.NlMtu = mtu;
				err = SetIpInterfaceEntry(&ipiface);
			}

			if (err != NO_ERROR)
			{
				LOG_WARN << "TUN: Setting "
					<< family_name << " mtu failed: "
					<< error_format(err) << " [status="
					<< err << " if_index="
					<< iface_index << "]";
			}
			else
			{
				LOG_DBG << family_name
					<< " MTU set to " << mtu
					<< " on interface " << iface_index
					<< " using SetIpInterfaceEntry()";
			}
		}

#elif __APPLE__
		std::tuple<net::ip::network_v4, std::string> default_gateway()
		{
			auto [result, ret] = run_command("netstat -rn -f inet");
			if (!ret)
				return {};

			std::vector<std::string> strings;
			boost::split(strings,
				result,
				boost::is_any_of("\n"));
			boost::regex expression(
				R"((default)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S*).*)");

			for (const auto word : strings)
			{
				boost::smatch what;
				if (boost::regex_match(
					word,
					what,
					expression))
				{
					std::string gateway = std::string(what[2]);
					boost::system::error_code ec;
					using net::ip::address_v4::from_string;

					auto gw = from_string(gateway, ec);
					if (ec)
						continue;
					net::ip::address_v4 mask{ 0 };

					auto net = net::ip::network_v4(gw, mask);
					LOG_DBG << "Default gateway: " << gw.to_string();

					return { net, ""};
				}
			}

			return {};
		}
#endif

	}
}
