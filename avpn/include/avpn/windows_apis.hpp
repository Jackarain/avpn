//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#pragma once

#include "utils/logging.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#	define WIN32_LEAN_AND_MEAN
#endif // !WIN32_LEAN_AND_MEAN

#ifndef _WINSOCK_DEPRECATED_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#endif // _WINSOCK_DEPRECATED_NO_WARNINGS

#include <tchar.h>
#include <windows.h>
#include <winreg.h>
#include <winioctl.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#include <mstcpip.h>
#include <winternl.h>
#include <cfgmgr32.h>
#include <combaseapi.h>

#include <string>
#include <memory>
#include <optional>

#include <boost/throw_exception.hpp>
#include <boost/algorithm/string/trim.hpp>
#include <boost/asio/ip/network_v4.hpp>

namespace avpn {

	namespace details {

		inline void utf8_utf16(const std::string& utf8, std::wstring& utf16)
		{
			auto len = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, NULL, 0);
			if (len > 0)
			{
				wchar_t* tmp = (wchar_t*)malloc(sizeof(wchar_t) * len);
				if (!tmp)
					boost::throw_exception(std::bad_alloc());
				MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, tmp, len);
				utf16.assign(tmp);
				free(tmp);
			}
		}

		inline void utf16_utf8(const std::wstring& utf16, std::string& utf8)
		{
			auto len = WideCharToMultiByte(CP_UTF8, 0, utf16.c_str(), -1, NULL, 0, 0, 0);
			if (len > 0)
			{
				char* tmp = (char*)malloc(sizeof(char) * len);
				if (!tmp)
					boost::throw_exception(std::bad_alloc());
				WideCharToMultiByte(CP_UTF8, 0, utf16.c_str(), -1, tmp, len, 0, 0);
				utf8.assign(tmp);
				free(tmp);
			}
		}

		inline std::string error_format(DWORD err)
		{
			// Retrieve the system error message for the last-error code
			LPVOID lpMsgBuf;

			FormatMessage(
				FORMAT_MESSAGE_ALLOCATE_BUFFER |
				FORMAT_MESSAGE_FROM_SYSTEM |
				FORMAT_MESSAGE_IGNORE_INSERTS,
				NULL,
				err,
				MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
				(LPTSTR)&lpMsgBuf,
				0, NULL);

			// Display the error message and exit the process.
			std::string error_msg;
#ifdef UNICODE
			std::wstring tmp((LPTSTR)lpMsgBuf);
			utf16_utf8(tmp, error_msg);
#else
			error_msg.assign((char*)lpMsgBuf);
#endif // UNICODE
			LocalFree(lpMsgBuf);

			boost::trim(error_msg);

			return error_msg;
		}

		inline DWORD get_interface_index(const wchar_t* guid)
		{
			ULONG index = 0;
			DWORD status;
			std::wstring wstr;
			wstr.reserve(256);
			wstr = L"\\DEVICE\\TCPIP_" + std::wstring(guid);
			if ((status = GetAdapterIndex(wstr.data(), &index)) != NO_ERROR)
				return (DWORD)~0;
			else
				return index;
		}

		inline auto free_ppft = [](PMIB_IPFORWARDTABLE ppft) { ::free(ppft); };

		inline std::shared_ptr<MIB_IPFORWARDTABLE> get_windows_routing_table()
		{
			ULONG size = 0;
			PMIB_IPFORWARDTABLE rt = nullptr;
			DWORD status;
			std::shared_ptr<MIB_IPFORWARDTABLE> sprt;

			status = GetIpForwardTable(NULL, &size, TRUE);
			if (status == ERROR_INSUFFICIENT_BUFFER)
			{
				rt = (MIB_IPFORWARDTABLE*)::malloc(size);
				sprt.reset(rt, free_ppft);
				status = GetIpForwardTable(rt, &size, TRUE);
				if (status != NO_ERROR)
				{
					LOG_ERR << "NOTE: GetIpForwardTable returned error: "
						<< error_format(status) << "  (code=" << status << ")";
					return {};
				}
			}

			return sprt;
		}

		inline std::optional<MIB_IPFORWARDROW>
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
					[[maybe_unused]] const DWORD index = row->dwForwardIfIndex;
					const DWORD metric = row->dwForwardMetric1;

					if (!net && !mask && metric < lowest_metric)
					{
						ret = *row;
						lowest_metric = metric;
					}
				}
			}

			return { ret };
		}

		inline auto free_pai = [](PIP_ADAPTER_INFO pai) { ::free(pai); };

		inline std::shared_ptr<IP_ADAPTER_INFO> get_adapter_info_list()
		{
			ULONG size = 0;
			PIP_ADAPTER_INFO pi = nullptr;
			DWORD status;
			std::shared_ptr<IP_ADAPTER_INFO> spi;

			if ((status = GetAdaptersInfo(NULL, &size)) != ERROR_BUFFER_OVERFLOW)
			{
				LOG_ERR << "GetAdaptersInfo #1 failed (status="
					<< status << ") : " << error_format(status);
			}
			else
			{
				pi = (PIP_ADAPTER_INFO)::malloc(size);
				spi.reset(pi, free_pai);
				if ((status = GetAdaptersInfo(pi, &size)) != NO_ERROR)
				{
					LOG_ERR << "GetAdaptersInfo #2 failed (status="
						<< status << ") : " << error_format(status);

					return {};
				}
			}

			return spi;
		}

		inline std::optional<net::ip::network_v4> get_default_gateway()
		{
			auto routes = details::get_windows_routing_table();
			auto row = details::get_default_gateway_row(&*routes);

			if (row)
			{
				net::ip::address_v4 gw{ ntohl(row->dwForwardNextHop) };
				net::ip::address_v4 mask{ ntohl(row->dwForwardMask) };
				net::ip::network_v4 net(gw, mask);

				LOG_DBG << "Default gateway: " << gw.to_string()
					<< ", lowest metric: " << row->dwForwardMetric1;

				return net;
			}

			return {};
		}

		inline void windows_set_mtu(const int iface_index,
			const short family, const int mtu)
		{
			DWORD err = 0;
			MIB_IPINTERFACE_ROW ipiface = { 0 };
			InitializeIpInterfaceEntry(&ipiface);
			const char* family_name = (family == AF_INET6) ? "IPv6" : "IPv4";
			ipiface.Family = family;
			ipiface.InterfaceIndex = iface_index;
			if (family == AF_INET6 && mtu < 1280)
			{
				LOG_DBG << "NOTE: IPv6 interface MTU < 1280 conflicts with IETF standards and might not work";
			}

			err = GetIpInterfaceEntry(&ipiface);
			if (err == NO_ERROR)
			{
				if (family == AF_INET)
				{
					ipiface.SitePrefixLength = 0;
				}
				ipiface.NlMtu = mtu;
				err = SetIpInterfaceEntry(&ipiface);
			}

			if (err != NO_ERROR)
			{
				LOG_WARN << "TUN: Setting " << family_name << " mtu failed: "
					<< error_format(err) << " [status=" << err << " if_index=" << iface_index << "]";
			}
			else
			{
				LOG_DBG << family_name << " MTU set to " << mtu << " on interface " << iface_index << " using SetIpInterfaceEntry()";
			}
		}
	}
}
