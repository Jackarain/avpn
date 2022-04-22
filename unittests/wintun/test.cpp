#define BOOST_TEST_MAIN

#ifdef USE_MIMALLOC

#ifdef MI_OVERRIDE
#	include <mimalloc.h>
#else
#	include <mimalloc-new-delete.h>
#endif

#ifdef _WIN32
#	include <mimalloc-new-delete.h>
#endif

#endif // USE_MIMALLOC

#include <boost/test/included/unit_test.hpp>
#include <cstdlib>
#include <ctime>

#include "boost/asio/ip/network_v4.hpp"
#include "boost/asio/io_context.hpp"
#include "boost/asio/stream_file.hpp"

#include "boost/throw_exception.hpp"
#include "boost/nowide/convert.hpp"

#include "boost/algorithm/string/trim.hpp"

#include "utils/misc.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#	define WIN32_LEAN_AND_MEAN
#endif // !WIN32_LEAN_AND_MEAN

#ifndef _WINSOCK_DEPRECATED_NO_WARNINGS
#	define _WINSOCK_DEPRECATED_NO_WARNINGS
#endif // _WINSOCK_DEPRECATED_NO_WARNINGS

#include <tchar.h>
#include <windows.h>
#include <winreg.h>
#include <winioctl.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#include <mstcpip.h>
#include <ip2string.h>
#include <winternl.h>
#include <cfgmgr32.h>
#include <ndisguid.h>
#include <combaseapi.h>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Cfgmgr32.lib")
#pragma comment(lib, "Ole32.lib")

#include <algorithm>
#include <iostream>
#include <string>
#include <vector>
#include <deque>
#include <memory>
#include <span>
#include <condition_variable>

#include "vpncore/tuntap_config.hpp"
#include "vpncore/endpoint_pair.hpp"

#include "utils/scoped_exit.hpp"
#include "utils/logging.hpp"

extern "C" {
	#include "ring_buffer.h"
	#include "wintun_main.h"
	#include "adapter.h"
}


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

	inline DWORD get_interface_index(const TCHAR* guid)
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

	static auto free_ppft = [](PMIB_IPFORWARDTABLE ppft) { ::free(ppft); };

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

	static auto free_pai = [](PIP_ADAPTER_INFO pai) { ::free(pai); };

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

	inline std::optional<boost::asio::ip::network_v4> get_default_gateway()
	{
		auto routes = details::get_windows_routing_table();
		auto row = details::get_default_gateway_row(&*routes);

		if (row)
		{
			boost::asio::ip::address_v4 gw{ ntohl(row->dwForwardNextHop) };
			boost::asio::ip::address_v4 mask{ ntohl(row->dwForwardMask) };
			boost::asio::ip::network_v4 net(gw, mask);

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

	struct init_wintun
	{
		init_wintun()
		{
			install_wintun();
			InitWintun();
		}

		~init_wintun()
		{
			WintunCloseAdapter(handle_);
			UnInitWintun();
			LOG_WARN << "init_wintun_apis::~init_wintun_apis()";
		}

		WINTUN_ADAPTER_HANDLE handle_{ 0 };
	};
}

static inline ULONG
wintun_ring_packet_align(ULONG size)
{
	return (size + (WINTUN_PACKET_ALIGN - 1)) & ~(WINTUN_PACKET_ALIGN - 1);
}

static inline ULONG
wintun_ring_wrap(ULONG value)
{
	return value & (WINTUN_RING_CAPACITY - 1);
}

static details::init_wintun initer;


HANDLE g_send_ring_handle;
HANDLE g_receive_ring_handle;

struct tun_ring* g_send_ring;
struct tun_ring* g_receive_ring;

HANDLE g_send_event_moved;
HANDLE g_receive_event_moved;

//////////////////////////////////////////////////////////////////////////

bool writeable()
{
	struct tun_ring* ring = g_send_ring;

	ULONG head = ring->head;
	ULONG tail = ring->tail;

	if ((head >= WINTUN_RING_CAPACITY) || (tail >= WINTUN_RING_CAPACITY))
		return false;

	auto buf_space = wintun_ring_wrap(head - tail - WINTUN_PACKET_ALIGN);
	if (buf_space <= 0)
		return false;

	return true;
}

bool readable()
{
	struct tun_ring* ring = g_receive_ring;

	ULONG head = ring->head;
	ULONG tail = ring->tail;

	if ((head >= WINTUN_RING_CAPACITY) || (tail >= WINTUN_RING_CAPACITY))
		return false;

	if (head == tail)
		return false;

	auto content_len = wintun_ring_wrap(tail - head);
	if (content_len < sizeof(struct TUN_PACKET_HEADER))
		return false;

	return true;
}

int write_wintun(std::string_view buf)
{
	struct tun_ring* ring = g_send_ring;

	ULONG head = ring->head;
	ULONG tail = ring->tail;

	// 如果发送缓冲超出大小范围, 则表示出错.
	if ((head >= WINTUN_RING_CAPACITY) || (tail >= WINTUN_RING_CAPACITY))
	{
		LOG_WARN << "write_wintun(): head/tail value is over capacity";
		return -1;
	}

	// 计算要发送的数据包对齐大小.
	auto aligned_packet_size = wintun_ring_packet_align(ULONG(sizeof(struct TUN_PACKET_HEADER) + buf.size()));

	// 计算剩余空间的大小.
	auto buf_space = wintun_ring_wrap(head - tail - WINTUN_PACKET_ALIGN);

	// 如果要发送的数据大小大于剩余空间, 则表示未发送.
	if (aligned_packet_size > buf_space)
	{
		// LOG_WARN << "write_wintun(): ring is full";
		return 0;
	}

	// 复制数据到发送ring buffer.
	auto packet = (struct TUN_PACKET*)&ring->data[tail];
	packet->size = (uint32_t)buf.size();
	memcpy(packet->data, buf.data(), buf.size());

	// 修改send ring的尾部位置.
	ring->tail = wintun_ring_wrap(tail + aligned_packet_size);

	// 可通知状态, 发送通知.
	if (ring->alertable != 0)
		SetEvent(g_send_event_moved);

	return (int)buf.size();
}

int read_wintun(std::string_view buf)
{
	struct tun_ring* ring = g_receive_ring;

	ULONG head = ring->head;
	ULONG tail = ring->tail;

	// 首尾超出了ring buffer范围.
	if ((head >= WINTUN_RING_CAPACITY) || (tail >= WINTUN_RING_CAPACITY))
	{
		LOG_WARN << "Wintun: ring capacity exceeded";
		return -1;
	}

	// 无数据可读.
	if (head == tail)
	{
		/* nothing to read */
		return 0;
	}

	// 获取ring buffer中的可读取的数据大小.
	auto content_len = wintun_ring_wrap(tail - head);

	// 如果不够TUN_PACKET_HEADER大小, 则说明发生了错误.
	if (content_len < sizeof(struct TUN_PACKET_HEADER))
	{
		LOG_WARN << "Wintun: incomplete packet header in send ring";
		return -1;
	}

	// 从读取位置开始, 解析一个TUN_PACKET.
	auto packet = (struct TUN_PACKET*)&ring->data[head];

	// packet->size 不应该大于 WINTUN_MAX_PACKET_SIZE 大小.
	if (packet->size > WINTUN_MAX_PACKET_SIZE)
	{
		LOG_WARN << "Wintun: packet too big in send ring";
		return -1;
	}

	// 计算对齐大小.
	auto aligned_packet_size = wintun_ring_packet_align(sizeof(struct TUN_PACKET_HEADER) + packet->size);

	// 对齐数据大小不应该大于可读取的数据大小.
	if (aligned_packet_size > content_len)
	{
		LOG_WARN << "Wintun: incomplete packet in send ring";
		return -1;
	}

	if (buf.size() < packet->size)
	{
		LOG_WARN << "Wintun: read buffer size too small";
		return -1;
	}

	// 复制数据到接收缓冲区.
	memcpy((void*)buf.data(), packet->data, packet->size);

	// 计算新的head位置.
	head = wintun_ring_wrap(head + aligned_packet_size);
	ring->head = head;

	return packet->size;
}

static
USHORT IPChecksum(uint8_t* Buffer, DWORD Len)
{
	ULONG Sum = 0;
	for (; Len > 1; Len -= 2, Buffer += 2)
		Sum += *(USHORT*)Buffer;
	if (Len)
		Sum += *Buffer;
	Sum = (Sum >> 16) + (Sum & 0xffff);
	Sum += (Sum >> 16);
	return (USHORT)(~Sum);
}


static
void MakeICMP(uint8_t* Packet)
{
	memset(Packet, 0, 28);
	Packet[0] = 0x45;
	*(USHORT*)&Packet[2] = htons(28);
	Packet[8] = 255;
	Packet[9] = 1;
	*(ULONG*)&Packet[12] = htonl((10 << 24) | (0 << 16) | (0 << 8) | (1 << 0)); /* 10.0.0.1 */
	*(ULONG*)&Packet[16] = htonl((10 << 24) | (0 << 16) | (0 << 8) | (8 << 0)); /* 10.0.0.8 */
	*(USHORT*)&Packet[10] = IPChecksum(Packet, 20);
	Packet[20] = 8;
	*(USHORT*)&Packet[22] = IPChecksum(&Packet[20], 8);
}


bool open_tun()
{
	GUID AdapterGuid;
	[[maybe_unused]] HRESULT hr = CoCreateGuid(&AdapterGuid);

	initer.handle_ = WintunCreateAdapter(L"AVPN", L"AvpnAdapter", &AdapterGuid);

	BOOST_TEST(initer.handle_ != nullptr);

	MIB_UNICASTIPADDRESS_ROW AddressRow;
	InitializeUnicastIpAddressEntry(&AddressRow);
	WintunGetAdapterLUID(initer.handle_, &AddressRow.InterfaceLuid);

	const std::string local = "10.0.0.8";
	const std::string mask = "255.255.0.0";

	auto tun_addr = boost::asio::ip::address_v4::from_string(local);
	auto tun_mask = boost::asio::ip::address_v4::from_string(mask);
	auto tun_network = boost::asio::ip::network_v4(tun_addr, tun_mask);

	AddressRow.Address.Ipv4.sin_family = AF_INET;
	AddressRow.Address.Ipv4.sin_addr.S_un.S_addr = htonl(tun_addr.to_ulong());
	AddressRow.OnLinkPrefixLength = (UINT8)tun_network.prefix_length();
	AddressRow.DadState = IpDadStatePreferred;
	auto LastError = CreateUnicastIpAddressEntry(&AddressRow);

	BOOL NoError = LastError == ERROR_SUCCESS || LastError == ERROR_OBJECT_ALREADY_EXISTS;

	BOOST_TEST(NoError == TRUE);

	if (LastError != ERROR_SUCCESS && LastError != ERROR_OBJECT_ALREADY_EXISTS)
	{
		LOG_ERR << "Failed to set IP address: " << details::error_format(LastError);
		return false;
	}

	LPOLESTR dev_guid = NULL;
	[[maybe_unused]] auto rc0 = StringFromIID(AdapterGuid, &dev_guid);
	scoped_exit free_dev_guid([&]() mutable { CoTaskMemFree(dev_guid);  });

	auto if_index = details::get_interface_index(dev_guid);
	details::windows_set_mtu(if_index, AF_INET, 1450);

	auto handle = open_wintun("AVPN");
	BOOST_TEST(handle != INVALID_HANDLE_VALUE);
	if (handle == INVALID_HANDLE_VALUE)
	{
		LOG_ERR << "open_wintun: " << details::error_format(GetLastError());
		return false;
	}

	g_send_ring_handle = CreateFileMapping(INVALID_HANDLE_VALUE, NULL,
		PAGE_READWRITE,
		0,
		sizeof(struct tun_ring),
		NULL);
	g_receive_ring_handle = CreateFileMapping(INVALID_HANDLE_VALUE,
		NULL,
		PAGE_READWRITE,
		0,
		sizeof(struct tun_ring),
		NULL);

	g_send_ring = (struct tun_ring*)MapViewOfFile(g_send_ring_handle,
		FILE_MAP_ALL_ACCESS,
		0,
		0,
		sizeof(struct tun_ring));

	g_receive_ring = (struct tun_ring*)MapViewOfFile(g_receive_ring_handle,
		FILE_MAP_ALL_ACCESS,
		0,
		0,
		sizeof(struct tun_ring));

	g_send_event_moved = CreateEvent(NULL, FALSE, FALSE, NULL);
	g_receive_event_moved = CreateEvent(NULL, FALSE, FALSE, NULL);

	struct tun_register_rings rr;
	ZeroMemory(&rr, sizeof(rr));

	// wintun 的 发送队列, 即是我们的接收队列.
	rr.send.ring = g_receive_ring;
	rr.send.ring_size = sizeof(struct tun_ring);
	rr.send.tail_moved = g_receive_event_moved;

	// wintun 的 接收队列, 即是我们的发送队列.
	rr.receive.ring = g_send_ring;
	rr.receive.ring_size = sizeof(struct tun_ring);
	rr.receive.tail_moved = g_send_event_moved;

	DWORD bytes_returned = 0;
	BOOL res = DeviceIoControl(handle, TUN_IOCTL_REGISTER_RINGS, &rr, sizeof(rr),
		NULL, 0, &bytes_returned, NULL);

	BOOST_TEST(res == TRUE);

	auto write_thr = std::thread([] {

		std::string bufs(1052, 0);
		MakeICMP((uint8_t*)bufs.data());

		int64_t total = 0;
		int64_t last_total = 0;

		auto last_time = time_clock::steady_clock::now();

		for (;;)
		{
			int ret = write_wintun(bufs);
			if (ret < 0)
				break;
			if (ret == 0)
			{
				for (; !writeable();)
					Sleep(1);
				continue;
			}

			total += ret;
			auto size = total - last_total;
			if (size > 512 * 1024 * 1024)
			{
				auto now = time_clock::steady_clock::now();
				auto dur = now - last_time;
				last_time = now;
				last_total = total;

				auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(dur);
				auto rate = (double)size / ((double)ms.count() / 1000);

				LOG_DBG << "Send: " << add_suffix((float)rate, "/s");
			}
		}
	});

	auto read_thr = std::thread([] {
		std::string read_bufs(1500, 0);

		int64_t total = 0;
		int64_t last_total = 0;

		auto last_time = time_clock::steady_clock::now();

		LARGE_INTEGER Frequency;
		QueryPerformanceFrequency(&Frequency);
		ULONG64 SpinMax = Frequency.QuadPart / 1000 / 10; /* 1/10 ms */

		while (true)
		{
			int ret;
			LARGE_INTEGER SpinStart;
			QueryPerformanceCounter(&SpinStart);

			for (;;)
			{
				ret = read_wintun(read_bufs);
				if (ret > 0)
				{
					auto endp = avpn::lookup_endpoint_pair((const uint8_t*)read_bufs.data(), ret);
					endp.to_string();
					break;
				}
				if (ret == 0)
				{
					LARGE_INTEGER SpinNow;
					QueryPerformanceCounter(&SpinNow);
					if ((ULONG64)SpinNow.QuadPart - (ULONG64)SpinStart.QuadPart >= SpinMax)
					{
						// LOG_DBG << "WaitForSingleObject";
						WaitForSingleObject(g_receive_event_moved, INFINITE);
						break;
					}
					Sleep(0);
					continue;

					// LOG_DBG << "WaitForSingleObject";
					// WaitForSingleObject(g_receive_event_moved, INFINITE);
				}

				break;
			}

			if (ret == -1)
				break;

			total += ret;
			auto size = total - last_total;
			if (size > 512 * 1024 * 1024)
			{
				auto now = time_clock::steady_clock::now();
				auto dur = now - last_time;
				last_time = now;
				last_total = total;

				auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(dur);
				auto rate = (double)size / ((double)ms.count() / 1000);

				LOG_DBG << "Recvive: " << add_suffix((float)rate, "/s");
			}
		}
	});

	write_thr.join();
	read_thr.join();

// 	g_receive_handle.assign(g_receive_tail_moved);
// 	g_send_handle.assign(g_send_tail_moved);


	return true;
}



BOOST_AUTO_TEST_CASE(wintun_test)
{
	open_tun();
}

