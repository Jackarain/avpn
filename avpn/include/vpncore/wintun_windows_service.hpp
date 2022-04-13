//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#pragma once

#include "boost/asio/ip/network_v4.hpp"
#include "boost/asio/io_context.hpp"
#include "boost/asio/strand.hpp"
#include "boost/asio/windows/object_handle.hpp"

#include "boost/throw_exception.hpp"
#include "boost/nowide/convert.hpp"

#include "boost/algorithm/string/trim.hpp"

#if defined(WIN32) || defined(_WIN32) || defined(_WIN64) || defined(WIN64)

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

			return {ret};
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

		inline ULONG wintun_ring_packet_align(ULONG size)
		{
			return (size + (WINTUN_PACKET_ALIGN - 1)) & ~(WINTUN_PACKET_ALIGN - 1);
		}

		inline ULONG wintun_ring_wrap(ULONG value)
		{
			return value & (WINTUN_RING_CAPACITY - 1);
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
				UnInitWintun();
				LOG_WARN << "init_wintun_apis::~init_wintun_apis()";
			}
		};

	}


	using details::get_default_gateway;

	class wintun_windows_service
		: public boost::asio::detail::service_base<wintun_windows_service>
	{
		// c++11 noncopyable.
		wintun_windows_service(const wintun_windows_service&) = delete;
		wintun_windows_service& operator=(const wintun_windows_service&) = delete;

		int read_wintun(std::string_view buf)
		{
			struct tun_ring* ring = m_receive_ring;
			if (m_abort || !ring)
				return -1;

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
			auto content_len = details::wintun_ring_wrap(tail - head);

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
			auto aligned_packet_size = details::wintun_ring_packet_align(sizeof(struct TUN_PACKET_HEADER) + packet->size);

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
			head = details::wintun_ring_wrap(head + aligned_packet_size);
			ring->head = head;

			return packet->size;
		}

		int write_wintun(std::string_view buf)
		{
			struct tun_ring* ring = m_send_ring;
			if (m_abort || !ring)
				return -1;

			ULONG head = ring->head;
			ULONG tail = ring->tail;

			// 如果发送缓冲超出大小范围, 则表示出错.
			if ((head >= WINTUN_RING_CAPACITY) || (tail >= WINTUN_RING_CAPACITY))
			{
				LOG_WARN << "write_wintun(): head/tail value is over capacity";
				return -1;
			}

			// 计算要发送的数据包对齐大小.
			auto aligned_packet_size = details::wintun_ring_packet_align(sizeof(struct TUN_PACKET_HEADER) + buf.size());

			// 计算剩余空间的大小.
			auto buf_space = details::wintun_ring_wrap(head - tail - WINTUN_PACKET_ALIGN);

			// 如果要发送的数据大小大于剩余空间, 则表示未发送.
			if (aligned_packet_size > buf_space)
				return 0;

			// 复制数据到发送ring buffer.
			auto packet = (struct TUN_PACKET*)&ring->data[tail];
			packet->size = buf.size();
			memcpy(packet->data, buf.data(), buf.size());

			// 修改send ring的尾部位置.
			ring->tail = details::wintun_ring_wrap(tail + aligned_packet_size);

			// 可通知状态, 发送通知.
			if (ring->alertable != 0)
				SetEvent(m_send_event_moved);

			return buf.size();
		}

	public:
		using executor_type = boost::asio::any_io_executor;

		explicit wintun_windows_service(boost::asio::io_context& io_context)
			: boost::asio::detail::service_base<wintun_windows_service>(io_context)
			, m_receive_object_moved(io_context)
			, m_strand(io_context.get_executor())
		{
			static details::init_wintun initer;
		}

		~wintun_windows_service()
		{
			close();
		}

		executor_type get_executor() noexcept
		{
			return this->get_io_context().get_executor();
		}

		bool open(const dev_config& cfg)
		{
			LOG_DBG << "open wintun with: " << cfg.local_;

			GUID AdapterGuid = { 0xdeadbab1, 0xcafe, 0xbeef, { 0x01, 0x23, 0x45, 0x67, 0x00, 0x00, 0x00, 0xff } };
			if (!m_wintun_handle)
			{
				for (int n = 0; n < 5; n++)
				{
					m_wintun_handle = WintunCreateAdapter(L"AVPN", L"AvpnAdapter", &AdapterGuid);
					if (!m_wintun_handle)
						LOG_WARN << "WintunCreateAdapter fail, try to open exist adapter!";
					if (!m_wintun_handle)
						m_wintun_handle = WintunOpenAdapter(L"AVPN");
					if (!m_wintun_handle)
						LOG_WARN << "WintunCreateAdapter fail, retry again: " << n;
					if (m_wintun_handle)
						break;
				}
			}
			else
			{
				DeleteUnicastIpAddressEntry(&m_address_row);
			}

			MIB_UNICASTIPADDRESS_ROW AddressRow;
			InitializeUnicastIpAddressEntry(&AddressRow);
			WintunGetAdapterLUID(m_wintun_handle, &AddressRow.InterfaceLuid);

			auto tun_addr = boost::asio::ip::address_v4::from_string(cfg.local_);
			auto tun_mask = boost::asio::ip::address_v4::from_string(cfg.mask_);
			auto tun_network = boost::asio::ip::network_v4(tun_addr, tun_mask);

			AddressRow.Address.Ipv4.sin_family = AF_INET;
			AddressRow.Address.Ipv4.sin_addr.S_un.S_addr = htonl(tun_addr.to_ulong());
			AddressRow.OnLinkPrefixLength = (UINT8)tun_network.prefix_length();
			AddressRow.DadState = IpDadStatePreferred;
			auto LastError = CreateUnicastIpAddressEntry(&AddressRow);
			if (LastError != ERROR_SUCCESS && LastError != ERROR_OBJECT_ALREADY_EXISTS)
			{
				LOG_ERR << "Failed to set IP address: " << details::error_format(LastError);
				return false;
			}
			m_address_row = AddressRow;

			LPOLESTR dev_guid = NULL;
			[[maybe_unused]] auto rc0 = StringFromIID(AdapterGuid, &dev_guid);
			scoped_exit free_dev_guid([&]() mutable { CoTaskMemFree(dev_guid);  });

			auto if_index = details::get_interface_index(dev_guid);
			details::windows_set_mtu(if_index, AF_INET, 1450);

			m_wintun_file = open_wintun("AVPN");
			if (m_wintun_file == INVALID_HANDLE_VALUE)
			{
				LOG_ERR << "open_wintun: " << details::error_format(GetLastError());
				return false;
			}

			m_send_ring_handle = CreateFileMapping(INVALID_HANDLE_VALUE, NULL,
				PAGE_READWRITE,
				0,
				sizeof(struct tun_ring),
				NULL);
			if (m_send_ring_handle == INVALID_HANDLE_VALUE || m_send_ring_handle == NULL)
			{
				LOG_ERR << "CreateFileMapping for send: " << details::error_format(GetLastError());
				return false;
			}
			m_receive_ring_handle = CreateFileMapping(INVALID_HANDLE_VALUE,
				NULL,
				PAGE_READWRITE,
				0,
				sizeof(struct tun_ring),
				NULL);
			if (m_receive_ring_handle == INVALID_HANDLE_VALUE || m_receive_ring_handle == NULL)
			{
				LOG_ERR << "CreateFileMapping for write: " << details::error_format(GetLastError());
				return false;
			}
			m_send_ring = (struct tun_ring*)MapViewOfFile(m_send_ring_handle,
				FILE_MAP_ALL_ACCESS,
				0,
				0,
				sizeof(struct tun_ring));

			m_receive_ring = (struct tun_ring*)MapViewOfFile(m_receive_ring_handle,
				FILE_MAP_ALL_ACCESS,
				0,
				0,
				sizeof(struct tun_ring));

			m_send_event_moved = CreateEvent(NULL, FALSE, FALSE, NULL);
			m_receive_event_moved = CreateEvent(NULL, FALSE, FALSE, NULL);
			m_receive_object_moved.assign(m_receive_event_moved);

			struct tun_register_rings rr;
			ZeroMemory(&rr, sizeof(rr));

			rr.send.ring = m_receive_ring;
			rr.send.ring_size = sizeof(struct tun_ring);
			rr.send.tail_moved = m_receive_event_moved;

			rr.receive.ring = m_send_ring;
			rr.receive.ring_size = sizeof(struct tun_ring);
			rr.receive.tail_moved = m_send_event_moved;

			BOOL res;
			DWORD bytes_returned;
			res = DeviceIoControl(m_wintun_file, TUN_IOCTL_REGISTER_RINGS, &rr, sizeof(rr),
				NULL, 0, &bytes_returned, NULL);
			m_abort = false;

			LOG_DBG << "open wintun with: " << cfg.local_ << " successfully!";
			return true;
		}

		void close()
		{
			if (m_abort)
				return;

			m_abort = true;

			CloseHandle(m_send_event_moved);
			boost::system::error_code ignore_ec;
			m_receive_object_moved.close(ignore_ec);

			if (m_send_ring)
			{
				UnmapViewOfFile(m_send_ring);
				m_send_ring = nullptr;
			}

			if (m_receive_ring)
			{
				UnmapViewOfFile(m_receive_ring);
				m_receive_ring = nullptr;
			}

			if (m_send_ring_handle != INVALID_HANDLE_VALUE)
			{
				CloseHandle(m_send_ring_handle);
				m_send_ring_handle = INVALID_HANDLE_VALUE;
			}
			if (m_receive_ring_handle != INVALID_HANDLE_VALUE)
			{
				CloseHandle(m_receive_ring_handle);
				m_receive_ring_handle = INVALID_HANDLE_VALUE;
			}

			if (m_wintun_file != INVALID_HANDLE_VALUE)
			{
				CloseHandle(m_wintun_file);
				m_wintun_file = INVALID_HANDLE_VALUE;
			}

			if (m_wintun_handle != nullptr)
			{
				WintunCloseAdapter(m_wintun_handle);
				m_wintun_handle = nullptr;
			}

			LOG_WARN << "wintun close...";
		}

		struct initiate_async_read_some
		{
			using executor_type = wintun_windows_service::executor_type;

			initiate_async_read_some(wintun_windows_service* self)
				: self_(self)
			{}

			inline executor_type get_executor() const noexcept
			{
				return self_->get_executor();
			}

			template <typename Handler, typename MutableBufferSequence>
			void operator()(Handler&& handler, const MutableBufferSequence& buffers)
			{
				auto bufsize = boost::asio::buffer_size(buffers);
				auto bufptr = boost::asio::buffer_cast<uint8_t*>(buffers);
				std::string_view bufs((const char*)bufptr, bufsize);

				auto bytes_transferred = self_->read_wintun(bufs);
				if (bytes_transferred == 0)
				{
					LARGE_INTEGER Frequency;
					QueryPerformanceFrequency(&Frequency);
					ULONG64 SpinMax = Frequency.QuadPart / 1000 / 10;

					LARGE_INTEGER SpinStart;
					QueryPerformanceCounter(&SpinStart);

					for (; !self_->m_abort;)
					{
						bytes_transferred = self_->read_wintun(bufs);
						if (bytes_transferred > 0)
							break;

						if (bytes_transferred == 0)
						{
							LARGE_INTEGER SpinNow;
							QueryPerformanceCounter(&SpinNow);
							if ((ULONG64)SpinNow.QuadPart - (ULONG64)SpinStart.QuadPart >= SpinMax)
								break;

							Sleep(0);
							continue;
						}
					}
				}

				boost::system::error_code ec;

				// 经过spin后, 还是没有接收到数据, 则丢入等待协程.
				if (bytes_transferred == 0)
				{
					boost::asio::co_spawn(this->get_executor(),
						[self_ = self_, handler = std::move(handler), bufs = std::move(bufs)]
					() mutable->boost::asio::awaitable<void>
					{
						boost::system::error_code ec;
						int bytes_transferred = 0;

						scoped_exit fallback([&]() mutable
							{
								handler(ec, bytes_transferred);
							});

						if (self_->m_abort)
						{
							ec = boost::asio::error::operation_aborted;
							co_return;
						}

						auto& object = self_->m_receive_object_moved;
						for (;;)
						{
							co_await object.async_wait(uawaitable[ec]);
							if (ec)
								co_return;

							bytes_transferred = self_->read_wintun(bufs);
							if (bytes_transferred == 0)
								continue;
							if (bytes_transferred > 0)
								break;
							if (bytes_transferred < 0)
							{
								ec = boost::asio::error::operation_aborted;
								co_return;
							}
						}

						// 回调用户.
						fallback.dismiss();
						ec = {};
						handler(ec, bytes_transferred);

						co_return;
					}, boost::asio::detached);

					return;
				}
				else if (bytes_transferred < 0)
				{
					ec = boost::asio::error::operation_aborted;
				}

				// 回调用户.
				handler(ec, bytes_transferred);
			}

			wintun_windows_service* self_;
		};

		template <typename MutableBufferSequence, typename ReadHandler>
		BOOST_ASIO_INITFN_AUTO_RESULT_TYPE(ReadHandler,
			void(boost::system::error_code, std::size_t))
			async_read_some(const MutableBufferSequence& buffers, ReadHandler&& handler)
		{
			return async_initiate<ReadHandler,
				void(boost::system::error_code, std::size_t)>(
					initiate_async_read_some(this), handler, buffers);
		}

		struct initiate_async_write_some
		{
			using executor_type = wintun_windows_service::executor_type;

			initiate_async_write_some(wintun_windows_service* self)
				: self_(self)
			{}

			executor_type get_executor() const noexcept
			{
				return self_->get_executor();
			}

			template <typename Handler, typename ConstBufferSequence>
			void operator()(Handler&& handler, const ConstBufferSequence& buffers)
			{
				auto bufptr = boost::asio::buffer_cast<uint8_t*>(buffers);
				auto bufsize = boost::asio::buffer_size(buffers);
				std::string_view bufs((const char*)bufptr, bufsize);
				boost::system::error_code ec;

				auto bytes_transferred = self_->write_wintun(bufs);
				if (bytes_transferred <= 0 || self_->m_instrand > 0)
				{
					if ((self_->m_instrand == 0 && bytes_transferred < 0)
						|| self_->m_abort)
					{
						handler(ec, bytes_transferred);
						return;
					}
					self_->m_instrand++;

					// ring buffer已满, 写不进了, 开启协程写入.
					boost::asio::co_spawn(self_->m_strand,
						[self_ = self_, handler = std::move(handler), bufs = std::move(bufs)]
					() mutable->boost::asio::awaitable<void>
					{
						auto bytes_transferred = self_->write_wintun(bufs);
						boost::system::error_code ec;

						scoped_exit fallback([&]() mutable
							{
								self_->m_instrand--;
								handler(ec, bytes_transferred);
							});

						if (bytes_transferred < 0 || self_->m_abort)
						{
							ec = boost::asio::error::operation_aborted;
							co_return;
						}

						while (bytes_transferred == 0)
						{
							timer wait_timer(self_->get_executor());

							wait_timer.expires_from_now(std::chrono::milliseconds(1));
							co_await wait_timer.async_wait(uawaitable[ec]);

							bytes_transferred = self_->write_wintun(bufs);
							if (bytes_transferred < 0)
							{
								ec = boost::asio::error::operation_aborted;
								co_return;
							}
						}

						// 回调用户.
						fallback.dismiss();
						ec = {};
						self_->m_instrand--;
						handler(ec, bytes_transferred);

						co_return;
					}, boost::asio::detached);
				}

				handler(ec, bytes_transferred);
			}

			wintun_windows_service* self_;
		};

		template <typename ConstBufferSequence, typename WriteHandler>
		BOOST_ASIO_INITFN_AUTO_RESULT_TYPE(WriteHandler,
			void(boost::system::error_code, std::size_t))
			async_write_some(const ConstBufferSequence& buffers, WriteHandler&& handler)
		{
			return async_initiate<WriteHandler,
				void(boost::system::error_code, std::size_t)>(
					initiate_async_write_some(this), handler, buffers);
		}

		std::vector<device_tuntap> take_device_list()
		{
			return m_device_list;
		}

	private:
		std::vector<device_tuntap> m_device_list;
		dev_config m_config;

		HANDLE m_send_ring_handle{ INVALID_HANDLE_VALUE };
		HANDLE m_receive_ring_handle{ INVALID_HANDLE_VALUE };

		HANDLE m_send_event_moved{ INVALID_HANDLE_VALUE };
		HANDLE m_receive_event_moved{ INVALID_HANDLE_VALUE };
		boost::asio::windows::object_handle m_receive_object_moved;
		HANDLE m_wintun_file{ INVALID_HANDLE_VALUE };

		struct tun_ring* m_send_ring{ nullptr };
		struct tun_ring* m_receive_ring{ nullptr };

		volatile int m_instrand{ 0 };
		boost::asio::strand<boost::asio::any_io_executor> m_strand;

		WINTUN_ADAPTER_HANDLE m_wintun_handle{ 0 };
		MIB_UNICASTIPADDRESS_ROW m_address_row{ 0 };

		bool m_abort{ true };
	};
}

#endif
