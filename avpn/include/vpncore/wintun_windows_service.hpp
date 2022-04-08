//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#pragma once

#include "boost/asio/ip/network_v4.hpp"
#include "boost/asio/io_context.hpp"

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

#include <iostream>
#include <string>
#include <vector>
#include <deque>
#include <memory>
#include <span>
#include <condition_variable>

#include "vpncore/tuntap_config.hpp"
#include "utils/logging.hpp"

#include "wintun.h"

namespace avpn {

	static WINTUN_CREATE_ADAPTER_FUNC* WintunCreateAdapter;
	static WINTUN_CLOSE_ADAPTER_FUNC* WintunCloseAdapter;
	static WINTUN_OPEN_ADAPTER_FUNC* WintunOpenAdapter;
	static WINTUN_GET_ADAPTER_LUID_FUNC* WintunGetAdapterLUID;
	static WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC* WintunGetRunningDriverVersion;
	static WINTUN_DELETE_DRIVER_FUNC* WintunDeleteDriver;
	static WINTUN_SET_LOGGER_FUNC* WintunSetLogger;
	static WINTUN_START_SESSION_FUNC* WintunStartSession;
	static WINTUN_END_SESSION_FUNC* WintunEndSession;
	static WINTUN_GET_READ_WAIT_EVENT_FUNC* WintunGetReadWaitEvent;
	static WINTUN_RECEIVE_PACKET_FUNC* WintunReceivePacket;
	static WINTUN_RELEASE_RECEIVE_PACKET_FUNC* WintunReleaseReceivePacket;
	static WINTUN_ALLOCATE_SEND_PACKET_FUNC* WintunAllocateSendPacket;
	static WINTUN_SEND_PACKET_FUNC* WintunSendPacket;

	namespace details {

		static HMODULE InitializeWintun(void)
		{
			HMODULE Wintun =
				LoadLibraryExW(L"wintun.dll", NULL, LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
			if (!Wintun)
				return NULL;
#define X(Name) ((*(FARPROC *)&Name = GetProcAddress(Wintun, #Name)) == NULL)
			if (X(WintunCreateAdapter) || X(WintunCloseAdapter) || X(WintunOpenAdapter) || X(WintunGetAdapterLUID) ||
				X(WintunGetRunningDriverVersion) || X(WintunDeleteDriver) || X(WintunSetLogger) || X(WintunStartSession) ||
				X(WintunEndSession) || X(WintunGetReadWaitEvent) || X(WintunReceivePacket) || X(WintunReleaseReceivePacket) ||
				X(WintunAllocateSendPacket) || X(WintunSendPacket))
#undef X
			{
				DWORD LastError = GetLastError();
				FreeLibrary(Wintun);
				SetLastError(LastError);
				return NULL;
			}
			return Wintun;
		}

		static HANDLE AdapterOpenDeviceObject(const std::wstring& interfaceFilename)
		{
			HANDLE Handle = CreateFileW(
				interfaceFilename.data(),
				GENERIC_READ | GENERIC_WRITE,
				FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
				NULL,
				OPEN_EXISTING,
				0,
				NULL);
			return Handle;
		}

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

		static void CALLBACK WINTUN_LOGGER_CALLBACK(WINTUN_LOGGER_LEVEL Level, DWORD64 Timestamp, LPCWSTR Message)
		{
			LOG_DBG << "WINTUN_LOGGER_CALLBACK: " << Message;
		}

		struct init_wintun_apis
		{
			init_wintun_apis()
			{
				wintun_ = InitializeWintun();
				if (!wintun_)
					LOG_WARN << "init_wintun_apis, faild: " << error_format(GetLastError());
				else
					WintunSetLogger(WINTUN_LOGGER_CALLBACK);
			}

			~init_wintun_apis()
			{
				if (wintun_)
					FreeLibrary(wintun_);

				LOG_WARN << "init_wintun_apis::~init_wintun_apis()";
			}

			HMODULE handle()
			{
				return wintun_;
			}

			HMODULE wintun_;
		};
	}

	using details::get_default_gateway;

	class wintun_windows_service
		: public boost::asio::detail::service_base<wintun_windows_service>
	{
		// c++11 noncopyable.
		wintun_windows_service(const wintun_windows_service&) = delete;
		wintun_windows_service& operator=(const wintun_windows_service&) = delete;

		class wintun_operation
		{
		public:
			virtual ~wintun_operation() = default;
			virtual void operator()(void*, const boost::system::error_code&, std::size_t) = 0;
			virtual void transfer(void**, size_t*) = 0;
		};

		template<typename Handler, typename MutableBufferSequence, typename ExecutorType>
		class wintun_recv_op : public wintun_operation
		{
		public:
			wintun_recv_op(Handler&& handler, const MutableBufferSequence& buffers, ExecutorType executor)
				: handler_(std::forward<Handler>(handler))
				, buffer_sequence_(buffers)
				, executor_(executor)
			{}

			void operator()(void* incoming,
				const boost::system::error_code& ec, std::size_t bytes_transferred) override
			{
				bytes_transferred = std::min(bytes_transferred, boost::asio::buffer_size(buffer_sequence_));
				boost::asio::buffer_copy(buffer_sequence_, boost::asio::buffer(incoming, bytes_transferred));

				boost::asio::dispatch(executor_,
					[handler = std::forward<Handler>(handler_), ec, bytes_transferred]() mutable
				{
					handler(ec, bytes_transferred);
				});
			}

			void transfer(void**, size_t*) override
			{}

		// private:
			Handler handler_;
			const MutableBufferSequence& buffer_sequence_;
			ExecutorType executor_;
		};

		template<typename Handler, typename MutableBufferSequence, typename ExecutorType>
		class wintun_send_op : public wintun_operation
		{
		public:
			wintun_send_op(Handler&& handler, const MutableBufferSequence& buffers, ExecutorType executor)
				: handler_(std::forward<Handler>(handler))
				, buffer_sequence_(buffers)
				, executor_(executor)
			{}

			void operator()(void* incoming,
				const boost::system::error_code& ec, std::size_t bytes_transferred) override
			{
				boost::asio::dispatch(executor_,
					[handler = std::forward<Handler>(handler_), ec, bytes_transferred]() mutable
				{
					handler(ec, bytes_transferred);
				});
			}

			void transfer(void** ptr, size_t* bytes_transferred) override
			{
				*bytes_transferred = boost::asio::buffer_size(buffer_sequence_);
				*ptr = boost::asio::buffer_cast<void*>(buffer_sequence_);
			}

			// private:
			Handler handler_;
			const MutableBufferSequence& buffer_sequence_;
			ExecutorType executor_;
		};

		using operation_ptr = std::unique_ptr<wintun_operation>;
		using op_queue = std::deque<operation_ptr>;

	public:
		using executor_type = boost::asio::any_io_executor;

		explicit wintun_windows_service(boost::asio::io_context& io_context)
			: boost::asio::detail::service_base<wintun_windows_service>(io_context)
			, m_io_handle(io_context)
		{
			static details::init_wintun_apis initer;
		}

		~wintun_windows_service()
		{
			close();

			if (m_wintun_rthread.joinable())
				m_wintun_rthread.join();
			if (m_wintun_wthread.joinable())
				m_wintun_wthread.join();
		}

		executor_type get_executor() noexcept
		{
			return this->get_io_context().get_executor();
		}

		void internal_read_thread()
		{
			HANDLE WaitHandles[] = { WintunGetReadWaitEvent(m_tun_session), m_quit_event };

			std::unique_lock lock(m_read_mtx);
			m_read_cv.wait(lock, [this, WaitHandles]() mutable -> bool
			{
				while (!m_read_op.empty())
				{
					auto op = std::move(m_read_op.front());
					m_read_op.pop_front();

					while (!m_abort)
					{
						DWORD PacketSize;
						BYTE* Packet = WintunReceivePacket(m_tun_session, &PacketSize);
						if (Packet)
						{
							boost::system::error_code ec;
							(*op)((void*)Packet, ec, (size_t)PacketSize);

							WintunReleaseReceivePacket(m_tun_session, Packet);
							break;
						}

						DWORD LastError = GetLastError();
						switch (LastError)
						{
						case ERROR_NO_MORE_ITEMS:
							if (WaitForMultipleObjects(_countof(WaitHandles), WaitHandles, FALSE, INFINITE) == WAIT_OBJECT_0)
								continue;
							return true;
						default:
							LOG_ERR << "Packet read failed: " << details::error_format(LastError);
							return true;
						}
					}
				}

				return m_abort;
			});

			boost::system::error_code ec = boost::asio::error::operation_aborted;
			for (auto& op : m_read_op)
				(*op)((void*)nullptr, ec, (size_t)0);

			LOG_DBG << "internal_read_thread, quit...";
		}

		void internal_write_thread()
		{
			std::unique_lock lock(m_write_mtx);
			m_write_cv.wait(lock, [this]() mutable -> bool
				{
					while (!m_write_op.empty())
					{
						auto op = std::move(m_write_op.front());
						m_write_op.pop_front();

						void* ptr = nullptr;
						size_t size = 0;

						op->transfer(&ptr, &size);

						while (!m_abort)
						{
							BYTE* Packet = WintunAllocateSendPacket(m_tun_session, (DWORD)size);
							if (Packet)
							{
								std::memcpy(Packet, ptr, size);
								WintunSendPacket(m_tun_session, Packet);

								boost::system::error_code ec;
								(*op)((void*)nullptr, ec, (size_t)size);

								break;
							}

							auto LastError = GetLastError();
							if (LastError != ERROR_BUFFER_OVERFLOW)
							{
								LOG_ERR << "Packet write failed: " << details::error_format(LastError);
								return true;
							}

							auto ret = WaitForSingleObject(m_quit_event, 16);
							if (ret == WAIT_OBJECT_0 || ret == WAIT_ABANDONED)
								return true;
						}
					}

					return m_abort;
				});

			boost::system::error_code ec = boost::asio::error::operation_aborted;
			for (auto& op : m_write_op)
				(*op)((void*)nullptr, ec, (size_t)0);

			LOG_DBG << "internal_write_thread, quit...";
		}

		bool open(const dev_config& cfg)
		{
			auto randstr = gen_unique_string(sizeof(GUID));
			GUID AdapterGuid;
			std::memcpy((void*)&AdapterGuid, (const void*)randstr.data(), sizeof(GUID));
			// GUID ExampleGuid = { 0xdeadbabe, 0xcafe, 0xbeef, { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef } };
			m_tun_adapter = WintunCreateAdapter(L"AVPN", L"AvpnAdapter", &AdapterGuid);
			if (!m_tun_adapter)
			{
				LOG_ERR << "Failed to create adapter: " << details::error_format(GetLastError());
				return false;
			}

			DWORD Version = WintunGetRunningDriverVersion();
			LOG_DBG << "Wintun v" << ((Version >> 16) & 0xff) << "." << ((Version >> 0) & 0xff) << " loaded";

			MIB_UNICASTIPADDRESS_ROW AddressRow;
			InitializeUnicastIpAddressEntry(&AddressRow);
			WintunGetAdapterLUID(m_tun_adapter, &AddressRow.InterfaceLuid);

			auto tun_addr = boost::asio::ip::address_v4::from_string(cfg.local_);
			auto tun_mask = boost::asio::ip::address_v4::from_string(cfg.mask_);
			auto tun_network = boost::asio::ip::network_v4(tun_addr, tun_mask);

			AddressRow.Address.Ipv4.sin_family = AF_INET;
			// htonl((10 << 24) | (6 << 16) | (7 << 8) | (7 << 0)); /* 10.6.7.7 */
			AddressRow.Address.Ipv4.sin_addr.S_un.S_addr = htonl(tun_addr.to_ulong());
			// This is tun_addr / prefix_length network.
			AddressRow.OnLinkPrefixLength = (UINT8)tun_network.prefix_length();
			AddressRow.DadState = IpDadStatePreferred;
			auto LastError = CreateUnicastIpAddressEntry(&AddressRow);
			if (LastError != ERROR_SUCCESS && LastError != ERROR_OBJECT_ALREADY_EXISTS)
			{
				LOG_ERR << "Failed to set IP address: " << details::error_format(LastError);
				return false;
			}

			AddressRow.InterfaceLuid;
			WCHAR InstanceIdStr[MAX_GUID_STRING_LEN] = { 0 };
			StringFromGUID2(AdapterGuid, InstanceIdStr, _countof(InstanceIdStr));
			LOG_DBG << "InstanceIdStr: " << InstanceIdStr;

			m_tun_session = WintunStartSession(m_tun_adapter, 0x400000);
			m_quit_event = CreateEventW(NULL, TRUE, FALSE, NULL);

			m_wintun_rthread = std::thread([this]() { internal_read_thread(); });
			m_wintun_wthread = std::thread([this]() { internal_write_thread(); });

			m_abort = false;

			return true;
		}

		void close()
		{
			if (m_abort)
				return;

			m_abort = true;

			m_read_cv.notify_one();
			m_write_cv.notify_one();

			if (m_quit_event != INVALID_HANDLE_VALUE)
			{
				SetEvent(m_quit_event);
				CloseHandle(m_quit_event);

				m_quit_event = INVALID_HANDLE_VALUE;
			}

			if (m_tun_session != INVALID_HANDLE_VALUE)
				WintunEndSession(m_tun_session);
			if (m_tun_adapter != INVALID_HANDLE_VALUE)
				WintunCloseAdapter(m_tun_adapter);

			m_tun_adapter = (WINTUN_ADAPTER_HANDLE)INVALID_HANDLE_VALUE;
			m_tun_session = (WINTUN_SESSION_HANDLE)INVALID_HANDLE_VALUE;

			LOG_WARN << "wintun close...";
		}

		struct initiate_async_read_some
		{
			using executor_type = wintun_windows_service::executor_type;

			initiate_async_read_some(wintun_windows_service* self)
				: self_(self)
			{}

			executor_type get_executor() const noexcept
			{
				return self_->get_executor();
			}

			template <typename Handler, typename MutableBufferSequence>
			void operator()(Handler&& handler, const MutableBufferSequence& buffers)
			{
				std::lock_guard lock(self_->m_read_mtx);
				auto executor = boost::asio::get_associated_executor(handler, this->get_executor());
				self_->m_read_op.emplace_back(new wintun_recv_op<Handler,
					MutableBufferSequence, decltype(executor)>(std::forward<Handler>(handler), buffers, executor));
				self_->m_read_cv.notify_one();
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
				std::lock_guard lock(self_->m_write_mtx);
				auto executor = boost::asio::get_associated_executor(handler, this->get_executor());
				self_->m_write_op.emplace_back(new wintun_send_op<Handler,
					ConstBufferSequence, decltype(executor)>(std::forward<Handler>(handler), buffers, executor));
				self_->m_write_cv.notify_one();
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

		bool take_mac(char mac[6])
		{
			std::memcpy(mac, m_mac_addr.data(), 6);
			return true;
		}

		// 获取当前打开的wintun设备的mtu.
		int take_mtu()
		{
			return m_frame_mtu;
		}

		int get_if_index() const
		{
			return m_if_index;
		}

	private:
		std::vector<device_tuntap> m_device_list;
		dev_config m_config;

		std::thread m_wintun_wthread;
		std::thread m_wintun_rthread;

		std::mutex m_write_mtx;
		std::condition_variable m_write_cv;
		op_queue m_write_op;

		std::mutex m_read_mtx;
		std::condition_variable m_read_cv;
		op_queue m_read_op;

		std::deque<std::span<char>> m_write_queue;
		std::deque<std::span<char>> m_read_queue;

		WINTUN_ADAPTER_HANDLE m_tun_adapter{ (WINTUN_ADAPTER_HANDLE)INVALID_HANDLE_VALUE };
		WINTUN_SESSION_HANDLE m_tun_session{ (WINTUN_SESSION_HANDLE)INVALID_HANDLE_VALUE };

		HANDLE m_quit_event;

		bool m_abort{ true };

		int m_frame_mtu{ -1 };
		std::vector<uint8_t> m_mac_addr;
		boost::asio::stream_file m_io_handle;
		int m_if_index{ -1 };
	};
}

#endif
