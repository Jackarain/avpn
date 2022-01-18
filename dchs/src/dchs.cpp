#include "dchs/dchs.hpp"
#include "dchs/mainnet_genesis_block.hpp"
#include "dchs/async_connect.hpp"
#include "dchs/url_parser.hpp"
#include "dchs/scoped_exit.hpp"
#include "dchs/simple_http.hpp"
#include "dchs/multipart.hpp"
#include "dchs/fileop.hpp"
#include "dchs/version.hpp"

#include "vpncore/endpoint_pair.hpp"

#include <chrono>
#include <iomanip>

#include <boost/json.hpp>
#include <boost/date_time.hpp>

#include <boost/regex.hpp>


#ifdef __clang__
#	pragma clang diagnostic push
#	pragma clang diagnostic ignored "-Wexpansion-to-defined"
#endif

#include <fmt/ostream.h>
#include <fmt/printf.h>
#include <fmt/format.h>

#ifdef __clang__
#	pragma clang diagnostic pop
#endif


namespace dchs {
	using namespace std::chrono_literals;

	dchs_service::dchs_service(io_context_pool& ios, const server_config& config)
		: m_io_context_pool(ios)
		, m_io_context(m_io_context_pool.server_io_context())
		, m_config(config)
		, m_tuntap(m_io_context)
		, m_tuntap_timer(m_io_context)
		, m_channel(m_io_context, m_io_context_pool)
	{
	}

	dchs_service::~dchs_service()
	{
		LOG_DBG << "~dchs_service()";
	}

	void dchs_service::start()
	{
		start_vpn();
	}

	void dchs_service::stop()
	{
		boost::system::error_code ignore_ec;
		m_abort = true;

		LOG_DBG << "close channel.";
		m_channel.close();

		LOG_DBG << "stop tuntap.";
		if (m_start_tuntap)
			m_tuntap.close();

		LOG_DBG << "dchs_service.stop()";
	}

	void dchs_service::start_tun(boost::asio::yield_context& yield)
	{
		boost::system::error_code ec;

		while (!m_abort)
		{
			avpn::MessageT msg;
			auto& content = msg.content;
			content.resize(128 * 1024);

			auto bytes = m_tuntap.async_read_some(boost::asio::buffer(content), yield[ec]);
			if (ec)
			{
				LOG_WARN << "start_tun, async_read_some: " << ec.message();
				break;
			}

			// 解析ip相关的信息.
			auto endp = avpn::lookup_endpoint_pair((const uint8_t*)content.data(), bytes);

			// 解析不出来的ip包, 直接跳过...
			if (endp.empty())
				continue;

			// 保存数据包类型.
			if (endp.type_ == avpn::ip_type::ip_tcp)
				msg.type = avpn::pkt_type::pt_tcp;
			else if (endp.type_ == avpn::ip_type::ip_udp)
				msg.type = avpn::pkt_type::pt_udp;

			// 根据程序的身份, 准备透传.
			if (m_config.identity_ == dchs_server)
			{
				// 作为server时, 要根据ip寻找到对应的通信通道.
			}
			else if (m_config.identity_ == dchs_client)
			{
				// 未连接状态, 丢弃所有packet.
				if (m_channel_status != avpn::channel_status::st_connected)
					break;

				// 透传到channel.
				m_channel.client_write(std::move(msg), endp);
			}
		}

		LOG_WARN << "start_tun quit...";
	}

	void dchs_service::start_vpn()
	{
		boost::system::error_code ec;

		// 客户端启动客户端通信通道.
		if (m_config.identity_ == dchs::dchs_client)
			m_channel.start_connect(m_config.upstreams_,
				[this](avpn::channel_status status)
				{
					m_channel_status = status;

					// 连接成功, 如果没有启动tun, 则启动tun设备.
					if (status == avpn::channel_status::st_connected)
					{
						LOG_DBG << "vpn connected";

						if (m_start_tuntap)
							return;
						m_start_tuntap = true;

						std::string ipaddr = m_channel.virtual_ipaddr();
						if (ipaddr.empty())
						{
							LOG_ERR << "vpn virtual ip address is empty!";
							return;
						}

						setup_tun(ipaddr);

						LOG_DBG << "vpn device start...";

						boost::asio::spawn(m_io_context_pool.get_io_context().get_executor(),
						[this](boost::asio::yield_context yield) mutable
						{
							start_tun(yield);
						});
					}

					// 断开状态.
					if (status == avpn::channel_status::st_disconnect)
					{
						if (m_abort)
							return;

						LOG_WARN << "vpn disconnect...";
					}
				},
				[this](std::string&& message) { do_tuntap_write(std::move(message)); }
			);

		// 服务器则将启动服务器通信通道.
		if (m_config.identity_ == dchs::dchs_server)
			m_channel.start_listen(m_config.tcp_listens_, m_config.udp_listens_,
				[this](avpn::channel_status status) { boost::ignore_unused(status); },
				[this](std::string&& message) { do_tuntap_write(std::move(message)); }
			);
	}

	void dchs_service::start_tuntap_write(boost::asio::yield_context& yield)
	{
		boost::system::error_code ec;

		while (!m_abort)
		{
			while (!m_abort && !m_tuntap_write_deque.empty())
			{
				m_tuntap.async_write_some(boost::asio::buffer(m_tuntap_write_deque.front()), yield[ec]);
				if (ec)
				{
					LOG_ERR << "start_tuntap_write, async_write error: " << ec.message();
					return;
				}
				m_tuntap_write_deque.pop_front();
			}

			while (!m_abort)
			{
				m_tuntap_timer.expires_from_now(std::chrono::seconds(10)); // 每10s发起一次ping以保活.
				m_tuntap_timer.async_wait(yield[ec]);
				if (ec == boost::system::errc::operation_canceled
					|| m_tuntap_write_deque.size() > 0)
					break;
			}
		}

		LOG_WARN << "start_tuntap_write quit...";
	}

	void dchs_service::do_tuntap_write(std::string&& message)
	{
		boost::asio::post(m_io_context.get_executor(), [this, message = std::move(message)]() mutable
		{
			m_tuntap_write_deque.emplace_back(std::move(message));
			boost::system::error_code ignore_ec;
			m_tuntap_timer.cancel(ignore_ec);
		});
	}

	void dchs_service::setup_tun(const std::string& ipaddr)
	{
		// 先关闭设备.
		m_tuntap.close();

		// 获取相关信息并配置网卡.
		avpn::dev_config dc = { ipaddr, "255.255.0.0", "10.0.0.0", "", "", "", 0, avpn::dev_tun, 0 };
		dc.dev_name_ = m_config.ifdev_;
		auto dev_list = m_tuntap.take_device_list();
		std::string guid;
		for (auto& i : dev_list)
		{
			if (i.name_ == dc.dev_name_)
			{
				dc.guid_ = i.guid_;
				break;
			}
		}

#ifdef AVPN_LINUX
		dc.dev_name_ = "";
		dc.guid_ = "";
		dc.dev_type_ = avpn::dev_tun;
		dc.tun_fd_ = -1;
#else
		dc.dev_type_ = avpn::dev_tun;
#endif

		if (!m_tuntap.open(dc))
		{
			LOG_ERR << "open tun device: " << dc.dev_name_ << " fail!";
			return;
		}
	}

}
