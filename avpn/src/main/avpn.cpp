//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#include "avpn/avpn.hpp"
#include "avpn/version.hpp"

#include "utils/async_connect.hpp"
#include "utils/url_parser.hpp"
#include "utils/scoped_exit.hpp"
#include "utils/fileop.hpp"

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


namespace avpn {
	using namespace std::chrono_literals;

	avpn_service::avpn_service(io_context_pool& ios, const server_config& config)
		: m_io_context_pool(ios)
		, m_io_context(m_io_context_pool.server_io_context())
		, m_config(config)
		, m_tuntap(m_io_context)
		, m_tuntap_timer(m_io_context)
		, m_channel(m_io_context, m_io_context_pool, config.channel_params_)
	{
	}

	avpn_service::~avpn_service()
	{
		LOG_DBG << "~avpn_service()";
	}

	void avpn_service::start()
	{
		// 客户端启动客户端通信通道.
		if (m_config.identity_ == avpn::avpn_client)
			run_as_client();

		// 服务器则将启动服务器通信通道.
		if (m_config.identity_ == avpn::avpn_server)
			run_as_server();
	}

	void avpn_service::stop()
	{
		boost::system::error_code ignore_ec;
		m_abort = true;

		// 退出时删除路由.
		for (auto& route : m_channel_status.routes_)
		{
			auto [ret, ok] = del_route(route);
			if (ok)
				LOG_DBG << "del route: " << route << " route added successfully!";
			else
				LOG_DBG << "del route: " << route << " fail, reason: " << ret;
		}

		LOG_DBG << "avpn_service close channel.";
		m_channel.close();

		LOG_DBG << "avpn_service stop tuntap.";
		m_tuntap.close();
		m_tuntap_timer.cancel_one(ignore_ec);

		LOG_DBG << "avpn_service.stop()";
	}

	boost::asio::awaitable<void> avpn_service::start_tun_read_loop()
	{
		boost::system::error_code ec;
		avpn::vpn_message msg;

		while (!m_abort)
		{
			auto& content = msg.content;
			content.resize(128 * 1024);

			auto bytes = co_await m_tuntap.async_read_some(boost::asio::buffer(content),
					boost::asio::redirect_error(boost::asio::use_awaitable, ec));
			if (ec)
			{
				LOG_WARN << "start_tun, async_read_some: " << ec.message();
				break;
			}

			// resize content.
			content.resize(bytes);

			// 解析ip相关的信息.
			auto endp = avpn::lookup_endpoint_pair((const uint8_t*)content.data(), bytes);

			// 解析不出来的ip包, 直接跳过...
			if (endp.empty())
				continue;

			// 保存数据包类型.
			if (endp.type_ == avpn::ip_type::ip_tcp)
				msg.type = vpt_tcp;
			else if (endp.type_ == avpn::ip_type::ip_udp)
				msg.type = vpt_udp;
			else if (endp.type_ == avpn::ip_type::ip_icmp)
				msg.type = vpt_icmp;

			// 根据程序的身份, 准备透传.
			if (m_config.identity_ == avpn_server)
			{
				// 作为server时, 要根据ip寻找到对应的通信通道.
				if (m_channel_status.status_ != avpn::connection_status::st_listen)
					continue;

				// 透传到channel.
				m_channel.server_write(std::move(msg), endp);
			}
			else if (m_config.identity_ == avpn_client)
			{
				// 未连接状态, 丢弃所有packet.
				if (m_channel_status.status_ != avpn::connection_status::st_connected)
					continue;

				// 透传到channel.
				m_channel.client_write(std::move(msg), endp);
			}
		}

		LOG_WARN << "start_tun_read_loop quit...";
	}

	void avpn_service::run_as_client()
	{
		m_channel.start_connect(m_config.upstreams_,
			[this](avpn::channel_status cs)
			{
				m_channel_status = cs;
				auto status = cs.status_;

				// 连接成功, 如果没有启动tun, 则启动tun设备.
				if (status == avpn::connection_status::st_connected)
				{
					LOG_DBG << "vpn connected";

					if (m_start_tuntap)
						return;
					m_start_tuntap = true;

					auto ipaddr = m_channel.vnet_ipaddr();
					setup_tun(ipaddr);

					LOG_DBG << "vpn device start...";

					boost::asio::co_spawn(m_io_context_pool.get_io_context().get_executor(),
						start_tun_read_loop(), boost::asio::detached);
				}

				// 断开状态.
				if (status == avpn::connection_status::st_disconnect)
				{
					m_start_tuntap = false;
					m_tuntap.close();

					if (m_abort)
						return;

					LOG_WARN << "vpn disconnect...";
				}
			},
			[this](std::string&& message) { do_tuntap_write(std::move(message)); }
			);
	}

	void avpn_service::run_as_server()
	{
		m_channel.start_listen(m_config.tcp_listens_, m_config.udp_listens_,
			[this](avpn::channel_status cs)
			{
				auto st = cs.status_;
				if (st == avpn::connection_status::st_listen)
				{
					if (m_start_tuntap)
						return;

					m_start_tuntap = true;
					m_channel_status = cs;

					setup_tun(m_channel.vnet());

					LOG_DBG << "vpn device start...";

					boost::asio::co_spawn(m_io_context_pool.get_io_context().get_executor(),
						start_tun_read_loop(), boost::asio::detached);
				}
			},
			[this](std::string&& message) { do_tuntap_write(std::move(message)); }
			);
	}

	void avpn_service::do_tuntap_write(std::string&& message)
	{
		boost::asio::co_spawn(m_io_context.get_executor(),
			[this, message = std::move(message)]() mutable -> boost::asio::awaitable<void>
			{
				m_tuntap_writing = !m_tuntap_write_deque.empty();
				m_tuntap_write_deque.emplace_back(std::move(message));

				// 若正在写入, 则直接返回, 而不再作任何处理.
				if (!m_tuntap_writing)
				{
					boost::system::error_code ec;

					while (!m_abort && !m_tuntap_write_deque.empty())
					{
						co_await m_tuntap.async_write_some(
							boost::asio::buffer(m_tuntap_write_deque.front()),
								boost::asio::redirect_error(boost::asio::use_awaitable, ec));
						if (ec)
						{
							LOG_ERR << "do_tuntap_write, async_write error: " << ec.message();
							co_return;
						}
						m_tuntap_write_deque.pop_front();
					}
				}
			}, boost::asio::detached);
	}

	void avpn_service::setup_tun(const boost::asio::ip::network_v4& net)
	{
		// 先关闭设备.
		m_tuntap.close();

		auto mask = net.netmask();
		auto addr = net.address();
		auto ipaddr = addr.to_string();

		uint32_t gw = (addr.to_uint() & mask.to_uint()) + 1;
		auto gateway = boost::asio::ip::make_address_v4(gw);

		LOG_DBG << "setup_tun ip: " << ipaddr
			<< ", mask: " << mask.to_string()
			<< ", gateway: " << gateway.to_string()
			<< ", tun: " << m_config.ifdev_;

		// 构造配置参数.
		avpn::dev_config dc = { ipaddr, mask.to_string(),
			gateway.to_string(), "", "", "", 0 };
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

		if (!m_tuntap.open(dc))
		{
			LOG_ERR << "open tun device: " << dc.dev_name_ << " fail!";
			return;
		}

		for (auto& route : m_channel_status.routes_)
		{
			auto [ret, ok] = add_route(route);
			if (ok)
				LOG_DBG << "add route: " << route << " route added successfully!";
			else
				LOG_ERR << "add route: " << route << " route added fail, reason: " << boost::trim_copy(ret);
		}

		m_vnet = net;
	}

}
