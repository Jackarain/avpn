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
#include "utils/uawaitable.hpp"
#include "utils/misc.hpp"

#include "vpncore/endpoint_pair.hpp"

#include <chrono>
#include <iomanip>

#include <boost/date_time.hpp>
#include <boost/regex.hpp>


namespace avpn {
	using namespace std::chrono_literals;

	avpn_service::avpn_service(io_context_pool& ios, const server_config& config)
		: m_io_context_pool(ios)
		, m_io_context(m_io_context_pool.server_io_context())
		, m_config(config)
		, m_tuntap(m_io_context)
		, m_tick_timer(m_io_context)
		, m_vpn_tunnel(m_io_context, m_io_context_pool,
			config.channel_params_, static_cast<avpn_service&>(*this))
	{
	}

	avpn_service::~avpn_service()
	{
		// 退出时删除所有添加的路由.
		if (!m_channel_status.server_ip_.empty())
		{
			del_route("0.0.0.0/0 " + m_channel_status.vgateway_);
			del_route(m_channel_status.server_ip_ + "/32");
		}

		// 删除所有avpn临时文件.
		auto avpn_tmp_dir = std::filesystem::temp_directory_path() / "avpn";
		std::error_code ignore_ec;
		std::filesystem::remove_all(avpn_tmp_dir, ignore_ec);

		LOG_DBG << "~avpn_service()";
	}

	void avpn_service::start()
	{
		m_abort = false;

		// 开启定时器.
		boost::asio::co_spawn(m_tick_timer.get_executor(),
			tick(), boost::asio::detached);

		// 客户端启动客户端通信通道.
		if (m_config.identity_ == Identity::avpn_client)
			run_as_client();

		// 服务器则将启动服务器通信通道.
		if (m_config.identity_ == Identity::avpn_server)
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
				LOG_DBG << "del route: " << route << " route remove successfully!";
			else
				LOG_DBG << "del route: " << route << " fail, reason: " << ret;
		}

		LOG_DBG << "avpn_service close channel.";
		m_vpn_tunnel.close();

		LOG_DBG << "avpn_service stop tuntap.";
		m_tuntap.close();
		m_tick_timer.cancel(ignore_ec);
		auto server_ip = m_channel_status.server_ip_;
		auto vgateway = m_channel_status.vgateway_;
		m_channel_status = {};
		m_channel_status.server_ip_ = server_ip;
		m_channel_status.vgateway_ = vgateway;
		m_vnet = {};
		m_upload_stat = {};
		m_down_stat = {};
		m_start_tuntap = false;

		LOG_DBG << "avpn_service.stop()";
	}

	boost::asio::awaitable<void> avpn_service::start_tun_read_loop()
	{
		boost::system::error_code ec;
		avpn::vpn_message msg;

		while (!m_abort)
		{
			auto& content = msg.content_;
			content.resize(128 * 1024);

			auto bytes = co_await m_tuntap.async_read_some(
				boost::asio::buffer(content), uawaitable[ec]);
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
			if (m_config.identity_ == Identity::avpn_server)
			{
				// 作为server时, 要根据ip寻找到对应的通信通道.
				if (m_channel_status.status_ != avpn::connection_status::st_listen)
					continue;

				// 透传到channel.
				m_vpn_tunnel.server_forward_tun(std::move(msg), std::move(endp));
			}
			else if (m_config.identity_ == Identity::avpn_client)
			{
				// 未连接状态, 丢弃所有packet.
				if (m_channel_status.status_ != avpn::connection_status::st_connected)
					continue;

				// 统计上传数据量用于计算上传速率.
				m_upload_stat.bytes_ += (int64_t)msg.content_.size();

				// 透传到channel.
				m_vpn_tunnel.client_forward_tun(std::move(msg), std::move(endp));
			}
		}

		LOG_WARN << "start_tun_read_loop quit...";
	}

	void avpn_service::run_as_client()
	{
		m_vpn_tunnel.start_client_connect(m_config.upstreams_);
	}

	void avpn_service::run_as_server()
	{
		m_vpn_tunnel.start_server_listen(m_config.tcp_listens_, m_config.udp_listens_);
	}

	boost::asio::awaitable<void> avpn_service::tick()
	{
		boost::system::error_code ec;

		int64_t downloaded = 0;
		int64_t uploaded = 0;

		auto calc_speed = [&](speed_stat& stat,
			time_clock::steady_clock::time_point& now,
			int64_t& before_total
			) mutable
		{
			auto all_already = stat.bytes_;
			auto all_total = all_already - before_total;
			before_total = all_already;
			auto deltams = now - stat.time_;
			stat.time_ = now;
			auto speed = int64_t((double)all_total / ((double)deltams.count() / 1000.0f));
			stat.rate_ = (speed * 2 + stat.rate_) / 3;
		};

		while (!m_abort)
		{
			m_tick_timer.expires_from_now(std::chrono::seconds(1));
			co_await m_tick_timer.async_wait(uawaitable[ec]);
			if (ec)
			{
				LOG_WARN << "avpn_service::tick, ec: " << ec.message();
				co_return;
			}

			auto now = time_clock::steady_clock::now();

			calc_speed(m_down_stat, now, downloaded);
			calc_speed(m_upload_stat, now, uploaded);
		}

		co_return;
	}

	void avpn_service::do_tuntap_write(std::string&& message)
	{
		boost::asio::co_spawn(m_io_context.get_executor(),
			[this, message = std::move(message)]() mutable -> boost::asio::awaitable<void>
			{
				boost::system::error_code ec;
				co_await m_tuntap.async_write_some(
					boost::asio::buffer(message), uawaitable[ec]);

				// 统计发送数据量用于计算发送速率.
				m_down_stat.bytes_ += (int64_t)message.size();
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
#ifdef WIN32
		// 如果指定的tap设备有问题, 则默认选择第一个网卡.
		if (dc.guid_.empty() && !dev_list.empty())
		{
			LOG_WARN << "Not found tun: " << dc.dev_name_ << ", use default: " << dev_list[0].name_;
			dc.dev_name_ = dev_list[0].name_;
			dc.guid_ = dev_list[0].guid_;
		}
#endif // WIN32

		auto defgw = get_default_gateway();
		auto defgw_string = defgw->address().to_string();

		if (!m_tuntap.open(dc))
		{
			LOG_ERR << "open tun device: " << dc.dev_name_ << " fail!";
			return;
		}

		if (m_channel_status.passbyvpn_ && m_config.identity_ == Identity::avpn_client)
		{
			auto vgateway = gateway.to_string();

			m_channel_status.vaddr_ = ipaddr;
			m_channel_status.vgateway_ = vgateway;

			del_route("0.0.0.0/0 " + vgateway);
			del_route(m_channel_status.server_ip_ + "/32 " + vgateway);

			if (set_default_route(ipaddr, vgateway, defgw_string, m_channel_status.server_ip_))
				LOG_DBG << "Default gateway: " << defgw_string << " change successfully!";
			else
				LOG_WARN << "Default gateway: " << defgw_string << ", change faild!";
		}

		for (auto& route : m_channel_status.routes_)
		{
			auto [ret, ok] = add_route(route);
			if (ok)
				LOG_DBG << "Add route: " << route << " route added successfully!";
			else
				LOG_ERR << "Add route: " << route << " route added fail, reason: " << boost::trim_copy(ret);
		}

		if (m_config.snat_)
		{
			// TODO: do snat...
		}

		if (!m_channel_status.dns_.empty() && m_config.identity_ == Identity::avpn_client)
		{
			if (set_dns(m_channel_status.dns_, ipaddr))
				LOG_DBG << "Set dns: " << m_channel_status.dns_ << " successfully";
		}

		m_vnet = net;
	}

	void avpn_service::on_status(avpn::channel_status cs)
	{
		if (m_config.identity_ == Identity::avpn_client)
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

				auto ipaddr = m_vpn_tunnel.vnet_ipaddr();
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

			return;
		}

		if (m_config.identity_ == Identity::avpn_server)
		{
			auto st = cs.status_;
			if (st == avpn::connection_status::st_listen)
			{
				if (m_start_tuntap)
					return;

				m_start_tuntap = true;
				m_channel_status = cs;

				setup_tun(m_vpn_tunnel.vnet());

				LOG_DBG << "vpn device start...";

				boost::asio::co_spawn(m_io_context_pool.get_io_context().get_executor(),
					start_tun_read_loop(), boost::asio::detached);
			}

			return;
		}

		BOOST_ASSERT(false && "invalid identity");
	}

	int64_t avpn_service::upload_rate() const
	{
		return m_upload_stat.rate_;
	}

	int64_t avpn_service::download_rate() const
	{
		return m_down_stat.rate_;
	}

}

