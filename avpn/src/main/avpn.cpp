//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#include "avpn/avpn.hpp"
#include "avpn/version.hpp"
#include "avpn/fec_cache.hpp"

#include "utils/async_connect.hpp"
#include "utils/url_parser.hpp"
#include "utils/scoped_exit.hpp"
#include "utils/uawaitable.hpp"
#include "utils/misc.hpp"

#include "vpncore/endpoint_pair.hpp"

#include <chrono>
#include <iomanip>

#include <boost/date_time.hpp>


namespace avpn {
	using namespace std::chrono_literals;

	avpn_service::avpn_service(io_context_pool& ios, const service_config& config)
		: m_io_context_pool(ios)
		, m_main_context(m_io_context_pool.main_io_context())
		, m_config(config)
		, m_client_id(gen_unique_string(32))
		, m_tundev(m_main_context)
		, m_tick_timer(m_main_context)
	{}

	avpn_service::~avpn_service()
	{
 		// TODO: 退出时删除所有添加的路由.

		// 删除所有avpn临时文件.
		auto avpn_tmp_dir = std::filesystem::temp_directory_path() / "avpn";
		std::error_code ignore_ec;
		std::filesystem::remove_all(avpn_tmp_dir, ignore_ec);

		LOG_DBG << "avpn_service::~avpn_service()";
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

		// TODO: 退出时删除路由.
		LOG_DBG << "avpn_service stop tuntap.";
		m_tundev.close();
		m_tick_timer.cancel(ignore_ec);
		m_vnet = {};
		m_upload_stat = {};
		m_down_stat = {};

		LOG_DBG << "avpn_service.stop()";
	}

	boost::asio::awaitable<void> avpn_service::start_tun_read_loop()
	{
		boost::system::error_code ec;
		fec::vpn_packet msg;

		while (!m_abort)
		{
			auto content = msg.data();

			auto bytes = co_await m_tundev.async_read_some(
				boost::asio::buffer(content, 1450), uawaitable[ec]);
			if (ec)
			{
				LOG_ERR << "start_tun_read_loop, async_read_some: " << ec.message();
				break;
			}

			// resize content.
			msg.resize(bytes);

			// 解析ip相关的信息.
			auto endp = avpn::lookup_endpoint_pair(content, bytes);

			// 解析不出来的ip包, 直接跳过...
			if (endp.empty())
				continue;

			// 保存数据包类型.
			msg.type((fec::vpn_packet_type)endp.type_);

			// 根据程序的身份, 准备透传.
			if (m_config.identity_ == Identity::avpn_server)
			{
				// TODO: 作为server时, 要根据目标虚拟ip寻找到对应的通信通道.
				// 透传到tunnel.
			}
			else if (m_config.identity_ == Identity::avpn_client)
			{
				// TODO: 作为client时, 未连接状态, 丢弃所有packet.

				// 统计上传数据量用于计算上传速率.
				m_upload_stat.bytes_ += (int64_t)bytes;
				auto index = m_down_stat.speeder_count_ % speed_entries;
				m_upload_stat.speeder_[index] = m_upload_stat.bytes_;

				// 透传到tunnel.
			}
		}

		LOG_WARN << "start_tun_read_loop quit...";
		co_return;
	}

	void avpn_service::do_tuntap_write(std::string&& message)
	{
		boost::asio::co_spawn(m_main_context.get_executor(),
			[this, message = std::move(message)]() mutable->boost::asio::awaitable<void>
		{
			boost::system::error_code ec;
			co_await m_tundev.async_write_some(
				boost::asio::buffer(message), uawaitable[ec]);

			// 统计发送数据量用于计算发送速率.
			m_down_stat.bytes_ += (int64_t)message.size();
			auto index = m_down_stat.speeder_count_ % speed_entries;
			m_down_stat.speeder_[index] = m_down_stat.bytes_;
		}, boost::asio::detached);
	}

	void avpn_service::run_as_client()
	{
// 		m_vpn_tunnel.start_client_connect(
// 			m_config.upstreams_, m_config.passphrase_);
	}

	void avpn_service::run_as_server()
	{
// 		m_vpn_tunnel.start_server_listen(m_config.tcp_listens_,
// 			m_config.udp_listens_, m_config.passphrase_);
	}

	boost::asio::awaitable<void> avpn_service::tick()
	{
		boost::system::error_code ec;

		auto calc_speed = [&](speed_stat& stat,
			steady_clock::time_point& now) mutable
		{
			int nowindex = stat.speeder_count_ % speed_entries;
			stat.speeder_time_[nowindex] = now;
			auto speeder_count = stat.speeder_count_ + 1;
			if (speeder_count > 0)
			{
				int checkindex = speeder_count >= speed_entries
					? speeder_count % speed_entries : 0;

				auto deltams = now - stat.speeder_time_[checkindex];
				auto amount = stat.speeder_[nowindex] - stat.speeder_[checkindex];

				if (amount < 0)
					amount = 0;

				if (deltams.count() <= 0)
					deltams = std::chrono::milliseconds(1);

				stat.rate_ = int64_t((double)amount / ((double)deltams.count() / 1000.0f));
			}

			stat.speeder_count_ = speeder_count;
		};

		while (!m_abort)
		{
			m_tick_timer.expires_from_now(std::chrono::seconds(1));
			co_await m_tick_timer.async_wait(uawaitable[ec]);
			if (ec)
			{
				LOG_ERR << "avpn_service::tick, ec: " << ec.message();
				break;
			}

			auto now = time_clock::steady_clock::now();

			calc_speed(m_down_stat, now);
			calc_speed(m_upload_stat, now);
		}

		LOG_WARN << "avpn_service::tick() quit...";
		co_return;
	}

	void avpn_service::setup_tun(const boost::asio::ip::network_v4& net)
	{
		// 先关闭设备.
		m_tundev.close();

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
		auto dev_list = m_tundev.take_device_list();
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
			LOG_INFO << "Not found tun: " << dc.dev_name_ << ", use default: " << dev_list[0].name_;
			dc.dev_name_ = dev_list[0].name_;
			dc.guid_ = dev_list[0].guid_;
		}
#endif // WIN32

		auto defgw = get_default_gateway();
		auto defgw_string = defgw->address().to_string();

		if (!m_tundev.open(dc))
		{
			LOG_ERR << "open tun device: " << dc.dev_name_ << " fail!";
			return;
		}

		m_vnet = net;
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

