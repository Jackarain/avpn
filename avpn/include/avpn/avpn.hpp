//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#pragma once


#include "avpn/vpn_tunnel.hpp"

#include "utils/internal.hpp"
#include "utils/time_clock.hpp"

#include "vpncore/tuntap.hpp"

namespace avpn {

	struct server_config
	{
		std::vector<std::string> upstreams_;

		std::vector<std::string> tcp_listens_;
		std::vector<std::string> udp_listens_;

		std::string ifdev_;
		bool snat_{ false };

		int controller_{ -1 };
		avpn::Identity identity_;
		avpn::tunnel_params tunnel_params_;

		bool ignore_route =  {false};
	};

	using namespace util;
	using time_clock::steady_clock;

	class avpn_service
	{
		const static int speed_entries = 3;
		struct speed_stat
		{
			int64_t speeder_[speed_entries]{ 0 };
			steady_clock::time_point speeder_time_[speed_entries]{ steady_clock::now() };
			int64_t speeder_count_{ 0 };

			int64_t bytes_{ 0 };
			int64_t rate_{ 0 };
		};

		// c++11 noncopyable.
		avpn_service(const avpn_service&) = delete;
		avpn_service& operator=(const avpn_service&) = delete;

	public:
		avpn_service(io_context_pool& ios, const server_config& config);
		~avpn_service();

	public:
		void start();
		void stop();

		void do_tuntap_write(std::string&& message);
		void on_status(avpn::tunnel_status cs);

		int64_t upload_rate() const;
		int64_t download_rate() const;

	private:
		boost::asio::awaitable<void> start_tun_read_loop();

		void run_as_client();
		void run_as_server();

		boost::asio::awaitable<void> tick();

		void setup_tun(const boost::asio::ip::network_v4& net);

	private:
		io_context_pool& m_io_context_pool;
		boost::asio::io_context& m_io_context;
		server_config m_config;
		bool m_start_tuntap{ false };
		avpn::tunnel_status m_tunnel_status;
		avpn::tuntap m_tuntap;
		timer m_tick_timer;
		boost::asio::ip::network_v4 m_vnet;
		avpn::vpn_tunnel m_vpn_tunnel;
		speed_stat m_down_stat;
		speed_stat m_upload_stat;
		bool m_abort{ false };
	};
}
