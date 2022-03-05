//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#pragma once

#include "avpn/internal.hpp"
#include "vpncore/tuntap.hpp"
#include "vpncore/channel.hpp"

namespace avpn {

	struct server_config
	{
		std::vector<std::string> upstreams_;

		std::vector<std::string> tcp_listens_;
		std::vector<std::string> udp_listens_;

		std::string ifdev_;

		int identity_;
		avpn::channel_params channel_params_;
	};

	class avpn_service
	{
		// c++11 noncopyable.
		avpn_service(const avpn_service&) = delete;
		avpn_service& operator=(const avpn_service&) = delete;

	public:
		avpn_service(io_context_pool& ios, const server_config& config);
		~avpn_service();

	public:
		void start();
		void stop();

	private:
		boost::asio::awaitable<void> start_tun_read_loop();

		void run_as_client();
		void run_as_server();

		void do_tuntap_write(std::string&& message);
		void setup_tun(const boost::asio::ip::network_v4& net);

	private:
		io_context_pool& m_io_context_pool;
		boost::asio::io_context& m_io_context;
		server_config m_config;
		bool m_start_tuntap{ false };
		avpn::channel_status m_channel_status;
		avpn::tuntap m_tuntap;
		std::deque<std::string> m_tuntap_write_deque;
		bool m_tuntap_writing{ false };
		timer m_tuntap_timer;
		boost::asio::ip::network_v4 m_vnet;
		avpn::channel m_channel;

		std::atomic_bool m_abort{ false };
	};
}
