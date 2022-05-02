//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#pragma once


#include "avpn/vpn_tunnel.hpp"

#include "utils/internal.hpp"

#include "vpncore/tun_device.hpp"

namespace avpn {

	enum class Identity {
		avpn_server = 0,
		avpn_client = 1
	};

	struct tunnel_params
	{
		// fec数据设置, 指定多少份fec数据.当data_shards_
		// 为1时, 不再使用fec恢复算法, 转变成parity_shards_
		// 指定的倍数发包.
		int data_shards_;

		// fec冗余设置.
		// 当data_shards_大于1时, parity_shards_
		// 指定为多少份恢复数据包, 即最大可丢失多少个数
		// 据包还能恢复.
		// 如果data_shards_设置为1时, 则parity_shards_
		// 为具体发包倍数.
		// 例如: data_shards_为1, 而parity_shards_为0,
		// 则为原样发包, parity_shards_为1则为2倍发包,
		// 最大5倍.
		int parity_shards_;

		// 可以指定不同的连接模式
		// 具体值为: 0为udp only, 1为udp/tcp混合, 2为tcp only.
		int mode_;

		// 压缩选项, 指定压缩算法
		// 可以指定的压缩算法: deflate, lz4, zstd.
		std::string compress_;
		// 保持网络活动消息间隔.
		int keepalive_;

		// server推送路由.
		std::vector<std::string> pushroutes_;

		// server推送dns.
		std::string pushdns_;

		// 客户端默认通过vpn server作为全局网络出口此时的
		// server必须做nat, 否则可能无法通过vpn server上网.
		bool passbyvpn_;

		// 作为client时, 是否忽略掉服务器推送的路由.
		bool ignore_pushroute = { false };

		// 是否允许客户端之间通信.
		bool c2c_;

		// server下的vpn子网配置.
		std::string subnet_;
	};

	struct service_config
	{
		// 作为client时, 目标vpn服务器信息.
		std::vector<std::string> upstreams_;

		// 作为server时, tcp服务端口.
		std::vector<std::string> tcp_listens_;

		// 作为server时, udp服务端口.
		std::vector<std::string> udp_listens_;

		// 作为server时, 指定ecdh的私钥(base64编码)
		// 作为client时, 指定为server的ecdh公钥信息.
		std::string passphrase_;

		// 指定tun设备名称.
		std::string ifdev_;

		// 用于控制avpn的controller的信息.avpn将自动连接
		// controller, 并等待controller发送控制信息：开
		// 启或关闭, 或获取avpn实时速率等信息.
		std::string controller_;

		// 当前avpn运行的模式: server/client.
		avpn::Identity identity_;

		// vpn隧道相关参数.
		avpn::tunnel_params tunnel_params_;
	};



	using namespace util;
	using std::chrono::steady_clock;

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
		avpn_service(io_context_pool& ios, const service_config& config);
		~avpn_service();

	public:
		void start();
		void stop();

		int64_t upload_rate() const;
		int64_t download_rate() const;

	private:
		boost::asio::awaitable<void> start_tun_read_loop();
		void do_tuntap_write(std::string&& message);

		void run_as_client();
		void run_as_server();

		boost::asio::awaitable<void> tick();

		void setup_tun(const boost::asio::ip::network_v4& net);

	private:
		// io context pool
		// 用于使用不同的io_context为不同的client服务.
		io_context_pool& m_io_context_pool;

		// 主线程io_context, 用于统一调度之类.
		boost::asio::io_context& m_main_context;

		// avpn服务配置.
		service_config m_config;

		// 随机id, 用于client连接前标识身份.避免server
		// 重复在同一个client分配资源.
		std::string m_client_id;

		// tun设备.
		avpn::tun_device m_tundev;

		// 定时器, 用于处理一系列定时任务.
		timer m_tick_timer;

		// 虚拟网络.
		boost::asio::ip::network_v4 m_vnet;

		// 上下行速率统计.
		speed_stat m_down_stat;
		speed_stat m_upload_stat;

		// 服务停止标志.
		bool m_abort{ false };
	};
}
