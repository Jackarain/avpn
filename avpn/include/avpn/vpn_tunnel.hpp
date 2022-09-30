//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#pragma once

#include "utils/io_context_pool.hpp"
#include "utils/scoped_exit.hpp"
#include "utils/url_view.hpp"
#include "utils/async_connect.hpp"
#include "utils/io.hpp"
#include "utils/logging.hpp"
#include "utils/misc.hpp"
#include "utils/crypto.hpp"
#include "utils/asio_util.hpp"

#include "avpn/endpoint_pair.hpp"

#include "avpn/reedsolomon.hpp"
#include "avpn/fec_cache.hpp"
#include "avpn/avpn.hpp"


namespace avpn {

	class vpn_tunnel : public std::enable_shared_from_this<vpn_tunnel>
	{
		// 速率统计相关数据结构.
		const static inline int speed_entries = 3;
		struct speed_stat
		{
			int64_t speeder_[speed_entries]{ 0 };
			time_point speeder_time_[speed_entries]{ steady_clock::now() };
			int64_t speeder_count_{ 0 };

			int64_t bytes_{ 0 };
			int64_t rate_{ 0 };
		};

		// c++11 noncopyable.
		vpn_tunnel(const vpn_tunnel&) = delete;
		vpn_tunnel& operator=(const vpn_tunnel&) = delete;

		// avoid direct call construct object...
		vpn_tunnel() = delete;
		vpn_tunnel(net::io_context&, std::shared_ptr<avpn_service>&,
			const service_config&, std::string, std::string);

	public:
		static std::shared_ptr<vpn_tunnel> make(
			net::io_context&, std::shared_ptr<avpn_service>&,
				const service_config&, std::string, std::string);
		~vpn_tunnel();

	public:
		// 开始tunnel工作.
		void start_tunnel(uint8_t ds, uint8_t ps);

		// 关闭tunnel.
		void close_tunnel();

		// 返回当前上下行实时速率.
		int64_t upload_rate() const;
		int64_t download_rate() const;

		// 设置限速.
		void upload_limit(int limit);
		void download_limit(int limit);

		// 重新绑定 tunnel 的 tcp socket 对象.
		void rebind_tcp_socket(tcp::socket s);

		// 提交一个tun读取的packet到队列.
		void tun_submit(vpn_tun_packet pkt);

		// 提交一个网络数据包到队列.
		void net_submit(vpn_packet pkt,
			std::optional<udp::endpoint> remote);

		// 启动tcp消息.
		void start_tcp_loop();

		// 设置/返回client的id.
		std::string client_id() const;
		void client_id(const std::string& id);

		// 返回协商的密钥.
		std::string shared_key() const;
		// 返回加密对象.
		crypto_util::stream_crypto& crypto();

		// 设置/返回server分配的vnet addr.
		net::ip::network_v4 vnet_addr() const;
		void vnet_addr(const net::ip::network_v4& vaddr);

		// 设置/返回远端udp的endpoint.
		udp::endpoint remote_endpoint() const;
		void remote_endpoint(const udp::endpoint& endp);

		// 设置/返回tunnel的ipproto.
		Proto ipproto() const;
		void ipproto(Proto proto);

		// 设置/返回tunnel最后活跃时间.
		time_point last_see() const;
		void last_see(const time_point& now);

		// Obtains the executor associated with the io_context.
		net::any_io_executor get_executor();

	private:
		// 定时任务处理, 如keepalive等相关处理.
		net::awaitable<void> tick();
		Proto cherry_pick(bool default_udp = false) const;

		// 速率计算.
		void compute_speed(speed_stat& stat, int bytes);
		void compute_speed(speed_stat& stat, const time_point& now);

		// 通过udp/tcp协议发送数据包.
		void udp_write_pkt(vpn_packet pkt);
		void tcp_write_pkt(vpn_packet pkt);

		void internal_write_pkt(vpn_packet pkt, bool defalut_udp = false);

		// 速率限制.
		net::awaitable<void> speed_limit(
			const int& size, bool w = true);

		// forward tcp packet to tun.
		void tcp_forward();

		// 处理tun上的ip包.
		void process_tun_packet(vpn_packet& pkt);

		// process net packet.
		void process_net_packet(vpn_packet& pkt);

		// 作为server时, 接收到keepalive消息.
		void on_vpn_keepalive(vpn_packet& pkt);
		// 作为client时, 接收到keepalive_reply消息.
		void on_vpn_keepalive_reply(vpn_packet& pkt);

		// 接收到transfer/compress消息.
		void on_vpn_transfer(vpn_packet& pkt);
		void on_vpn_transfer_compress(vpn_packet& pkt);

		// 检查packet.
		std::optional<endpoint_pair>
		check_packet(const uint8_t* data, int size);

	private:
		// 用于当前tunnel业务调度.
		net::io_context& m_io_context;

		// service 对象引用.
		std::weak_ptr<avpn_service> m_serivce;

		// vpn相关配置.
		service_config m_config;

		// 当前vpn的身份.
		Identity m_identity;

		// 对方的pubkey.
		std::string m_pubkey;

		// 客户端的client id.
		std::string m_client_id;

		// 客户端通信协议.
		Proto m_ipproto{ Proto::avpn_unknown };

		// 对方fec编码使用的ds, ps.
		// 本端解码时需要使用对方的ds,ps来进行fec解码.
		uint8_t m_peer_ds{ 0 };
		uint8_t m_peer_ps{ 0 };

		// 当前context运行线程.
		std::thread::id m_thread_id;

		// fec纠错相关统计信息.
		uint32_t m_num_corrected{ 0 };
		uint32_t m_num_incorrect{ 0 };
		uint32_t m_num_received{ 0 };
		uint32_t m_num_expired{ 0 };
		uint64_t m_packet_id{ 0 };

		// 网络统计信息.
		int m_num_send_packet{ 0 };
		int m_num_recv_packet{ 0 };

		// 上下行速率统计.
		speed_stat m_down_stat;
		speed_stat m_upload_stat;

		// 上下行速率限制.
		int m_upload_limit{ 0 };
		int m_download_limit{ 0 };

		// 上下行限速桶.
		int m_ulimit_bucket{ 0 };
		int m_dlimit_bucket{ 0 };

		// rtt估值.
		int64_t m_rtt{ 0 };

		// 与remote通信的tcp socket id及tcp socket.
		tcp::socket m_tcp_socket;

		// tcp write 队列.
		std::deque<vpn_packet> m_tcp_oqe;

		// tcp read 缓冲.
		net::streambuf m_tcp_rbuf;

		// tcp 连接状态.
		bool m_tcp_connect_ready{ false };

		// 用于密钥交换.
		crypto_util::keyexchange m_keyexchange;
		// 用于加密.
		std::unique_ptr<crypto_util::stream_crypto> m_crypto;

		// 密钥.
		std::string m_shared_key;

		// 分配的vaddr.
		net::ip::network_v4 m_vaddr;
		uint32_t m_self_vaddr;

		// 对方udp的endpoint.
		udp::endpoint m_remote_endpoint;

		// 最后活跃时间.
		time_point m_last_see{ steady_clock::now() };

		// timer, 处理本tunnel相关定时工作.
		// 如: keepalive等工作.
		asio_timer m_tick_timer;
		time_point m_time_now{ steady_clock::now() };

		// fec解码器.
		fec_recover m_recover;

		// fec编码器.
		fec_encode_group m_feg;

		// 退出标志.
		boost::tribool m_abort{ boost::indeterminate };
	};
}
