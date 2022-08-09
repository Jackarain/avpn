//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#pragma once

#include "avpn/tun_device.hpp"
#include "avpn/fec_cache.hpp"
#include "avpn/vpn_client_table.hpp"
#include "avpn/endpoint_pair.hpp"

#include "utils/acl.hpp"
#include "utils/misc.hpp"
#include "utils/io_context_pool.hpp"

#include "socks/socks_server.hpp"



namespace avpn {

	using namespace util;
	using namespace socks;

	//////////////////////////////////////////////////////////////////////////

	enum class Identity {
		avpn_server = 0,
		avpn_client = 1
	};

	enum class Proto {
		avpn_unknown = -1,
		avpn_udp = 0,
		avpn_mix = 1,
		avpn_tcp = 2,
	};

	//////////////////////////////////////////////////////////////////////////

	struct tunnel_params
	{
		// fec数据设置, 指定多少份fec数据.当data_shards_为1时, 不再
		// 使用fec恢复算法, 转变成parity_shards_指定的倍数发包.
		int data_shards_;

		// fec冗余设置.
		// 当data_shards_大于1时, parity_shards_指定为多少份恢复数
		// 据包, 即最大可丢失多少个数据包还能恢复.
		// 如果data_shards_设置为1时, 则parity_shards_为具体发包倍
		// 数.
		// 例如: data_shards_为1, 而parity_shards_为0, 则为原样发
		// 包, parity_shards_为1则为2倍发包, 最大5倍.
		int parity_shards_;

		// 可以指定不同的连接模式
		// 具体值为: 0为udp only, 1为udp/tcp混合, 2为tcp only.
		Proto mode_;

		// 压缩选项, 指定压缩算法
		// 可以指定的压缩算法: deflate, lz4, zstd.
		std::string compress_;

		// 保持网络活动消息间隔.
		int keepalive_;

		// server推送路由.
		std::vector<std::string> pushroutes_;

		// server推送dns.
		uint32_t pushdns_{ 0 };

		// 客户端默认通过vpn server作为全局网络出口此时的server必须做
		// nat, 否则可能无法通过vpn server上网.
		bool passbyvpn_{ false };

		// 作为client时, 是否忽略掉服务器推送的路由.
		bool ignore_pushroute_ = { false };

		// server的IP地址.
		std::string server_ip_;

		// 是否允许客户端之间通信.
		bool c2c_;

		// server下的vpn子网配置.
		std::string subnet_;
	};


	//////////////////////////////////////////////////////////////////////////

	struct service_config
	{
		// 作为client时, 目标vpn服务器信息.
		std::vector<std::string> upstreams_;

		// 作为server时, tcp服务端口.
		std::vector<std::string> tcp_listens_;

		// 作为server时, udp服务端口.
		std::vector<std::string> udp_listens_;

		// 作为server时, 指定ecdh的私钥(base64编码)
		// 作为client时, 指定为server的ecdh公钥信息(base64编码).
		// client 本身的密钥对由系统自动随机生成, 在握手时通过协议传
		// 输公钥到server.
		// server 通过握手协议拿到client的公钥, 及本参数指定的密钥对,
		// 协商出解密密钥.
		// client 通过本参数指定的server的公钥, 及自己生成的密钥对,
		// 协商出解密密钥.
		std::string passphrase_;

		// 指定tun设备名称.
		std::string ifdev_;

		// 用于控制avpn的controller的信息.avpn将自动连接controller,
		// 并等待controller发送控制信息：开启或关闭, 或获取avpn实时速
		// 率等信息.
		std::string controller_;

		// 当前avpn运行的模式: server/client.
		avpn::Identity identity_;

		// vpn隧道相关参数.
		avpn::tunnel_params tunnel_params_;

		// socks server options.
		socks_server_option socks_opt_;
	};


	//////////////////////////////////////////////////////////////////////////

	class vpn_tunnel;

	using vpn_tunnel_ptr = std::shared_ptr<vpn_tunnel>;
	using vpn_tunnel_weak_ptr = std::weak_ptr<vpn_tunnel>;
	using ip_assign_type = std::tuple<std::string, uint32_t>;

#if defined(AVPN_WINDOWS)
	using wintun_device = basic_tun_service<avpn::wintun_windows_service>;
	using tuntap_device = basic_tun_service<avpn::tuntap_windows_service>;
	using vtun_device_type = vtun_device<wintun_device, tuntap_device>;
#else
	using vtun_device_type = vtun_device<tun_device>;
#endif

	class vpn_conntrack;
	using vpn_conntrack_ptr = std::shared_ptr<vpn_conntrack>;

	class avpn_service
		: public socks_server_base
		, public std::enable_shared_from_this<avpn_service>
	{
		// c++11 noncopyable.
		avpn_service(const avpn_service&) = delete;
		avpn_service& operator=(const avpn_service&) = delete;

		// avoid direct call construct object...
		avpn_service() = delete;
		avpn_service(io_context_pool&, const service_config&);

		friend class vpn_tunnel;

	public:
		// 创建apvn service对象, 因为avpn_service必须是一个shared_ptr对象
		// 所以为了避免直接调用构造avpn_service对象, 将avpn_service的构造
		// 函数设置为private, 只能通过make_avpn_service创建shared_ptr对象
		// 以避免误用.
		static std::shared_ptr<avpn_service>
			make_avpn_service(io_context_pool&, avpn::service_config);
		virtual ~avpn_service();

		virtual void remove_client(size_t id) override;
		virtual bool do_auth(const std::string& userid,
			const std::string& passwd, int version) override;
		virtual bool auth_require() override;

	public:
		// 启动和停止vpn服务.
		void start();
		void stop();

		// 返回当前上下行实时速率.
		int64_t upload_rate() const;
		int64_t download_rate() const;

		// server endpoint.
		std::vector<tcp::endpoint> server_endpoint() const;

		// client key.
		std::string client_key() const;

		// service config.
		const service_config& config() const;

	private:
		// tun相关的读取与发送.
		net::awaitable<void> start_tun_read_loop();
		void do_tun_write(vpn_packet_ptr);

		// 处理server/client上的tun设备pkt.
		void do_server_tun_read(vpn_packet, endpoint_pair);
		void do_client_tun_read(vpn_packet, endpoint_pair);

		// udp相关的读取与发送.
		net::awaitable<void> start_udp_read_loop(int);
		void do_udp_write(vpn_packet_ptr, udp::endpoint);
		net::awaitable<void> udp_write(vpn_packet_ptr, udp::endpoint);

		// 启动avpn服务.
		void run_as_client();
		void run_as_server();

		net::awaitable<void> run_client();

		// 定时器, 用于计算像一些定时运算, 如统计速率.
		net::awaitable<void> tick();

		// 配置tun设备.
		// 打开tun设备, 然后设置tun设备的子网, ip, 以及网关信息.
		// client在每次认证完成后根据server分配的ip信息配置 tun
		// 设备.
		// server在启动时根据配置参数信息配置tun设备.
		net::awaitable<void> setup_tun(const net::ip::network_v4&);

		// 分配一个虚拟ip给client.
		ip_assign_type ip_assigner();

		// 作为server时, 初始化tcp连接监听.
		bool init_acceptors();

		// 作为client时, 根据连接协议筛选出server信息.
		net::awaitable<void> make_endpoint(std::string protocol);

		// 作为server时, 监听client的tcp/udp连接.
		net::awaitable<void> start_tcp_listen(tcp::acceptor&);
		net::awaitable<void> start_udp_server();

		// 作为client时, 开始进行tcp连接.
		net::awaitable<void> start_tcp_client();
		net::awaitable<bool> connect_server(tcp::socket&);

		// 作为client时, 开始udp客户端服务.
		net::awaitable<void> start_udp_client();
		net::awaitable<void> make_udp_client();
		// 作为client时, 发起udp握手请求.
		net::awaitable<void> start_udp_handshake();

		// 处理tcp/udp连接握手认证.
		net::awaitable<void> on_tcp_handshake(
			tcp::socket, size_t);
		net::awaitable<void> on_udp_handshake(
			udp::endpoint, vpn_packet, uint32_t);

		// 作为client时, 处理server的udp握手回复.
		net::awaitable<void> on_udp_handshake_reply(
			udp::endpoint, vpn_packet);

		// 在tcp连接上读取一个vpn_packet消息.
		net::awaitable<int> tcp_read_packet(tcp::socket&,
			vpn_packet&, size_t);
		// 在tcp连接上发送一个vpn_packet消息.
		net::awaitable<void> tcp_write_packet(tcp::socket&,
			vpn_packet&, size_t);

		// 根据虚拟ip/client id查询对应的tunnel信息.
		vpn_tunnel_ptr lookup_tunnel(uint32_t);
		vpn_tunnel_ptr lookup_tunnel(std::string);

		net::awaitable<vpn_tunnel_ptr> async_lookup_tunnel(uint32_t);
		net::awaitable<vpn_tunnel_ptr> async_lookup_tunnel(std::string);

		net::awaitable<vpn_tunnel_ptr>
			async_make_tunnel(std::string, std::string);

		// 创建隧道对象.
		vpn_tunnel_ptr make_tunnel(uint32_t, std::string, std::string);
		net::awaitable<void> start_tunnel_tcp(vpn_tunnel_ptr);

		// 作为client时, 重置tcp连接计数.
		void reset_tcp_cnt(int);

	private:
		// io context pool
		// 用于使用不同的io_context为不同的client服务.
		io_context_pool& m_ioc_pool;

		// 主线程io_context, 用于统一调度之类.
		net::io_context& m_main_context;

		// avpn服务配置.
		service_config m_config;

		// 运行的身份.
		Identity m_identity{ Identity::avpn_server };

		// 随机id, 用于client连接前标识身份, 避免server重复在同一个
		// client分配资源.
		std::string m_client_id;

		// 随机生成的密钥对, 用于client和server的公钥协商出解
		// 密密钥.
		std::string m_client_key;

		// 作为client时, server的udp端口信息.
		std::vector<udp::endpoint> m_server_udp_endps;
		// 作为client时, server的tcp端口信息.
		std::vector<tcp::endpoint> m_server_tcp_endps;

		// client连接超时计数.
		int m_client_tcp_cnt{ 0 };
		// client的udp创建标志.
		int m_start_udp{ 0 };

		// client重启计数.
		enum {
			vpn_restart       = 0b00000001,
			vpn_tcp_loop_exit = 0b00000010,
			vpn_tun_loop_exit = 0b00000100,
			vpn_restart_ready = 0b00000111,
			vpn_restart_busy  = 0b00001000,
		};
		int m_client_reset_flag{ 0 };

		// 作为client时, server推送的路由, dns, passbyvpn信息.
		tunnel_params m_push_params;

		// tun设备.
		vtun_device_type m_tundev;

		// m_tick_timer 定时器, 用于处理一系列定时任务.
		// m_tun_wait_timer 定时器, 用于等待tun设备异步退出.
		asio_timer m_tick_timer;
		asio_timer m_tun_wait_timer;

		// 专门用于退出时取消asio_util::async_connect.
		net::cancellation_signal m_cancel_sig;

		// 作为server时, 用于tcp的服务器acceptor.
		std::vector<tcp::acceptor> m_tcp_acceptors;

		// socks clients连接表.
		std::unordered_map<size_t, socks_session_weak_ptr> m_socks_clients;

		// udp socket集合.
		// 作为server时, m_udp_sockets初始化为几个用于监听client的
		// udp消息的udp socket.
		// 作为client时, 可以随时创建新的udp_socket用于和server通信.
		// last_see_ 用作client时, 标识最后和server通信时间, 如果超
		// 时则可创建新的udp_socket替代超时的udp_socket.
		struct udp_socket
		{
			udp_socket(time_point now, udp::socket&& sock)
				: last_see_(now)
				, sock_(std::move(sock))
			{}

			time_point last_see_;
			udp::socket sock_;
		};
		using udp_socket_ptr = std::shared_ptr<udp_socket>;
		std::vector<udp_socket_ptr> m_udp_sockets;

		// 作为server时, 保存client连接的容器.
		// 所有client连接将保存到这个容器, 这个容器不管理client的生命
		// 期, 在client的生命期后, 需要从该容器手工清除.
		vpn_client_table m_clients;

		// 作为tun2socks的client时, 连接跟踪.
		vpn_conntrack_ptr m_conntrack;

		int64_t m_upload_speed{ 0 };
		int64_t m_down_speed{ 0 };

		// 作为client时, tunnel对象.
		vpn_tunnel_weak_ptr m_tunnel;

		// 子网信息, 包含本机虚拟ip信息; 作为server时, 由配置参数确
		// 定, 作为client时, 由认证完成时确定.
		net::ip::network_v4 m_subnet;

		// 作为server时, 虚拟 IP 分配器.
		net::ip::address_v4_range m_ip_assigner;
		net::ip::address_v4_range::iterator m_ip_iterator;

		// 访问控制路由表, 命中的ip则转入tun2socks协议.
		acl_util::lpm_table m_routes;

		// 服务停止标志.
		bool m_abort{ false };
	};
}
