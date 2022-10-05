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

#include "utils/base_stream.hpp"
#include "utils/crypto.hpp"
#include "utils/acl.hpp"
#include "utils/misc.hpp"

#include "socks/socks_server.hpp"

#include <boost/assign/list_inserter.hpp>

#include <boost/bimap/bimap.hpp>
#include <boost/bimap/unordered_set_of.hpp>
#include <boost/bimap/multiset_of.hpp>

#include <boost/thread/lockable_adapter.hpp>

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

		// 作为client时, 是否忽略掉服务器推送的信息.
		bool ignore_push_ = { false };

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

		// 作为client时, 必选项, 必须设置为server的public key(base64编码).
		// 作为server时, 此选项为可选项, 如果存在, 则表示必须由server
		// 指定的public key才能和server通信, 并且可以通过这个参数指定
		// client的public key所固定的ip.
		// 具体语法为:
		// pubkey1:ip1;pubkey2:ip2;...
		std::string public_key_;

		// 作为client时, 此选项为可选项, 手工设置ecdh的私钥(base64编码)
		// 而不是由系统自动生成, 这样可以通过server绑定client的pubkey
		// 所对应的ip, 同时也便于实现双向认证, 如果不设置将由系统自动生
		// 成一个临时的密钥对.
		// 作为server时, 必选项, 设置该server的全局私钥对(base64编码),
		// 其公钥可分发给client, client通过其公钥来和server协商密钥.
		std::string private_key_;

		// ssl 证书目录.
		// 证书目录, 包含以下文件:
		// 证书文件: ssl_crt.pem
		// 证书密钥文件: ssl_key.pem
		// tmp dh文件: ssl_dh.pem
		// 证书解密密钥: ssl_crt.pwd
		std::string ssl_certificate_dir_;

		// 指定tun设备名称.
		std::string ifdev_;

		// 外部传递tun fd到avpn中.
		// avpn将使用ptun_fd_构造一个对象直接访问tun设备.
		int ptun_fd_{ -1 };

		// 外部传递的unix domain socket的fd.
		// avpn将通过这个unix domain socket读取或发出ip数据包, 这个
		// socket只是一个与tun设备的ipc通信.
		int utun_fd_{ -1 };

		// 用于控制avpn的controller的信息.avpn将自动连接controller,
		// 并等待controller发送控制信息：开启或关闭, 或获取avpn实时速
		// 率等信息.
		std::string controller_;

		// 当前avpn运行的模式: server/client.
		avpn::Identity identity_;

		// Tun mtu大小, 必须让tun网卡的mtu大小保证能通过物理网络
		// 的mtu大小.
		int mtu_size_;

		// 传输网络使用ipv6, 这个标志将影响计算avpn的packet及
		// tun的mtu.
		bool using_ipv6_;

		// vpn隧道相关参数.
		avpn::tunnel_params tunnel_params_;

		// socks server options.
		socks_server_option socks_opt_;

		// post up script.
		std::string post_up_script_;
	};



	//////////////////////////////////////////////////////////////////////////

	class vpn_tunnel;

	using vpn_tunnel_ptr = std::shared_ptr<vpn_tunnel>;
	using vpn_tunnel_weak_ptr = std::weak_ptr<vpn_tunnel>;
	using ip_assign_type = std::tuple<std::string, uint32_t>;

#if defined(AVPN_WINDOWS) && defined(AVPN_USE_WINTUN)
	using wintun_device = basic_tun_service<avpn::wintun_windows_service>;
	using tuntap_device = basic_tun_service<avpn::tuntap_windows_service>;
	using vtun_device_type = vtun_device<wintun_device, tuntap_device>;
#else
#if defined(AVPN_WINDOWS)
	using vtun_device_type = vtun_device<tuntap_device>;
#else
	using vtun_device_type = vtun_device<tun_device>;
#endif
#endif

	class vpn_conntrack;
	using vpn_conntrack_ptr = std::shared_ptr<vpn_conntrack>;

	// 带mutex的vector类, 访问对象前可调用lock加锁以保证线程安装.
	template<typename Ty, class Alloc = std::allocator<Ty>>
	class safe_vector
		: public std::vector<Ty, Alloc>
		, public boost::lockable_adapter<std::mutex>
	{};

	class avpn_service
		: public socks_server_base
		, public std::enable_shared_from_this<avpn_service>
	{
		// c++11 noncopyable.
		avpn_service(const avpn_service&) = delete;
		avpn_service& operator=(const avpn_service&) = delete;

		// avoid direct call construct object...
		avpn_service() = delete;
		avpn_service(net::io_context&, const service_config&);

		friend class vpn_tunnel;

		// udp socket定义.
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

		// avpn_service 内部信息相关统计.
		struct internal_stat
		{
			int64_t packet_spent_time_{ 0 };

			int64_t tun_rx_{ 0 };
			int64_t tun_tx_{ 0 };

			int64_t tun_rx_perseconds_{ 0 };
			int64_t tun_tx_perseconds_{ 0 }; // 暂不统计.
		};

	public:
		// 创建apvn service对象, 因为avpn_service必须是一个shared_ptr对象
		// 所以为了避免直接调用构造avpn_service对象, 将avpn_service的构造
		// 函数设置为private, 只能通过make_avpn_service创建shared_ptr对象
		// 以避免误用.
		static std::shared_ptr<avpn_service>
			make_avpn_service(net::io_context&, avpn::service_config);
		virtual ~avpn_service();

		// socks server相关.
		virtual void remove_socks_client(size_t id) override;
		virtual const socks::socks_server_option& option() override;

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

		// remove vpn_tunnel.
		void remove_tunnel(uint32_t);

	private:
		// 初始化ssl context.
		void init_ssl_context();

		// tun相关的读取与发送.
		net::awaitable<void> tun_read_loop();
		void do_tun_write(vpn_packet);

		// 处理server/client上的tun设备pkt.
		void do_server_tun_read(vpn_packet, endpoint_pair);
		void do_client_tun_read(vpn_packet, endpoint_pair);

		// udp相关的读取与发送.
		net::awaitable<void> udp_read_loop(int);
		void do_udp_write(vpn_packet, udp::endpoint);

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
		net::awaitable<void> make_endpoint(std::string);

		// 作为server时, 监听client的tcp/udp连接.
		net::awaitable<void> start_tcp_listen(tcp::acceptor&);
		void build_server_udp_sockets();
		net::awaitable<void> start_udp_server();

		// 作为server时, 处理udp数据包.
		void server_dispatch_udp(vpn_packet, udp::endpoint);

		// 作为client时, 处理udp数据包.
		void client_dispatch_udp(vpn_packet, udp::endpoint);

		// 作为client时, 开始进行tcp连接.
		net::awaitable<void> start_tcp_client();
		net::awaitable<bool> connect_tcp_server(tcp::socket&);

		// 作为client时, 开始udp客户端服务.
		net::awaitable<void> start_udp_client();
		void build_client_udp_sockets(size_t);
		// 作为client时, 发起udp握手请求.
		net::awaitable<void> start_udp_handshake();

		// 处理tcp/udp连接握手认证.
		net::awaitable<void> on_tcp_handshake(
			tcp::socket);
		net::awaitable<void> on_udp_handshake(
			udp::endpoint, vpn_packet, uint32_t);

		// 作为client时, 处理server的udp握手回复.
		net::awaitable<void> on_udp_handshake_reply(
			udp::endpoint, vpn_packet);

		// 在tcp连接上读取一个vpn_packet消息.
		net::awaitable<int> tcp_read_packet(tcp::socket&,
			vpn_packet&);
		// 在tcp连接上发送一个vpn_packet消息.
		net::awaitable<void> tcp_write_packet(tcp::socket&,
			vpn_packet&);

		// 根据虚拟ip/client id查询对应的tunnel信息.
		vpn_tunnel_ptr lookup_tunnel(uint32_t);
		vpn_tunnel_ptr lookup_tunnel(std::string);

		net::awaitable<vpn_tunnel_ptr>
			async_make_tunnel(std::string, std::string);

		// 创建隧道对象.
		vpn_tunnel_ptr make_tunnel(uint32_t, std::string, std::string);

		// 作为client时, 重置tcp连接计数.
		void tcp_reconnect(int);

		// 随机选择一个udp socket指针.
		udp_socket_ptr pick_random_usock(int index = -1);

	private:
		// 主线程io_context, 用于统一调度之类.
		net::io_context& m_main_context;

		// avpn服务配置.
		service_config m_config;

		// 运行的身份.
		Identity m_identity{ Identity::avpn_server };

		// 主线程id.
		std::thread::id m_main_thread_id;

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
		int m_tcp_reconnect_cnt{ 0 };

		// client状态.
		enum {
			vst_none     = 0b00000000, // 无状态, 初始状态.
			vst_starting = 0b00000001, // 进入启动状态.
			vst_tcping   = 0b00000010, // 正在开始tcp连接状态.
			vst_tcped    = 0b00000100, // tcp连接退出状态.
			vst_restart  = 0b00001000, // 进入重新运行client状态.
			vst_running  = 0b00010000, // 进入运行状态.
			vst_stopped  = 0b10000000, // 已经完全停止状态.
		};
		int m_client_state{ vst_none };

		// 作为client时, server推送的路由, dns, passbyvpn信息.
		tunnel_params m_push_params;

		// tun设备.
		vtun_device_type m_tundev;

		// m_tick_timer 定时器, 用于处理一系列定时任务.
		// m_tun_wait_timer 定时器, 用于等待tun设备异步退出.
		asio_timer m_tick_timer;
		asio_timer m_tun_wait_timer;

		// 内部部分信息统计.
		internal_stat m_internal_stat;

		// 专门用于退出时取消asio_util::async_connect.
		net::cancellation_signal m_cancel_sig;

		// 作为server时, 用于tcp的服务器acceptor.
		std::vector<tcp::acceptor> m_tcp_acceptors;

		// socks clients连接表.
		using socks_session_weak_ptr =
			std::weak_ptr<socks_session_base>;
		using socks_session_ptr =
			std::shared_ptr<socks_session_base>;
		std::unordered_map<size_t, socks_session_weak_ptr> m_socks_clients;

		// ssl context.
		net::ssl::context m_ssl_ctx{ net::ssl::context::sslv23 };

		// udp socket集合.
		// 作为server时, m_udp_sockets初始化为几个用于监听client的
		// udp消息的udp socket.
		// 作为client时, 可以随时创建新的udp_socket用于和server通信.
		// last_see_ 用作client时, 标识最后和server通信时间, 如果超
		// 时则可创建新的udp_socket替代超时的udp_socket.
		safe_vector<udp_socket_ptr> m_udp_sockets;

		// 正在发送的udp数据包数量.
		uint64_t m_udp_writing{ 0 };

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

		// 退出时路由清理操作表.
		std::vector<std::string> m_cl_routes;

		// 作为server时, client的pubkey所对应的ip分配表.
		// 通过此表固定分配ip.
		// 这里key表示pubkey, value表示ip, 双向唯一且可索引.
		using staic_ipp_type = boost::bimaps::bimap<
			boost::bimaps::unordered_set_of<std::string>,
			boost::bimaps::unordered_set_of<std::string>
		>;
		staic_ipp_type m_staic_ipp;

		// 访问控制路由表, 命中的ip则转入tun2socks协议.
		acl_util::lpm_table m_routes;

		// 服务停止标志.
		bool m_abort{ false };
	};
}
