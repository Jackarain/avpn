//
// Copyright (C) 2025 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#ifndef INCLUDE__2025_11_20__AVPN_HPP
#define INCLUDE__2025_11_20__AVPN_HPP

#include "libavpn/io_context_pool.hpp"
#include "libavpn/netlink_route.hpp"
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/network_v4.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/json.hpp>

#include <memory>
#include <atomic>
#include <map>
#include <set>
#include <vector>
#include <string>
#include <ctime>


namespace libavpn {

	// 服务配置参数.
	struct service_config
	{
		// 指定 tun 设备名称.
		std::string ifdev_;

		// tun 设备文件描述符, 通过外部打开的 tun 设备传入.
		// 通常用于使用 SCM_RIGHTS 机制将 tun 设备传递给当前程序.
		// -1 表示不使用外部传入的 tun 设备.
		int ptun_fd_{ -1 };

		// tun 设备文件描述符, 通过 Unix Domain Datagram Socket 将 IP 数据包通过
		// IPC 的方式读写到当前程序中.
		// -1 表示不使用 IPC 方式来读写 tun 设备.
		int utun_fd_{ -1 };

		// 控制服务地址, 用于接受控制命令.
		// 格式如: "ws://ip:port", 由 avpn 主动连接到控制端服务, 接受控制命令.
		// 当为空字符串时, 表示不启用控制服务功能.
		// 注意: 控制服务通常用于动态下发配置, 启动/停止 service 等功能.
		std::string controller_;

		// 目标 vpn 服务器, 当从 tun 设备读取到数据后, 需要将 IP 数据包发送下一个的服务.
		// 如果是作为网关服务的话, nexthop 应该为空.
		std::string nexthop_;

		// TCP 服务监听, 用于接受来自远程 vpn 服务器发来的 IP 数据包.
		std::vector<std::string> tcp_listens_;

		// UDP 服务监听, 用于接受来自远程 vpn 服务器发来的 IP 数据包.
		std::vector<std::string> udp_listens_;

		// 本端的公私钥对.
		std::string private_key_;
		std::string public_key_;

		// public key list, 存储远端的公钥列表.
		std::vector<std::string> pkl_;

		// Tun mtu 大小, 必须让 tun 网卡的 mtu 大小保证能通过物理网络的 mtu 大小.
		int mtu_size_{ 1450 };

		// 保持网络活动消息间隔.
		int keepalive_{ 60 };

		// 当 avpn 作为 gateway 时, 推送路由给 client 端.
		std::vector<std::string> pushroutes_;

		// 当 avpn 作为 gateway 时, 推送 dns 给 client 端.
		uint32_t pushdns_{ 0 };

		// 当 avpn 作为 gateway 时, 是否默认通过当前 gateway 作为全局网络出口.
		// 注意：作为 gateway 必须做 nat 配置, 否则可能无法通过 vpn 上网.
		bool passbyvpn_{ false };

		// 绕过 vpn 走物理线路的目标 (client, 支持 IP/CIDR 或域名).
		std::vector<std::string> bypassroutes_;

		// 当 avpn 作为 gateway 时, 是否忽略掉 vpn server 推送的 route/dns 信息.
		bool ignore_push_{ false };

		// 当 avpn 作为 gateway 时, 是否允许客户端之间通信.
		bool c2c_{ false };

		// 当 avpn 作为 gateway 时, vpn 子网配置.
		// 格式如: "10.0.0.0/16".
		std::string subnet_;

		// IPv6 内网子网配置, 格式如 "fd00:8888::/64", 默认为 fd00:8888::/64.
		std::string v6_subnet_;

		// fec 数据设置, 指定多少份 fec 数据.
		// 当 data_shards_ 为 1 时, 不再使用 fec 恢复算法, 转变成 parity_shards_ 指定的
		// 倍数发包.
		int data_shards_{ 0 };

		// fec冗余设置.
		// 当 data_shards_ 大于 1 时, parity_shards_ 指定为多少份恢复数据包, 即最大可丢
		// 失多少个数据包还能恢复.
		// 如果 data_shards_ 设置为 1 时, 则 parity_shards_ 为具体发包倍数.
		// 例如: data_shards_ 为 1, 而 parity_shards_ 为0, 则为原样发包, parity_shards_
		// 为 1 则为 2 倍发包, 最大 5 倍.
		int parity_shards_{ 0 };

		// 压缩选项, 指定压缩算法, 可以指定的压缩算法: deflate, lz4, zstd, 默认为空不压缩.
		std::string compress_;

		// 数据特征混淆密钥串, 非空时启用混淆.
		// 开启后加密数据帧外层填充随机垃圾数据以打乱包长特征.
		// 注意: 两端必须配置相同密钥, 旧版本对端无法解析混淆数据.
		std::string obfuscate_key_;

		// hook 命令, 通过 shell 执行, 支持 %i 替换为 tun 接口名.
		// pre_up_ 在 tun 接口启用前执行; post_up_ 在接口配置完成后执行;
		// pre_down_ 在接口拆除前执行; post_down_ 在接口拆除后执行.
		std::string pre_up_;
		std::string post_up_;
		std::string pre_down_;
		std::string post_down_;
	};

	// 命名空间及类型别名.
	namespace net = boost::asio;
	using net::ip::udp;
	using net::ip::tcp;

	class avpn_session;
	class tun_device;
	class vpn_controller;

	class avpn_service
		: public std::enable_shared_from_this<avpn_service>
	{
	private:
		// c++11 noncopyable.
		avpn_service(const avpn_service&) = delete;
		avpn_service& operator=(const avpn_service&) = delete;

		// avoid direct call construct object...
		avpn_service() = delete;
		avpn_service(io_context_pool&, const service_config&);

	public:
		static std::shared_ptr<avpn_service>
			create_service(io_context_pool& ioc_pool, const service_config& config);
		virtual ~avpn_service();

	public:
		// 启动服务.
		bool start();

		// 停止服务.
		void stop();

		// 采集服务状态快照 (供控制通道状态上报 / get_status RPC 使用).
		boost::json::object status_json() const;

	private:
		// 启动 tun 设备读写任务.
		bool start_tun_io_task();

		// 作为 gateway 运行.
		bool run_as_gateway();

		// 作为 client 运行.
		bool run_as_client();

		// 创建客户端会话并设置回调 (重连时复用).
		bool create_client_tunnel();

		// UDP 接收循环 (gateway 监听).
		net::awaitable<void> udp_receive_loop(
			std::shared_ptr<net::ip::udp::socket> socket);

		// TCP 接收循环 (gateway 监听).
		net::awaitable<void> tcp_accept_loop(
			std::shared_ptr<net::ip::tcp::acceptor> acceptor);

		// 客户端 UDP 接收循环.
		net::awaitable<void> client_udp_receive_loop(
			std::shared_ptr<net::ip::udp::socket> socket);

		// 客户端网络变化监控: 检测本地出口地址变化, 变化时重建 UDP socket.
		net::awaitable<void> client_network_monitor();

		// 重建客户端 UDP socket (网络切换后使用新的本地端口/地址).
		void renew_client_udp();

		// 获取到指定服务器时本机将使用的出口源地址 (空表示失败).
		net::ip::address local_source_address(
			const net::ip::udp::endpoint& server);

		// 周期性输出会话带宽统计.
		net::awaitable<void> bandwidth_report_loop();

		// 客户端 TCP 连接.
		net::awaitable<void> client_tcp_connect();

		// tun 读取循环: 从 tun 读取 IP 包并转发给相应会话.
		net::awaitable<void> tun_read_loop();

		// 等待握手完成并配置 tun 设备 (client).
		net::awaitable<void> wait_handshake_and_setup_tun();

		// 应用 gateway 推送的路由 (passbyvpn / pushroutes).
		void setup_system_routes();

		// 周期刷新绕过路由 (域名解析结果可能变化).
		net::awaitable<void> bypass_route_refresh_loop();

		// 重新解析并刷新绕过路由.
		void refresh_bypass_routes();

		// 恢复握手前保存的默认路由.
		void restore_system_routes();

		// 路由一个 tun 读取到的 IP 包.
		void route_tun_packet(std::vector<uint8_t> ip_packet);

		// 将 IP 包写入 tun 设备.
		void write_to_tun(std::vector<uint8_t> ip_packet);

		// 处理 gateway 收到的 UDP 数据包.
		void on_gateway_udp_packet(
			const std::shared_ptr<net::ip::udp::socket>& socket,
			const net::ip::udp::endpoint& remote, std::vector<uint8_t> data);

		// 处理 gateway 接受的 TCP 连接.
		net::awaitable<void> on_gateway_tcp_connection(
			net::ip::tcp::socket stream);

		// 根据虚拟地址查找会话.
		std::shared_ptr<avpn_session> find_session(uint32_t vaddr) const;

		// 会话关闭回调.
		void on_session_close(const std::shared_ptr<avpn_session>& session);

		// 分配虚拟地址 (gateway).
		uint32_t alloc_vaddr();

		// 释放虚拟地址.
		void free_vaddr(uint32_t vaddr);

	private:
		// DDoS 缓解措施.
		class ddos_guard;
		friend class ddos_guard;

	private:
		// io_context 池引用.
		io_context_pool& m_ioc_pool;

		// 主 io_context 服务.
		net::io_context& m_main_context;

		// 服务配置参数.
		service_config m_config;

		// 控制通道 (controller 非空时启动).
		// 用 shared_ptr 持有: stop() 时 reset 后, 运行中的 worker/serve 协程
		// 仍通过自身持有的 shared_from_this 保活, 协程结束后再析构.
		std::shared_ptr<vpn_controller> m_controller;

		// 服务启动时间 (Unix 秒, 0 表示未启动).
		std::time_t m_started_at{ 0 };

		// 服务中止标志.
		std::atomic_bool m_abort{ false };

		// PostUp hook 是否已执行 (客户端重连时接口不销毁, 避免重复执行).
		bool m_post_up_done_{ false };

		// 周期任务定时器, 停止时 cancel 以唤醒协程自然退出.
		net::steady_timer m_bandwidth_timer;
		net::steady_timer m_bypass_timer;
		net::steady_timer m_netmon_timer;

		// tun 设备.
		std::unique_ptr<tun_device> m_tundev;

		// gateway: 会话表 (远端 udp endpoint 字符串 -> 会话).
		std::map<std::string, std::shared_ptr<avpn_session>> m_sessions;

		// gateway: 按对端静态公钥索引的会话表 (网络切换后识别用).
		std::map<std::string, std::shared_ptr<avpn_session>> m_sessions_by_pubkey;

		// client: 唯一会话.
		std::shared_ptr<avpn_session> m_tunnel;

		// gateway: UDP 监听 socket.
		std::vector<std::shared_ptr<net::ip::udp::socket>> m_udp_sockets;

		// gateway: TCP 监听 acceptor.
		std::vector<std::shared_ptr<net::ip::tcp::acceptor>> m_tcp_acceptors;

		// client: UDP socket.
		std::shared_ptr<net::ip::udp::socket> m_client_udp;

		// client: nexthop endpoint.
		net::ip::udp::endpoint m_nexthop_udp;
		net::ip::tcp::endpoint m_nexthop_tcp;

		// 客户端是否使用 TCP 传输.
		bool m_use_tcp_transport{ false };

		// client: 握手前保存的默认路由 (断开时恢复).
		std::vector<nl_route_entry> m_saved_default_routes;

		// client: 是否已修改系统路由.
		bool m_routes_modified{ false };

		// client: 绕过路由使用的物理网关.
		std::string m_bypass_phys_via;
		std::string m_bypass_phys_dev;

		// client: 绕过路由刷新循环是否已启动.
		bool m_bypass_refresh_started{ false };

		// DDoS 防护.
		std::unique_ptr<ddos_guard> m_ddos;

		// gateway: vpn 子网.
		net::ip::network_v4 m_subnet;

		// gateway: 已分配的虚拟地址.
		std::set<uint32_t> m_allocated_addrs;
		uint32_t m_next_vaddr{ 0 };
		uint32_t m_vaddr_end{ 0 };
	};

}

#endif // INCLUDE__2025_11_20__AVPN_HPP
