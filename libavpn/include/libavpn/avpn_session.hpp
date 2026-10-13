//
// avpn_session.hpp
// ~~~~~~~~~~~~~~~~
//
// Copyright (C) 2025 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#ifndef INCLUDE__2026_10_14__AVPN_SESSION_HPP
#define INCLUDE__2026_10_14__AVPN_SESSION_HPP

#include "libavpn/avpn.hpp"
#include "libavpn/avpn_crypto.hpp"
#include "libavpn/avpn_frame.hpp"
#include "libavpn/avpn_keys.hpp"
#include "libavpn/avpn_datapath.hpp"
#include "libavpn/avpn_obfuscate.hpp"

#include <boost/asio/ip/udp.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/any_io_executor.hpp>

#include <functional>
#include <memory>
#include <array>
#include <deque>
#include <map>
#include <atomic>
#include <chrono>
#include <string>

namespace libavpn {

	namespace net = boost::asio;

	// 会话角色.
	enum class session_role : uint8_t
	{
		initiator = 0,   // 客户端/端点端 (主动发起握手).
		responder = 1,   // 网关端 (响应握手).
	};

	// 传输类型 (对应会话参数 0x10).
	enum class transport_type : uint8_t
	{
		udp = 0,
		tcp = 1,
	};

	// 一个对端会话 (tunnel).
	//
	// 负责:
	//   1. 1-RTT 握手 (hint + 两把握手密钥 + 四次 DH 派生会话主密钥).
	//   2. 加密数据通道: 帧头计数器 + AEAD; 开纠错时按组补冗余片.
	//   3. 次代回绕换钥, 全局序号防重放.
	//   4. 漫游: 换网后带 cookie 重新绑定, 不用重新握手.
	//   5. 保活与超时释放, 主动断开.
	class avpn_session : public std::enable_shared_from_this<avpn_session>
	{
	public:
		// IP 数据包回调 (写入 tun).
		using ip_packet_handler = std::function<void(std::vector<uint8_t>)>;

		// 会话关闭回调.
		using close_handler = std::function<void(
			const std::shared_ptr<avpn_session>&)>;

		// 会话建立完成回调 (responder 握手成功后调用, 用于网关登记会话).
		using established_handler = std::function<void()>;

		// UDP 数据报批量发送回调 (由 service 提供共享的 udp socket).
		using udp_send_handler = std::function<void(
			const net::ip::udp::endpoint&, std::vector<std::vector<uint8_t>>)>;

		// 虚拟地址分配回调 (responder 使用).
		using vaddr_allocator = std::function<std::pair<uint32_t, uint8_t>(
			uint32_t requested)>;

		// 会话创建 (由 service 调用).
		static std::shared_ptr<avpn_session> create(
			net::io_context& ioc,
			const service_config& config,
			session_role role);

		~avpn_session();

		avpn_session(const avpn_session&) = delete;
		avpn_session& operator=(const avpn_session&) = delete;

	public:
		// 速率统计 (字节/秒).
		struct speed_stat
		{
			int64_t rate_{ 0 };
			int64_t bytes_{ 0 };
			std::chrono::steady_clock::time_point start_{
				std::chrono::steady_clock::now() };
		};

		// 设置回调.
		void set_ip_packet_handler(ip_packet_handler h);
		void set_close_handler(close_handler h);
		void set_established_handler(established_handler h);
		void set_udp_send_handler(udp_send_handler h);
		void set_vaddr_allocator(vaddr_allocator h);

		// 启动 initiator 会话: 通过 UDP 连接 server 并发起握手.
		net::awaitable<void> run_initiator_udp(net::ip::udp::endpoint server);

		// 启动 initiator 会话: 使用已建立的 TCP 连接发起握手.
		net::awaitable<void> run_initiator_tcp(net::ip::tcp::socket stream);

		// 作为 responder: 收到一个 UDP 数据报.
		// 返回 true 表示数据报已被消费 (握手包或有效数据包).
		bool on_udp_packet(const net::ip::udp::endpoint& remote,
			std::string_view data);

		// 作为 responder: 处理一个已接受的 TCP 连接.
		net::awaitable<void> run_responder_tcp(net::ip::tcp::socket stream);

		// 从 tun 提交一个 IP 数据包, 发送到对端.
		void tun_submit(std::vector<uint8_t> ip_packet);

		// 从 tun 提交一批 IP 数据包 (按顺序, 属于本会话): 能塞进一帧的
		// 会按容器聚合, 省下每包 20 字节的封装. 只聚合已经拿在手里的包,
		// 不为攒包等待 (见 doc/protocol_v2.md 2.4).
		void tun_submit_batch(
			const std::vector<std::vector<uint8_t>>& packets,
			std::size_t from, std::size_t count);

		// 主动断开并发送 disconnect 控制消息.
		void disconnect();

		// 立即关闭会话.
		void close();

		// 状态查询.
		bool established() const { return m_established; }
		bool aborted() const { return m_abort; }
		session_role role() const { return m_role; }
		transport_type transport() const { return m_transport; }
		// TCP 控制连接 (TCP 隧道时有效).
		std::shared_ptr<net::ip::tcp::socket> tcp_stream() const
		{ return m_tcp_stream; }
		uint32_t vaddr() const { return m_vaddr; }
		uint8_t prefix_length() const { return m_params.prefix_len; }
		int mtu() const { return m_params.mtu; }
		int keepalive() const { return m_params.keepalive_sec; }
		void set_keepalive(int seconds);
		const session_params& negotiated_config() const { return m_params; }
		const std::string& client_id() const { return m_client_id; }
		const std::string& peer_public_key() const { return m_peer_static_pub; }
		const net::ip::udp::endpoint& remote_udp() const { return m_remote_udp; }
		std::chrono::steady_clock::time_point last_seen() const
		{ return m_last_seen; }

		// 带宽统计 (字节/秒).
		int64_t upload_bytes() const { return m_upload_bytes; }
		int64_t download_bytes() const { return m_download_bytes; }
		int64_t upload_rate() const { return m_upload_stat.rate_; }
		int64_t download_rate() const { return m_down_stat.rate_; }

		// 漫游凭证; 全 0 表示这次会话不用漫游帧.
		const std::array<uint8_t, roam_cookie_size>& roam_cookie() const
		{ return m_datapath.roam_cookie(); }

		// 报文最前面是不是本会话的漫游凭证.
		// 网关对陌生端点的分流靠它: 解密之前就能认出是哪个会话.
		bool matches_roam_cookie(std::string_view data) const;

		// 换网重新绑定之后轮换漫游凭证, 并把新凭证告诉对端; 返回被顶出
		// 窗口的那把 (服务侧用它清理凭证索引). 没有漫游凭证时返回全 0.
		std::array<uint8_t, roam_cookie_size> rotate_roam_cookie();

		// 更新对端 UDP endpoint (网络切换后回包地址跟随).
		void update_remote_udp(const net::ip::udp::endpoint& remote);

		// 网络变化后立即发送漫游保活, 使对端尽快感知新 endpoint.
		void notify_network_changed();

		// 获取执行器.
		net::any_io_executor get_executor()
		{ return m_ioc.get_executor(); }

	private:
		avpn_session(net::io_context& ioc, const service_config& config,
			session_role role);

		// ---- 握手 ----

		// initiator 发送握手请求 (hint + 随机数 + 密文).
		void send_handshake_msg1();

		// initiator 处理握手回复; 成功返回 true.
		bool handle_handshake_msg2(std::string_view wire);

		// responder 尝试把一条报文当作握手请求处理, 成功返回 true.
		bool try_handshake(const net::ip::udp::endpoint& remote,
			std::string_view wire);

		// responder 回复握手应答.
		void send_handshake_msg2(const std::string& peer_static_pub,
			const handshake_req& req);

		// 握手时间戳防重放.
		bool check_anti_replay(const std::string& peer_pub, uint64_t ts);

		// 会话建立后的收尾: 配好数据面, 起定时器, 回调通知.
		void on_established();

		// 按协商的参数装配数据面与漫游凭证.
		void apply_params();

		// 网关端把客户端"想要的取值"变成这一会话最终要用的取值.
		session_params make_responder_params(const session_params& wish,
			uint32_t vaddr, uint8_t prefix);

		// ---- 数据路径 ----

		// 写一个明文 (IP 包或控制消息); roam 为 true 时做成漫游帧.
		void send_plaintext(std::string_view plaintext, bool roam = false);

		// 把一批 IP 包按需要拆成若干帧发出 (能塞进一帧的按容器聚合).
		void send_ip_batch(bool roam);

		// 该不该顺带一次漫游凭证 (一直在发却收不到下行时).
		bool nudge_cookie() const;

		// 按传输类型把线上帧排队发送.
		void queue_frame(std::string_view frame);

		// 混淆层: 谈成了并且两端都配了密钥串才套.
		bool obfuscate_enabled() const;

		// 这一帧最前面是不是本会话的漫游凭证 (带凭证的帧不套混淆层).
		bool frame_has_cookie(std::string_view frame) const;
		void flush_udp_batch();
		void queue_tcp_wire(std::vector<uint8_t> wire);
		void start_tcp_write();

		// 处理一条线上帧 (握手或数据).
		bool handle_wire(std::string_view wire);

		// 处理解出来的明文.
		void handle_plaintext(std::string_view plaintext);
		void handle_control_message(std::string_view plaintext);
		void handle_container(std::string_view plaintext);
		void deliver_ip_packet(std::vector<uint8_t> data);

		// 发送保活 / 保活回复 / 断开.
		void send_keepalive(bool roam);
		void send_keepalive_reply(uint64_t timestamp);
		void send_disconnect();

		// 定时器: 保活、超时、纠错收尾.
		net::awaitable<void> tick();
		void start_tick();

		// TCP 控制连接读取循环.
		net::awaitable<void> tcp_read_loop(tcp::socket& stream);

		// 带宽统计.
		void update_speed(speed_stat& stat, int64_t bytes,
			std::chrono::steady_clock::time_point now);

	private:
		// io_context 引用.
		net::io_context& m_ioc;

		// 服务配置.
		service_config m_config;

		// 会话角色与传输类型.
		session_role m_role;
		transport_type m_transport{ transport_type::udp };

		// 会话状态.
		std::atomic_bool m_established{ false };
		std::atomic_bool m_abort{ false };

		// 回调.
		ip_packet_handler m_ip_packet_handler;
		close_handler m_close_handler;
		established_handler m_established_handler;
		udp_send_handler m_udp_send_handler;
		vaddr_allocator m_vaddr_allocator;

		// 密钥材料.
		std::string m_static_priv;       // 本端静态私钥 (原始字节).
		std::string m_static_pub;        // 本端静态公钥 (原始字节).
		std::vector<std::string> m_peer_pubs;   // 对端静态公钥白名单.

		// 握手临时密钥.
		std::string m_eph_priv;
		std::string m_eph_pub;

		// 握手密钥 (由双方静态密钥派生).
		std::string m_hs_shared;         // 共享秘密.
		std::string m_key_temp;          // 请求方向.
		std::string m_key_resp;          // 回复方向.

		// 对端信息.
		std::string m_peer_static_pub;   // 已认证的对端静态公钥.
		std::string m_peer_eph_pub;      // 对端临时公钥.
		net::ip::udp::endpoint m_remote_udp;
		std::string m_client_id;         // 客户端标识 (16 字节).

		// 会话参数与数据面.
		session_params m_params;
		datapath m_datapath;

		// 会话主密钥 (四次 DH 派生).
		std::string m_master;

		// 排队等发送的 UDP 帧.
		std::vector<std::vector<uint8_t>> m_udp_pending;

		// 一批待聚合的 IP 包 (复用缓冲, 免得每批分配).
		std::vector<std::string_view> m_batch_packets;

		// 混淆层用的随机数发生器 (会话开始时播种).
		obfuscate_rand m_obfuscate_rand;

		// 分配的虚拟地址.
		uint32_t m_vaddr{ 0 };

		// 发出去的帧数 (决定什么时候顺带 cookie) 与上次收到下行的时间.
		uint64_t m_tx_frames{ 0 };
		std::chrono::steady_clock::time_point m_last_rx{
			std::chrono::steady_clock::now() };
		uint64_t m_last_keepalive_ms{ 0 };
		bool m_tx_since_rx{ false };

		// 保活 / 超时状态.
		std::chrono::steady_clock::time_point m_last_seen{
			std::chrono::steady_clock::now() };
		net::steady_timer m_tick_timer;
		bool m_tick_started{ false };

		// 握手重试定时器.
		net::steady_timer m_hs_timer;
		int m_hs_retry{ 0 };

		// TCP 发送队列与写合并状态.
		std::deque<std::vector<uint8_t>> m_tcp_oqe;
		std::shared_ptr<tcp::socket> m_tcp_stream;
		net::steady_timer m_tcp_cork_timer;
		bool m_tcp_writing{ false };

		// 握手防重放 (对端公钥 -> 最近一次时间戳).
		std::map<std::string, uint64_t> m_hs_replay;

	private:
		speed_stat m_upload_stat;
		speed_stat m_down_stat;
		std::int64_t m_upload_bytes{ 0 };
		std::int64_t m_download_bytes{ 0 };
	};

} // namespace libavpn

#endif // INCLUDE__2026_10_14__AVPN_SESSION_HPP
