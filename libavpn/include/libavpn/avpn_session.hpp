//
// avpn_session.hpp
// ~~~~~~~~~~~~~~~~
//
// Copyright (C) 2025 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#ifndef INCLUDE__2025_11_20__AVPN_SESSION_HPP
#define INCLUDE__2025_11_20__AVPN_SESSION_HPP

#include "libavpn/avpn.hpp"
#include "libavpn/avpn_protocol.hpp"
#include "libavpn/avpn_fec.hpp"
#include "libavpn/avpn_compress.hpp"
#include "libavpn/replay_window.hpp"

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

	// 传输类型.
	enum class transport_type : uint8_t
	{
		udp = 0,
		tcp = 1,
	};

	// 一个对端会话 (tunnel).
	//
	// 负责:
	//   1. 1-RTT 完全加密握手 (initiator 发起, responder 响应).
	//   2. 会话密钥派生 (四次 DH + HKDF).
	//   3. 加密数据通道: 先压缩, 后加密; 接收方先解密, 再解压.
	//   4. UDP 传输 (可选 FEC 纠删码) 与 TCP 传输.
	//   5. keepalive 保活与超时释放.
	//   6. 主动断开 (disconnect 协议).
	class avpn_session : public std::enable_shared_from_this<avpn_session>
	{
	public:
		// IP 数据包回调 (写入 tun).
		using ip_packet_handler = std::function<void(std::vector<uint8_t>)>;

		// 会话关闭回调.
		using close_handler = std::function<void(const std::shared_ptr<avpn_session>&)>;

		// 会话建立完成回调 (responder 握手成功后调用, 用于网关登记会话).
		using established_handler = std::function<void()>;

		// UDP 数据报发送回调 (由 service 提供共享的 udp socket).
		using udp_send_handler = std::function<void(
			const net::ip::udp::endpoint&, std::vector<uint8_t>)>;

		// 虚拟地址分配回调 (responder 使用).
		// 参数 requested 为客户端请求的地址 (0 表示不请求), 返回 {vaddr, prefix_length}.
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
		// 设置回调.
		void set_ip_packet_handler(ip_packet_handler h);
		void set_close_handler(close_handler h);
		void set_established_handler(established_handler h);
		void set_udp_send_handler(udp_send_handler h);
		void set_vaddr_allocator(vaddr_allocator h);

		// 启动 initiator 会话: 通过 UDP 连接 server 并发起握手.
		net::awaitable<void> run_initiator_udp(
			net::ip::udp::endpoint server);

		// 启动 initiator 会话: 使用已建立的 TCP 连接 (控制连接) 发起握手.
		net::awaitable<void> run_initiator_tcp(
			net::ip::tcp::socket stream);

		// 作为 responder: 收到一个 UDP 数据报.
		// 返回 true 表示数据报已被消费 (握手包或有效数据包), false 表示丢弃.
		bool on_udp_packet(const net::ip::udp::endpoint& remote,
			std::string_view data);

		// 作为 responder: 处理一个已接受的 TCP 连接 (控制连接).
		net::awaitable<void> run_responder_tcp(
			net::ip::tcp::socket stream);

		// 从 tun 提交一个 IP 数据包, 发送到对端.
		void tun_submit(std::vector<uint8_t> ip_packet);

		// 主动断开并发送 disconnect 协议.
		void disconnect();

		// 立即关闭会话 (不发送 disconnect).
		void close();

		// 状态查询.
		bool established() const { return m_established; }
		bool aborted() const { return m_abort; }
		session_role role() const { return m_role; }
		transport_type transport() const { return m_transport; }
		// TCP 控制连接 (TCP 隧道时有效, 用于 Android VPN 建立后重新 protect).
		std::shared_ptr<net::ip::tcp::socket> tcp_stream() const
		{ return m_tcp_stream; }
		uint32_t vaddr() const { return m_vaddr; }
		uint8_t prefix_length() const { return m_session_config.prefix_length; }
		int mtu() const { return m_session_config.mtu; }
		int keepalive() const { return m_session_config.keepalive; }
		void set_keepalive(int seconds);
		const session_config& negotiated_config() const { return m_session_config; }
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

		// 尝试用本会话接收密钥解密一个 UDP 数据报 (用于对端网络切换后的
		// 会话识别). 成功返回 true, 不修改会话状态.
		bool try_decrypt_udp(std::string_view data) const;

		// 更新对端 UDP endpoint (网络切换后服务端回包地址跟随).
		void update_remote_udp(const net::ip::udp::endpoint& remote);

		// 网络变化后立即发送保活, 使对端尽快感知新 endpoint.
		void notify_network_changed();

		// 获取执行器.
		net::any_io_executor get_executor()
		{ return m_ioc.get_executor(); }

	private:
		avpn_session(net::io_context& ioc, const service_config& config,
			session_role role);

		// ---- 握手 ----

		// initiator 发送握手 Message 1.
		void send_handshake_msg1();

		// 处理握手 Message 2 (由 initiator 收到后调用).
		bool handle_handshake_msg2(std::string_view plaintext);

		// 尝试用白名单公钥解密握手 Message 1 (responder).
		// 成功返回 true, 并通过 msg1 输出解析结果, matched_pub 输出匹配的公钥.
		bool try_decrypt_handshake_msg1(std::string_view nonce,
			std::string_view ciphertext, handshake_msg1& msg1,
			std::string& matched_pub);

		// 尝试处理一个握手 Message 1 (responder, 完整流程).
		bool try_handshake(const net::ip::udp::endpoint& remote,
			std::string_view data);

		// responder 回复握手 Message 2.
		void send_handshake_msg2(const std::string& peer_static_pub,
			const handshake_msg1& msg1);

		// 防重放检查.
		bool check_anti_replay(const std::string& peer_pub, uint64_t ts);

		// 派生临时握手密钥 K_temp.
		std::string derive_temp_key(const std::string& peer_static_pub) const;

		// 派生 Message 2 响应密钥.
		std::string derive_resp_key(const std::string& peer_static_pub,
			const std::string& peer_eph_pub);

		// 派生会话密钥.
		// init_eph_priv: 本端临时私钥; init_static_priv: 本端静态私钥;
		// resp_static_pub: 对端静态公钥; resp_eph_pub: 对端临时公钥.
		bool derive_session_keys(const std::string& init_eph_priv,
			const std::string& init_static_priv,
			const std::string& resp_static_pub,
			const std::string& resp_eph_pub);

		// ---- 数据路径 ----

		// 发送方向密钥.
		const std::string& send_key() const
		{
			return m_role == session_role::initiator ? m_key_c2s : m_key_s2c;
		}
		// 接收方向密钥.
		const std::string& recv_key() const
		{
			return m_role == session_role::initiator ? m_key_s2c : m_key_c2s;
		}

		// 发送/接收方向 nonce 会话盐.
		const std::string& send_nonce_salt() const
		{
			return m_role == session_role::initiator ?
				m_nonce_salt_c2s : m_nonce_salt_s2c;
		}
		const std::string& recv_nonce_salt() const
		{
			return m_role == session_role::initiator ?
				m_nonce_salt_s2c : m_nonce_salt_c2s;
		}

		// 由会话盐与计数器构造 12 字节 AEAD nonce.
		std::string make_nonce(const std::string& salt,
			uint32_t counter) const;

		// 加密明文帧为线上格式, 按协商配置附加混淆封装.
		// 返回 [salt][len_enc][garbage][counter][ciphertext] 或
		// [counter][ciphertext], 失败返回空.
		std::vector<uint8_t> encrypt_frame(const std::string& key,
			uint32_t counter, std::string_view plaintext);

		// 加密并发送明文帧 (按传输类型分发).
		void send_plaintext(const std::string& key, std::string_view plaintext);

		// 加密并发送 UDP 帧.
		void encrypt_and_send_udp(const std::string& key,
			std::string_view plaintext);

		// 将明文帧推入 TCP 写队列.
		void queue_tcp_frame(const std::string& key,
			std::string_view plaintext);

		// 启动 TCP 写队列泵.
		void start_tcp_write();

		// 处理收到的加密 UDP 数据报.
		bool process_udp_packet(std::string_view wire);

		// 处理解密后的明文消息体.
		void process_plaintext(std::string_view plaintext);

		// 处理 data 消息.
		void process_data_msg(std::string_view body);

		// 将恢复/解压后的 IP 包交付给 tun.
		void deliver_ip_packet(std::vector<uint8_t> data);

		// 按协商配置创建/重建 FEC 编解码器.
		void setup_fec();

		// 发送数据消息 (由 tun_submit 调用).
		void send_data_message(const std::vector<uint8_t>& ip_packet);

		// keepalive/超时 tick.
		net::awaitable<void> tick();
		void start_tick();

		// 发送 keepalive.
		void send_keepalive();
		void send_keepalive_reply(uint64_t timestamp);

		// TCP 控制连接读取循环.
		net::awaitable<void> tcp_read_loop(tcp::socket& stream);

		// 解析 IP 包协议类型 (用于 TCP 传输).
		uint8_t ip_proto(const uint8_t* data, std::size_t size) const;
		bool is_tcp_syn(const uint8_t* data, std::size_t size) const;

	private:
		// io_context 引用.
		net::io_context& m_ioc;

		// 服务配置.
		service_config m_config;

		// 会话角色.
		session_role m_role;

		// 传输类型.
		transport_type m_transport{ transport_type::udp };

		// 会话状态.
		std::atomic_bool m_established{ false };
		std::atomic_bool m_abort{ false };

		// 回调.
		ip_packet_handler m_ip_packet_handler;
		close_handler m_close_handler;
		established_handler m_established_handler;
		udp_send_handler m_udp_send_handler;

		// 密钥材料.
		std::string m_static_priv;       // 本端静态私钥 (原始字节).
		std::string m_static_pub;        // 本端静态公钥 (原始字节).
		std::vector<std::string> m_peer_pubs;   // 对端静态公钥白名单.

		// 握手临时密钥.
		std::string m_eph_priv;          // 本端临时私钥.
		std::string m_eph_pub;           // 本端临时公钥.

		// 对端信息.
		std::string m_peer_static_pub;   // 已认证的对端静态公钥.
		std::string m_peer_eph_pub;      // 对端临时公钥.
		net::ip::udp::endpoint m_remote_udp;
		std::string m_client_id;         // 客户端身份 (32 字节).

		// 会话密钥.
		std::string m_key_c2s;           // client -> server 加密密钥.
		std::string m_key_s2c;           // server -> client 加密密钥.

		// AEAD nonce 会话盐 (每方向独立, 握手时派生).
		std::string m_nonce_salt_c2s;
		std::string m_nonce_salt_s2c;

		// 发送计数器 (每包递增).
		uint32_t m_send_counter{ 0 };

		// 接收重放窗口.
		replay_window m_recv_replay;

		// 协商的会话配置.
		session_config m_session_config;

		// 分配的虚拟地址.
		uint32_t m_vaddr{ 0 };

		// 客户端在握手 Message 1 中请求的虚拟地址 (responder 记录用).
		uint32_t m_requested_vaddr{ 0 };

		// 压缩器.
		compressor m_compressor;

		// FEC 编码/解码.
		std::unique_ptr<fec_encode_group> m_fec_encoder;
		std::unique_ptr<fec_decode_group> m_fec_decoder;

		// FEC 分组 id 生成.
		uint32_t m_fec_id{ 0 };

		// 保活/超时状态.
		std::chrono::steady_clock::time_point m_last_seen{
			std::chrono::steady_clock::now() };
		std::chrono::steady_clock::time_point m_last_keepalive{
			std::chrono::steady_clock::now() };
		net::steady_timer m_tick_timer;
		// tick 协程启动标记 (避免同一会话重复启动, 共享定时器导致互相取消).
		bool m_tick_started{ false };

		// 带宽统计.
		struct speed_stat
		{
			// 环形采样: 记录最近几次的累计字节数及采样时刻, 用于计算速率.
			int64_t rate_{ 0 };
			std::array<int64_t, 3> samples_{ 0, 0, 0 };
			std::array<std::chrono::steady_clock::time_point, 3> sample_time_{};
			std::size_t idx_{ 0 };
		};
		void update_speed(speed_stat& stat, int64_t bytes,
			std::chrono::steady_clock::time_point now);

		int64_t m_upload_bytes{ 0 };
		int64_t m_download_bytes{ 0 };
		speed_stat m_upload_stat;
		speed_stat m_down_stat;

		// 握手重发定时器.
		net::steady_timer m_hs_timer;

		// TCP 控制连接 (属于本会话).
		std::shared_ptr<tcp::socket> m_tcp_stream;

		// TCP 写队列.
		std::deque<std::vector<uint8_t>> m_tcp_oqe;
		bool m_tcp_writing{ false };

		// 握手重发次数.
		int m_hs_retry{ 0 };

		// 虚拟地址分配回调.
		vaddr_allocator m_vaddr_allocator;

		// 防重放: 每个对端公钥最近接受的时间戳.
		std::map<std::string, uint64_t> m_msg1_ts;
	};

} // namespace libavpn

#endif // INCLUDE__2025_11_20__AVPN_SESSION_HPP
