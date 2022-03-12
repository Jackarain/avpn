//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#pragma once

#include <iostream>
#include <functional>
#include <cstring> // for std::memcpy
#include <map>
#include <unordered_map>
#include <set>
#include <concepts>
#include <shared_mutex>

#include <boost/asio/io_context.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/defer.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/ip/v6_only.hpp>
#include <boost/asio/ip/address_v4.hpp>
#include <boost/asio/ip/network_v4.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/read_until.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/buffer.hpp>

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/ssl.hpp>

#include <boost/circular_buffer.hpp>

#include <zlib.h>

#include "avpn/io_context_pool.hpp"
#include "avpn/reedsolomon.hpp"

#include "vpncore/endpoint_pair.hpp"
#include "vpncore/fec_cache.hpp"

#include "utils/scoped_exit.hpp"
#include "utils/bitfield.hpp"
#include "utils/url_parser.hpp"
#include "utils/async_connect.hpp"
#include "utils/yield_cancellation_slot_bind.hpp"
#include "utils/time_clock.hpp"
#include "utils/io.hpp"
#include "utils/logging.hpp"
#include "utils/misc.hpp"
#include "utils/uawaitable.hpp"

namespace avpn {

	namespace http = boost::beast::http;			// from <boost/beast/http.hpp>
	using tcp = boost::asio::ip::tcp;               // from <boost/asio/ip/tcp.hpp>
	using udp = boost::asio::ip::udp;               // from <boost/asio/ip/udp.hpp>
	namespace websocket = boost::beast::websocket;  // from <boost/beast/websocket.hpp>
	using ws = websocket::stream<tcp::socket>;		// from <boost/beast/websocket.hpp>
	using time_point = time_clock::steady_clock::time_point;

	using timer = boost::asio::basic_waitable_timer<time_clock::steady_clock>;
	using ws_stream = websocket::stream<boost::beast::tcp_stream>;

	using namespace util;
	using namespace stream_endian;

	enum {
		avpn_server = 0,
		avpn_client = 1
	};

	const static std::string test_google_key = "VLTATWJGVH5W7V7DX6V436FG74";
	const static int normal_mtu = 1500;
	const static int static_mtu = 1400;
	const static uint16_t avpn_protocol_version = 1;
	//////////////////////////////////////////////////////////////////////////

	enum {
		vpt_compress_tcp = 0,
		vpt_tcp,
		vpt_compress_udp,
		vpt_udp,
		vpt_icmp,
		vpt_compress_fec,
		vpt_fec,
		vpt_udp_handshake,
		vpt_udp_handshake_reply,
		vpt_keepalive,
		vpt_auth,
	};

	const static int max_client_udp_socket = 4;

	//////////////////////////////////////////////////////////////////////////

	struct vpn_message
	{
		vpn_message() = default;
		~vpn_message() = default;

		vpn_message(vpn_message && msg) noexcept
			: type(msg.type)
			, content(std::move(msg.content))
		{}

		vpn_message& operator=(vpn_message&& msg) noexcept
		{
			type = msg.type;
			content = std::move(msg.content);

			return *this;
		}

		uint8_t type = vpt_tcp;
		std::string content;
	};

	struct vpn_remote_endpoint
	{
	public:
		// 初始化指定个数的endpoint数量
		vpn_remote_endpoint(size_t size = 0, int identity = avpn::avpn_client)
			: endpoints_(size)
			, identity_(identity)
		{}

		// 获取最有效的udp endpoint, 用于udp通信.
		udp::endpoint acquire() const noexcept
		{
			std::shared_lock lock(mutex_);

			if (identity_ == avpn::avpn_client)
				return client_endpoint();

			return server_endpoint();
		}

		// 当作为client时, 添加指定数量的server的endpoint.
		// 当作为server时, 动态添加最新活跃的endpoint进来.
		void update(const udp::endpoint& endp) noexcept
		{
			std::unique_lock lock(mutex_);
			endpoints_.push_back(endp);
		}

		// 更新指定下标的endpoint.
		void update(const udp::endpoint& endp, int index) noexcept
		{
			std::unique_lock lock(mutex_);
			endpoints_[index] = endp;
		}

		// 获取容器大小.
		size_t size() const noexcept
		{
			std::shared_lock lock(mutex_);
			return endpoints_.size();
		}

		// 清空容器.
		void clear() noexcept
		{
			std::unique_lock lock(mutex_);
			endpoints_.clear();
		}

		// 重置容器大小.
		void resize(size_t size)
		{
			std::unique_lock lock(mutex_);
			endpoints_.resize(size);
		}

	private:
		const udp::endpoint& client_endpoint() const noexcept
		{
			const auto& endp = endpoints_[next_endpoint_];
			next_endpoint_ = (next_endpoint_ + 1) % endpoints_.size();
			return endp;
		}

		const udp::endpoint& server_endpoint() const noexcept
		{
			return endpoints_.back();
		}

	private:
		mutable std::shared_mutex mutex_;
		boost::circular_buffer<udp::endpoint> endpoints_;
		mutable int next_endpoint_{ 0 };
		int identity_;
	};

	struct vpn_connection
	{
		vpn_connection(ws_stream&& stream, const std::string& host)
			: ws_stream_(std::move(stream))
			, reconnect_timer_(ws_stream_.get_executor())
			, remote_host_(host)
		{}

		~vpn_connection()
		{
			if (remote_host_.empty())
				LOG_DBG << "vpn connection leave";
			else
				LOG_DBG << "vpn connection leave, remote: " << remote_host_;
		}

		int identity_{ avpn::avpn_server };	// 0 server, 1 client.

		fec_cache fec_dec_;					// fec 解码缓冲器.
		uint32_t gid_{ 0 };					// fec 编码group id.

		time_point enc_tm_;					// fec 编码缓冲接收起始时间.
		std::vector<vpn_message> fec_enc_;	// fec 编码缓冲.
		int64_t fec_enc_size_{ 0 };			// 缓冲字节数.

		uint32_t vnet_{ 0 };				// 本机虚拟IP, 作为client时, 由server分配.
		std::string remote_host_;			// 远程主机地址字符串, 通过ws连接获取.

		vpn_remote_endpoint endps_{ 5, avpn::avpn_server };	// 作为server时, client的endpoint.

		// TODO: 支持并发tcp连接.
		ws_stream ws_stream_;								// 通过ws通信的tcp连接.
		std::deque<std::string> ws_msg_deque_;				// ws发送队列.
		bool deque_writing_{ false };						// ws发送标志.

		timer reconnect_timer_;						// 重连定时器, 作为client时使用.
		int64_t connection_id_{ -1 };				// 连接id.
	};

	using vpn_connection_ptr = std::shared_ptr<vpn_connection>;
	using vpn_connection_weak_ptr = std::weak_ptr<vpn_connection>;

	inline bool operator<(const vpn_connection_ptr& lh, const vpn_connection_ptr& rh)
	{
		if (lh < rh)
			return true;
		return false;
	}

	inline bool operator<(const vpn_connection_weak_ptr& lh, const vpn_connection_weak_ptr& rh)
	{
		auto lhp = lh.lock();
		auto rhp = rh.lock();

		if (lhp < rhp)
			return true;
		return false;
	}

	//////////////////////////////////////////////////////////////////////////

	enum vpn_tcp_mode
	{
		only_udp,
		tcpudp_mix,
		only_tcp,
	};

	struct channel_params
	{
		int data_shards_;			// fec数据设置.
		int parity_shards_;			// fec冗余设置.
		int fec_delay_;				// fec超时设置, 用于指定收集fec数据时间.
		int mode_;					// 在udp网络完全不通的环境下使用tcp网络.
		bool compress_;				// 压缩选项.
		bool auto_fec_;				// 自动调整fec参数以适应网络变化.
		int keepalive_;				// 保持网络活动消息.

		std::vector<std::string> routes_;	// server推送路由.
		std::string pushdns_;				// server推送dns.
		bool passbyvpn_;					// 客户端默认通过vpn.
		bool c2c_;							// 客户端之间通信.
		std::string subnet_;				// vpn子网配置.
	};

	enum connection_status
	{
		st_connected,
		st_disconnect,
		st_listen,
	};

	struct channel_status
	{
		bool passbyvpn_{ false };
		std::vector<std::string> routes_;
		connection_status status_;
	};

	class avpn_service;
	class channel
	{
		using string_body = boost::beast::http::string_body;
		using string_response = boost::beast::http::response<string_body>;

		using dynamic_body = boost::beast::http::dynamic_body;
		using dynamic_request = boost::beast::http::request<dynamic_body>;
		using request_parser = boost::beast::http::request_parser<dynamic_request::body_type>;

		using http_status = boost::beast::http::status;
		using fields = boost::beast::http::fields;

		struct http_params
		{
			std::vector<std::string> command_;
			size_t connection_id_;
			boost::beast::tcp_stream& stream_;
			dynamic_request& request_;
			request_parser& parser_;
			boost::beast::flat_buffer& buffer_;
		};

		channel(const channel&) = delete;
		channel& operator=(const channel&) = delete;

	public:
		channel(boost::asio::io_context& io, io_context_pool& ios,
			const channel_params& params, avpn_service& service);

		// 根据用户设置的参数, 启动一个server.
		void start_listen(std::vector<std::string> tcp_listens,
			std::vector<std::string> udp_listens);

		// 启动一个client时向server发起连接.
		void start_connect(const std::vector<std::string>&);

		// 关闭channel.
		void close();

		// 根据运行身份的不同, 将tun读取到的数据包分别交由
		// server_forward_tun 或 client_forward_tun 进行透传.
		void server_forward_tun(vpn_message&&, endpoint_pair&&);
		void client_forward_tun(vpn_message&&, endpoint_pair&&);

		// 本机虚拟网络.
		boost::asio::ip::network_v4 vnet_ipaddr() const;

		// 虚拟网络信息, 包含虚拟网关信息在vnet的address中.
		boost::asio::ip::network_v4 vnet() const;

	private:
		// 初始化tcp连接接收器, 即ws服务器的acceptor.
		bool init_tcp_acceptors();

		// listen client连接, 一旦有客户端连接成功, 将启动start_ws_connection
		// 处理这个客户端连接.
		boost::asio::awaitable<void> start_ws_listen(tcp::acceptor& a);
		boost::asio::awaitable<void> start_ws_connection(
			size_t connection_id, boost::beast::tcp_stream stream);

		// 用于超时相关处理.
		void keepalive(vpn_connection_weak_ptr ptr);
		void ws_expires_after(vpn_connection& connection, int seconds);

		// 启动TCP读取协程, 将读取到的数据包交由process_tcp_packet处理.
		boost::asio::awaitable<void> start_tcp_read(vpn_connection_ptr connection_ptr);

		// 协议处理函数, tcp和udp处理函数.
		boost::asio::awaitable<void> process_tcp_packet(uint32_t type,
			stream_endian::bitstream& reader, vpn_connection_ptr& connection_ptr);
		boost::asio::awaitable<void> process_udp_packet(uint8_t type,
			stream_endian::bitstream& reader, udp::socket& sock, const udp::endpoint& endp);

		// 直接转发数据到指定tcp socket.
		boost::asio::awaitable<void> forward_tcp_write(
			const vpn_connection_ptr& connection_ptr, std::string&& msg);

		// 直接转发数据包到指定udp socket.
		boost::asio::awaitable<void> forward_udp_write(udp::socket& sock,
			const udp::endpoint& endp, std::string&& msg);

		// 转发数据包到网络, 自动根据配置转发.
		boost::asio::awaitable<void> forward_channel_write(
			vpn_connection_ptr connection_ptr, avpn::vpn_message&& msg);

		// 启动udp socket服务, 成功后自动启动start_udp_read_loop进入循环
		// 读取udp数据包请求.
		boost::asio::awaitable<void> start_udp_socket();
		boost::asio::awaitable<void> start_udp_read_loop(size_t index);
		boost::asio::awaitable<void> start_tcp_connect();

		// 管理vpn_connection_ptr相关操作.
		void add_connection(vpn_connection_ptr& connection_ptr, uint32_t vaddr);
		void remove_connection(uint32_t vaddr);
		vpn_connection_ptr lookup_connection(uint32_t vaddr);

		// 管理临时进来的连接相关.
		void add_incoming(vpn_connection_ptr& connection_ptr, int64_t id);
		void remove_incoming(int64_t id);

		// http请求的response处理.
		boost::asio::awaitable<void> http_response_handle(
			const http_params& params, std::string response, http_status status);

		// IP分配器, 用于server给连接上来的client分配虚拟IP.
		std::tuple<std::string, uint32_t> ip_assigner();

		// 协议相关处理子函数.
		boost::asio::awaitable<void> do_vpt_auth(
			stream_endian::bitstream& reader, vpn_connection_ptr& connection_ptr);

		boost::asio::awaitable<bool> do_vpt_compress(
			stream_endian::bitstream& reader, std::string& bufs);

		boost::asio::awaitable<void> do_vpt_packet(uint8_t type,
			stream_endian::bitstream& reader, const udp::endpoint* endp);
		boost::asio::awaitable<vpn_connection_ptr> do_vpt_fec_packet(stream_endian::bitstream& reader);

		boost::asio::awaitable<void> do_vpt_udp_handshake(
			stream_endian::bitstream& reader, udp::socket& sock, const udp::endpoint& endp);
		boost::asio::awaitable<void> do_vpt_udp_handshake_reply(
			stream_endian::bitstream& reader, const udp::endpoint& endp);

		// 处理接收到的FEC数据.
		boost::asio::awaitable<void> do_fec_process(vpn_connection_ptr& connection_ptr);

		// 处理将要发送到网络的FEC数据.
		boost::asio::awaitable<void> run_fec_dispatch();

		// 编码并发送fec数据.
		boost::asio::awaitable<bool> do_fec_perform(vpn_connection_ptr& connection_ptr);

	private:
		avpn_service& m_vpn_service;
		boost::asio::io_context& m_main_ioc;
		avpn::io_context_pool& m_ioc_pool;

		// 通道参数配置, 包含fec参数.
		channel_params m_params;

		std::vector<std::string> m_upstreams;
		std::vector<std::string> m_tcp_listens;
		std::vector<std::string> m_udp_listens;

		// 作为server时, 用于ws的服务器acceptor.
		std::vector<tcp::acceptor> m_ws_acceptors;

		// 专门用于退出时取消asio_util::async_connect.
		boost::asio::cancellation_signal m_cancel_sig;

		// udp socket集合, 作为server时, m_udp_sockets
		// 是由m_udp_listens初始化的几个用于listen的
		// udp socket.
		// 作为client时, 可以随时创建新的udp_socket用于
		// 和server通信.
		// last_see_ 用作client时, 标识最后和server
		// 通信时间, 如果超时则可创建新的udp_socket替代
		// 超时的udp_socket.
		struct udp_socket
		{
			time_point last_see_;
			udp::socket sock_;
		};
		std::vector<udp_socket> m_udp_sockets;

		// 运行的身份.
		int m_identity{ -1 };

		// channel for server.
		std::mutex m_server_mtx;

		// 作为server时, key是一个32bit的 ipv4 vnet 地址.
		std::unordered_map<uint32_t, vpn_connection_weak_ptr> m_remotes;
		// 作为server时, key是一个connection id, 临时连接表
		// 用于快速退出.
		std::unordered_map<int64_t, vpn_connection_weak_ptr> m_incomings;

		// 作为client时, 唯一的vpn_remote.
		vpn_connection_weak_ptr m_client;

		// 作为client时, 参数中 upstreams 解析
		// 出的 udp server 的endpoint.
		vpn_remote_endpoint m_remote_endps;

		// 本机作为client时, server为其分配的虚拟ip.
		boost::asio::ip::network_v4 m_vnet_ipaddr;

		// 本机作为client时, server通告的prefix长度.
		int8_t m_prefix_length{ -1 };

		// 子网信息, 作为server时由参数确定, 作为
		// client时由握手完成时确定.
		boost::asio::ip::network_v4 m_subnet;

		// 作为server时, 虚拟 IP 分配器.
		boost::asio::ip::address_v4_range m_ip_assigner;
		boost::asio::ip::address_v4_range::iterator m_ip_iterator;

		// 作为client时, server推送的route, 用于退出时
		// 清除路由.
		std::vector<std::string> m_routes;

		// server 和 client 都要用到fec timer, 用于间隔指定时间
		// 处理从tun收集到的数据包, 并通过fec编码发送.
		// 这是fec工作的核心, 运行负载将会很高, 如何减少这个工作
		// 负载是个值得思考的问题.
		timer m_fec_timer;
		timer m_wait_timer;

		// 退出标志.
		bool m_abort{ false };
	};
}
