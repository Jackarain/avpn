//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#pragma once

#include "utils/io_context_pool.hpp"
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

#include "vpncore/endpoint_pair.hpp"

#include "avpn/reedsolomon.hpp"
#include "avpn/fec_cache.hpp"


namespace avpn {

	namespace http = boost::beast::http;			// from <boost/beast/http.hpp>
	using tcp = boost::asio::ip::tcp;               // from <boost/asio/ip/tcp.hpp>
	using udp = boost::asio::ip::udp;               // from <boost/asio/ip/udp.hpp>
	namespace websocket = boost::beast::websocket;  // from <boost/beast/websocket.hpp>
	using ws = websocket::stream<tcp::socket>;		// from <boost/beast/websocket.hpp>
	using time_point = time_clock::steady_clock::time_point;

	using namespace util;
	using namespace stream_endian;

	enum class Identity {
		avpn_server = 0,
		avpn_client = 1
	};


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
		vpt_keepalive_reply,
		vpt_auth,
	};


	//////////////////////////////////////////////////////////////////////////

	struct vpn_message
	{
		vpn_message() = default;
		vpn_message(vpn_message&& msg) noexcept;
		vpn_message& operator=(vpn_message&& msg) noexcept;

		uint8_t type = vpt_tcp;
		std::string content_;
	};

	//////////////////////////////////////////////////////////////////////////

	class vpn_remote_endpoint
	{
		vpn_remote_endpoint(const vpn_remote_endpoint&) = delete;
		vpn_remote_endpoint& operator=(const vpn_remote_endpoint&) = delete;

	public:
		// 初始化指定个数的endpoint数量
		vpn_remote_endpoint(size_t size = 0, Identity identity = Identity::avpn_client);

		// 重置endpoints.
		void reset(size_t size = 0, Identity identity = Identity::avpn_client);

		// 获取最有效的udp endpoint, 用于udp通信.
		udp::endpoint acquire() const noexcept;

		// 用于client获取下一个endpoint.
		std::tuple<int, udp::endpoint> next_endpoint() const noexcept;

		// 当作为client时, 添加指定数量的server的endpoint.
		// 当作为server时, 动态添加最新活跃的endpoint进来.
		void update(const udp::endpoint& endp) noexcept;

		// 更新指定下标的endpoint.
		void update(const udp::endpoint& endp, int index) noexcept;

		// 获取容器大小.
		size_t size() const noexcept;

		// 清空容器.
		void clear() noexcept;

		// 重置容器大小.
		void resize(size_t size);

	private:
		const udp::endpoint& client_endpoint() const noexcept;
		const udp::endpoint& server_endpoint() const noexcept;

	private:
		mutable std::shared_mutex mutex_;
		boost::circular_buffer<udp::endpoint> endpoints_;
		mutable int next_endpoint_{ 0 };
		Identity identity_;
	};


	//////////////////////////////////////////////////////////////////////////

	class vpn_connection
	{
	private:
		vpn_connection(const vpn_connection&) = delete;
		vpn_connection& operator=(const vpn_connection&) = delete;

	public:
		vpn_connection(boost::asio::any_io_executor executor, const std::string& host,
			fec::matrix* enc_matrix, fec::matrix* dec_matrix);
		~vpn_connection();

		void reset();

		Identity identity_{ Identity::avpn_server };	// server / client.

		fec::fec_cache fec_dec_;					// fec 解码缓冲器.
		uint32_t gid_{ 0 };					// fec 编码group id.
		fec::matrix* dec_matrix_;			// 用于rs解码的矩阵.

		int dec_ds_{ 0 };					// 记录rs解码的ds大小.
		int dec_ps_{ 0 };					// 记录rs解码的ps大小.

		time_point keepalive_;				// keepalive 时间记录.

		time_point enc_tm_;					// fec 编码缓冲接收起始时间.
		std::vector<vpn_message> fec_enc_;	// fec 编码缓冲.
		int64_t fec_enc_size_{ 0 };			// 缓冲字节数.
		fec::matrix* enc_matrix_;			// 用于rs编码的矩阵.

		uint32_t vnet_{ 0 };				// 本机虚拟IP, 作为client时, 由server分配.
		std::string remote_host_;			// 远程主机地址字符串, 通过ws连接获取.

		vpn_remote_endpoint endps_;			// 作为server时, client的endpoint.

		// TODO: 支持并发tcp连接.
		tcp::socket tcp_stream_;					// tcp连接通信.
		std::deque<std::string> tcp_msg_deque_;		// tcp发送队列.
		bool deque_writing_{ false };				// tcp发送标志.

		int64_t connection_id_{ -1 };				// 连接id.
	};

	using vpn_connection_ptr = std::shared_ptr<vpn_connection>;
	using vpn_connection_weak_ptr = std::weak_ptr<vpn_connection>;

	inline bool operator<(const vpn_connection_ptr& lh, const vpn_connection_ptr& rh);
	inline bool operator<(const vpn_connection_weak_ptr& lh, const vpn_connection_weak_ptr& rh);

	//////////////////////////////////////////////////////////////////////////

	enum vpn_tcp_mode
	{
		only_udp,
		tcpudp_mix,
		only_tcp,
	};

	struct tunnel_params
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

	struct tunnel_status
	{
		bool passbyvpn_{ false };
		std::vector<std::string> routes_;
		std::string dns_;
		std::string server_ip_;
		std::string vaddr_;
		std::string vgateway_;
		connection_status status_;
	};

	class avpn_service;
	class vpn_tunnel
	{
		vpn_tunnel(const vpn_tunnel&) = delete;
		vpn_tunnel& operator=(const vpn_tunnel&) = delete;

	public:
		vpn_tunnel(boost::asio::io_context& io, io_context_pool& ios,
			const tunnel_params& params, avpn_service& service);
		~vpn_tunnel();

		// 根据用户设置的参数, 启动一个server.
		void start_server_listen(std::vector<std::string> tcp_listens,
			std::vector<std::string> udp_listens);

		// 启动一个client时向server发起连接.
		void start_client_connect(const std::vector<std::string>&);

		// 关闭tunnel.
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

		// listen client连接, 一旦有客户端连接成功, 将启动start_tcp_connection
		// 处理这个客户端连接.
		boost::asio::awaitable<void> start_tcp_listen(tcp::acceptor& a);
		boost::asio::awaitable<void> start_tcp_connection(
			size_t connection_id, tcp::socket stream);

		// 作为client, 开始发起tcp连接.
		boost::asio::awaitable<void> start_tcp_client_connect();
		boost::asio::awaitable<bool> connect_server(vpn_connection_ptr& connection_ptr);

		// 用于超时相关处理.
		void keepalive();
		void server_checktimeout();
		void reset_connection_expires(vpn_connection& connection);

		// 启动TCP读取协程, 将读取到的数据包交由process_tcp_packet处理.
		boost::asio::awaitable<void> start_tcp_read_loop(vpn_connection_ptr connection_ptr);
		boost::asio::awaitable<void> start_udp_read_loop(size_t index);

		// 协议处理函数, tcp和udp处理函数.
		boost::asio::awaitable<void> process_tcp_packet(uint32_t type,
			stream_endian::bitstream& reader, vpn_connection_ptr& connection_ptr);
		boost::asio::awaitable<void> process_udp_packet(uint8_t type,
			stream_endian::bitstream& reader, udp::socket& sock, const udp::endpoint endp);

		// 直接转发数据到指定tcp socket.
		boost::asio::awaitable<void> forward_tcp_write(
			const vpn_connection_ptr& connection_ptr, std::string msg);

		// 直接转发数据包到指定udp socket.
		boost::asio::awaitable<void> forward_udp_write(udp::socket& sock,
			udp::endpoint endp, std::string msg);

		// 转发数据包到网络, 自动根据配置转发.
		boost::asio::awaitable<void> forward_tunnel_write(
			vpn_connection_ptr connection_ptr, vpn_message msg);

		// 启动udp socket服务, 成功后自动启动start_udp_read_loop进入循环
		// 读取udp数据包请求.
		boost::asio::awaitable<void> start_udp_server();
		boost::asio::awaitable<void> start_udp_client();

		// 管理vpn_connection_ptr相关操作.
		void add_connection(vpn_connection_ptr& connection_ptr, uint32_t vaddr);
		void remove_connection(uint32_t vaddr);
		vpn_connection_ptr lookup_connection(uint32_t vaddr);

		// 管理临时进来的连接相关.
		void add_incoming(vpn_connection_ptr& connection_ptr, int64_t id);
		void remove_incoming(int64_t id);

		// IP分配器, 用于server给连接上来的client分配虚拟IP.
		std::tuple<std::string, uint32_t> ip_assigner();
		// 压缩相关协议.
		int vpt_compress(int type, std::string& content);

		// 协议相关处理子函数.
		boost::asio::awaitable<void> do_server_vpt_auth(
			stream_endian::bitstream& reader, vpn_connection_ptr& connection_ptr);
		boost::asio::awaitable<void> do_client_vpt_auth(
			stream_endian::bitstream& reader, vpn_connection_ptr& connection_ptr);

		boost::asio::awaitable<vpn_connection_ptr> do_udp_keepalive(
			stream_endian::bitstream& reader, udp::socket& sock, const udp::endpoint& endp);

		boost::asio::awaitable<bool> do_vpt_compress(
			stream_endian::bitstream& reader, std::string& bufs);

		boost::asio::awaitable<void> do_vpt_packet(uint8_t type,
			stream_endian::bitstream& reader, const udp::endpoint* endp);

		boost::asio::awaitable<vpn_connection_ptr>
			do_vpt_fec_packet(stream_endian::bitstream& reader);

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
		io_context_pool& m_ioc_pool;

		// 通道参数配置, 包含fec参数.
		tunnel_params m_params;

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
		using udp_socket_ptr = std::unique_ptr<udp_socket>;
		std::vector<udp_socket_ptr> m_udp_sockets;

		// 运行的身份.
		Identity m_identity{ Identity::avpn_server };

		// 用于rs编码的矩阵.
		fec::matrix m_enc_matrix;
		fec::matrix m_dec_matrix;

		// mutex for m_remotes.
		std::shared_mutex m_remotes_mtx;

		// 作为server时, key是一个32bit的 ipv4 vnet 地址.
		std::unordered_map<uint32_t, vpn_connection_weak_ptr> m_remotes;

		// mutex for m_incomings.
		std::shared_mutex m_incomings_mtx;

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

		// 连接重试定时器.
		timer m_connect_retry_timer;

		// keepalive定时器.
		timer m_keepalive_timer;

		// 退出标志.
		bool m_abort{ false };
	};
}
