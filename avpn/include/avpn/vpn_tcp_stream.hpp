//
// Copyright (C) 2022 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#include "avpn/avpn.hpp"

namespace avpn {

	using accept_handler =
		std::function<void(const boost::system::error_code&)>;

	using closed_handler =
		std::function<void(const boost::system::error_code&)>;

	class vpn_tcp_stream :
		public std::enable_shared_from_this<vpn_tcp_stream>
	{
		enum class tcp_state
		{
			ts_invalid = -1,
			ts_closed = 0,
			ts_listen = 1,
			ts_syn_sent = 2,
			ts_syn_rcvd = 3,
			ts_established = 4,
			ts_fin_wait_1 = 5,
			ts_fin_wait_2 = 6,
			ts_close_wait = 7,
			ts_closing = 8,
			ts_last_ack = 9,
			ts_time_wait = 10
		};

		union tcp_flags
		{
			struct unamed_struct
			{
				bool fin : 1;
				bool syn : 1;
				bool rst : 1;
				bool psh : 1;
				bool ack : 1;
				bool urg : 1;
				bool ece : 1;
				bool cwr : 1;
			} flag;
			uint8_t data;
		};

		struct tsm	// tcp state machine
		{
			tsm()
				: state_(tcp_state::ts_invalid)
				, seq_(0)
				, ack_(0)
				, win_(0)
				, lseq_(0)
				, lack_(0)
				, lwin_(0)
			{}

			tcp_state state_;
			uint32_t seq_;
			uint32_t ack_; // 对端发过来的ack, 用来确认是否丢包, 这里不存在丢包所以不用处理.
			uint32_t win_;

			uint32_t lseq_;	// 随本端数据发送而增大.
			uint32_t lack_;	// 最后回复的ack, 是seq+收到的数据的大小.
			uint32_t lwin_;
		};

		// c++11 noncopyable.
		vpn_tcp_stream(const vpn_tcp_stream&) = delete;
		vpn_tcp_stream& operator=(const vpn_tcp_stream&) = delete;

	public:
		vpn_tcp_stream(net::io_context& ioc,
			std::weak_ptr<avpn_service> service);
		~vpn_tcp_stream();

		// 状态机状态输出为字符串.
		std::string tcp_state_string(tcp_state s) const;

		// 设置tcp accept回调.
		void set_accept_handler(accept_handler h);

		// 设置tcp连接断开回调.
		void set_closed_handler(closed_handler h);

		// 关闭tcp连接.
		void do_close();

		// 强制reset连接.
		void reset();

		// 处理tcp协议.
		void process_tcp_stack(
			vpn_packet pkt, endpoint_pair endp);

		// 处理tcp协程.
		net::awaitable<void> tcp_stack(
			vpn_packet pkt, endpoint_pair endp);

	private:
		// 用于当前vpn_conntrack业务调度.
		net::io_context& m_io_context;

		//  service 对象引用.
		std::weak_ptr<avpn_service> m_serivce;

		// 发起tcp连接接受状态.
		accept_handler m_accept_handler;

		// 关闭tcp连接状态.
		closed_handler m_closed_handler;

		// 连接接受状态.
		bool m_accepted{ false };

		// 关闭连接状态.
		bool m_closed{ false };

		// 当前tcp连接状态.
		tsm m_tsm;

		// tcp转发连接.
		tcp::socket m_socket;

		// 中止tcp状态机.
		bool m_abort{ false };
	};
}
