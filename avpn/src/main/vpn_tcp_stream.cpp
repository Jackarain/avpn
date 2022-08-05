//
// Copyright (C) 2022 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#include "avpn/vpn_tcp_stream.hpp"
#include "utils/uawaitable.hpp"

namespace avpn {

	vpn_tcp_stream::vpn_tcp_stream(net::io_context& ioc,
		std::weak_ptr<avpn_service> service)
		: m_io_context(ioc)
		, m_serivce(service)
		, m_socket(m_io_context)
	{
	}

	vpn_tcp_stream::~vpn_tcp_stream()
	{
	}

	std::string vpn_tcp_stream::tcp_state_string(tcp_state s) const
	{
		switch (s)
		{
		case tcp_state::ts_invalid: return "ts_invalid";
		case tcp_state::ts_closed: return "ts_closed";
		case tcp_state::ts_listen: return "ts_listen";
		case tcp_state::ts_syn_sent: return "ts_syn_sent";
		case tcp_state::ts_syn_rcvd: return "ts_syn_rcvd";
		case tcp_state::ts_established: return "ts_established";
		case tcp_state::ts_fin_wait_1: return "ts_fin_wait_1";
		case tcp_state::ts_fin_wait_2: return "ts_fin_wait_2";
		case tcp_state::ts_close_wait: return "ts_close_wait";
		case tcp_state::ts_closing: return "ts_closing";
		case tcp_state::ts_last_ack: return "ts_last_ack";
		case tcp_state::ts_time_wait: return "ts_time_wait";
		}
		return "error tcp state";
	}

	void vpn_tcp_stream::set_accept_handler(accept_handler h)
	{
		m_accept_handler = h;
	}

	void vpn_tcp_stream::set_closed_handler(closed_handler h)
	{
		m_closed_handler = h;
	}

	void vpn_tcp_stream::do_close()
	{
		if (m_closed)
			return;

		m_closed = true;
		m_closed_handler({});
	}

	void vpn_tcp_stream::reset()
	{
		// TODO: send reset tcp packet.
		do_close();
	}

	void vpn_tcp_stream::process_tcp_stack(
		vpn_packet pkt, endpoint_pair endp)
	{
		net::co_spawn(m_io_context,
			tcp_stack(std::move(pkt), std::move(endp)), net::detached);
	}

	net::awaitable<void> vpn_tcp_stream::tcp_stack(
		vpn_packet pkt, endpoint_pair endp)
	{
		auto self = shared_from_this();
		auto buf = pkt.payload();

		const uint8_t* p = buf;
		auto last_state = m_tsm.state_;

		uint8_t ihl = ((*(uint8_t*)(p)) & 0x0f) * 4;
		uint16_t total = ntohs(*(uint16_t*)(p + 2));
		uint8_t type = *(uint8_t*)(p + 9);

		if (type != ip_tcp) // only tcp
			co_return;

		p = p + ihl;

		// 下面开始执行tcp状态机, 总体参考下面实现, 稍作修改的地方几个就是这里初始状态设置
		// 为ts_invalid, 而不是closed, 因为这里我需要判断一个tcp stream对象是已经closed
		// 的, 还是新开的等待连接的对象, 另外执行到time_wait时, 按标准需要等待2MSL个时间
		// 再关闭, 在这个时间一直占用, 因为avpn里当一个连接到time_wait状态的时候, 对外实际
		// 是一个连接, 这个连接关闭了并不影响下一次, client使用相同ip:port来向相同server:
		// port发起请求.
		//
		//
		//                              +---------+ ---------\      active OPEN
		//                              |  CLOSED |            \    -----------
		//                              +---------+<---------\   \   create TCB
		//                                |     ^              \   \  snd SYN
		//                   passive OPEN |     |   CLOSE        \   \
		//                   ------------ |     | ----------       \   \
		//                    create TCB  |     | delete TCB         \   \
		//                                V     |                      \   \
		//                              +---------+            CLOSE    |    \
		//                              |  LISTEN |          ---------- |     |
		//                              +---------+          delete TCB |     |
		//                   rcv SYN      |     |     SEND              |     |
		//                  -----------   |     |    -------            |     V
		// +---------+      snd SYN,ACK  /       \   snd SYN          +---------+
		// |         |<-----------------           ------------------>|         |
		// |   SYN   |                    rcv SYN                     |   SYN   |
		// |   RCVD  |<-----------------------------------------------|   SENT  |
		// |         |                    snd ACK                     |         |
		// |         |------------------           -------------------|         |
		// +---------+   rcv ACK of SYN  \       /  rcv SYN,ACK       +---------+
		//   |           --------------   |     |   -----------
		//   |                  x         |     |     snd ACK
		//   |                            V     V
		//   |  CLOSE                   +---------+
		//   | -------                  |  ESTAB  |
		//   | snd FIN                  +---------+
		//   |                   CLOSE    |     |    rcv FIN
		//   V                  -------   |     |    -------
		// +---------+          snd FIN  /       \   snd ACK          +---------+
		// |  FIN    |<-----------------           ------------------>|  CLOSE  |
		// | WAIT-1  |------------------                              |   WAIT  |
		// +---------+          rcv FIN  \                            +---------+
		//   | rcv ACK of FIN   -------   |                            CLOSE  |
		//   | --------------   snd ACK   |                           ------- |
		//   V        x                   V                           snd FIN V
		// +---------+                  +---------+                   +---------+
		// |FINWAIT-2|                  | CLOSING |                   | LAST-ACK|
		// +---------+                  +---------+                   +---------+
		//   |                rcv ACK of FIN |                 rcv ACK of FIN |
		//   |  rcv FIN       -------------- |    Timeout=2MSL -------------- |
		//   |  -------              x       V    ------------        x       V
		//    \ snd ACK                 +---------+delete TCB         +---------+
		//     ------------------------>|TIME WAIT|------------------>| CLOSED  |
		//                              +---------+                   +---------+


		uint32_t seq = ntohl(*(uint32_t*)(p + 4));
		m_tsm.ack_ = ntohl(*(uint32_t*)(p + 8));
		uint32_t offset = (((*(p + 12)) >> 4) & 0x0f) * 4;
		tcp_flags flags;
		flags.data = *(p + 13);
		uint16_t ws = ntohs(*(uint16_t*)(p + 14));
		// 不检查chksum, 本机检查chksum意义不大.
		// uint32_t chksum = ntohl(*(uint32_t*)(p + 16));
		auto payload_len = total - (20 + offset);

		if (flags.flag.syn && m_tsm.state_ != tcp_state::ts_invalid)
		{
			LOG_WARN << "tcp stack: " << endp << " unexpected syn, skip it!";
			co_return;
		}

		m_tsm.win_ = ws;

		// 收到rst强制中断.
		if (flags.flag.rst)
		{
			if (m_tsm.state_ == tcp_state::ts_invalid && m_closed_handler)
			{
				m_closed_handler(boost::asio::error::network_reset);
				m_closed_handler = {};
			}

			m_tsm.state_ = tcp_state::ts_closed;
			LOG_DBG << "tcp stack: " << endp
				<< " " << tcp_state_string(last_state)
				<< " -> flags.flag.rst";

			do_close();
			co_return;
		}

		bool keep_alive = false;
		// tcp keep alive, only ack.
		if (m_tsm.state_ == tcp_state::ts_established && seq == m_tsm.seq_ - 1)
		{
			LOG_DBG << "tcp stack: " << endp
				<< " " << tcp_state_string(last_state)
				<< " tcp keep alive, skip it";
			keep_alive = true;
			co_return;
		}

		// 记录当前seq.
		m_tsm.seq_ = seq;

		switch (m_tsm.state_)
		{
		case tcp_state::ts_listen:
		case tcp_state::ts_time_wait:
		case tcp_state::ts_closed:
		{
			// 连接关闭了还发数据过来, rst响应之.
			LOG_DBG << "tcp stack: " << endp
				<< " " << tcp_state_string(last_state)
				<< " -> "
				<< tcp_state_string(m_tsm.state_)
				<< " case ts_listen/ts_time_wait/ts_closed";
			reset();
			co_return;
		}
		break;
		case tcp_state::ts_invalid:	// 初始状态, 如果不是syn, 则是个错误的数据包, 这里跳过.
		{
			if (!flags.flag.syn)
			{
				if (m_closed_handler)
				{
					m_closed_handler(boost::asio::error::network_reset);
					m_closed_handler = {};
				}
				reset();
				co_return;
			}

			m_tsm.state_ = tcp_state::ts_syn_rcvd;	// 更新状态为syn接收到的状态.
			LOG_DBG << "tcp stack: " << endp
				<< " " << tcp_state_string(last_state)
				<< " -> tcp_state::ts_syn_rcvd";

			// 通知用户层接收到连接.
			if (m_accept_handler)
			{
				m_accept_handler({});
				m_accept_handler = {};
			}
			co_return;	// 直接返回, 由用户层确认是否接受连接回复syn ack.
		}
		break;
		case tcp_state::ts_syn_rcvd:
		{
			if (!flags.flag.syn)
			{
				reset();
				co_return;
			}

			m_tsm.state_ = tcp_state::ts_syn_rcvd;	// 更新状态为syn接收到的状态.
			LOG_DBG << "tcp stack: " << endp
				<< " " << tcp_state_string(last_state)
				<< " -> retransmission tcp_state::ts_syn_rcvd";
			co_return;
		}
		break;
		case tcp_state::ts_syn_sent: // 这个状态只表示被动回复syn, 而不是主动syn请求.
		{
			// 期望客户端回复ack完成握手, 因为前面已经发了syn ack,
			// 这里收到的不是ack的话, 肯定是出错了, 这里先暂时跳过.
			if (!flags.flag.ack)
			{
				reset();
				co_return;
			}
			else
			{
				m_tsm.state_ = tcp_state::ts_established;	// 连接建立.
				LOG_DBG << "tcp stack: " << endp
					<< " " << tcp_state_string(last_state)
					<< " -> tcp_state::ts_established";
			}
		}
		[[fallthrough]];
		case tcp_state::ts_established:
		{
			// 收到客户端fin, 被动关闭, 发送ack置状态为close_wait, 等待last ack.
			if (flags.flag.fin)
			{
				m_tsm.state_ = tcp_state::ts_close_wait;
				LOG_DBG << "tcp stack: " << endp
					<< " " << tcp_state_string(last_state)
					<< " -> tcp_state::ts_close_wait";
			}

			// 连接状态中, 只是一个ack包而已, 不用对ack包再ack.
			if (payload_len == 0 && !flags.flag.fin)
				co_return;
		}
		break;
		case tcp_state::ts_fin_wait_1:		// 表示主动关闭.
		{
			bool need_ack = false;

			// 同时发出fin, 转为状态ts_time_wait, 回复ack, 关闭这个连接.
			if (flags.flag.fin && flags.flag.ack)
			{
				LOG_DBG << "tcp stack: " << endp
					<< " " << tcp_state_string(last_state)
					<< " -> tcp_state::ts_closed";

				m_tsm.state_ = tcp_state::ts_closed;
				do_close();
				need_ack = true;
			}

			// 主动与本地客户端断开, 表示已经向本地客户端发出了fin, 还未收到这个fin的ack.
			if (!flags.flag.ack)
			{
				if (flags.flag.fin)	// 收到fin, 回复ack.
				{
					LOG_DBG << "tcp stack: " << endp
						<< " " << tcp_state_string(last_state)
						<< " -> tcp_state::ts_closing";

					m_tsm.state_ = tcp_state::ts_closing;
					do_close();
					need_ack = true;
				}
				else
				{
					reset();
					co_return;
				}
			}

			if (!need_ack)
			{
				// 只是收到ack, 转为fin_wait_2, 等待本地客户端的fin.
				LOG_DBG << "tcp stack: " << endp
					<< " " << tcp_state_string(last_state)
					<< " -> tcp_state::ts_fin_wait_2";

				m_tsm.state_ = tcp_state::ts_fin_wait_2;
				co_return;
			}
		}
		break;
		case tcp_state::ts_fin_wait_2:
		{
			if (!flags.flag.fin)	// 只期望收到fin, 除非有数据, 否则都跳过.
			{
				if (payload_len <= 0)
					co_return;
			}

			// 收到fin, 发回ack, 并关闭这个连接, 进入2MSL状态.
			if (flags.flag.fin)
			{
				LOG_DBG << "tcp stack: " << endp
					<< " " << tcp_state_string(last_state)
					<< " -> tcp_state::ts_closed";

				m_tsm.state_ = tcp_state::ts_closed;
				do_close();
			}
		}
		break;
		case tcp_state::ts_close_wait:
		{
			// 对方主动关闭.
			// 等待自己发出fin给本地, 这时收到的ack, 只是最后部分半开状态的向
			// 本地发出数据, 本地回复的ack而已, 所以在这里, 只需要简单的跳过.
			if (flags.flag.ack)
				co_return;

			// 统统跳过, 在自己发没出fin之前, 所有除对数据的ack之外, 全是错误的
			// 数据, 这里可以直接rst掉这个连接.
			reset();
			co_return;
		}
		break;
		case tcp_state::ts_last_ack:
		case tcp_state::ts_closing:
		{
			if (!flags.flag.ack)
			{
				co_return;
			}

			// 如果是close_wait, 则表示收到是last ack, 关闭这个连接.
			// 如果是closing, 则表示收到的是fin的ack, 进入2MSL状态.
			LOG_DBG << "tcp stack: " << endp
				<< " " << tcp_state_string(last_state)
				<< " -> tcp_state::ts_closed";

			m_tsm.state_ = tcp_state::ts_closed;
			do_close();
			co_return;
		}
		break;
		}

		// 发送tcp payload部分通过socks连接.
		// 发送完成后, 回复ack给本地连接.
		// auto payload = buf + 20 + offset;
		// payload_len;

		co_return;
#if 0
		// save tcp payload.
		if (payload_len > 0 && !keep_alive)
		{
			auto payload = buf + 20 + offset;
			auto target = boost::asio::buffer_cast<void*>(
				m_tcp_recv_buffer.prepare(payload_len));
			std::memcpy(target, payload, payload_len);
			m_tcp_recv_buffer.commit(payload_len);
		}

		int ack = m_tsm.seq_ + payload_len;
		if (payload_len == 0)
			ack += 1;

		// 回写ack.
		ip_buffer buffer(40, m_endp_reserve);
		auto ip = buffer.data();
		auto tcp = ip + 20;

		flags.data = 0;
		flags.flag.ack = 1;

		m_tsm.lack_ = ack;

		make_tcp_header(tcp, 20, buffer.endp_, m_tsm.lseq_, m_tsm.lack_, flags.data);

		// 回调写回ack数据.
		m_write_ip_handler(buffer);
#endif
	}

	net::awaitable<int>
	vpn_tcp_stream::tcp_read_packet(
		tcp::socket& stream, vpn_packet& pkt, size_t id)
	{
		boost::system::error_code ec;
		int start_len_tag = -1;

		// 先读取4个字节的头.
		co_await net::async_read(stream,
			net::buffer((void*)&start_len_tag, 4),
			net::transfer_exactly(4), uawaitable[ec]);
		if (ec)
		{
			LOG_ERR << "tcp_read_packet, id: "
				<< id << ", stream read tag error: " << ec.message();
			co_return -1;
		}

		{
			start_len_tag = ntohl(start_len_tag);
			if ((uint32_t)start_len_tag > (uint32_t)avpn_static_mtu)
			{
				LOG_ERR << "tcp_read_packet, id: "
					<< id << ", stream verify size fail: " << start_len_tag;
				co_return -1;
			}
		}

		// 读取body本身.
		co_await net::async_read(stream,
			net::buffer(pkt.data(), start_len_tag),
			net::transfer_exactly(start_len_tag), uawaitable[ec]);
		if (ec)
		{
			LOG_ERR << "tcp_read_packet, id: "
				<< id << ", stream read body error: " << ec.message();
			co_return -1;
		}

		pkt.resize(start_len_tag);

		co_return start_len_tag;
	}

	net::awaitable<void>
	vpn_tcp_stream::tcp_write_packet(tcp::socket& stream,
		vpn_packet& pkt, size_t id)
	{
		boost::system::error_code ec;
		uint32_t start_len_tag = htonl((uint32_t)pkt.size());

		co_await net::async_write(stream,
			net::buffer(&start_len_tag, 4), uawaitable[ec]);
		if (ec)
		{
			LOG_ERR << "tcp_write_packet, id: " << id
				<< " stream async_write tag error: " << ec.message();
			co_return;
		}

		co_await net::async_write(stream,
			net::buffer(pkt.data(), pkt.size()), uawaitable[ec]);
		if (ec)
		{
			LOG_ERR << "tcp_write_packet, id: " << id
				<< " stream async_write body error: " << ec.message();
			co_return;
		}

		co_return;
	}

}
