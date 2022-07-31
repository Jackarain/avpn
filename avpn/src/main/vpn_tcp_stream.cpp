//
// Copyright (C) 2022 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#include "avpn/vpn_tcp_stream.hpp"

namespace avpn {

	vpn_tcp_stream::vpn_tcp_stream(net::io_context& ioc)
		: m_io_context(ioc)
	{
	}

	vpn_tcp_stream::~vpn_tcp_stream()
	{
	}

	void vpn_tcp_stream::set_accept_handler(accept_handler h)
	{
		m_accept_handler = h;
	}

	void vpn_tcp_stream::set_closed_handler(closed_handler h)
	{
		m_closed_handler = h;
	}

	void vpn_tcp_stream::process_tcp_stack(const uint8_t* buf, int len)
	{
		auto self = shared_from_this();

		boost::ignore_unused(buf);
		boost::ignore_unused(len);

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

	}

}
