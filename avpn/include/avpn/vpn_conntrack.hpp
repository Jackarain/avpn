//
// Copyright (C) 2022 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#include "avpn/avpn.hpp"
#include "avpn/vpn_tcp_stream.hpp"


namespace avpn {

	using tcp_stream_ptr = std::shared_ptr<vpn_tcp_stream>;

	class vpn_conntrack
	{
		// c++11 noncopyable.
		vpn_conntrack(const vpn_conntrack&) = delete;
		vpn_conntrack& operator=(const vpn_conntrack&) = delete;
	public:
		vpn_conntrack(net::io_context& ioc,
			std::weak_ptr<avpn_service> service);
		~vpn_conntrack();

		// 转发ip包到对应的tcp状态机.
		void forward_ip(vpn_packet pkt, endpoint_pair endp);

	private:
		// 预创建tcp stream.
		tcp_stream_ptr make_tcp_stream();

		// 根据endpoint_pair查找stream对象.
		tcp_stream_ptr lookup_stream(const endpoint_pair& endp);

		// 发起tcp连接请求时, 实际向外发起连接.
		void handle_accept(tcp_stream_ptr stream,
			const boost::system::error_code& ec);

		// tcp连接关闭时, 响应关闭连接.
		void handle_closed(tcp_stream_ptr stream,
			const boost::system::error_code& ec);

	private:
		// 用于当前vpn_conntrack业务调度.
		net::io_context& m_io_context;

		// service 对象引用.
		std::weak_ptr<avpn_service> m_serivce;

		// tcp conntrack.
		std::unordered_map<endpoint_pair, tcp_stream_ptr> m_conntrack;
	};

}
