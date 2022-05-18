//
// Copyright (C) 2019 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#include "avpn/vpn_tunnel.hpp"
#include "avpn/avpn.hpp"
#include "avpn/protocol.hpp"

#include "utils/scoped_exit.hpp"

namespace avpn {

	vpn_tunnel::vpn_tunnel(net::io_context& ioc,
		std::shared_ptr<avpn_service>& vpn,
		const service_config& cfg,
		std::string pubkey, std::string passphrase)
		: m_io_context(ioc)
		, m_vpn_serivce(vpn)
		, m_config(cfg)
		, m_identity(cfg.identity_)
		, m_pubkey(pubkey)
		, m_tcp_socket(ioc)
		, m_keyexchange(passphrase)
		, m_shared_key(m_keyexchange.GenerateSharedKey(pubkey))
		, m_tick_timer(ioc)
		, m_feg(cfg.tunnel_params_.data_shards_,
			cfg.tunnel_params_.parity_shards_)
	{}

	std::shared_ptr<vpn_tunnel>
	vpn_tunnel::make(net::io_context& ioc,
		std::shared_ptr<avpn_service>& vpn,
		const service_config& cfg,
		std::string pubkey, std::string passphrase)
	{
		return std::shared_ptr<vpn_tunnel>(new
			vpn_tunnel(ioc, vpn, cfg, pubkey, passphrase));
	}

	void vpn_tunnel::start_tunnel(uint8_t ds, uint8_t ps)
	{
		if (m_abort != boost::indeterminate)
			return;

		m_data_shards = ds;
		m_parity_shards = ps;

		m_abort = false;

		// 启动tick协程.
		auto self = shared_from_this();
		net::co_spawn(m_io_context,
			[this, self]() mutable -> net::awaitable<void>
			{
				co_await tick();
			}, net::detached);
	}

	void vpn_tunnel::close_tunnel()
	{
		m_abort = true;

		boost::system::error_code ec;
		m_tick_timer.cancel(ec);
	}

	void vpn_tunnel::start_tcp_loop()
	{
		auto self = shared_from_this();
		net::co_spawn(m_io_context,
			[this, self]() mutable -> net::awaitable<void>
			{
				co_await tcp_loop();
			}, net::detached);
	}

	tcp::socket& vpn_tunnel::tcp_socket()
	{
		return m_tcp_socket;
	}

	void vpn_tunnel::tcp_socket(tcp::socket&& s, size_t id)
	{
		boost::system::error_code ec;
		m_tcp_socket.close(ec);

		m_tcp_socket = std::move(s);
		m_tcp_socket_id = id;
	}

	net::awaitable<void>
	vpn_tunnel::tun_forward(vpn_packet_ptr pkt, endpoint_pair endp)
	{
		[[maybe_unused]] auto self = shared_from_this();

		auto& params = m_config.tunnel_params_;

		{
			// 更新pkt数据.
			uint32_t src = endp.src_.address().to_v4().to_uint();
			m_feg.update(*pkt, src);
		}

		// 默认使用udp发送.
		bool use_tcp_transfer = false;

		// 只有以下情况, 将使用tcp发送.
		// 1. tcp only 状态时.
		// 2. 作为server时, 远端udp不可用时.
		// 3. TODO: 混合模式, tcp发送为闲时, 使用tcp发送.
		if (params.mode_ == 2 ||
			(m_remote_endpoint.port() == 0 &&
				m_identity == Identity::avpn_server))
		{
			// 使用tcp发送至客户端.
			use_tcp_transfer = true;
		}

		if (use_tcp_transfer)
			co_await tcp_write_packet(m_tcp_socket, pkt);
		else
			udp_write_packet(pkt);

		// 保存到fec编码器, 如果已经编码, 则需要发送编码部分.
		bool ret = m_feg.save(pkt);
		if (!ret)
			co_return;

		// 循环发送已编码部分.
		for (int i = m_data_shards;
			i < m_data_shards + m_parity_shards; i++)
		{
			pkt = m_feg.pkts_[i];

			if (use_tcp_transfer)
				co_await tcp_write_packet(m_tcp_socket, pkt);
			else
				udp_write_packet(pkt);
		}

		co_return;
	}

	net::awaitable<void>
	vpn_tunnel::udp_forward(vpn_packet_ptr pkt, udp::endpoint remote)
	{
		[[maybe_unused]] auto self = shared_from_this();

		co_await process_udp_packet(pkt);
		co_return;
	}

	void vpn_tunnel::udp_write_packet(vpn_packet_ptr& pkt)
	{
		auto service = m_vpn_serivce.lock();
		if (!service)
			return;

		service->do_udp_write(pkt, m_remote_endpoint);
	}

	std::string vpn_tunnel::client_id() const
	{
		return m_client_id;
	}

	void vpn_tunnel::client_id(const std::string& id)
	{
		m_client_id = id;
	}

	std::string vpn_tunnel::shared_key() const
	{
		return m_shared_key;
	}

	net::ip::network_v4 vpn_tunnel::vnet_addr() const
	{
		return m_vaddr;
	}

	void vpn_tunnel::vnet_addr(const net::ip::network_v4& vaddr)
	{
		m_vaddr = vaddr;
	}

	udp::endpoint vpn_tunnel::remote_endpoint() const
	{
		return m_remote_endpoint;
	}

	void vpn_tunnel::remote_endpoint(const udp::endpoint& endp)
	{
		m_remote_endpoint = endp;
	}

	time_point vpn_tunnel::last_see() const
	{
		return m_last_see;
	}

	void vpn_tunnel::last_see(const time_point& now)
	{
		m_last_see = now;
	}

	net::any_io_executor vpn_tunnel::get_executor()
	{
		return m_io_context.get_executor();
	}

	net::awaitable<void> vpn_tunnel::tick()
	{
		boost::system::error_code ec;

		while (!m_abort)
		{
			m_tick_timer.expires_from_now(std::chrono::seconds(1));
			co_await m_tick_timer.async_wait(uawaitable[ec]);

			if (m_identity == Identity::avpn_server)
				continue;
		}

		co_return;
	}

	net::awaitable<void> vpn_tunnel::tcp_loop()
	{
		while (!m_abort)
		{
			vpn_packet pkt;

			auto ret = co_await tcp_read_packet(m_tcp_socket, pkt);
			if (ret == -1)
				break;

			// 创建packet指针再通过tun_forward传入协程.
			auto ptr = std::make_shared<vpn_packet>(std::move(pkt));

			if (!co_await process_tcp_packet(ptr))
			{
				LOG_ERR << "process_tcp_packet, break tcp loop.";
				break;
			}
		}

		LOG_WARN << "tcp_loop, tcp loop quit...";
		co_return;
	}

	net::awaitable<int> vpn_tunnel::tcp_read_packet(
		tcp::socket& stream, vpn_packet& pkt)
	{
		boost::system::error_code ec;
		int start_len_tag = -1;

		// 先读取4个字节的头.
		co_await net::async_read(stream,
			net::buffer((void*)&start_len_tag, 4),
			net::transfer_exactly(4), uawaitable[ec]);
		if (ec)
		{
			LOG_ERR << "tcp_read_packet"
				<< ", id: " << m_tcp_socket_id
				<< ", read tag error: " << ec.message();
			co_return -1;
		}

		{
			start_len_tag = ntohl(start_len_tag);
			if ((uint32_t)start_len_tag > (uint32_t)static_mtu)
			{
				LOG_ERR << "tcp_read_packet"
					<< ", id: " << m_tcp_socket_id
					<< ", verify size fail: " << start_len_tag;
				co_return -1;
			}
		}

		// 读取body本身.
		co_await net::async_read(stream,
			net::buffer(pkt.data(), start_len_tag),
			net::transfer_exactly(start_len_tag), uawaitable[ec]);
		if (ec)
		{
			LOG_ERR << "tcp_read_packet"
				<< ", id: " << m_tcp_socket_id
				<< ", read body error: " << ec.message();
			co_return -1;
		}

		pkt.resize(start_len_tag);

		co_return start_len_tag;
	}

	net::awaitable<void> vpn_tunnel::tcp_write_packet(
		tcp::socket& stream, vpn_packet_ptr& pkt)
	{
		boost::system::error_code ec;
		uint32_t start_len_tag = htonl((uint32_t)pkt->size());

		co_await net::async_write(stream,
			net::buffer(&start_len_tag, 4), uawaitable[ec]);
		if (ec)
		{
			LOG_ERR << "tcp_write_packet"
				<< ", id: " << m_tcp_socket_id
				<< ", async_write tag error: " << ec.message();
			co_return;
		}

		co_await net::async_write(stream,
			net::buffer(pkt->data(), pkt->size()), uawaitable[ec]);
		if (ec)
		{
			LOG_ERR << "tcp_write_packet"
				<< ", id: " << m_tcp_socket_id
				<< ", async_write body error: " << ec.message();
			co_return;
		}

		co_return;
	}

	void vpn_tunnel::tcp_write_packet(vpn_packet_ptr& pkt)
	{
		[[maybe_unused]] auto self = shared_from_this();

		net::co_spawn(get_executor(),
			[this, self, pkt]() mutable -> net::awaitable<void>
			{
				co_await tcp_write_packet(m_tcp_socket, pkt);
			}, net::detached);
	}

	net::awaitable<bool> vpn_tunnel::process_tcp_packet(vpn_packet_ptr pkt)
	{
		bool enc = false;
		uint8_t type = 0;
		uint32_t src;

		int ret = unwrap_common_header(*pkt, enc, type, src);
		if (ret == -1)
			co_return false;

		switch (type)
		{
		case vpt_handshake:
			break;
		case vpt_handshake_reply:
			break;

		case vpt_keepalive:
			co_await on_vpn_keepalive();
			break;
		case vpt_keepalive_reply:
			break;

		case vpt_transfer:
			co_await on_vpn_transfer(std::move(pkt));
			break;
		case vpt_transfer_compress:
			co_await on_vpn_transfer_compress(std::move(pkt));
			break;
		}

		co_return true;
	}

	net::awaitable<void> vpn_tunnel::process_udp_packet(vpn_packet_ptr pkt)
	{
		bool enc = false;
		uint8_t type = 0;
		uint32_t src;

		int ret = unwrap_common_header(*pkt, enc, type, src);
		if (ret == -1)
			co_return;

		switch (type)
		{
		case vpt_handshake:
			break;
		case vpt_handshake_reply:
			break;

		case vpt_keepalive:
			co_await on_vpn_keepalive();
			break;
		case vpt_keepalive_reply:
			break;

		case vpt_transfer:
			co_await on_vpn_transfer(std::move(pkt));
			break;
		case vpt_transfer_compress:
			co_await on_vpn_transfer_compress(std::move(pkt));
			break;
		}

		co_return;
	}

	net::awaitable<void> vpn_tunnel::on_vpn_keepalive()
	{
		last_see(steady_clock::now());
		co_return;
	}

	net::awaitable<void>
	vpn_tunnel::on_vpn_transfer(vpn_packet_ptr pkt)
	{
		auto service = m_vpn_serivce.lock();
		if (!service)
			co_return;

		uint32_t src = 0;
		std::string_view data;

		uint32_t gid;
		uint8_t pid;

		int ret = unwrap_transfer(*pkt, src, gid, pid);
		if (ret < 0)
			co_return;

		auto write_pkt = [this, service](vpn_packet_ptr& pkt)
			mutable -> net::awaitable<void>
		{
			auto content = pkt->payload();
			auto content_size = pkt->payload_size();

			auto ep = parser_endpoint(content, content_size);
			auto& dst_addr = ep.dst_;

			auto uint_dst = dst_addr.address().to_v4().to_uint();
			udp::endpoint uendp(dst_addr.address(), 0);

			if (m_identity == Identity::avpn_server
				&& same_ipv4_network(m_vaddr, uint_dst))
			{
				// 不允许内网互通.
				if (!m_config.tunnel_params_.c2c_)
					co_return;

				// 通过avpn service查找对应的tunnel
				// 然后转发内网数据到这个tunnel.
				auto dst_tunnel = service->lookup_tunnel(uint_dst);
				if (!dst_tunnel)
					co_return;

				co_await dst_tunnel->tun_forward(pkt, std::move(ep));
				co_return;
			}

			// 转发到tun设备.
			service->do_tun_write(pkt);

			co_return;
		};

		// 如果是data shards, 则write到tun设备或转发.
		if (pid < m_data_shards)
			co_await write_pkt(pkt);

		// 更新feg解码器, 并检查解码结果将结果write到tun设备或转发.
		m_recover.update(gid, pid,
			m_data_shards, m_parity_shards, pkt);

		auto results = std::move(m_recover.results_);
		if (results.empty())
			co_return;

		for (auto& p : results)
		{
			if (!p)
				continue;
			co_await write_pkt(p);
		}

		co_return;
	}

	net::awaitable<void>
	vpn_tunnel::on_vpn_transfer_compress(vpn_packet_ptr pkt)
	{
		uint32_t src = 0;

		uint32_t gid;
		uint8_t pid;
		uint8_t ctype;

		int ret = unwrap_transfer_compress(*pkt, src, gid, pid, ctype);
		if (ret < 0)
			co_return;

		// TODO: 处理压缩数据包.

		co_return;
	}

}
