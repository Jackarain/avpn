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
		, m_serivce(vpn)
		, m_config(cfg)
		, m_identity(cfg.identity_)
		, m_pubkey(pubkey)
		, m_tcp_socket(ioc)
		, m_keyexchange(passphrase)
		, m_shared_key(m_keyexchange.GenerateSharedKey(m_pubkey))
		, m_tick_timer(ioc)
		, m_feg(cfg.tunnel_params_.data_shards_,
			cfg.tunnel_params_.parity_shards_)
	{
		m_crypto = std::make_unique<crypto_util::stream_crypto>(m_shared_key);
	}

	std::shared_ptr<vpn_tunnel>
	vpn_tunnel::make(net::io_context& ioc,
		std::shared_ptr<avpn_service>& vpn,
		const service_config& cfg,
		std::string pubkey, std::string passphrase)
	{
		return std::shared_ptr<vpn_tunnel>(new
			vpn_tunnel(ioc, vpn, cfg, pubkey, passphrase));
	}

	vpn_tunnel::~vpn_tunnel()
	{
		LOG_DBG << "vpn_tunnel::~vpn_tunnel, this: " << this;
	}

	void vpn_tunnel::start_tunnel(uint8_t ds, uint8_t ps)
	{
		if (m_abort || !m_abort)
			return;

		LOG_DBG << "start tunnel: " << this
			<< ", ds: " << ds
			<< ", ps : " << ps;

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
		LOG_INFO << "closing vpn_tunnel: " << this;

		m_abort = true;

		m_upload_stat = {};
		m_down_stat = {};

		boost::system::error_code ec;
		m_tick_timer.cancel(ec);

		if (m_tcp_socket.is_open())
			m_tcp_socket.close(ec);
	}

	int64_t vpn_tunnel::upload_rate() const
	{
		return m_upload_stat.rate_;
	}

	int64_t vpn_tunnel::download_rate() const
	{
		return m_down_stat.rate_;
	}

	net::awaitable<void> vpn_tunnel::tcp_loop()
	{
		LOG_DBG << "Enter tcp loop: " << this;

		while (!m_abort)
		{
			vpn_packet pkt;

			auto ret = co_await tcp_read_packet(m_tcp_socket, pkt);
			if (ret == -1)
				break;

			// 创建packet指针再通过tun_forward传入协程.
			auto ptr = std::make_shared<vpn_packet>(std::move(pkt));
			m_num_recv_packet++;
			if (!co_await process_tcp_packet(ptr))
			{
				LOG_ERR << "process_tcp_packet, break tcp loop.";
				break;
			}

			// 计算下载速率.
			compute_speed(m_down_stat, pkt.size());
		}

		std::string qmsg = "tcp_loop, tcp loop quit";
		scoped_exit se([&]() mutable {
			LOG_WARN << qmsg;
			});

		// 当运行身份为client时, 尝试重连服务器.
		if (!m_abort && m_identity == Identity::avpn_client)
		{
			auto service = m_serivce.lock();
			if (!service)
				co_return;

			// 重置tcp重连计数, 等待tcp重连.
			qmsg += " with reconnect";
			service->reset_tcp_cnt(1);
		}
		co_return;
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
		uint32_t src = 0;

		{
			// 更新pkt数据.
			src = endp.src_.address().to_v4().to_uint();
			m_feg.make_fec_header(*pkt, src);
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

		// 通过udp或tcp发送pkt.
		if (use_tcp_transfer)
			co_await tcp_write_packet(m_tcp_socket, pkt);
		else
			udp_write_pkt(pkt);

		// 计算上行速率.
		compute_speed(m_upload_stat, pkt->size());

		// TCP倍发模式, 无需要fec, 直接发送冗余.
		if (params.data_shards_ == 1)
		{
			if (pkt->type() != vpn_packet_t::pkt_tcp)
				co_return;

			params.parity_shards_ =
				std::min<int>(5, params.parity_shards_);

			for (int i = 0;
				i < params.parity_shards_ - 1;
				i++)
			{
				udp_write_pkt(pkt);

				// 计算上行速率.
				compute_speed(m_upload_stat, pkt->size());
			}

			co_return;
		}

		// fec编码, 如果成功编码, 则需要发送编码部分.
		bool ret = m_feg.encode(pkt, src);
		if (!ret)
			co_return;

		// 循环发送已编码部分.
		for (int i = m_feg.ds_; i < m_feg.shards_; i++)
		{
			pkt = m_feg.pkts_[i];

			if (use_tcp_transfer)
				co_await tcp_write_packet(m_tcp_socket, pkt);
			else
				udp_write_pkt(pkt);

			// 计算上行速率.
			compute_speed(m_upload_stat, pkt->size());
		}

		co_return;
	}

	net::awaitable<void>
	vpn_tunnel::udp_forward(vpn_packet_ptr pkt, udp::endpoint remote)
	{
		[[maybe_unused]] auto self = shared_from_this();

		if (m_identity == Identity::avpn_server)
		{
			if (m_remote_endpoint != remote)
				LOG_INFO << "Update: " << this
						<< " udp endpoint: " << remote;
			m_remote_endpoint = remote;
		}

		m_num_recv_packet++;
		compute_speed(m_down_stat, pkt->size());
		co_await process_udp_packet(pkt);
		co_return;
	}

	void vpn_tunnel::udp_write_pkt(vpn_packet_ptr& pkt)
	{
		auto service = m_serivce.lock();
		if (!service)
			return;

		m_num_send_packet++;

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

	crypto_util::stream_crypto& vpn_tunnel::crypto()
	{
		return *m_crypto;
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
		if (m_remote_endpoint != endp)
			LOG_INFO << "Update: " << this
				<< " remote endpoint: " << endp;
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
		LOG_DBG << "vpn_tunnel enter tick: " << this;
		int print_stat_interval = 0;

		while (!m_abort)
		{
			boost::system::error_code ec;

			m_tick_timer.expires_from_now(std::chrono::seconds(1));
			co_await m_tick_timer.async_wait(uawaitable[ec]);
			if (ec)
				break;

			auto now = std::chrono::steady_clock::now();

			// 计算上下行速率.
			compute_speed(m_down_stat, now);
			compute_speed(m_upload_stat, now);

			// 输出统计信息.
			if (++print_stat_interval >= 10)
			{
				print_stat_interval = 0;
				LOG_INFO << "Packet corrected: " << m_num_corrected
					<< ", incorrect: " << m_num_incorrect
					<< ", send: " << m_num_send_packet
					<< ", recv: " << m_num_recv_packet
					<< ", D: " << m_down_stat.rate_
					<< ", U: " << m_upload_stat.rate_;
			}

			if (m_identity == Identity::avpn_server)
				continue;
		}

		LOG_WARN << "vpn_tunnel::tick() quit...";
		co_return;
	}

	void vpn_tunnel::compute_speed(speed_stat& stat, int bytes)
	{
		// 统计上传数据量用于计算上传速率.
		stat.bytes_ += (int64_t)bytes;
		auto index = stat.speeder_count_ % speed_entries;
		stat.speeder_[index] = stat.bytes_;
	}

	void vpn_tunnel::compute_speed(speed_stat& stat, const time_point& now)
	{
		auto& speeder_time = stat.speeder_time_;

		int nowindex = stat.speeder_count_ % speed_entries;
		speeder_time[nowindex] = now;

		auto speeder_count = stat.speeder_count_ + 1;
		if (speeder_count > 0)
		{
			int checkindex = speeder_count >= speed_entries
				? speeder_count % speed_entries : 0;

			auto& speeder = stat.speeder_;

			auto deltams = now - speeder_time[checkindex];
			auto amount = speeder[nowindex] - speeder[checkindex];

			if (amount < 0)
				amount = 0;

			auto ms = std::chrono::duration_cast<
				std::chrono::milliseconds>(deltams);
			if (ms.count() <= 0)
				ms = std::chrono::milliseconds(1);

			stat.rate_ = int64_t((double)amount /
				((double)ms.count() / 1000.0f));
		}

		stat.speeder_count_ = speeder_count;
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
			if ((uint32_t)start_len_tag > (uint32_t)avpn_static_mtu)
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

		m_num_send_packet++;
		co_return;
	}

	void vpn_tunnel::tcp_write_pkt(vpn_packet_ptr& pkt)
	{
		auto self = shared_from_this();
		net::co_spawn(get_executor(),
			[this, self, pkt]() mutable -> net::awaitable<void>
			{
				co_await tcp_write_packet(m_tcp_socket, pkt);
				co_return;
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
		auto service = m_serivce.lock();
		if (!service)
			co_return;

		uint32_t src = 0;
		std::string_view data;

		uint32_t gid;
		uint8_t pid;

		int ret = unwrap_transfer(*pkt, src, gid, pid);
		if (ret < 0)
			co_return;

		BOOST_ASSERT(gid > 0);
		BOOST_ASSERT(pid < (m_data_shards + m_parity_shards));

		// 更新最后可见时间.
		if (m_identity == Identity::avpn_server)
			last_see(steady_clock::now());

		auto write_pkt = [this, service](vpn_packet_ptr pkt)
			mutable -> net::awaitable<void>
		{
			auto content = pkt->payload();
			auto ep = parser_endpoint(content, avpn_payload_size);
			if (ep.size_ <= 0 || ep.size_ > avpn_payload_size)
			{
				m_num_incorrect++;
				co_return;
			}
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
				if (dst_tunnel)
				{
					// 内网转发.
					co_await dst_tunnel->tun_forward(pkt, std::move(ep));
					co_return;
				}
			}

			// 转发到tun设备.
			service->do_tun_write(pkt);

			co_return;
		};

		// 如果是data shards, 则write到tun设备或转发.
		if (pid < m_data_shards)
			co_await write_pkt(pkt);

		// ds等于1时, 关闭fec. TODO: 倍发模式也通过recover判断是否
		// 已经接收到.
		if (m_data_shards == 1)
			co_return;

		co_await net::this_coro::executor;

		// 更新fec解码器, 并检查解码结果将结果write到tun设备或转发.
		m_recover.update(gid, pid,
			m_data_shards, m_parity_shards, pkt);

		// 获取fec解码结果并循环发送到tun设备.
		auto results = std::move(m_recover.results_);
		if (results.empty())
			co_return;

		// 更新统计信息.
		m_num_corrected += (int)results.size();

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
