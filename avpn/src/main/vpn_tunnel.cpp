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

	template<typename Handler>
	struct write_packet_op
	{
		write_packet_op(tcp::socket& s,
			vpn_packet_ptr pkt,
			Handler&& h)
			: stream_(s)
			, pkt_(pkt)
			, handler_(static_cast<Handler&&>(h))
		{
		}

		write_packet_op(write_packet_op&& other) noexcept
			: stream_(other.stream_)
			, pkt_(std::move(other.pkt_))
			, start_(other.start_)
			, start_len_tag_(std::move(other.start_len_tag_))
			, handler_(std::move(other.handler_))
		{}

		void operator()(boost::system::error_code error,
			std::size_t)
		{
			switch (start_)
			{
			case 0:
			{
				*start_len_tag_ =
					htonl((uint32_t)pkt_->size());

				start_ = 1;
				net::async_write(stream_,
					net::buffer(start_len_tag_.get(), 4),
						static_cast<write_packet_op&&>(*this));
			}
			return;
			case 1:
			{
				if (error)
					break;

				start_ = 2;
				net::async_write(stream_,
					net::buffer(pkt_->data(), pkt_->size()),
						static_cast<write_packet_op&&>(*this));
			}
			return;
			default:
				break;
			}

			handler_(static_cast<const boost::system::error_code&>(error));
		}

		tcp::socket& stream_;
		vpn_packet_ptr pkt_;
		int start_{ 0 };
		std::unique_ptr<uint32_t> start_len_tag_{
			std::make_unique<uint32_t>(0) };
		Handler handler_;
	};


	//////////////////////////////////////////////////////////////////////////

	struct write_packet_qe
	{
		write_packet_qe(
			tcp::socket& stream,
			std::deque<vpn_packet>& qe,
			boost::tribool& abort,
			int& num_send_packet,
			std::shared_ptr<vpn_tunnel>& self)
			: stream_(stream)
			, pkt_qe_(qe)
			, abort_(abort)
			, num_send_packet_(num_send_packet)
			, self_(self)
		{}

		write_packet_qe(write_packet_qe&& other) noexcept
			: stream_(other.stream_)
			, pkt_qe_(other.pkt_qe_)
			, abort_(other.abort_)
			, num_send_packet_(other.num_send_packet_)
			, self_(std::move(other.self_))
		{}

		void operator()(boost::system::error_code error, int start = 0)
		{
			switch (start)
			{
			case 1:
				while (!abort_ && !pkt_qe_.empty())
				{
					write_packet_op(stream_,
						std::make_shared<vpn_packet>(
							std::move(pkt_qe_.front())),
								static_cast<write_packet_qe&&>(*this))
									({}, 0);
			return;  default:
					if (abort_ || pkt_qe_.empty())
					{
						LOG_ERR << "write_packet_qe"
							<< ", error: " << error.message()
							<< ", pkt_qe: " << pkt_qe_.size()
							<< ", abort: " << abort_.value;
						return;
					}
					pkt_qe_.pop_front();
					if (error)
					{
						LOG_ERR << "write_packet_qe"
							<< ", error: " << error.message();
						return;
					}
					num_send_packet_++;
				}
			}
		}

		tcp::socket& stream_;
		std::deque<vpn_packet>& pkt_qe_;
		boost::tribool& abort_;
		int& num_send_packet_;
		std::shared_ptr<vpn_tunnel> self_;
	};


	//////////////////////////////////////////////////////////////////////////
	template<typename Handler>
	struct read_packet_op
	{
		read_packet_op(tcp::socket& s,
			vpn_packet_ptr pkt,
			Handler&& h)
			: stream_(s)
			, pkt_(pkt)
			, handler_(static_cast<Handler&&>(h))
		{}

		read_packet_op(read_packet_op&& other) noexcept
			: stream_(other.stream_)
			, pkt_(std::move(other.pkt_))
			, start_(other.start_)
			, start_len_tag_(std::move(other.start_len_tag_))
			, handler_(std::move(other.handler_))
		{}

		void operator()(boost::system::error_code error,
			[[maybe_unused]] std::size_t bytes)
		{
			switch (start_)
			{
			case 0:
			{
				start_ = 1;
				net::async_read(stream_,
					net::buffer(start_len_tag_.get(), 4),
						static_cast<read_packet_op&&>(*this));
			}
			return;
			case 1:
			{
				if (error)
					break;

				*start_len_tag_ = ntohl(*start_len_tag_);
				if ((uint32_t)*start_len_tag_ > (uint32_t)avpn_packet_size)
				{
					error = net::error::invalid_argument;
					break;
				}

				start_ = 2;
				net::async_read(stream_,
					net::buffer(pkt_->data(), *start_len_tag_),
						static_cast<read_packet_op&&>(*this));
			}
			return;
			default:
				if (!error)
				{
					BOOST_ASSERT(bytes == *start_len_tag_);
					pkt_->resize(*start_len_tag_);
				}
				break;
			}

			handler_(static_cast<const boost::system::error_code&>(error));
		}

		tcp::socket& stream_;
		vpn_packet_ptr pkt_;
		int start_{ 0 };
		std::unique_ptr<uint32_t> start_len_tag_{
			std::make_unique<uint32_t>(0) };
		Handler handler_;
	};


	//////////////////////////////////////////////////////////////////////////

	vpn_tunnel::vpn_tunnel(net::io_context& ioc,
		std::shared_ptr<avpn_service>& vpn,
		const service_config& cfg,
		std::string pubkey, std::string privatekey)
		: m_io_context(ioc)
		, m_serivce(vpn)
		, m_config(cfg)
		, m_identity(cfg.identity_)
		, m_pubkey(pubkey)
		, m_tcp_socket(ioc)
		, m_keyexchange(privatekey)
		, m_shared_key(m_keyexchange.GenerateSharedKey(m_pubkey))
		, m_tick_timer(ioc)
		, m_feg(cfg.tunnel_params_.data_shards_,
			cfg.tunnel_params_.parity_shards_)
	{
		m_io_context.post([this]() mutable
		{
			m_thread_id = std::this_thread::get_id();
		});

		m_crypto = std::make_unique<
			crypto_util::stream_crypto>(m_shared_key);
	}

	std::shared_ptr<vpn_tunnel>
	vpn_tunnel::make(net::io_context& ioc,
		std::shared_ptr<avpn_service>& vpn,
		const service_config& cfg,
		std::string pubkey, std::string privatekey)
	{
		return std::shared_ptr<vpn_tunnel>(new
			vpn_tunnel(ioc, vpn, cfg, pubkey, privatekey));
	}

	vpn_tunnel::~vpn_tunnel()
	{
		auto serivce = m_serivce.lock();
		if (serivce)
			serivce->remove_tunnel(m_self_vaddr);

		LOG_DBG << "vpn_tunnel::~vpn_tunnel, this: " << this;
	}

	void vpn_tunnel::start_tunnel(uint8_t ds, uint8_t ps)
	{
		if (m_abort || !m_abort)
			return;

		LOG_DBG << "start tunnel: " << this
			<< ", ds: " << ds
			<< ", ps : " << ps;

		m_peer_ds = ds;
		m_peer_ps = ps;

		m_abort = false;

		// 启动tick协程.
		auto self = shared_from_this();
		net::co_spawn(m_io_context,
			[this, self]() mutable -> net::awaitable<void>
			{
				co_await tick();
				co_return;
			}, net::detached);
	}

	void vpn_tunnel::close_tunnel()
	{
		auto self = shared_from_this();
		net::co_spawn(m_io_context,
			[this, self]() mutable -> net::awaitable<void>
			{
				LOG_INFO << "closing vpn_tunnel: " << this
					<< ", thread: " << std::this_thread::get_id();

				m_abort = true;

				m_upload_stat = {};
				m_down_stat = {};

				boost::system::error_code ec;
				m_tick_timer.cancel(ec);

				if (m_tcp_connect_ready)
					m_tcp_socket.close(ec);

				m_tcp_oqe.clear();

				co_return;
			}, net::detached);
	}

	int64_t vpn_tunnel::upload_rate() const
	{
		return m_upload_stat.rate_;
	}

	int64_t vpn_tunnel::download_rate() const
	{
		return m_down_stat.rate_;
	}

	void vpn_tunnel::upload_limit(int limit)
	{
		m_upload_limit = limit;
	}

	void vpn_tunnel::download_limit(int limit)
	{
		m_download_limit = limit;
	}

	void vpn_tunnel::rebind_tcp_socket(tcp::socket s)
	{
		boost::system::error_code ec;
		m_tcp_socket.close(ec);
		m_tcp_oqe.clear();

		// 如果socket的executor和当前vpn_tunnel的executor是同一个
		// executor, 则直接move对象到当前vpn_tunnel中.
		// 若不是, 则重新通过assign构造一个新的socket.
		// 这样做是为了确保 socket 对象和vpn_tunnel的 executor 是
		// 同一个, 避免vpn_tunnel运行在多线程上.
		if (s.get_executor() == this->get_executor())
		{
			m_tcp_socket = std::move(s);
			return;
		}

		auto endpoint = s.local_endpoint(ec);
		m_tcp_socket.assign(endpoint.protocol(), s.release());
	}

	void vpn_tunnel::tun_submit(vpn_tun_packet pkt)
	{
		if (m_thread_id == std::this_thread::get_id())
		{
			process_tun_packet(pkt.pkt_);
			return;
		}

		auto self = shared_from_this();
		net::post(m_io_context,
			[this, self, pkt = std::move(pkt)]
			() mutable
			{
				process_tun_packet(pkt.pkt_);
			});
	}

	void vpn_tunnel::net_submit(vpn_packet pkt,
		std::optional<udp::endpoint> remote)
	{
		if (m_identity == Identity::avpn_server)
		{
			if (remote && *remote != m_remote_endpoint)
				m_remote_endpoint = *remote;
		}

		if (m_thread_id == std::this_thread::get_id())
		{
			process_net_packet(pkt);
			return;
		}

		auto self = shared_from_this();
		net::post(m_io_context,
		[this, self, pkt = std::move(pkt)]
		() mutable
		{
			process_net_packet(pkt);
		});
	}

	void vpn_tunnel::start_tcp_loop()
	{
		BOOST_ASSERT(!m_tcp_connect_ready);
		if (m_tcp_connect_ready)
			return;

		// 启动网络转发.
		tcp_forward();
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
		m_self_vaddr = vaddr.address().to_uint();
	}

	udp::endpoint vpn_tunnel::remote_endpoint() const
	{
		return m_remote_endpoint;
	}

	void vpn_tunnel::remote_endpoint(const udp::endpoint& endp)
	{
		m_remote_endpoint = endp;
	}

	Proto vpn_tunnel::ipproto() const
	{
		return m_ipproto;
	}

	void vpn_tunnel::ipproto(Proto proto)
	{
		if (m_ipproto == Proto::avpn_unknown)
		{
			m_ipproto = proto;
			LOG_DBG << this << ", Ipproto update: "
				<< static_cast<int>(m_ipproto);
			return;
		}

		if (m_ipproto == Proto::avpn_udp && proto == Proto::avpn_tcp)
		{
			m_ipproto = Proto::avpn_mix;
			LOG_DBG << this << ", Ipproto update: "
				<< static_cast<int>(m_ipproto);
		}
		if (m_ipproto == Proto::avpn_tcp && proto == Proto::avpn_udp)
		{
			m_ipproto = Proto::avpn_mix;;
			LOG_DBG << this << ", Ipproto update: "
				<< static_cast<int>(m_ipproto);
		}
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
		[[maybe_unused]] auto self = shared_from_this();
		int tick_interval = 0;

		LOG_DBG << "Enter vpn_tunnel::tick: " << this
			<< ", thread: " << std::this_thread::get_id();

		while (!m_abort.value)
		{
			boost::system::error_code ec;

			m_tick_timer.expires_from_now(std::chrono::seconds(1));
			co_await m_tick_timer.async_wait(uawaitable[ec]);
			if (ec)
			{
				LOG_WARN << "vpn_tunnel::tick, ec: " << ec.message();
				break;
			}

			// 更新限制桶大小.
			if (m_upload_limit > 0)
				m_ulimit_bucket = m_upload_limit;
			if (m_download_limit > 0)
				m_dlimit_bucket = m_download_limit;

			auto now = std::chrono::steady_clock::now();

			// 更新download/upload记录.
			compute_speed(m_down_stat, 0);
			compute_speed(m_upload_stat, 0);

			// 计算上下行速率.
			compute_speed(m_down_stat, now);
			compute_speed(m_upload_stat, now);

			// 输出统计信息.
			if (++tick_interval % 10 == 0)
			{
				auto duration = std::chrono::nanoseconds(m_rtt);
				auto t = std::chrono::duration_cast
					<std::chrono::milliseconds>(duration);
				LOG_IFMT("{}, {}c, {}w, {}e, {}g, {}r"
					", {}tx, {}rx, {}d, {}u, {}q, {}rtt",
					static_cast<const void*>(this),
					m_num_corrected,
					m_num_incorrect,
					m_num_expired,
					m_fec_group_id,
					m_num_received,
					m_num_send_packet,
					m_num_recv_packet,
					m_down_stat.rate_,
					m_upload_stat.rate_,
					m_tcp_oqe.size(),
					t.count());
			}

			if (m_identity == Identity::avpn_server)
				continue;

			auto keepalive = m_config.tunnel_params_.keepalive_ / 1000;
			if (keepalive == 0)
				keepalive = 1;
			if (tick_interval % keepalive == 0)
			{
				// keepalive, 随机使用tcp/udp发送.
				uint64_t timestamp = now.time_since_epoch().count();
				auto pkt = make_keepalive(m_self_vaddr, m_client_id,
					m_num_recv_packet, m_num_send_packet, timestamp);

				internal_write_pkt(std::move(pkt));
			}
		}

		LOG_WARN << "Quit vpn_tunnel::tick " << this;
		co_return;
	}

	Proto vpn_tunnel::cherry_pick() const
	{
		auto& params = m_config.tunnel_params_;
		auto ipproto = m_ipproto;

		if (m_remote_endpoint.port() == 0)
			return Proto::avpn_tcp;

		if (!m_tcp_connect_ready)
			return Proto::avpn_udp;

		if ((params.mode_ == Proto::avpn_tcp ||
			ipproto == Proto::avpn_mix) &&
			m_tcp_oqe.empty() &&
			std::rand() % 2 == 0)
			return Proto::avpn_tcp;

		return Proto::avpn_udp;
	}

	void vpn_tunnel::compute_speed(speed_stat& stat, int bytes)
	{
		// 统计上传/下载数据量用于计算上传/下载速率.
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

	void vpn_tunnel::udp_write_pkt(vpn_packet pkt)
	{
		auto service = m_serivce.lock();
		if (!service)
			return;

		m_num_send_packet++;
		service->do_udp_write(std::move(pkt), m_remote_endpoint);
	}

	void vpn_tunnel::tcp_write_pkt(vpn_packet pkt)
	{
		// tcp 连接暂时不可用, 仅输出日志.
		if (!m_tcp_connect_ready)
		{
			static std::chrono::system_clock::time_point last_time;

			auto cur_time = std::chrono::system_clock::now();
			auto timeout = cur_time - last_time;

			// 此处只是为了避免在同一时间里频繁输出日志.
			if (timeout > std::chrono::seconds(1))
			{
				last_time = cur_time;
				LOG_WARN << "tcp_write_packet, tcp socket not ready";
			}

			return;
		}

		// 将pkt加入发送队列.
		bool deque_writing = !m_tcp_oqe.empty();
		m_tcp_oqe.emplace_back(std::move(pkt));

		// 正在发送中, 返回.
		if (deque_writing)
			return;

		// 开始循环发送tcp wirte队列.
		auto self = shared_from_this();
		write_packet_qe(m_tcp_socket, m_tcp_oqe,
			m_abort, m_num_send_packet, self)({}, 1);
	}

	void vpn_tunnel::internal_write_pkt(vpn_packet pkt)
	{
		auto pick = cherry_pick();

		if (pick == Proto::avpn_tcp)
			tcp_write_pkt(std::move(pkt));
		else
			udp_write_pkt(std::move(pkt));
	}

	net::awaitable<void> vpn_tunnel::speed_limit(
		const int& size, bool w /*= true*/)
	{
		int* bucket = nullptr;

		if (w && m_upload_limit > 0)
			bucket = &m_ulimit_bucket;
		else if (!w && m_download_limit > 0)
			bucket = &m_dlimit_bucket;
		else
			co_return;

		boost::system::error_code ec;
		asio_timer waiter(get_executor());

		while (*bucket <= 0 && !m_abort)
		{
			waiter.expires_from_now(std::chrono::milliseconds(1));
			co_await waiter.async_wait(uawaitable[ec]);
		}

		*bucket -= size;
		co_return;
	}

	void vpn_tunnel::tcp_forward()
	{
		m_tcp_connect_ready = true;
		auto self = shared_from_this();

		if (!m_abort)
		{
			auto ptr = std::make_shared<vpn_packet>();

			read_packet_op(m_tcp_socket, ptr,
				[this, self, ptr](boost::system::error_code ec) mutable
				{
					if (!ec)
					{
						// 计算下载速率.
						compute_speed(m_down_stat, ptr->size());
						m_num_recv_packet++;

						// 继续下一次tcp接收转发.
						tcp_forward();

						// 将接收到的packet提交到队列.
						// net_submit(std::move(*ptr), {});
						process_net_packet(*ptr);

						return;
					}

					// tcp出错, 状态设置为未就绪.
					m_tcp_connect_ready = false;

					// 准备重连.
					std::string suffix;
					scoped_exit se([&]() mutable
						{
							// 输出日志信息.
							LOG_WARN << "Quit tcp loop: "
								<< this << suffix;
						});

					// 当运行身份为client时, 尝试重连服务器.
					if (!m_abort &&
						m_identity == Identity::avpn_client)
					{
						auto service = m_serivce.lock();
						if (!service)
							return;

						// 重置tcp重连计数, 等待tcp重连.
						suffix = " with reconnect";
						service->tcp_reconnect(1);
					}
				})({}, 0);
		}
	}

	void vpn_tunnel::process_tun_packet(vpn_packet& pkt)
	{
		auto& params = m_config.tunnel_params_;

		// 更新pkt数据, 计算gid, pid等信息.
		if (m_config.tunnel_params_.compress_ == "zstd")
			m_feg.make_fec_zstd(pkt, m_self_vaddr);
		else
			m_feg.make_fec_normal(pkt, m_self_vaddr);

		// 从fec编码缓冲中获取已经fec编码.
		std::vector<vpn_packet_ptr> paritys = m_feg.acquire();

		// 重复发送模式.
		if (params.data_shards_ == 1)
		{
			int repeated = params.parity_shards_ + 1;

			// 计算上行速率.
			compute_speed(m_upload_stat, pkt.size() * repeated);

			for (int i = 0; i < repeated; i++)
			{
				if (repeated == 1)
				{
					internal_write_pkt(std::move(pkt));
					break;
				}

				auto dup = dup_vpn_packet(pkt);
				if (i != 0)
				{
					if (m_config.tunnel_params_.compress_ == "zstd")
						m_feg.make_fec_zstd(dup, m_self_vaddr);
					else
						m_feg.make_fec_normal(dup, m_self_vaddr);
				}

				internal_write_pkt(std::move(dup));
			}

			return;
		}

		// 计算上行速率.
		compute_speed(m_upload_stat, pkt.size());

		// 发送pkt到对方.
		internal_write_pkt(std::move(pkt));

		// 循环发送已FEC编码部分.
		for (auto& p : paritys)
		{
			BOOST_ASSERT(p != nullptr && "tun_forward");

			// 计算上行速率.
			compute_speed(m_upload_stat, p->size());

			// 发送到对方.
			internal_write_pkt(std::move(*p));
		}

		return;
	}

	void vpn_tunnel::process_net_packet(vpn_packet& pkt)
	{
		bool enc = false;
		uint8_t type = 0;
		uint32_t src;

		m_num_recv_packet++;
 		compute_speed(m_down_stat, pkt.size());

		int ret = unwrap_common_header(pkt, enc, type, src);
		if (ret == -1)
			return;

		switch (type)
		{
		case vpt_handshake:
			break;
		case vpt_handshake_reply:
			break;

		case vpt_keepalive:
			on_vpn_keepalive(pkt);
			break;
		case vpt_keepalive_reply:
			on_vpn_keepalive_reply(pkt);
			break;

		case vpt_transfer:
			on_vpn_transfer(pkt);
			break;
		case vpt_transfer_compress:
			on_vpn_transfer_compress(pkt);
			break;
		}
	}

	void vpn_tunnel::on_vpn_keepalive(vpn_packet& pkt)
	{
		if (m_identity == Identity::avpn_server)
		{
			uint32_t src, rx, tx;
			std::string id;
			uint64_t timestamp;

			unwrap_keepalive(pkt, src, id, rx, tx, timestamp);

			auto p = make_keepalive_reply(src, m_client_id,
					m_num_recv_packet, m_num_send_packet, timestamp);

			if (m_ipproto == Proto::avpn_tcp ||
				m_ipproto == Proto::avpn_mix)
				tcp_write_pkt(std::move(p));
			else
				udp_write_pkt(std::move(p));
		}

		last_see(steady_clock::now());
	}

	void vpn_tunnel::on_vpn_keepalive_reply(vpn_packet& pkt)
	{
		uint32_t src = 0;
		uint32_t rx = 0;
		uint32_t tx = 0;
		uint64_t timestamp = 0;
		std::string id;

		unwrap_keepalive_reply(pkt, src, id, rx, tx, timestamp);

		auto now = steady_clock::now();
		auto rtt = now.time_since_epoch().count() - timestamp;

		auto duration = std::chrono::nanoseconds(rtt);
		if (duration < std::chrono::seconds(60) &&
			duration >= std::chrono::nanoseconds(0))
		{
			if (m_rtt == 0)
				m_rtt = static_cast<int64_t>(rtt);

			m_rtt = (static_cast<int64_t>(rtt) * 7 + m_rtt) / 8;
		}

		last_see(now);
	}

	void vpn_tunnel::on_vpn_transfer(vpn_packet& pkt)
	{
		auto service = m_serivce.lock();
		if (!service)
			return;

		uint32_t src = 0;
		uint32_t gid = 0;
		uint8_t pid = 0;

		int ret = unwrap_transfer(pkt, src, gid, pid);
		if (ret < 0)
			return;

		auto shards = m_peer_ds + m_peer_ps;
		if (pid >= shards)
		{
			LOG_ERR << this << ", transfer pkt"
				<< ", gid: " << gid
				<< ", pid: " << pid
				<< ", shards: " << shards;
			m_num_incorrect++;
			return;
		}

		BOOST_ASSERT(gid > 0 && "on_vpn_transfer");
		BOOST_ASSERT(pid < shards && "on_vpn_transfer");

		if (std::abs(static_cast<std::intmax_t>(m_fec_group_id - gid)) < 1000)
			m_fec_group_id = gid;
		else
			m_fec_group_id = std::max(gid, m_fec_group_id);

		// 更新最后可见时间.
		if (m_identity == Identity::avpn_server)
			last_see(steady_clock::now());

		auto write_pkt = [this, service](vpn_packet& pkt) mutable
		{
			auto endp = check_packet(pkt.payload(), avpn_static_mtu);
			if (!endp)
			{
				m_num_incorrect++;
				LOG_ERR << this << ", incorrect pkt"
					<< ", gid: " << pkt.gid_
					<< ", pid: " << pkt.pid_;
				return;
			}

			auto& ep = *endp;
			auto& dst_addr = ep.dst_;

			auto uint_dst = dst_addr.address().to_v4().to_uint();
			udp::endpoint uendp(dst_addr.address(), 0);

			if (m_identity == Identity::avpn_server
				&& same_ipv4_network(m_vaddr, uint_dst))
			{
				// 不允许内网互通.
				if (!m_config.tunnel_params_.c2c_)
					return;

				// 通过avpn service查找对应的tunnel
				// 然后转发内网数据到这个tunnel.
				auto dst_tunnel = service->lookup_tunnel(uint_dst);
				if (dst_tunnel)
				{
					// 内网转发.
					dst_tunnel->tun_submit(
						vpn_tun_packet(std::move(pkt), std::move(ep)));
					return;
				}
			}

			// 转发到tun设备.
			service->do_tun_write(std::move(pkt));
			return;
		};

		// 更新fec recover.
		auto ptr = dup_vpn_packet_ptr(pkt);
		auto [whole, expired] = m_recover.update(
			gid, pid, m_peer_ds, m_peer_ps, ptr);

		// 将接收到的ip包write到tun设备.
		if (!expired)
		{
			m_num_received++;

			if (pid < m_peer_ds || m_peer_ds == 1)
				write_pkt(pkt);

			// 对方重复发送模式时, 只要接收到任何1个包, 则表示
			// 可以退出recover逻辑.
			if (m_peer_ds == 1)
				return;
		}
		else
		{
			m_num_expired++;
			return;
		}

		// group还不完整, 表示还不能恢复丢失的数据包
		// 需要更新多的数据包.
		if (!whole)
			return;

		// 运行到这里如果触发断言, 则表示 recover 在处理
		// 对方重复发送模式时有问题.
		BOOST_ASSERT(m_peer_ds != 1 && "on_vpn_transfer");

		// 获取fec解码恢复的ip包, 并write到tun设备.
		auto results = m_recover.acquire();
		for (auto& p : results)
		{
			if (!p)
				continue;

			write_pkt(*p);
		}

		// 更新统计信息.
		m_num_corrected += (int)results.size();
	}

	void vpn_tunnel::on_vpn_transfer_compress(vpn_packet& pkt)
	{
		auto service = m_serivce.lock();
		if (!service)
			return;

		uint32_t src = 0;
		uint32_t gid;
		uint8_t pid;
		uint8_t ctype;

		auto dst_ptr = unwrap_transfer_compress(pkt, src, gid, pid, ctype);
		if (!dst_ptr)
			return;

		BOOST_ASSERT(gid > 0 && "on_vpn_transfer_compress");
		BOOST_ASSERT(pid < (m_peer_ds + m_peer_ps)
			&& "on_vpn_transfer_compress");

		// 更新最后可见时间.
		if (m_identity == Identity::avpn_server)
			last_see(steady_clock::now());

		auto write_pkt = [this, service](vpn_packet& pkt) mutable
		{
			auto endp = check_packet(pkt.payload(), avpn_static_mtu);
			if (!endp)
			{
				m_num_incorrect++;
				return;
			}

			auto& ep = *endp;
			auto& dst_addr = ep.dst_;

			auto uint_dst = dst_addr.address().to_v4().to_uint();
			udp::endpoint uendp(dst_addr.address(), 0);

			if (m_identity == Identity::avpn_server
				&& same_ipv4_network(m_vaddr, uint_dst))
			{
				// 不允许内网互通.
				if (!m_config.tunnel_params_.c2c_)
					return;

				// 通过avpn service查找对应的tunnel
				// 然后转发内网数据到这个tunnel.
				auto dst_tunnel = service->lookup_tunnel(uint_dst);
				if (dst_tunnel)
				{
					// 内网转发.
					dst_tunnel->tun_submit(
						vpn_tun_packet(std::move(pkt), std::move(ep)));
					return;
				}
			}

			// 转发到tun设备.
			service->do_tun_write(std::move(pkt));
		};

		// 更新fec recover.
		auto ptr = dup_vpn_packet_ptr(pkt);
		auto [whole, expired] = m_recover.update(
			gid, pid, m_peer_ds, m_peer_ps, ptr);

		// 将接收到的ip包write到tun设备.
		if (!expired)
		{
			m_num_received++;

			if (pid < m_peer_ds || m_peer_ds == 1)
				write_pkt(pkt);

			// 对方重复发送模式时, 只要接收到任何1个包, 则表示
			// 可以退出recover逻辑.
			if (m_peer_ds == 1)
				return;
		}
		else
		{
			m_num_expired++;
			return;
		}

		// group还不完整, 表示还不能恢复丢失的数据包
		// 需要更新多的数据包.
		if (!whole)
			return;

		// 运行到这里如果触发断言, 则表示 recover 在处理
		// 对方重复发送模式时有问题.
		BOOST_ASSERT(m_peer_ds != 1 && "on_vpn_transfer_compress");

		// 获取fec解码恢复的ip包, 并write到tun设备.
		auto results = m_recover.acquire();
		for (auto& p : results)
		{
			if (!p)
				continue;

			auto dst = unwrap_transfer_compress(*p, src, gid, pid, ctype);
			if (!dst)
				continue;

			write_pkt(*dst);
		}

		// 更新统计信息.
		m_num_corrected += (int)results.size();
	}

	std::optional<endpoint_pair>
	vpn_tunnel::check_packet(const uint8_t* data, int size)
	{
		auto ep = parser_endpoint(data, size);
		if (ep.size_ <= 0 ||
			ep.size_ > avpn_static_mtu)
		{
			return {};
		}

		return ep;
	}

}
