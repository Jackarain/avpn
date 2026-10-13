//
// avpn_session.cpp
// ~~~~~~~~~~~~~~~~
//
// Copyright (C) 2025 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#include "libavpn/avpn_session.hpp"

#include "libavpn/asio_util.hpp"
#include "libavpn/use_awaitable.hpp"
#include "libavpn/logging.hpp"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/ip/address_v4.hpp>

#include <algorithm>
#include <cstring>
#include <array>
#include <cstdlib>

namespace libavpn {

	namespace {

		// 握手请求的重发间隔与最多重发次数.
		constexpr std::chrono::seconds hs_retry_interval{ 5 };
		constexpr int hs_max_retry = 5;

		// 一直在发却这么久收不到下行: 补一个漫游帧, 让对端跟上换网.
		constexpr std::chrono::seconds no_rx_nudge{ 1 };

		// 对端这么久没动静就当会话死了.
		constexpr std::chrono::seconds peer_idle_timeout{ 120 };

		// 会话参数的下限/上限.
		constexpr uint16_t min_mtu = 576;

		// TCP 传输的写合并: 短时间内的多个帧合并成一次写入.
		constexpr std::chrono::milliseconds tcp_cork_delay{ 2 };
		constexpr std::size_t tcp_cork_max_bytes = 128 * 1024;
		constexpr std::size_t tcp_read_chunk = 128 * 1024;

		// TCP 单帧长度前缀上限 (防御异常帧).
		constexpr std::size_t tcp_max_frame = 65535;

		// 当前毫秒时间戳.
		inline uint64_t now_ms()
		{
			return static_cast<uint64_t>(
				std::chrono::duration_cast<std::chrono::milliseconds>(
					std::chrono::system_clock::now().time_since_epoch())
					.count());
		}

		inline uint64_t get_u64_le(const uint8_t* p)
		{
			uint64_t v = 0;
			for (int i = 0; i < 8; i++)
				v |= static_cast<uint64_t>(p[i]) << (i * 8);
			return v;
		}

		inline void put_u64_le(std::string& out, uint64_t v)
		{
			for (int i = 0; i < 8; i++)
				out.push_back(static_cast<char>((v >> (i * 8)) & 0xff));
		}

		inline std::string_view as_view(const std::string& s)
		{
			return std::string_view(s.data(), s.size());
		}

		// hint 是否为空 (8 个 0 表示客户端没有带).
		bool hint_empty(std::string_view hint)
		{
			for (auto c : hint)
			{
				if (c != 0)
					return false;
			}
			return true;
		}

		// 解析 IPv6 内网子网字符串 (格式如 "fd00:8888::/64"); 成功返回 true.
		bool parse_v6_subnet(const std::string& text,
			net::ip::address_v6& net, uint8_t& prefix)
		{
			net = net::ip::make_address_v6("fd00:8888::");
			prefix = 64;
			if (text.empty())
				return false;

			boost::system::error_code ec;
			const auto slash = text.find('/');
			const auto host = slash == std::string::npos ?
				text : text.substr(0, slash);
			const auto v6 = net::ip::make_address_v6(host, ec);
			if (ec)
				return false;
			net = v6;
			if (slash != std::string::npos)
			{
				const int plen = std::atoi(text.c_str() + slash + 1);
				if (plen >= 0 && plen <= 128)
					prefix = static_cast<uint8_t>(plen);
			}
			return true;
		}

		// 八字节漫游凭证是否为空.
		bool cookie_empty(const std::array<uint8_t, 8>& cookie)
		{
			for (auto c : cookie)
			{
				if (c != 0)
					return false;
			}
			return true;
		}

	} // namespace

	avpn_session::avpn_session(net::io_context& ioc,
		const service_config& config, session_role role)
		: m_ioc(ioc)
		, m_config(config)
		, m_role(role)
		, m_tick_timer(ioc)
		, m_hs_timer(ioc)
		, m_tcp_cork_timer(ioc)
	{
		// 解析本端静态私钥 (base64 编码的 32 字节).
		if (!config.private_key_.empty())
		{
			m_static_priv = crypto::base64_decode(config.private_key_);
			if (m_static_priv.size() != crypto::x25519_key_size)
				m_static_priv.clear();
		}

		if (m_static_priv.empty())
		{
			// 自动生成静态密钥对.
			auto kp = crypto::x25519_generate_keypair();
			m_static_priv = kp.first;
			m_static_pub = kp.second;
		}
		else
		{
			m_static_pub = crypto::x25519_public_key(m_static_priv);
		}

		// 对端公钥.
		if (role == session_role::initiator)
		{
			// 对端是网关, 公钥来自 public_key_.
			if (!config.public_key_.empty())
			{
				auto pub = crypto::base64_decode(config.public_key_);
				if (pub.size() == crypto::x25519_key_size)
				{
					m_peer_pubs.push_back(pub);
					m_peer_static_pub = pub;
				}
			}
		}
		else
		{
			// 对端是客户端, 公钥来自白名单.
			for (auto& pk : config.pkl_)
			{
				auto pub = crypto::base64_decode(pk);
				if (pub.size() == crypto::x25519_key_size)
					m_peer_pubs.push_back(std::move(pub));
			}
		}

		// 客户端标识 (16 字节, 只写日志).
		m_client_id = crypto::random_bytes(16);
	}

	avpn_session::~avpn_session() = default;

	std::shared_ptr<avpn_session> avpn_session::create(net::io_context& ioc,
		const service_config& config, session_role role)
	{
		return std::shared_ptr<avpn_session>(
			new avpn_session(ioc, config, role));
	}

	void avpn_session::set_ip_packet_handler(ip_packet_handler h)
	{
		m_ip_packet_handler = std::move(h);
	}

	void avpn_session::set_close_handler(close_handler h)
	{
		m_close_handler = std::move(h);
	}

	void avpn_session::set_established_handler(established_handler h)
	{
		m_established_handler = std::move(h);
	}

	void avpn_session::set_udp_send_handler(udp_send_handler h)
	{
		m_udp_send_handler = std::move(h);
	}

	void avpn_session::set_vaddr_allocator(vaddr_allocator h)
	{
		m_vaddr_allocator = std::move(h);
	}

	void avpn_session::set_keepalive(int seconds)
	{
		m_params.keepalive_sec = static_cast<uint16_t>(
			std::max(1, std::min(seconds, 65535)));
	}

	bool avpn_session::matches_roam_cookie(std::string_view data) const
	{
		if (!m_established || cookie_empty(m_roam_cookie))
			return false;
		if (data.size() < m_roam_cookie.size() + frame_header_size)
			return false;
		return std::memcmp(data.data(), m_roam_cookie.data(),
			m_roam_cookie.size()) == 0;
	}

	// ------------------------------------------------------------------
	// 握手
	// ------------------------------------------------------------------

	bool avpn_session::check_anti_replay(const std::string& peer_pub,
		uint64_t ts)
	{
		auto it = m_hs_replay.find(peer_pub);
		if (it != m_hs_replay.end() && ts <= it->second)
			return false;
		m_hs_replay[peer_pub] = ts;
		return true;
	}

	void avpn_session::apply_params()
	{
		m_vaddr = m_params.vaddr;
		m_roam_cookie = m_params.roam_cookie;
		m_datapath.configure(m_master, m_params,
			m_role == session_role::initiator);
		m_datapath.set_roam_cookie(m_roam_cookie);
	}

	void avpn_session::send_handshake_msg1()
	{
		if (m_peer_static_pub.empty())
		{
			XLOG_ERR << "No peer static public key configured";
			close();
			return;
		}

		// 两把握手密钥都由"双方静态密钥"的共享秘密派生.
		m_hs_shared = crypto::x25519_ecdh(m_static_priv, m_peer_static_pub);
		if (m_hs_shared.size() != crypto::x25519_key_size ||
			!derive_handshake_key(m_hs_shared, true, m_key_temp) ||
			!derive_handshake_key(m_hs_shared, false, m_key_resp))
		{
			XLOG_ERR << "Derive handshake keys failed";
			close();
			return;
		}

		handshake_req req;
		req.version = avpn_protocol_v2;
		std::memcpy(req.ephemeral_pub.data(), m_eph_pub.data(),
			std::min(m_eph_pub.size(), req.ephemeral_pub.size()));
		req.timestamp = now_ms();
		std::memcpy(req.client_id.data(), m_client_id.data(),
			std::min(m_client_id.size(), req.client_id.size()));
		req.requested_vaddr = m_config.vaddr_;
		// 客户端只表达"想要什么", 最终取值由网关在回复里定; 这里先不带参数.

		const std::string plaintext = req.serialize();
		if (plaintext.empty())
		{
			XLOG_ERR << "Serialize handshake request failed";
			close();
			return;
		}

		// hint: 客户端静态公钥的哈希前缀; 不带就填 8 个 0.
		std::array<uint8_t, handshake_hint_size> hint{};
		if (m_config.hint_)
			hint = make_handshake_hint(m_static_pub);

		const std::string nonce = crypto::random_bytes(crypto::aead_nonce_size);
		const std::string_view aad(
			reinterpret_cast<const char*>(hint.data()), hint.size());
		const std::string ciphertext =
			crypto::aead_encrypt(m_key_temp, nonce, plaintext, aad);
		if (ciphertext.empty())
		{
			XLOG_ERR << "Encrypt handshake request failed";
			close();
			return;
		}

		std::vector<uint8_t> wire;
		wire.reserve(hint.size() + nonce.size() + ciphertext.size());
		wire.insert(wire.end(), hint.begin(), hint.end());
		wire.insert(wire.end(), nonce.begin(), nonce.end());
		wire.insert(wire.end(), ciphertext.begin(), ciphertext.end());

		if (m_transport == transport_type::udp)
		{
			m_udp_pending.push_back(std::move(wire));
			flush_udp_batch();
		}
		else
		{
			queue_tcp_wire(std::move(wire));
		}
	}

	bool avpn_session::handle_handshake_msg2(std::string_view wire)
	{
		if (wire.size() < crypto::aead_nonce_size + crypto::aead_tag_size)
			return false;

		const std::string_view nonce = wire.substr(0, crypto::aead_nonce_size);
		const std::string_view ciphertext = wire.substr(crypto::aead_nonce_size);

		if (m_key_resp.empty())
		{
			m_hs_shared = crypto::x25519_ecdh(m_static_priv,
				m_peer_static_pub);
			if (m_hs_shared.size() != crypto::x25519_key_size ||
				!derive_handshake_key(m_hs_shared, false, m_key_resp))
				return false;
		}

		const std::string plaintext =
			crypto::aead_decrypt(m_key_resp, nonce, ciphertext);
		handshake_resp resp;
		if (plaintext.empty() || !parse_handshake_resp(plaintext, resp))
			return false;

		m_peer_eph_pub.assign(
			reinterpret_cast<const char*>(resp.ephemeral_pub.data()),
			resp.ephemeral_pub.size());

		if (!derive_master_key(m_static_priv, m_eph_priv, m_peer_static_pub,
			m_peer_eph_pub, m_master))
		{
			XLOG_ERR << "Derive session master key failed";
			return false;
		}

		m_params = resp.params;
		apply_params();
		on_established();

		XLOG_INFO << "Session established (client), vaddr: "
			<< net::ip::address_v4(m_vaddr).to_string()
			<< ", mtu: " << m_params.mtu
			<< ", fec: " << static_cast<int>(m_params.fec_data) << "/"
			<< static_cast<int>(m_params.fec_total);
		return true;
	}

	bool avpn_session::try_handshake(const net::ip::udp::endpoint& remote,
		std::string_view wire)
	{
		const std::size_t least = handshake_hint_size +
			crypto::aead_nonce_size + crypto::aead_tag_size;
		if (wire.size() < least)
			return false;

		const std::string_view hint = wire.substr(0, handshake_hint_size);
		const std::string_view nonce =
			wire.substr(handshake_hint_size, crypto::aead_nonce_size);
		const std::string_view ciphertext =
			wire.substr(handshake_hint_size + crypto::aead_nonce_size);
		const std::string aad(hint.data(), hint.size());
		const std::string_view aad_view(aad.data(), aad.size());
		const bool with_hint = !hint_empty(hint);

		handshake_req req;
		std::string matched;
		for (const auto& pub : m_peer_pubs)
		{
			// 带了 hint 就只试那一项; 没带就逐个白名单项试.
			if (with_hint)
			{
				const auto mine = make_handshake_hint(pub);
				if (std::memcmp(mine.data(), hint.data(), hint.size()) != 0)
					continue;
			}

			std::string shared = crypto::x25519_ecdh(m_static_priv, pub);
			std::string k_temp;
			if (shared.size() != crypto::x25519_key_size ||
				!derive_handshake_key(shared, true, k_temp))
				continue;

			const std::string plaintext =
				crypto::aead_decrypt(k_temp, nonce, ciphertext, aad_view);
			if (plaintext.empty() || !parse_handshake_req(plaintext, req))
				continue;

			m_hs_shared = std::move(shared);
			m_key_temp = std::move(k_temp);
			matched = pub;
			break;
		}

		if (matched.empty())
			return false;

		if (req.version != avpn_protocol_v2)
		{
			XLOG_WARN << "Unsupported protocol version: " << req.version;
			return false;
		}

		if (!check_anti_replay(matched, req.timestamp))
			return false;

		m_peer_static_pub = matched;
		m_peer_eph_pub.assign(
			reinterpret_cast<const char*>(req.ephemeral_pub.data()),
			req.ephemeral_pub.size());
		m_client_id.assign(
			reinterpret_cast<const char*>(req.client_id.data()),
			req.client_id.size());

		// 先把对端地址定下来, 回复才能发回请求来的那个地址.
		m_remote_udp = remote;
		send_handshake_msg2(matched, req);
		if (!m_established)
			return false;

		return true;
	}

	session_params avpn_session::make_responder_params(
		const session_params& wish, uint32_t vaddr, uint8_t prefix)
	{
		session_params p;

		// 认证标签: 客户端要 12 就给 12, 其余情况用 16.
		p.tag_len = wish.tag_len == 12 ? 12 : 16;

		// 纠错: 数据片 2 片以上才开; T 必须是 2 的幂且能整除数 2^32.
		const int ds = m_config.data_shards_;
		const int ps = m_config.parity_shards_;
		const int total = ds + ps;
		if (ds >= 2 && ps >= 1 &&
			(total == 2 || total == 4 || total == 8 || total == 16))
		{
			p.fec_total = static_cast<uint8_t>(total);
			p.fec_data = static_cast<uint8_t>(ds);
		}

		p.keepalive_sec = static_cast<uint16_t>(
			std::max(1, std::min(m_config.keepalive_, 65535)));
		p.group_abandon_ms = 1000;
		p.group_cache_ms = 2000;
		p.early_close_ms = 0;

		p.vaddr = vaddr;
		p.prefix_len = prefix;

		p.mtu = static_cast<uint16_t>(std::max<int>(min_mtu,
			std::min<int>(m_config.mtu_size_,
				static_cast<int>(p.shard_limit()))));

		if (!m_config.v6_subnet_.empty())
		{
			net::ip::address_v6 net;
			uint8_t plen = 64;
			if (parse_v6_subnet(m_config.v6_subnet_, net, plen))
			{
				p.v6_net = net;
				p.v6_prefix = plen;
			}
		}

		p.routes = m_config.pushroutes_;
		p.compress = 0;
		p.obfuscate = false;
		p.transport = m_transport == transport_type::udp ? 0 : 1;
		p.pushdns = m_config.pushdns_;
		p.passbyvpn = m_config.passbyvpn_;

		// 漫游凭证只在 UDP 下才有用.
		if (m_transport == transport_type::udp)
		{
			const std::string cookie = crypto::random_bytes(8);
			std::memcpy(p.roam_cookie.data(), cookie.data(),
				p.roam_cookie.size());
			p.cookie_beacon_k = 64;
		}
		else
		{
			p.roam_cookie.fill(0);
			p.cookie_beacon_k = 0;
		}

		if (!p.valid())
		{
			XLOG_WARN << "Session params not consistent, fall back to default";
			session_params fallback;
			p = fallback;
			p.vaddr = vaddr;
			p.prefix_len = prefix;
			p.routes = m_config.pushroutes_;
			p.pushdns = m_config.pushdns_;
			p.passbyvpn = m_config.passbyvpn_;
			p.transport = m_transport == transport_type::udp ? 0 : 1;
			if (m_transport == transport_type::udp)
			{
				const std::string cookie = crypto::random_bytes(8);
				std::memcpy(p.roam_cookie.data(), cookie.data(),
					p.roam_cookie.size());
				p.cookie_beacon_k = 64;
			}
		}

		return p;
	}

	void avpn_session::send_handshake_msg2(const std::string& peer_static_pub,
		const handshake_req& req)
	{
		// 网关临时密钥对.
		auto kp = crypto::x25519_generate_keypair();
		m_eph_priv = kp.first;
		m_eph_pub = kp.second;

		// 会话主密钥: 四次 X25519.
		if (!derive_master_key(m_static_priv, m_eph_priv, peer_static_pub,
			m_peer_eph_pub, m_master))
		{
			XLOG_ERR << "Derive session master key failed";
			return;
		}

		// 分配虚拟地址.
		uint32_t vaddr = 0;
		uint8_t prefix = 0;
		if (m_vaddr_allocator)
			std::tie(vaddr, prefix) = m_vaddr_allocator(req.requested_vaddr);

		m_params = make_responder_params(req.params, vaddr, prefix);

		handshake_resp resp;
		std::memcpy(resp.ephemeral_pub.data(), m_eph_pub.data(),
			std::min(m_eph_pub.size(), resp.ephemeral_pub.size()));
		resp.params = m_params;

		const std::string plaintext = resp.serialize();
		if (plaintext.empty())
			return;

		if (!derive_handshake_key(m_hs_shared, false, m_key_resp))
			return;

		const std::string nonce = crypto::random_bytes(crypto::aead_nonce_size);
		const std::string ciphertext =
			crypto::aead_encrypt(m_key_resp, nonce, plaintext);
		if (ciphertext.empty())
			return;

		std::vector<uint8_t> wire;
		wire.reserve(nonce.size() + ciphertext.size());
		wire.insert(wire.end(), nonce.begin(), nonce.end());
		wire.insert(wire.end(), ciphertext.begin(), ciphertext.end());

		if (m_transport == transport_type::udp)
		{
			m_udp_pending.push_back(std::move(wire));
			flush_udp_batch();
		}
		else
		{
			queue_tcp_wire(std::move(wire));
		}

		apply_params();
		on_established();

		XLOG_INFO << "Session established (gateway), vaddr: "
			<< net::ip::address_v4(m_vaddr).to_string()
			<< ", mtu: " << m_params.mtu
			<< ", fec: " << static_cast<int>(m_params.fec_data) << "/"
			<< static_cast<int>(m_params.fec_total);
	}

	void avpn_session::on_established()
	{
		m_established = true;
		const auto now = std::chrono::steady_clock::now();
		m_last_seen = now;
		m_last_rx = now;
		m_last_keepalive_ms = now_ms();
		m_tx_since_rx = false;

		start_tick();

		if (m_established_handler)
			m_established_handler();
	}

	// ------------------------------------------------------------------
	// 数据路径
	// ------------------------------------------------------------------

	void avpn_session::queue_frame(std::string_view frame)
	{
		std::vector<uint8_t> wire(frame.begin(), frame.end());
		if (m_transport == transport_type::udp)
			m_udp_pending.push_back(std::move(wire));
		else
			queue_tcp_wire(std::move(wire));
	}

	void avpn_session::flush_udp_batch()
	{
		if (m_udp_pending.empty())
			return;

		if (!m_abort && m_udp_send_handler)
			m_udp_send_handler(m_remote_udp, std::move(m_udp_pending));

		m_udp_pending.clear();
	}

	void avpn_session::queue_tcp_wire(std::vector<uint8_t> wire)
	{
		if (!m_tcp_stream || m_abort)
			return;
		if (wire.empty() || wire.size() > tcp_max_frame)
			return;

		const uint16_t len = static_cast<uint16_t>(wire.size());
		std::vector<uint8_t> frame;
		frame.reserve(2 + wire.size());
		frame.push_back(static_cast<uint8_t>((len >> 8) & 0xff));
		frame.push_back(static_cast<uint8_t>(len & 0xff));
		frame.insert(frame.end(), wire.begin(), wire.end());

		m_tcp_oqe.push_back(std::move(frame));
		start_tcp_write();
	}

	void avpn_session::start_tcp_write()
	{
		if (m_tcp_writing || m_tcp_oqe.empty() || !m_tcp_stream)
			return;

		m_tcp_writing = true;
		auto self = shared_from_this();
		auto stream = m_tcp_stream;

		net::co_spawn(m_ioc,
			[this, self, stream]() -> net::awaitable<void>
			{
				while (!m_abort && !m_tcp_oqe.empty())
				{
					// 把这段时间内排队的帧合并成一次写入.
					auto deadline = std::chrono::steady_clock::now() +
						tcp_cork_delay;
					std::vector<uint8_t> batch;
					std::size_t bytes = 0;

					for (;;)
					{
						while (!m_tcp_oqe.empty() &&
							bytes < tcp_cork_max_bytes)
						{
							auto& wire = m_tcp_oqe.front();
							bytes += wire.size();
							batch.insert(batch.end(),
								wire.begin(), wire.end());
							m_tcp_oqe.pop_front();
						}

						if (m_abort || bytes >= tcp_cork_max_bytes ||
							std::chrono::steady_clock::now() >= deadline)
							break;

						m_tcp_cork_timer.expires_at(deadline);
						boost::system::error_code tec;
						co_await m_tcp_cork_timer.async_wait(
							net_awaitable[tec]);
						if (m_abort)
							break;
					}

					if (batch.empty())
						break;

					boost::system::error_code ec;
					co_await net::async_write(*stream,
						net::buffer(batch), net_awaitable[ec]);
					if (ec)
						break;
				}
				m_tcp_writing = false;
				co_return;
			}, net::detached);
	}

	void avpn_session::send_plaintext(std::string_view plaintext, bool roam)
	{
		if (!m_established || m_abort || plaintext.empty())
			return;

		// 每 cookie_beacon_k 帧顺带一次 cookie, 让对端能跟着换网.
		bool use_roam = roam;
		if (m_params.cookie_beacon_k > 0 &&
			m_datapath.has_roam_cookie() &&
			++m_tx_frames % m_params.cookie_beacon_k == 0)
			use_roam = true;

		auto frames = m_datapath.seal(plaintext, now_ms(), use_roam);
		if (frames.empty())
			return;

		m_upload_bytes += static_cast<int64_t>(plaintext.size());
		update_speed(m_upload_stat, static_cast<int64_t>(plaintext.size()),
			std::chrono::steady_clock::now());

		for (auto& frame : frames)
			queue_frame(frame);

		if (m_transport == transport_type::udp)
			flush_udp_batch();

		m_tx_since_rx = true;
	}

	bool avpn_session::handle_wire(std::string_view wire)
	{
		auto payloads = m_datapath.on_frame(wire, now_ms());
		if (payloads.empty())
			return false;

		const auto now = std::chrono::steady_clock::now();
		m_last_seen = now;
		m_last_rx = now;
		m_tx_since_rx = false;

		for (auto& plaintext : payloads)
			handle_plaintext(plaintext);

		return true;
	}

	void avpn_session::handle_plaintext(std::string_view plaintext)
	{
		switch (classify_payload(plaintext))
		{
		case frame_kind::ip:
		{
			m_download_bytes += static_cast<int64_t>(plaintext.size());
			update_speed(m_down_stat, static_cast<int64_t>(plaintext.size()),
				std::chrono::steady_clock::now());
			deliver_ip_packet(std::vector<uint8_t>(
				plaintext.begin(), plaintext.end()));
			break;
		}
		case frame_kind::container:
			handle_container(plaintext);
			break;
		default:
			handle_control_message(plaintext);
			break;
		}
	}

	void avpn_session::handle_container(std::string_view plaintext)
	{
		std::vector<std::string_view> entries;
		if (!parse_container(plaintext, entries))
			return;

		for (auto& entry : entries)
		{
			if (classify_payload(entry) == frame_kind::ip)
			{
				m_download_bytes += static_cast<int64_t>(entry.size());
				update_speed(m_down_stat,
					static_cast<int64_t>(entry.size()),
					std::chrono::steady_clock::now());
				deliver_ip_packet(
					std::vector<uint8_t>(entry.begin(), entry.end()));
			}
			else
			{
				handle_control_message(entry);
			}
		}
	}

	void avpn_session::handle_control_message(std::string_view plaintext)
	{
		uint8_t code = 0;
		std::string_view body;
		if (!parse_control_message(plaintext, code, body))
			return;

		switch (code)
		{
		case control_keepalive:
		{
			uint64_t ts = 0;
			if (body.size() >= 8)
				ts = get_u64_le(reinterpret_cast<const uint8_t*>(body.data()));
			send_keepalive_reply(ts);
			break;
		}
		case control_keepalive_reply:
			break;
		case control_disconnect:
			XLOG_INFO << "Peer requested disconnect";
			close();
			break;
		default:
			// 不认识的扩展消息按约定忽略.
			break;
		}
	}

	void avpn_session::deliver_ip_packet(std::vector<uint8_t> data)
	{
		if (m_abort || data.empty())
			return;
		if (m_ip_packet_handler)
			m_ip_packet_handler(std::move(data));
	}

	void avpn_session::send_keepalive(bool roam)
	{
		if (!m_established || m_abort)
			return;

		std::string body;
		put_u64_le(body, now_ms());

		std::string message;
		append_control_message(message, control_keepalive, as_view(body));
		send_plaintext(as_view(message), roam);
	}

	void avpn_session::send_keepalive_reply(uint64_t timestamp)
	{
		if (!m_established || m_abort)
			return;

		std::string body;
		put_u64_le(body, timestamp);

		std::string message;
		append_control_message(message, control_keepalive_reply, as_view(body));
		send_plaintext(as_view(message), m_datapath.has_roam_cookie());
	}

	void avpn_session::send_disconnect()
	{
		if (!m_established || m_abort)
			return;

		std::string message;
		append_control_message(message, control_disconnect, std::string_view());
		send_plaintext(as_view(message), m_datapath.has_roam_cookie());
	}

	// ------------------------------------------------------------------
	// 报文入口
	// ------------------------------------------------------------------

	bool avpn_session::on_udp_packet(const net::ip::udp::endpoint& remote,
		std::string_view data)
	{
		if (m_abort)
			return false;

		if (!m_established)
		{
			if (m_role == session_role::responder)
				return try_handshake(remote, data);

			if (!handle_handshake_msg2(data))
				return false;
			m_remote_udp = remote;
			return true;
		}

		if (!handle_wire(data))
			return false;

		if (remote != m_remote_udp)
			update_remote_udp(remote);
		return true;
	}

	void avpn_session::tun_submit(std::vector<uint8_t> ip_packet)
	{
		if (!m_established || m_abort || ip_packet.empty())
			return;

		// 一直在发却收不到下行: 这一帧顺带 cookie, 让对端尽快跟上换网.
		const bool nudge = m_datapath.has_roam_cookie() &&
			(std::chrono::steady_clock::now() - m_last_rx >= no_rx_nudge);
		send_plaintext(std::string_view(
			reinterpret_cast<const char*>(ip_packet.data()),
			ip_packet.size()), nudge);
	}

	// ------------------------------------------------------------------
	// 定时器
	// ------------------------------------------------------------------

	void avpn_session::start_tick()
	{
		if (m_tick_started)
			return;
		m_tick_started = true;

		auto self = shared_from_this();
		net::co_spawn(m_ioc, [this, self]() -> net::awaitable<void>
			{
				co_await tick();
				co_return;
			}, net::detached);
	}

	net::awaitable<void> avpn_session::tick()
	{
		auto self = shared_from_this();
		while (!m_abort && m_established)
		{
			boost::system::error_code ec;
			m_tick_timer.expires_after(std::chrono::seconds(1));
			co_await m_tick_timer.async_wait(net_awaitable[ec]);
			if (m_abort || !m_established)
				break;

			const auto now = std::chrono::steady_clock::now();
			const uint64_t now_milli = now_ms();

			// 保活: 让 NAT 映射不超时, 也让对端不把我们当掉线的会话.
			if (m_params.keepalive_sec > 0 &&
				now_milli - m_last_keepalive_ms >=
					static_cast<uint64_t>(m_params.keepalive_sec) * 1000)
			{
				send_keepalive(m_datapath.has_roam_cookie());
				m_last_keepalive_ms = now_milli;
			}

			// 一直在发却收不到下行: 补一个漫游帧.
			if (m_tx_since_rx && m_datapath.has_roam_cookie() &&
				now - m_last_rx >= no_rx_nudge)
			{
				send_keepalive(true);
				m_tx_since_rx = false;
			}

			// 纠错的收尾: 提前关组, 或放弃半满的组.
			for (auto& frame : m_datapath.tick(now_milli))
				queue_frame(frame);
			flush_udp_batch();

			// 对端太久没动静: 释放会话.
			if (now - m_last_seen >= peer_idle_timeout)
			{
				XLOG_WARN << "Peer idle timeout, closing session";
				close();
				break;
			}
		}
		co_return;
	}

	void avpn_session::update_speed(speed_stat& stat, int64_t bytes,
		std::chrono::steady_clock::time_point now)
	{
		stat.bytes_ += bytes;

		const auto elapsed = std::chrono::duration_cast<
			std::chrono::milliseconds>(now - stat.start_).count();
		if (elapsed < 1000)
			return;

		stat.rate_ = stat.bytes_ * 1000 / elapsed;
		stat.bytes_ = 0;
		stat.start_ = now;
	}

	// ------------------------------------------------------------------
	// 传输层
	// ------------------------------------------------------------------

	net::awaitable<void> avpn_session::run_initiator_udp(
		net::ip::udp::endpoint server)
	{
		auto self = shared_from_this();

		m_role = session_role::initiator;
		m_transport = transport_type::udp;
		m_remote_udp = server;

		if (m_peer_static_pub.empty())
		{
			XLOG_ERR << "Initiator requires peer public key (public_key_)";
			close();
			co_return;
		}

		// 每次握手都新生成一对临时密钥.
		auto kp = crypto::x25519_generate_keypair();
		m_eph_priv = kp.first;
		m_eph_pub = kp.second;

		m_hs_retry = 0;
		send_handshake_msg1();

		// 等握手回复 (带重发与超时).
		while (!m_established && !m_abort)
		{
			boost::system::error_code ec;
			m_hs_timer.expires_after(hs_retry_interval);
			co_await m_hs_timer.async_wait(net_awaitable[ec]);
			if (m_abort)
				break;

			if (!m_established)
			{
				if (++m_hs_retry > hs_max_retry)
					break;
				send_handshake_msg1();
			}
		}

		if (!m_established && !m_abort)
		{
			XLOG_WARN << "Handshake timeout";
			close();
		}

		co_return;
	}

	net::awaitable<void> avpn_session::run_initiator_tcp(
		net::ip::tcp::socket stream)
	{
		auto self = shared_from_this();

		m_role = session_role::initiator;
		m_transport = transport_type::tcp;
		m_tcp_stream = std::make_shared<tcp::socket>(std::move(stream));
		{
			boost::system::error_code ec;
			auto remote = m_tcp_stream->remote_endpoint(ec);
			if (!ec)
				m_remote_udp = net::ip::udp::endpoint(remote.address(),
					remote.port());
		}

		if (m_peer_static_pub.empty())
		{
			XLOG_ERR << "Initiator requires peer public key (public_key_)";
			close();
			co_return;
		}

		auto kp = crypto::x25519_generate_keypair();
		m_eph_priv = kp.first;
		m_eph_pub = kp.second;

		// 读取循环处理握手回复与后续数据帧.
		auto stream_ptr = m_tcp_stream;
		net::co_spawn(m_ioc,
			[this, self, stream_ptr]() -> net::awaitable<void>
			{
				co_await tcp_read_loop(*stream_ptr);
				co_return;
			}, net::detached);

		m_hs_retry = 0;
		send_handshake_msg1();

		while (!m_established && !m_abort)
		{
			boost::system::error_code ec;
			m_hs_timer.expires_after(hs_retry_interval);
			co_await m_hs_timer.async_wait(net_awaitable[ec]);
			if (m_abort)
				break;

			if (!m_established)
			{
				if (++m_hs_retry > hs_max_retry)
					break;
				send_handshake_msg1();
			}
		}

		if (!m_established && !m_abort)
		{
			XLOG_WARN << "Handshake timeout (tcp)";
			close();
		}

		co_return;
	}

	net::awaitable<void> avpn_session::run_responder_tcp(
		net::ip::tcp::socket stream)
	{
		auto self = shared_from_this();

		m_role = session_role::responder;
		m_transport = transport_type::tcp;
		m_tcp_stream = std::make_shared<tcp::socket>(std::move(stream));
		{
			boost::system::error_code ec;
			auto remote = m_tcp_stream->remote_endpoint(ec);
			if (!ec)
				m_remote_udp = net::ip::udp::endpoint(remote.address(),
					remote.port());
		}

		co_await tcp_read_loop(*m_tcp_stream);

		if (!m_established && !m_abort)
			close();

		co_return;
	}

	net::awaitable<void> avpn_session::tcp_read_loop(tcp::socket& stream)
	{
		std::vector<uint8_t> buf;
		std::vector<uint8_t> chunk(tcp_read_chunk);

		while (!m_abort && stream.is_open())
		{
			boost::system::error_code ec;
			const std::size_t n = co_await stream.async_read_some(
				net::buffer(chunk), net_awaitable[ec]);
			if (ec)
				break;

			buf.insert(buf.end(), chunk.begin(), chunk.begin() + n);

			// 按 2 字节大端长度拆帧.
			std::size_t pos = 0;
			while (buf.size() - pos >= 2)
			{
				const std::size_t len =
					(static_cast<std::size_t>(buf[pos]) << 8) | buf[pos + 1];
				if (len == 0 || len > tcp_max_frame)
				{
					pos = buf.size();
					break;
				}
				if (buf.size() - pos - 2 < len)
					break;

				const std::string_view frame(
					reinterpret_cast<const char*>(buf.data() + pos + 2),
					len);
				pos += 2 + len;

				if (!m_established)
				{
					if (m_role == session_role::responder)
						try_handshake(m_remote_udp, frame);
					else
						handle_handshake_msg2(frame);
				}
				else
				{
					handle_wire(frame);
				}
			}

			if (pos > 0)
				buf.erase(buf.begin(), buf.begin() + pos);
		}

		if (!m_abort)
		{
			XLOG_INFO << "TCP tunnel closed by peer";
			close();
		}
		co_return;
	}

	void avpn_session::update_remote_udp(const net::ip::udp::endpoint& remote)
	{
		m_remote_udp = remote;
	}

	void avpn_session::notify_network_changed()
	{
		if (!m_established || m_abort)
			return;

		// 网络刚变: 立刻发一个带 cookie 的保活, 让对端把回包发到新地址.
		send_keepalive(m_datapath.has_roam_cookie());
	}

	void avpn_session::disconnect()
	{
		if (m_abort)
			return;

		send_disconnect();
		close();
	}

	void avpn_session::close()
	{
		if (m_abort.exchange(true))
			return;

		m_established = false;

		boost::system::error_code ec;
		m_tick_timer.cancel();
		m_hs_timer.cancel();
		m_tcp_cork_timer.cancel();
		m_tcp_oqe.clear();

		if (m_tcp_stream && m_tcp_stream->is_open())
			m_tcp_stream->close(ec);
		m_udp_pending.clear();

		if (m_close_handler)
			m_close_handler(shared_from_this());
	}

} // namespace libavpn
