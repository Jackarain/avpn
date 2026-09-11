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
#include "libavpn/avpn_crypto.hpp"
#include "libavpn/avpn_obfuscate.hpp"
#include "libavpn/asio_util.hpp"
#include "libavpn/use_awaitable.hpp"
#include "libavpn/logging.hpp"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/ip/address_v4.hpp>

#include <algorithm>
#include <cstring>
#include <array>

namespace libavpn {

	namespace {

		// KDF 信息字符串.
		constexpr std::string_view kdf_temp_info = "avpn-handshake-temp-v1";
		constexpr std::string_view kdf_resp_info = "avpn-handshake-resp-v1";
		constexpr std::string_view kdf_session_master_info = "avpn-session-master-v1";
		constexpr std::string_view kdf_c2s_info = "avpn-session-c2s-v1";
		constexpr std::string_view kdf_s2c_info = "avpn-session-s2c-v1";
		constexpr std::string_view kdf_nonce_salt_c2s_info =
			"avpn-nonce-salt-c2s-v1";
		constexpr std::string_view kdf_nonce_salt_s2c_info =
			"avpn-nonce-salt-s2c-v1";

		// FEC 批量聚合: 批量载荷首字节标记 (IP 包首字节为版本号, 不会是 0).
		constexpr uint8_t fec_batch_marker = 0x00;

		// 批量聚合延迟刷新的最大等待时间.
		constexpr std::chrono::milliseconds fec_batch_flush_delay{ 2 };

		// 单个批量分组允许聚合的最大包数 (限制延迟).
		constexpr std::size_t fec_batch_max_packets = 64;

		// 能力协商消息标记 (FEC 批量聚合).
		constexpr std::array<uint8_t, 4> capability_magic{ 'A', 'V', 'B', '1' };

		// 能力协商消息标记 (自适应 FEC 分组).
		constexpr std::array<uint8_t, 4> capability_magic_v2{ 'A', 'V', 'B', '2' };

		// FEC 探测发送间隔 (仅链路活跃时发送).
		constexpr std::chrono::milliseconds fec_probe_interval{ 100 };

		// 距最近一次数据收发超过该时间则暂停探测.
		constexpr std::chrono::milliseconds fec_probe_idle{ 2000 };

		// 链路空闲或对端不支持时降低探测轮询频率, 避免持续唤醒.
		constexpr std::chrono::milliseconds fec_probe_idle_poll{ 1000 };

		// TCP 传输的写合并: 在写之前短暂等待, 把这段时间内到达的多个
		// 帧合并成一次写入. 小的逐帧写入会让内核按帧生成 TCP 段并逐段
		// 通知网卡, 在虚拟化环境下每包开销很高; 合并成较大的写入后可
		// 借助 TSO/GSO 让内核一次提交一个大段, 显著降低每字节开销.
		constexpr std::chrono::milliseconds tcp_cork_delay{ 2 };

		// 单次 TCP 写入合并的最大字节数 (避免过大的内存分配).
		constexpr std::size_t tcp_cork_max_bytes = 128 * 1024;

		// TCP 读取缓冲大小: 一次读取可包含多个帧, 减少异步操作次数.
		constexpr std::size_t tcp_read_chunk = 128 * 1024;

		// 当前时间 (毫秒).
		inline uint64_t now_ms()
		{
			return static_cast<uint64_t>(
				std::chrono::duration_cast<std::chrono::milliseconds>(
					std::chrono::system_clock::now().time_since_epoch()).count());
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
		, m_compressor(compress_type::none)
		, m_fec_flush_timer(ioc)
		, m_probe_timer(ioc)
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

		// 设置对端公钥.
		if (role == session_role::initiator)
		{
			// 对端为 gateway, 公钥来自 public_key_.
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
			// 对端公钥白名单.
			for (auto& pk : config.pkl_)
			{
				auto pub = crypto::base64_decode(pk);
				if (pub.size() == crypto::x25519_key_size)
					m_peer_pubs.push_back(std::move(pub));
			}
		}

		// 客户端身份 (32 字节).
		m_client_id = crypto::random_bytes(avpn_client_id_size);

		// 压缩器.
		m_compressor.set_type(compress_type_from_string(config.compress_));

	}

	// 按协商配置创建/重建 FEC 编解码器.
	void avpn_session::setup_fec()
	{
		int ds = std::max(1, static_cast<int>(m_session_config.data_shards));
		int ps = std::max(0, static_cast<int>(m_session_config.parity_shards));
		if (ds > 1 || ps > 0)
		{
			m_fec_encoder = std::make_unique<fec_encode_group>(ds, ps);
			m_fec_decoder = std::make_unique<fec_decode_group>(ds, ps);
		}
		else
		{
			m_fec_encoder.reset();
			m_fec_decoder.reset();
		}
	}

	avpn_session::~avpn_session()
	{
		XLOG_DBG << "avpn_session::~avpn_session, role: "
			<< static_cast<int>(m_role);
	}

	std::shared_ptr<avpn_session> avpn_session::create(
		net::io_context& ioc, const service_config& config, session_role role)
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

	// 动态修改保活间隔 (launcher update_config 热更新).
	void avpn_session::set_keepalive(int seconds)
	{
		m_session_config.keepalive = std::max(1, seconds);
	}

	//////////////////////////////////////////////////////////////////////////
	// 握手

	std::string avpn_session::derive_temp_key(
		const std::string& peer_static_pub) const
	{
		auto dh = crypto::x25519_ecdh(m_static_priv, peer_static_pub);
		if (dh.empty())
			return {};
		return crypto::hkdf_sha256(dh, "", kdf_temp_info,
			crypto::x25519_key_size);
	}

	std::string avpn_session::derive_resp_key(
		const std::string& peer_static_pub, const std::string& peer_eph_pub)
	{
		std::string dh_es, dh_ss;

		if (m_role == session_role::initiator)
		{
			// resp_key = HKDF(ECDH(TPrivC, SPubS), salt=ECDH(SPrivC, SPubS)).
			dh_es = crypto::x25519_ecdh(m_eph_priv, peer_static_pub);
			dh_ss = crypto::x25519_ecdh(m_static_priv, peer_static_pub);
		}
		else
		{
			// resp_key = HKDF(ECDH(SPrivS, TPubC), salt=ECDH(SPrivS, SPubC)).
			dh_es = crypto::x25519_ecdh(m_static_priv, peer_eph_pub);
			dh_ss = crypto::x25519_ecdh(m_static_priv, peer_static_pub);
		}

		if (dh_es.empty() || dh_ss.empty())
			return {};

		return crypto::hkdf_sha256(dh_es, dh_ss, kdf_resp_info,
			crypto::x25519_key_size);
	}

	bool avpn_session::derive_session_keys(const std::string& init_eph_priv,
		const std::string& init_static_priv,
		const std::string& resp_static_pub,
		const std::string& resp_eph_pub)
	{
		// 四个 DH 值.
		auto dh_ss = crypto::x25519_ecdh(init_static_priv, resp_static_pub);
		auto dh_se = crypto::x25519_ecdh(init_static_priv, resp_eph_pub);
		auto dh_es = crypto::x25519_ecdh(init_eph_priv, resp_static_pub);
		auto dh_ee = crypto::x25519_ecdh(init_eph_priv, resp_eph_pub);

		if (dh_ss.empty() || dh_se.empty() || dh_es.empty() || dh_ee.empty())
			return false;

		// 三个非静态 DH 值排序后拼接, 保证两端一致.
		std::array<std::string, 3> dh_rest = { dh_se, dh_es, dh_ee };
		std::sort(dh_rest.begin(), dh_rest.end());

		std::string ikm = dh_rest[0] + dh_rest[1] + dh_rest[2];
		auto master = crypto::hkdf_sha256(ikm, dh_ss,
			kdf_session_master_info, crypto::x25519_key_size);
		if (master.empty())
			return false;

		m_key_c2s = crypto::hkdf_sha256(master, "", kdf_c2s_info,
			crypto::x25519_key_size);
		m_key_s2c = crypto::hkdf_sha256(master, "", kdf_s2c_info,
			crypto::x25519_key_size);

		m_nonce_salt_c2s = crypto::hkdf_sha256(master, "",
			kdf_nonce_salt_c2s_info, crypto::aead_nonce_salt_size);
		m_nonce_salt_s2c = crypto::hkdf_sha256(master, "",
			kdf_nonce_salt_s2c_info, crypto::aead_nonce_salt_size);

		if (m_key_c2s.empty() || m_key_s2c.empty() ||
			m_nonce_salt_c2s.empty() || m_nonce_salt_s2c.empty())
			return false;

		// 初始化数据方向的可复用 AEAD 上下文, 失败时回退到逐包创建.
		m_send_aead.init(send_key());
		m_recv_aead.init(recv_key());

		// 新会话重置发送计数器与接收重放窗口.
		m_send_counter = 0;
		m_recv_replay.reset();

		return true;
	}

	void avpn_session::send_handshake_msg1()
	{
		if (m_peer_static_pub.empty())
		{
			XLOG_ERR << "No peer static public key configured";
			return;
		}

		handshake_msg1 msg1;
		std::memcpy(msg1.ephemeral_pub.data(), m_eph_pub.data(),
			std::min<std::size_t>(m_eph_pub.size(), msg1.ephemeral_pub.size()));
		msg1.timestamp = now_ms();
		std::memcpy(msg1.client_id.data(), m_client_id.data(),
			std::min<std::size_t>(m_client_id.size(), msg1.client_id.size()));
		msg1.requested_vaddr = m_config.vaddr_;

		auto plaintext = serialize_handshake_msg1(msg1);
		auto k_temp = derive_temp_key(m_peer_static_pub);
		if (k_temp.empty())
			return;

		auto nonce = crypto::random_bytes(crypto::aead_nonce_size);
		auto ciphertext = crypto::aead_encrypt(k_temp, nonce, plaintext);
		if (ciphertext.empty())
			return;

		// 组装 wire = nonce || ciphertext.
		std::vector<uint8_t> wire;
		wire.reserve(nonce.size() + ciphertext.size());
		wire.insert(wire.end(), nonce.begin(), nonce.end());
		wire.insert(wire.end(), ciphertext.begin(), ciphertext.end());

		// 握手消息不走加密数据通道, 直接按传输类型发送.
		if (m_transport == transport_type::udp)
			send_udp_wire(std::move(wire));
		else
		{
			// TCP: 长度前缀帧.
			if (!m_tcp_stream)
				return;
			std::vector<uint8_t> frame;
			frame.reserve(2 + wire.size());
			uint16_t len = static_cast<uint16_t>(wire.size());
			frame.push_back(static_cast<uint8_t>((len >> 8) & 0xff));
			frame.push_back(static_cast<uint8_t>(len & 0xff));
			frame.insert(frame.end(), wire.begin(), wire.end());
			m_tcp_oqe.push_back(std::move(frame));
			start_tcp_write();
		}
	}

	bool avpn_session::try_decrypt_handshake_msg1(std::string_view nonce,
		std::string_view ciphertext, handshake_msg1& msg1,
		std::string& matched_pub)
	{
		for (auto& pub : m_peer_pubs)
		{
			auto k_temp = derive_temp_key(pub);
			if (k_temp.empty())
				continue;

			auto plaintext = crypto::aead_decrypt(k_temp, nonce, ciphertext);
			if (plaintext.empty())
				continue;

			if (!deserialize_handshake_msg1(plaintext, msg1))
				continue;

			matched_pub = pub;
			return true;
		}

		return false;
	}

	bool avpn_session::check_anti_replay(const std::string& peer_pub,
		uint64_t ts)
	{
		auto now = now_ms();

		// 时间窗口 ±30 秒.
		if (ts > now + 30000 || ts + 30000 < now)
			return false;

		// 时间戳递增性检查.
		auto it = m_msg1_ts.find(peer_pub);
		if (it != m_msg1_ts.end() && ts <= it->second)
			return false;

		m_msg1_ts[peer_pub] = ts;
		return true;
	}

	bool avpn_session::try_handshake(const net::ip::udp::endpoint& remote,
		std::string_view data)
	{
		if (data.size() < crypto::aead_nonce_size + crypto::aead_tag_size)
			return false;

		std::string_view nonce(data.data(), crypto::aead_nonce_size);
		std::string_view ciphertext(data.data() + crypto::aead_nonce_size,
			data.size() - crypto::aead_nonce_size);

		handshake_msg1 msg1;
		std::string matched_pub;
		if (!try_decrypt_handshake_msg1(nonce, ciphertext, msg1, matched_pub))
			return false;

		// 防重放检查.
		if (!check_anti_replay(matched_pub, msg1.timestamp))
			return false;

		// 记录对端信息.
		m_peer_static_pub = matched_pub;
		m_peer_eph_pub.assign(msg1.ephemeral_pub.begin(),
			msg1.ephemeral_pub.end());
		m_client_id.assign(msg1.client_id.begin(), msg1.client_id.end());
		m_requested_vaddr = msg1.requested_vaddr;
		m_remote_udp = remote;

		// 回复 Message 2 并建立会话.
		send_handshake_msg2(matched_pub, msg1);

		if (m_established)
			start_tick();

		return true;
	}

	void avpn_session::send_handshake_msg2(const std::string& peer_static_pub,
		const handshake_msg1& msg1)
	{
		// 生成服务端临时密钥对.
		auto kp = crypto::x25519_generate_keypair();
		m_eph_priv = kp.first;
		m_eph_pub = kp.second;

		m_peer_static_pub = peer_static_pub;
		m_peer_eph_pub.assign(msg1.ephemeral_pub.begin(),
			msg1.ephemeral_pub.end());
		m_client_id.assign(msg1.client_id.begin(), msg1.client_id.end());

		// 分配虚拟地址.
		uint32_t vaddr = 0;
		uint8_t prefix = 0;
		if (m_vaddr_allocator)
			std::tie(vaddr, prefix) = m_vaddr_allocator(m_requested_vaddr);
		m_vaddr = vaddr;
		m_session_config = make_session_config(m_config, vaddr, prefix);
		// TCP 传输本身可靠, 无需 FEC.
		if (m_transport == transport_type::tcp)
		{
			m_session_config.data_shards = 1;
			m_session_config.parity_shards = 0;
		}
		setup_fec();

		// 派生会话密钥.
		if (!derive_session_keys(m_eph_priv, m_static_priv,
				peer_static_pub, m_peer_eph_pub))
		{
			XLOG_ERR << "derive session keys failed";
			return;
		}

		handshake_msg2 msg2;
		std::memcpy(msg2.ephemeral_pub.data(), m_eph_pub.data(),
			std::min<std::size_t>(m_eph_pub.size(), msg2.ephemeral_pub.size()));
		msg2.config = m_session_config;

		auto plaintext = serialize_handshake_msg2(msg2);
		auto resp_key = derive_resp_key(peer_static_pub, m_peer_eph_pub);
		if (resp_key.empty())
			return;

		auto nonce = crypto::random_bytes(crypto::aead_nonce_size);
		auto ciphertext = crypto::aead_encrypt(resp_key, nonce, plaintext);
		if (ciphertext.empty())
			return;

		std::vector<uint8_t> wire;
		wire.reserve(nonce.size() + ciphertext.size());
		wire.insert(wire.end(), nonce.begin(), nonce.end());
		wire.insert(wire.end(), ciphertext.begin(), ciphertext.end());

		if (m_transport == transport_type::udp)
			send_udp_wire(std::move(wire));
		else
		{
			if (!m_tcp_stream)
				return;
			std::vector<uint8_t> frame;
			frame.reserve(2 + wire.size());
			uint16_t len = static_cast<uint16_t>(wire.size());
			frame.push_back(static_cast<uint8_t>((len >> 8) & 0xff));
			frame.push_back(static_cast<uint8_t>(len & 0xff));
			frame.insert(frame.end(), wire.begin(), wire.end());
			m_tcp_oqe.push_back(std::move(frame));
			start_tcp_write();
		}

		m_established = true;
		m_last_seen = std::chrono::steady_clock::now();

		// 通知网关登记会话 (替换同公钥旧会话等).
		if (m_established_handler)
			m_established_handler();

		// 宣告本端能力 (FEC 批量聚合).
		send_capability();
	}

	bool avpn_session::handle_handshake_msg2(std::string_view plaintext)
	{
		handshake_msg2 msg2;
		if (!deserialize_handshake_msg2(plaintext, msg2))
			return false;

		// 记录对端临时公钥.
		m_peer_eph_pub.assign(msg2.ephemeral_pub.begin(),
			msg2.ephemeral_pub.end());
		m_session_config = msg2.config;
		// TCP 传输本身可靠, 无需 FEC.
		if (m_transport == transport_type::tcp)
		{
			m_session_config.data_shards = 1;
			m_session_config.parity_shards = 0;
		}
		setup_fec();
		m_vaddr = msg2.config.vaddr;

		// 派生会话密钥.
		if (!derive_session_keys(m_eph_priv, m_static_priv,
				m_peer_static_pub, m_peer_eph_pub))
			return false;

		m_established = true;
		m_last_seen = std::chrono::steady_clock::now();

		// 宣告本端能力 (FEC 批量聚合).
		send_capability();

		XLOG_INFO << "Handshake established, vaddr: "
			<< net::ip::address_v4(m_vaddr).to_string()
			<< ", compress: " << compress_type_to_string(m_session_config.compress)
			<< ", fec: " << static_cast<int>(m_session_config.data_shards)
			<< "/" << static_cast<int>(m_session_config.parity_shards);

		return true;
	}

	//////////////////////////////////////////////////////////////////////////
	// 数据路径

	void avpn_session::send_plaintext(const std::string& key,
		std::string_view plaintext)
	{
		if (m_abort)
			return;

		// 统计上行明文数据量 (含 FEC 帧开销).
		m_upload_bytes += static_cast<int64_t>(plaintext.size());

		if (m_transport == transport_type::udp)
		{
			queue_udp_frame(key, plaintext);
			flush_udp_batch();
		}
		else
			queue_tcp_frame(key, plaintext);
	}

	// 同一次逻辑发送产生的多个帧: 先入批, 由调用方最后统一提交,
	// 使 service 能把这批等长帧合并为一次提交 (UDP GSO).
	void avpn_session::send_plaintext_batched(const std::string& key,
		std::string_view plaintext)
	{
		if (m_abort)
			return;

		m_upload_bytes += static_cast<int64_t>(plaintext.size());

		if (m_transport == transport_type::udp)
			queue_udp_frame(key, plaintext);
		else
			queue_tcp_frame(key, plaintext);
	}

	std::array<char, crypto::aead_nonce_size> avpn_session::make_nonce(
		const std::string& salt, uint32_t counter) const
	{
		std::array<char, crypto::aead_nonce_size> nonce{};
		std::size_t n = std::min<std::size_t>(salt.size(), nonce.size());
		std::memcpy(nonce.data(), salt.data(), n);
		// 计数器以小端追加在末尾 4 字节.
		for (int i = 0; i < 4; i++)
			nonce[nonce.size() - 4 + i] =
				static_cast<char>((counter >> (i * 8)) & 0xff);
		return nonce;
	}

	std::vector<uint8_t> avpn_session::encrypt_frame(const std::string& key,
		uint32_t counter, std::string_view plaintext)
	{
		// 混淆开启时, 长度字段作为 AEAD 的 AAD 参与认证, 防篡改.
		std::string_view aad;
		bool obf = m_session_config.obfuscate;

		obfuscate_head head;
		std::size_t obf_overhead = 0;
		if (obf)
		{
			if (!make_obfuscate_head(m_config.obfuscate_key_, head))
				return {};
			aad = std::string_view(
				reinterpret_cast<const char*>(head.len_field.data()),
				head.len_field.size());
			obf_overhead = head.salt.size() + head.len_field.size() +
				head.garbage.size();
		}

		auto nonce = make_nonce(send_nonce_salt(), counter);
		std::string_view nonce_view(nonce.data(), nonce.size());

		// 直接加密进线上缓冲区, 省去中间密文缓冲区的分配与一次拷贝.
		const std::size_t body_offset =
			obf_overhead + crypto::aead_counter_size;
		std::vector<uint8_t> wire(body_offset + plaintext.size() +
			crypto::aead_tag_size);

		if (obf)
		{
			std::size_t off = 0;
			std::memcpy(wire.data() + off, head.salt.data(), head.salt.size());
			off += head.salt.size();
			std::memcpy(wire.data() + off, head.len_field.data(),
				head.len_field.size());
			off += head.len_field.size();
			std::memcpy(wire.data() + off, head.garbage.data(),
				head.garbage.size());
		}

		uint8_t* counter_at = wire.data() + obf_overhead;
		counter_at[0] = static_cast<uint8_t>(counter & 0xff);
		counter_at[1] = static_cast<uint8_t>((counter >> 8) & 0xff);
		counter_at[2] = static_cast<uint8_t>((counter >> 16) & 0xff);
		counter_at[3] = static_cast<uint8_t>((counter >> 24) & 0xff);

		std::size_t body_len = 0;
		if (m_send_aead.ready())
		{
			if (!m_send_aead.encrypt(nonce_view, plaintext, aad,
					wire.data() + body_offset, wire.size() - body_offset,
					body_len))
				return {};
		}
		else
		{
			// 上下文不可用时回退到逐包创建.
			auto ciphertext = crypto::aead_encrypt(key, nonce_view,
				plaintext, aad);
			if (ciphertext.size() != plaintext.size() + crypto::aead_tag_size)
				return {};
			std::memcpy(wire.data() + body_offset, ciphertext.data(),
				ciphertext.size());
			body_len = ciphertext.size();
		}

		wire.resize(body_offset + body_len);
		return wire;
	}

	void avpn_session::queue_udp_frame(const std::string& key,
		std::string_view plaintext)
	{
		if (m_abort)
			return;

		uint32_t counter = m_send_counter++;
		auto wire = encrypt_frame(key, counter, plaintext);
		if (wire.empty())
			return;

		m_udp_pending.push_back(std::move(wire));
	}

	void avpn_session::flush_udp_batch()
	{
		if (m_udp_pending.empty())
			return;

		// 同一批帧通常来自同一个 FEC 分组, 大小一致, service 可借助
		// UDP GSO 把它们合并为一次 sendmsg 提交.
		if (!m_abort && m_udp_send_handler)
			m_udp_send_handler(m_remote_udp, std::move(m_udp_pending));

		m_udp_pending.clear();
	}

	void avpn_session::send_udp_wire(std::vector<uint8_t> wire)
	{
		if (m_abort || wire.empty() || !m_udp_send_handler)
			return;

		std::vector<std::vector<uint8_t>> batch;
		batch.push_back(std::move(wire));
		m_udp_send_handler(m_remote_udp, std::move(batch));
	}

	void avpn_session::queue_tcp_frame(const std::string& key,
		std::string_view plaintext)
	{
		if (!m_tcp_stream)
			return;

		uint32_t counter = m_send_counter++;
		auto body = encrypt_frame(key, counter, plaintext);
		if (body.empty())
			return;

		std::vector<uint8_t> frame;
		frame.reserve(2 + body.size());
		uint16_t len = static_cast<uint16_t>(body.size());
		frame.push_back(static_cast<uint8_t>((len >> 8) & 0xff));
		frame.push_back(static_cast<uint8_t>(len & 0xff));
		frame.insert(frame.end(), body.begin(), body.end());

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
					// 合并队列中的多个帧: 取走已排队的帧, 若尚未达到
					// 上限且队列为空, 则等到合并窗口结束再写入.
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

						if (m_abort ||
							bytes >= tcp_cork_max_bytes ||
							std::chrono::steady_clock::now() >= deadline)
							break;

						// 队列暂时为空: 等到合并窗口结束, 期间到达
						// 的帧会被下一轮取走.
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

	bool avpn_session::process_udp_packet(std::string_view wire)
	{
		// 混淆开启时, 先剥离随机垃圾数据, 长度字段作为 AAD 参与认证.
		std::string_view len_field;
		if (m_session_config.obfuscate)
		{
			if (!deobfuscate_packet(m_config.obfuscate_key_, wire, wire, len_field))
				return true;
		}

		if (wire.size() < crypto::aead_counter_size + crypto::aead_tag_size)
			return true;

		uint32_t counter = byteorder::get_u32_le(
			reinterpret_cast<const uint8_t*>(wire.data()));
		std::string_view ciphertext(
			wire.data() + crypto::aead_counter_size,
			wire.size() - crypto::aead_counter_size);

		auto nonce = make_nonce(recv_nonce_salt(), counter);

		// 原地解密: 所有调用方的 wire 都指向可写的接收缓冲区,
		// 省去每包的明文缓冲区分配与一次拷贝.
		auto* plain_at = const_cast<uint8_t*>(
			reinterpret_cast<const uint8_t*>(ciphertext.data()));
		std::size_t plain_len = 0;

		if (m_recv_aead.ready())
		{
			if (!m_recv_aead.decrypt(
					std::string_view(nonce.data(), nonce.size()),
					ciphertext, len_field, plain_at,
					ciphertext.size() - crypto::aead_tag_size, plain_len))
			{
				// 解密失败则丢弃.
				return true;
			}
		}
		else
		{
			auto plaintext = crypto::aead_decrypt(recv_key(),
				std::string_view(nonce.data(), nonce.size()), ciphertext,
				len_field);
			if (plaintext.empty())
				return true;
			std::memcpy(plain_at, plaintext.data(), plaintext.size());
			plain_len = plaintext.size();
		}

		std::string_view plaintext(
			reinterpret_cast<const char*>(plain_at), plain_len);

		// 认证通过后更新重放窗口.
		if (!m_recv_replay.check_and_update(counter))
			return true;

		m_last_seen = std::chrono::steady_clock::now();
		process_plaintext(plaintext);
		return true;
	}

	void avpn_session::process_plaintext(std::string_view plaintext)
	{
		if (plaintext.empty())
			return;

		// 统计下行明文数据量.
		m_download_bytes += static_cast<int64_t>(plaintext.size());

		msg_type type = static_cast<msg_type>(plaintext[0]);
		std::string_view body = plaintext.substr(1);

		// 收到数据即视为链路活跃, 单向流量下接收端也要继续探测.
		if (type == msg_type::data || type == msg_type::data_raw ||
			type == msg_type::data_afec)
			m_last_data_activity = std::chrono::steady_clock::now();

		switch (type)
		{
		case msg_type::data:
			process_data_msg(body);
			break;
		case msg_type::data_raw:
			// 未经 fec 编码的数据消息, 载荷可能仍是批量聚合.
			if (!body.empty() && body[0] == fec_batch_marker)
				parse_fec_batch(body);
			else
				deliver_ip_packet(std::vector<uint8_t>(
					body.begin(), body.end()));
			break;
		case msg_type::data_afec:
			process_afec_msg(body);
			break;
		case msg_type::fec_probe:
			handle_fec_probe(body);
			break;
		case msg_type::keepalive:
		{
			uint64_t ts = 0;
			if (body.size() >= 8)
			{
				ts = static_cast<uint64_t>(
					static_cast<unsigned char>(body[0])) |
					(static_cast<uint64_t>(
						static_cast<unsigned char>(body[1])) << 8) |
					(static_cast<uint64_t>(
						static_cast<unsigned char>(body[2])) << 16) |
					(static_cast<uint64_t>(
						static_cast<unsigned char>(body[3])) << 24) |
					(static_cast<uint64_t>(
						static_cast<unsigned char>(body[4])) << 32) |
					(static_cast<uint64_t>(
						static_cast<unsigned char>(body[5])) << 40) |
					(static_cast<uint64_t>(
						static_cast<unsigned char>(body[6])) << 48) |
					(static_cast<uint64_t>(
						static_cast<unsigned char>(body[7])) << 56);
			}
			send_keepalive_reply(ts);
			break;
		}
		case msg_type::keepalive_reply:
			break;
		case msg_type::ack:
		{
			// 对端能力协商.
			if (body.size() >= capability_magic_v2.size() &&
				std::memcmp(body.data(), capability_magic_v2.data(),
					capability_magic_v2.size()) == 0)
			{
				XLOG_INFO << "Peer announces adaptive FEC capability";
				m_peer_fec_batch = true;
				m_peer_fec_adaptive = true;
				m_cap_announce_left = 0;
			}
			// 声明支持 FEC 批量聚合 (旧版本能力).
			else if (body.size() >= capability_magic.size() &&
				std::memcmp(body.data(), capability_magic.data(),
					capability_magic.size()) == 0)
			{
				XLOG_INFO << "Peer announces FEC batch capability";
				m_peer_fec_batch = true;
			}
			break;
		}
		case msg_type::disconnect:
			XLOG_INFO << "Peer sent disconnect";
			close();
			break;
		default:
			break;
		}
	}

	void avpn_session::process_data_msg(std::string_view body)
	{
		if (m_fec_decoder && m_session_config.data_shards > 1)
		{
			// FEC 分片.
			if (body.size() < fec_frame_header_size)
				return;

			const uint8_t* p =
				reinterpret_cast<const uint8_t*>(body.data());
			uint32_t seq = byteorder::get_u32_le(p);
			uint16_t len = byteorder::get_u16_le(p + 4);
			std::string_view shard = body.substr(fec_frame_header_size);

			std::vector<uint8_t> ip_packet;
			if (m_fec_decoder->add(seq, len, shard, ip_packet))
				deliver_recovered_payload(std::move(ip_packet));
		}
		else
		{
			std::vector<uint8_t> data(body.begin(), body.end());
			deliver_ip_packet(std::move(data));
		}
	}

	void avpn_session::process_afec_msg(std::string_view body)
	{
		if (!m_fec_decoder)
			return;

		// 自适应 FEC 分片.
		if (body.size() < afec_frame_header_size)
			return;

		const uint8_t* p = reinterpret_cast<const uint8_t*>(body.data());
		uint32_t fec_id = byteorder::get_u32_le(p);
		uint8_t pid = p[4];
		uint8_t data_shards = p[5];
		uint8_t parity_shards = p[6];
		uint16_t len = byteorder::get_u16_le(p + 7);
		std::string_view shard = body.substr(afec_frame_header_size);

		std::vector<uint8_t> ip_packet;
		if (m_fec_decoder->add_adaptive(fec_id, pid, data_shards,
				parity_shards, len, shard, ip_packet))
			deliver_recovered_payload(std::move(ip_packet));
	}

	void avpn_session::deliver_recovered_payload(std::vector<uint8_t> payload)
	{
		// 批量聚合载荷以 0x00 标记开头, 需拆分为多个 IP 包.
		if (!payload.empty() && payload[0] == fec_batch_marker)
			parse_fec_batch(std::string_view(
				reinterpret_cast<const char*>(payload.data()),
				payload.size()));
		else
			deliver_ip_packet(std::move(payload));
	}

	void avpn_session::deliver_ip_packet(std::vector<uint8_t> data)
	{
		if (m_compressor.enabled())
		{
			std::vector<uint8_t> decompressed;
			if (!m_compressor.decompress(
					std::string_view(reinterpret_cast<const char*>(data.data()),
						data.size()),
					decompressed, avpn_max_mtu))
				return;

			if (m_ip_packet_handler)
				m_ip_packet_handler(std::move(decompressed));
		}
		else
		{
			if (m_ip_packet_handler)
				m_ip_packet_handler(std::move(data));
		}
	}

	void avpn_session::send_data_message(const std::vector<uint8_t>& ip_packet)
	{
		if (!m_established || m_abort)
			return;

		m_last_data_activity = std::chrono::steady_clock::now();

		// 先压缩.
		std::vector<uint8_t> compressed;
		std::string_view payload(
			reinterpret_cast<const char*>(ip_packet.data()), ip_packet.size());

		if (m_compressor.enabled())
		{
			if (!m_compressor.compress(payload, compressed))
				return;
			payload = std::string_view(
				reinterpret_cast<const char*>(compressed.data()),
				compressed.size());
		}

		const auto& key = send_key();

		if (m_fec_encoder && m_session_config.data_shards > 1)
		{
			// 对端支持时聚合为一批发送, 使分片接近 MTU, 避免逐包拆分
			// 造成包数放大; 否则按单包拆分以兼容旧版本对端.
			if (m_peer_fec_batch)
				append_fec_batch(payload);
			else
				encode_and_send_fec(payload);
		}
		else
		{
			// 无 FEC, 当 data_shards <= 1 且 parity_shards > 0 时按倍数发包.
			int copies = 1;
			if (m_session_config.data_shards <= 1 &&
				m_session_config.parity_shards > 0)
			{
				copies = static_cast<int>(m_session_config.parity_shards) + 1;
			}

			auto& plaintext = m_send_scratch;
			plaintext.clear();
			plaintext.reserve(1 + payload.size());
			plaintext.push_back(static_cast<uint8_t>(msg_type::data));
			plaintext.insert(plaintext.end(), payload.begin(), payload.end());

			std::string_view frame(
				reinterpret_cast<const char*>(plaintext.data()),
				plaintext.size());
			for (int i = 0; i < copies; i++)
				send_plaintext_batched(key, frame);
			flush_udp_batch();
		}
	}

	// 将单个载荷 FEC 编码后逐片加密发送.
	void avpn_session::encode_and_send_fec(std::string_view payload)
	{
		if (!m_fec_encoder)
			return;

		std::vector<std::vector<uint8_t>> frames;
		if (!m_fec_encoder->encode(++m_fec_id, payload, frames))
			return;

		const auto& key = send_key();
		for (auto& frame : frames)
		{
			auto& plaintext = m_send_scratch;
			plaintext.clear();
			plaintext.reserve(1 + frame.size());
			plaintext.push_back(static_cast<uint8_t>(msg_type::data));
			plaintext.insert(plaintext.end(), frame.begin(), frame.end());
			send_plaintext_batched(key, std::string_view(
				reinterpret_cast<const char*>(plaintext.data()),
				plaintext.size()));
		}
		flush_udp_batch();
	}

	// 按指定分片数做自适应 FEC 编码后逐片加密发送.
	void avpn_session::encode_and_send_afec(std::string_view payload,
		int data_shards, int parity_shards)
	{
		if (!m_fec_encoder)
			return;

		std::vector<std::vector<uint8_t>> frames;
		if (!m_fec_encoder->encode_variable(++m_fec_id, data_shards,
				parity_shards, payload, frames))
			return;

		const auto& key = send_key();
		for (auto& frame : frames)
		{
			auto& plaintext = m_send_scratch;
			plaintext.clear();
			plaintext.reserve(1 + frame.size());
			plaintext.push_back(static_cast<uint8_t>(msg_type::data_afec));
			plaintext.insert(plaintext.end(), frame.begin(), frame.end());
			send_plaintext_batched(key, std::string_view(
				reinterpret_cast<const char*>(plaintext.data()),
				plaintext.size()));
		}
		flush_udp_batch();
	}

	// 批量分组内单个分片的目标大小 (扣除加密/帧头开销后的 MTU).
	std::size_t avpn_session::fec_batch_shard_target() const
	{
		std::size_t overhead = 1 + fec_frame_header_size +
			crypto::aead_counter_size + crypto::aead_tag_size;
		if (m_session_config.obfuscate)
			overhead += obfuscate_max_overhead;

		std::size_t mtu = static_cast<std::size_t>(
			std::max(576, static_cast<int>(m_session_config.mtu)));
		if (mtu <= overhead + 64)
			return 64;
		return mtu - overhead;
	}

	std::size_t avpn_session::fec_batch_max_payload() const
	{
		std::size_t ds = std::max<std::size_t>(1,
			m_session_config.data_shards);
		return fec_batch_shard_target() * ds;
	}

	// 将一个载荷追加到当前批量分组, 达到阈值或超时后刷新.
	void avpn_session::append_fec_batch(std::string_view payload)
	{
		const std::size_t max_payload = fec_batch_max_payload();

		// 单个载荷本身过大, 直接走单包编码 (内部仍被拆分为多个分片).
		if (payload.size() + 2 > max_payload)
		{
			flush_fec_batch();
			encode_and_send_fec(payload);
			return;
		}

		if (!m_fec_pending.empty() &&
			m_fec_pending.size() + 2 + payload.size() > max_payload)
			flush_fec_batch();

		std::size_t len = payload.size();
		std::size_t off = m_fec_pending.size();
		m_fec_pending.resize(off + 2 + len);
		m_fec_pending[off] = static_cast<uint8_t>((len >> 8) & 0xff);
		m_fec_pending[off + 1] = static_cast<uint8_t>(len & 0xff);
		std::memcpy(m_fec_pending.data() + off + 2, payload.data(), len);
		++m_fec_pending_count;

		if (m_fec_pending.size() >= max_payload ||
			m_fec_pending_count >= fec_batch_max_packets)
			flush_fec_batch();
		else
			arm_fec_flush_timer();
	}

	void avpn_session::arm_fec_flush_timer()
	{
		if (m_fec_flush_armed)
			return;
		m_fec_flush_armed = true;

		auto self = shared_from_this();
		m_fec_flush_timer.expires_after(fec_batch_flush_delay);
		m_fec_flush_timer.async_wait(
			[this, self](const boost::system::error_code& ec)
			{
				if (ec)
					return;
				m_fec_flush_armed = false;
				flush_fec_batch();
			});
	}

	void avpn_session::flush_fec_batch()
	{
		if (m_fec_flush_armed)
		{
			m_fec_flush_armed = false;
			boost::system::error_code ec;
			asio_util::cancel(m_fec_flush_timer, ec);
		}

		if (m_fec_pending.empty())
			return;

		std::vector<uint8_t> payload;
		payload.reserve(m_fec_pending.size() + 1);
		payload.push_back(fec_batch_marker);
		payload.insert(payload.end(), m_fec_pending.begin(), m_fec_pending.end());

		const std::size_t pending_count = m_fec_pending_count;
		m_fec_pending.clear();
		m_fec_pending_count = 0;

		// 载荷能装进单个数据包时不做 fec 编码: 否则会被补齐成 ds+ps 个
		// 分片, 包数放大数倍, 在低速链路上反而把物理链路打满.
		// 封装开销 = 消息类型(1) + nonce + aead tag + IP/UDP 头.
		constexpr std::size_t raw_frame_overhead =
			1 + crypto::aead_counter_size + crypto::aead_tag_size + 28;
		if ((pending_count == 1 ||
				payload.size() <= fec_batch_shard_target()) &&
			payload.size() + raw_frame_overhead <= avpn_max_mtu)
		{
			auto& plaintext = m_send_scratch;
			plaintext.clear();
			plaintext.reserve(1 + payload.size());
			plaintext.push_back(static_cast<uint8_t>(msg_type::data_raw));
			plaintext.insert(plaintext.end(), payload.begin(), payload.end());
			send_plaintext(send_key(), std::string_view(
				reinterpret_cast<const char*>(plaintext.data()),
				plaintext.size()));
			return;
		}

		// 自适应分组: 载荷未填满整个分组时按需缩小分片数, 在保留 FEC
		// 保护的前提下减少数据报数量.
		const int ds = static_cast<int>(m_session_config.data_shards);
		const int ps = static_cast<int>(m_session_config.parity_shards);
		// 对端探测显示链路持续无丢包时关闭冗余分片 (仅影响本端发送方向).
		const int ps_cfg = m_fec_parity_off ? 0 : ps;
		if (m_peer_fec_adaptive && ds + ps_cfg <= afec_max_shards)
		{
			const std::size_t target = fec_batch_shard_target();
			int use_ds = static_cast<int>(
				(payload.size() + target - 1) / target);
			use_ds = std::clamp(use_ds, 1, std::max(1, ds));
			const int use_ps = ps_cfg > 0
				? std::clamp((use_ds * ps_cfg + ds - 1) / ds, 1, ps_cfg)
				: 0;
			if (use_ds < ds || use_ps != ps)
			{
				encode_and_send_afec(
					std::string_view(
						reinterpret_cast<const char*>(payload.data()),
						payload.size()), use_ds, use_ps);
				return;
			}
		}

		encode_and_send_fec(std::string_view(
			reinterpret_cast<const char*>(payload.data()), payload.size()));
	}

	// 拆分并交付批量分组中的各个 IP 包.
	void avpn_session::parse_fec_batch(std::string_view payload)
	{
		std::size_t pos = 1;
		while (pos + 2 <= payload.size())
		{
			uint16_t len = static_cast<uint16_t>(
				(static_cast<uint8_t>(payload[pos]) << 8) |
				static_cast<uint8_t>(payload[pos + 1]));
			pos += 2;
			if (len == 0 || pos + len > payload.size())
				break;

			deliver_ip_packet(std::vector<uint8_t>(
				payload.begin() + pos, payload.begin() + pos + len));
			pos += len;
		}
	}

	// 发送能力协商消息 (使用预留的 ack 类型, 旧版本对端会忽略).
	void avpn_session::send_capability()
	{
		if (!m_established || m_abort)
			return;

		// 逐条发送各项能力 (旧版本对端不认识的消息将被忽略).
		constexpr std::array<std::array<uint8_t, 4>, 2> magics{
			capability_magic, capability_magic_v2
		};
		for (const auto& magic : magics)
		{
			std::vector<uint8_t> plaintext;
			plaintext.reserve(1 + magic.size());
			plaintext.push_back(static_cast<uint8_t>(msg_type::ack));
			plaintext.insert(plaintext.end(),
				magic.begin(), magic.end());
			send_plaintext(send_key(), std::string_view(
				reinterpret_cast<const char*>(plaintext.data()),
				plaintext.size()));
		}
	}

	// 发送一个 FEC 探测包: [seq(4)][丢包标记(1)].
	// 丢包标记为本端对"对端探测"的观测结果, 对端据此调整其发送方向冗余.
	void avpn_session::send_fec_probe()
	{
		if (!m_established || m_abort)
			return;

		std::vector<uint8_t> body;
		body.reserve(1 + 4 + 1);
		body.push_back(static_cast<uint8_t>(msg_type::fec_probe));
		byteorder::put_u32_into(body, m_probe_seq++);
		body.push_back(m_probe_tracker.report());
		send_plaintext(send_key(), std::string_view(
			reinterpret_cast<const char*>(body.data()), body.size()));
	}

	void avpn_session::handle_fec_probe(std::string_view body)
	{
		if (body.size() < 5)
			return;

		const uint8_t* p = reinterpret_cast<const uint8_t*>(body.data());
		uint32_t seq = byteorder::get_u32_le(p);
		uint8_t loss = p[4];

		// 对端反馈其接收方向 (本端发送方向) 的链路质量: 滞回判断在对端
		// 完成, 这里直接跟随, 有丢包立即恢复配置冗余.
		if (loss != m_peer_loss_report)
		{
			m_peer_loss_report = loss;
			XLOG_INFO << "FEC peer reports loss=" << static_cast<int>(loss)
				<< ", vaddr: " << net::ip::address_v4(m_vaddr).to_string();
		}
		const bool parity_off = loss == 0;
		if (parity_off != m_fec_parity_off)
		{
			m_fec_parity_off = parity_off;
			XLOG_INFO << "FEC parity " << (parity_off ? "disabled" : "enabled")
				<< ", vaddr: " << net::ip::address_v4(m_vaddr).to_string();
		}

		// 统计对端探测的到达情况 (迟到/重复探测不记为丢包).
		m_probe_tracker.on_probe(seq);
	}

	net::awaitable<void> avpn_session::probe_loop()
	{
		auto self = shared_from_this();
		auto interval = fec_probe_interval;

		while (!m_abort)
		{
			boost::system::error_code ec;
			m_probe_timer.expires_after(interval);
			co_await m_probe_timer.async_wait(net_awaitable[ec]);
			if (m_abort)
				break;

			// 仅在链路活跃且对端支持时探测, 空闲时降低轮询频率,
			// 避免持续唤醒射频.
			auto now = std::chrono::steady_clock::now();
			if (!m_established || !m_peer_fec_adaptive ||
				(now - m_last_data_activity) > fec_probe_idle)
			{
				interval = fec_probe_idle_poll;
				continue;
			}

			interval = fec_probe_interval;
			send_fec_probe();
		}
		co_return;
	}

	void avpn_session::start_probe_loop()
	{
		if (m_probe_started)
			return;
		m_probe_started = true;

		auto self = shared_from_this();
		net::co_spawn(m_ioc,
			[this, self]() -> net::awaitable<void>
			{
				co_await probe_loop();
				co_return;
			}, net::detached);
	}

	//////////////////////////////////////////////////////////////////////////
	// 保活 / 超时

	void avpn_session::send_keepalive()
	{
		if (!m_established || m_abort)
			return;

		std::vector<uint8_t> body;
		body.push_back(static_cast<uint8_t>(msg_type::keepalive));
		byteorder::put_u64_into(body, now_ms());

		send_plaintext(send_key(), std::string_view(
			reinterpret_cast<const char*>(body.data()), body.size()));
		m_last_keepalive = std::chrono::steady_clock::now();
	}

	void avpn_session::send_keepalive_reply(uint64_t timestamp)
	{
		if (!m_established || m_abort)
			return;

		std::vector<uint8_t> body;
		body.push_back(static_cast<uint8_t>(msg_type::keepalive_reply));
		byteorder::put_u64_into(body, timestamp);

		send_plaintext(send_key(), std::string_view(
			reinterpret_cast<const char*>(body.data()), body.size()));
	}

	net::awaitable<void> avpn_session::tick()
	{
		auto self = shared_from_this();

		while (!m_abort)
		{
			boost::system::error_code ec;
			m_tick_timer.expires_after(std::chrono::seconds(1));
			co_await m_tick_timer.async_wait(net_awaitable[ec]);
			if (m_abort)
				break;

			if (!m_established)
				continue;

			// 能力协商消息重发 (对端为旧版本时不会回应).
			if ((!m_peer_fec_batch || !m_peer_fec_adaptive) &&
				m_cap_announce_left > 0)
			{
				send_capability();
				--m_cap_announce_left;
			}

			auto now = std::chrono::steady_clock::now();
			int keepalive = std::max<int>(1, m_session_config.keepalive);

			// 带宽速率采样.
			update_speed(m_upload_stat, m_upload_bytes, now);
			update_speed(m_down_stat, m_download_bytes, now);

			// 超时释放.
			if ((now - m_last_seen) > std::chrono::seconds(keepalive * 3))
			{
				XLOG_WARN << "Session timeout, close";
				close();
				break;
			}

			// 保活.
			if ((now - m_last_keepalive) > std::chrono::seconds(keepalive))
				send_keepalive();
		}

		co_return;
	}

	void avpn_session::start_tick()
	{
		// 握手路径与 run_responder_tcp 可能重复调用: 同一会话只允许一个
		// tick 协程, 多个协程共享 m_tick_timer 会互相取消导致 tick 停摆.
		if (m_tick_started)
			return;
		m_tick_started = true;

		auto self = shared_from_this();
		net::co_spawn(m_ioc,
			[this, self]() -> net::awaitable<void>
			{
				co_await tick();
				co_return;
			}, net::detached);

		start_probe_loop();
	}

	//////////////////////////////////////////////////////////////////////////
	// 公开接口

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

		// 生成临时密钥对.
		auto kp = crypto::x25519_generate_keypair();
		m_eph_priv = kp.first;
		m_eph_pub = kp.second;

		m_hs_retry = 0;
		send_handshake_msg1();

		// 等待握手完成 (带重发与超时).
		while (!m_established && !m_abort)
		{
			boost::system::error_code ec;
			m_hs_timer.expires_after(std::chrono::seconds(5));
			co_await m_hs_timer.async_wait(net_awaitable[ec]);
			if (m_abort)
				break;

			if (!m_established)
			{
				if (++m_hs_retry > 5)
					break;
				send_handshake_msg1();
			}
		}

		if (!m_established && !m_abort)
		{
			XLOG_WARN << "Handshake timeout";
			close();
		}
		else if (m_established)
		{
			start_tick();
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
		// 记录对端地址 (状态上报用).
		{
			boost::system::error_code ec;
			auto remote = m_tcp_stream->remote_endpoint(ec);
			if (!ec)
				m_remote_udp = net::ip::udp::endpoint(remote.address(), remote.port());
		}

		if (m_peer_static_pub.empty())
		{
			XLOG_ERR << "Initiator requires peer public key (public_key_)";
			close();
			co_return;
		}

		// 生成临时密钥对.
		auto kp = crypto::x25519_generate_keypair();
		m_eph_priv = kp.first;
		m_eph_pub = kp.second;

		// 启动 TCP 读取循环 (处理握手 Message 2 与后续数据帧).
		auto stream_ptr = m_tcp_stream;
		net::co_spawn(m_ioc,
			[this, self, stream_ptr]() -> net::awaitable<void>
			{
				co_await tcp_read_loop(*stream_ptr);
				co_return;
			}, net::detached);

		// 发送握手 Message 1.
		send_handshake_msg1();

		// 等待握手 Message 2 (带重发与超时).
		while (!m_established && !m_abort)
		{
			boost::system::error_code ec;
			m_hs_timer.expires_after(std::chrono::seconds(5));
			co_await m_hs_timer.async_wait(net_awaitable[ec]);
			if (m_abort)
				break;

			if (!m_established)
			{
				if (++m_hs_retry > 5)
					break;
				send_handshake_msg1();
			}
		}

		if (!m_established && !m_abort)
		{
			XLOG_WARN << "Handshake timeout (tcp)";
			close();
		}
		else if (m_established)
		{
			start_tick();
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
		auto stream_ptr = m_tcp_stream;
		// 记录对端地址 (状态上报用).
		{
			boost::system::error_code ec;
			auto remote = m_tcp_stream->remote_endpoint(ec);
			if (!ec)
				m_remote_udp = net::ip::udp::endpoint(remote.address(), remote.port());
		}

		// 等待握手完成.
		while (!m_established && !m_abort)
		{
			std::array<uint8_t, 2> lenbuf;
			boost::system::error_code ec;
			co_await net::async_read(*stream_ptr, net::buffer(lenbuf),
				net_awaitable[ec]);
			if (ec || m_abort)
				break;

			uint16_t len = static_cast<uint16_t>(
				(static_cast<uint16_t>(lenbuf[0]) << 8) | lenbuf[1]);
			if (len == 0 || len > avpn_max_packet_size)
				break;

			std::vector<uint8_t> wire(len);
			co_await net::async_read(*stream_ptr, net::buffer(wire),
				net_awaitable[ec]);
			if (ec || m_abort)
				break;

			on_udp_packet(m_remote_udp, std::string_view(
				reinterpret_cast<const char*>(wire.data()), wire.size()));
		}

		if (!m_established && !m_abort)
		{
			close();
			co_return;
		}

		start_tick();
		co_await tcp_read_loop(*stream_ptr);
		co_return;
	}

	net::awaitable<void> avpn_session::tcp_read_loop(tcp::socket& stream)
	{
		// 批量读取: 一次读取尽量多的数据再逐帧解析. 逐帧异步读取
		// (每帧两次读) 在高包速率下会产生大量异步操作和堆分配,
		// 是 TCP 传输的主要开销之一.
		std::vector<uint8_t> buf(tcp_read_chunk);
		std::size_t begin = 0;
		std::size_t end = 0;
		auto space = [&]() { return buf.size() - end; };

		while (!m_abort)
		{
			// 先把已解析部分前移, 为后续读取腾出空间.
			if (begin > 0)
			{
				if (end > begin)
					std::memmove(buf.data(), buf.data() + begin,
						end - begin);
				end -= begin;
				begin = 0;
			}

			// 读到至少一个长度头.
			while (end - begin < 2 && !m_abort)
			{
				boost::system::error_code ec;
				std::size_t n = co_await stream.async_read_some(
					net::buffer(buf.data() + end, space()),
					net_awaitable[ec]);
				if (ec || n == 0)
				{
					if (!m_abort)
						close();
					co_return;
				}
				end += n;

				if (space() == 0)
				{
					// 缓冲已满仍无完整数据 (异常帧), 避免死循环.
					if (!m_abort)
						close();
					co_return;
				}
			}

			uint16_t len = static_cast<uint16_t>(
				(static_cast<uint16_t>(buf[begin]) << 8) | buf[begin + 1]);
			if (len == 0 || len > avpn_max_packet_size)
			{
				if (!m_abort)
					close();
				co_return;
			}

			// 读到完整帧体.
			while (end - begin < 2 + static_cast<std::size_t>(len) &&
				!m_abort)
			{
				boost::system::error_code ec;
				std::size_t n = co_await stream.async_read_some(
					net::buffer(buf.data() + end, space()),
					net_awaitable[ec]);
				if (ec || n == 0)
				{
					if (!m_abort)
						close();
					co_return;
				}
				end += n;

				if (space() == 0)
				{
					if (!m_abort)
						close();
					co_return;
				}
			}

			// 握手期间由 on_udp_packet 处理 Message 1/2,
			// 建立后处理数据帧.
			on_udp_packet(m_remote_udp, std::string_view(
				reinterpret_cast<const char*>(buf.data() + begin + 2), len));
			begin += 2 + static_cast<std::size_t>(len);
		}

		if (!m_abort)
			close();

		co_return;
	}

	bool avpn_session::on_udp_packet(const net::ip::udp::endpoint& remote,
		std::string_view data)
	{
		if (m_abort)
			return true;

		if (!m_established)
		{
			if (m_role == session_role::initiator)
			{
				// 期望握手 Message 2.
				if (data.size() < crypto::aead_nonce_size +
						crypto::aead_tag_size)
					return false;

				std::string_view nonce(data.data(), crypto::aead_nonce_size);
				std::string_view ciphertext(
					data.data() + crypto::aead_nonce_size,
					data.size() - crypto::aead_nonce_size);

				auto resp_key = derive_resp_key(m_peer_static_pub, {});
				if (resp_key.empty())
					return false;

				auto plaintext = crypto::aead_decrypt(resp_key, nonce,
					ciphertext);
				if (plaintext.empty())
					return false;

				if (!handle_handshake_msg2(plaintext))
					return false;

				// 通知握手协程握手完成.
				boost::system::error_code ec;
				asio_util::cancel(m_hs_timer, ec);
				return true;
			}
			else
			{
				// responder: 尝试握手 Message 1.
				return try_handshake(remote, data);
			}
		}

		// 已建立: 处理数据帧.
		m_last_seen = std::chrono::steady_clock::now();
		process_udp_packet(data);
		return true;
	}

	void avpn_session::tun_submit(std::vector<uint8_t> ip_packet)
	{
		if (!m_established || m_abort)
			return;

		net::post(m_ioc,
			[self = shared_from_this(), pkt = std::move(ip_packet)]() mutable
			{
				self->send_data_message(pkt);
			});
	}

	bool avpn_session::try_decrypt_udp(std::string_view data) const
	{
		if (!m_established || m_abort)
			return false;
		if (m_transport != transport_type::udp)
			return false;

		std::string_view len_field;
		if (m_session_config.obfuscate)
		{
			if (!deobfuscate_packet(m_config.obfuscate_key_, data, data, len_field))
				return false;
		}
		if (data.size() < crypto::aead_counter_size + crypto::aead_tag_size)
			return false;

		uint32_t counter = byteorder::get_u32_le(
			reinterpret_cast<const uint8_t*>(data.data()));
		std::string_view ciphertext(
			data.data() + crypto::aead_counter_size,
			data.size() - crypto::aead_counter_size);

		// 用本会话接收密钥尝试解密, 仅判断认证是否成功.
		auto nonce = make_nonce(recv_nonce_salt(), counter);
		return !crypto::aead_decrypt(recv_key(),
			std::string_view(nonce.data(), nonce.size()), ciphertext,
			len_field).empty();
	}

	void avpn_session::update_remote_udp(const net::ip::udp::endpoint& remote)
	{
		m_remote_udp = remote;
		m_last_seen = std::chrono::steady_clock::now();
	}

	void avpn_session::notify_network_changed()
	{
		send_keepalive();
	}

	void avpn_session::update_speed(speed_stat& stat, int64_t bytes,
		std::chrono::steady_clock::time_point now)
	{
		auto idx = stat.idx_ % stat.samples_.size();
		stat.samples_[idx] = bytes;
		stat.sample_time_[idx] = now;
		stat.idx_++;

		// 窗口填满后, 用窗口首尾差值计算速率.
		if (stat.idx_ > stat.samples_.size())
		{
			auto old = stat.idx_ % stat.samples_.size();
			auto delta_bytes = bytes - stat.samples_[old];
			auto delta_time = now - stat.sample_time_[old];
			auto ms = std::chrono::duration_cast<
				std::chrono::milliseconds>(delta_time).count();
			if (ms > 0)
			{
				stat.rate_ = static_cast<int64_t>(
					static_cast<double>(delta_bytes) /
					(static_cast<double>(ms) / 1000.0));
			}
			else
			{
				stat.rate_ = 0;
			}
		}
	}

	void avpn_session::disconnect()
	{
		if (!m_established || m_abort)
		{
			close();
			return;
		}

		std::vector<uint8_t> plaintext;
		plaintext.push_back(static_cast<uint8_t>(msg_type::disconnect));
		plaintext.push_back(0); // reason.

		send_plaintext(send_key(), std::string_view(
			reinterpret_cast<const char*>(plaintext.data()),
			plaintext.size()));
		close();
	}

	void avpn_session::close()
	{
		if (m_abort.exchange(true))
			return;

		boost::system::error_code ec;
		asio_util::cancel(m_hs_timer, ec);
		asio_util::cancel(m_tick_timer, ec);
		asio_util::cancel(m_fec_flush_timer, ec);
		asio_util::cancel(m_probe_timer, ec);
		m_fec_flush_armed = false;
		m_fec_pending.clear();
		m_fec_pending_count = 0;
		m_udp_pending.clear();

		if (m_tcp_stream)
		{
			m_tcp_stream->close(ec);
			m_tcp_stream.reset();
		}

		if (m_close_handler)
			m_close_handler(shared_from_this());
	}

	uint8_t avpn_session::ip_proto(const uint8_t* data, std::size_t size) const
	{
		if (!data || size < 1)
			return 0;

		uint8_t version = (data[0] >> 4) & 0x0f;
		if (version == 4)
		{
			if (size < 20)
				return 0;
			return data[9];
		}
		else if (version == 6)
		{
			if (size < 40)
				return 0;
			// IPv6 下一个头.
			uint8_t next = data[6];
			const uint8_t* p = data + 40;
			std::size_t remaining = size - 40;
			// 跳过扩展头.
			while ((next == 0 || next == 43 || next == 44 || next == 51 ||
					next == 60 || next == 135) && remaining >= 2)
			{
				// 扩展头首字节即下一个头的类型.
				uint8_t next_hdr = p[0];
				if (next == 51)
				{
					// AH.
					std::size_t hdr_len = (p[1] + 2) * 4;
					if (hdr_len > remaining)
						return 0;
					p += hdr_len;
					remaining -= hdr_len;
				}
				else if (next == 44)
				{
					// 分段头, 固定 8 字节.
					if (remaining < 8)
						return 0;
					p += 8;
					remaining -= 8;
				}
				else if (next == 0)
				{
					// Hop-by-hop / dest options: 长度单位为 8 字节+8.
					std::size_t hdr_len = (p[1] + 1) * 8;
					if (hdr_len > remaining)
						return 0;
					p += hdr_len;
					remaining -= hdr_len;
				}
				else
				{
					// 路由/分段/移动.
					std::size_t hdr_len = (p[1] + 1) * 8;
					if (hdr_len > remaining)
						return 0;
					p += hdr_len;
					remaining -= hdr_len;
				}
				next = next_hdr;
			}
			return next;
		}

		return 0;
	}

	bool avpn_session::is_tcp_syn(const uint8_t* data, std::size_t size) const
	{
		if (ip_proto(data, size) != 6)
			return false;

		// 定位 TCP 头.
		const uint8_t* tcp = nullptr;
		uint8_t version = (data[0] >> 4) & 0x0f;
		if (version == 4)
		{
			if (size < 20)
				return false;
			std::size_t ihl = (data[0] & 0x0f) * 4;
			if (ihl < 20 || size < ihl + 20)
				return false;
			tcp = data + ihl;
		}
		else if (version == 6)
		{
			// 简化: 仅处理无扩展头的 IPv6.
			if (size < 40)
				return false;
			if (data[6] != 6)
				return false;
			tcp = data + 40;
		}
		else
		{
			return false;
		}

		// TCP flags 在偏移 13.
		uint8_t flags = tcp[13];
		// SYN=0x02.
		return (flags & 0x02) != 0 && (flags & 0x10) == 0; // SYN 且非 ACK.
	}

} // namespace libavpn
