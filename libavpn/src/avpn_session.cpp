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
		, m_compressor(compress_type::none)
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

	void avpn_session::set_udp_send_handler(udp_send_handler h)
	{
		m_udp_send_handler = std::move(h);
	}

	void avpn_session::set_vaddr_allocator(vaddr_allocator h)
	{
		m_vaddr_allocator = std::move(h);
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

		return !m_key_c2s.empty() && !m_key_s2c.empty();
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
		{
			if (m_udp_send_handler)
				m_udp_send_handler(m_remote_udp, std::move(wire));
		}
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
			std::tie(vaddr, prefix) = m_vaddr_allocator();
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
		{
			if (m_udp_send_handler)
				m_udp_send_handler(m_remote_udp, std::move(wire));
		}
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
			encrypt_and_send_udp(key, plaintext);
		else
			queue_tcp_frame(key, plaintext);
	}

	void avpn_session::encrypt_and_send_udp(const std::string& key,
		std::string_view plaintext)
	{
		auto nonce = crypto::random_bytes(crypto::aead_nonce_size);
		auto ciphertext = crypto::aead_encrypt(key, nonce, plaintext);
		if (ciphertext.empty())
			return;

		std::vector<uint8_t> wire;
		wire.reserve(nonce.size() + ciphertext.size());
		wire.insert(wire.end(), nonce.begin(), nonce.end());
		wire.insert(wire.end(), ciphertext.begin(), ciphertext.end());

		if (m_udp_send_handler)
			m_udp_send_handler(m_remote_udp, std::move(wire));
	}

	void avpn_session::queue_tcp_frame(const std::string& key,
		std::string_view plaintext)
	{
		if (!m_tcp_stream)
			return;

		auto nonce = crypto::random_bytes(crypto::aead_nonce_size);
		auto ciphertext = crypto::aead_encrypt(key, nonce, plaintext);
		if (ciphertext.empty())
			return;

		std::vector<uint8_t> frame;
		frame.reserve(2 + nonce.size() + ciphertext.size());
		uint16_t len = static_cast<uint16_t>(nonce.size() + ciphertext.size());
		frame.push_back(static_cast<uint8_t>((len >> 8) & 0xff));
		frame.push_back(static_cast<uint8_t>(len & 0xff));
		frame.insert(frame.end(), nonce.begin(), nonce.end());
		frame.insert(frame.end(), ciphertext.begin(), ciphertext.end());

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
					auto wire = std::move(m_tcp_oqe.front());
					m_tcp_oqe.pop_front();

					boost::system::error_code ec;
					co_await net::async_write(*stream,
						net::buffer(wire), net_awaitable[ec]);
					if (ec)
						break;
				}
				m_tcp_writing = false;
				co_return;
			}, net::detached);
	}

	bool avpn_session::process_udp_packet(std::string_view wire)
	{
		if (wire.size() < crypto::aead_nonce_size + crypto::aead_tag_size)
			return true;

		std::string_view nonce(wire.data(), crypto::aead_nonce_size);
		std::string_view ciphertext(wire.data() + crypto::aead_nonce_size,
			wire.size() - crypto::aead_nonce_size);

		auto plaintext = crypto::aead_decrypt(recv_key(), nonce, ciphertext);
		if (plaintext.empty())
		{
			// 解密失败则丢弃.
			return true;
		}

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

		switch (type)
		{
		case msg_type::data:
			process_data_msg(body);
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
			uint32_t fec_id = byteorder::get_u32_le(p);
			uint8_t total = p[4];
			uint8_t index = p[5];
			uint16_t len = byteorder::get_u16_le(p + 6);
			std::string_view shard = body.substr(fec_frame_header_size);

			std::vector<uint8_t> ip_packet;
			if (m_fec_decoder->add(fec_id, index, total, len, shard,
					ip_packet))
			{
				deliver_ip_packet(std::move(ip_packet));
			}
		}
		else
		{
			std::vector<uint8_t> data(body.begin(), body.end());
			deliver_ip_packet(std::move(data));
		}
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
			// FEC 编码后逐片加密发送.
			std::vector<std::vector<uint8_t>> frames;
			if (!m_fec_encoder->encode(++m_fec_id, payload, frames))
				return;

			for (auto& frame : frames)
			{
				std::vector<uint8_t> plaintext;
				plaintext.reserve(1 + frame.size());
				plaintext.push_back(static_cast<uint8_t>(msg_type::data));
				plaintext.insert(plaintext.end(), frame.begin(), frame.end());
				send_plaintext(key, std::string_view(
					reinterpret_cast<const char*>(plaintext.data()),
					plaintext.size()));
			}
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

			std::vector<uint8_t> plaintext;
			plaintext.reserve(1 + payload.size());
			plaintext.push_back(static_cast<uint8_t>(msg_type::data));
			plaintext.insert(plaintext.end(), payload.begin(), payload.end());

			std::string_view frame(
				reinterpret_cast<const char*>(plaintext.data()),
				plaintext.size());
			for (int i = 0; i < copies; i++)
				send_plaintext(key, frame);
		}
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
		auto self = shared_from_this();
		net::co_spawn(m_ioc,
			[this, self]() -> net::awaitable<void>
			{
				co_await tick();
				co_return;
			}, net::detached);
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
			co_await net::async_read(*m_tcp_stream, net::buffer(lenbuf),
				net_awaitable[ec]);
			if (ec || m_abort)
				break;

			uint16_t len = static_cast<uint16_t>(
				(static_cast<uint16_t>(lenbuf[0]) << 8) | lenbuf[1]);
			if (len == 0 || len > avpn_max_packet_size)
				break;

			std::vector<uint8_t> wire(len);
			co_await net::async_read(*m_tcp_stream, net::buffer(wire),
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
		co_await tcp_read_loop(*m_tcp_stream);
		co_return;
	}

	net::awaitable<void> avpn_session::tcp_read_loop(tcp::socket& stream)
	{
		while (!m_abort)
		{
			std::array<uint8_t, 2> lenbuf;
			boost::system::error_code ec;
			co_await net::async_read(stream, net::buffer(lenbuf),
				net_awaitable[ec]);
			if (ec || m_abort)
				break;

			uint16_t len = static_cast<uint16_t>(
				(static_cast<uint16_t>(lenbuf[0]) << 8) | lenbuf[1]);
			if (len == 0 || len > avpn_max_packet_size)
				break;

			std::vector<uint8_t> wire(len);
			co_await net::async_read(stream, net::buffer(wire),
				net_awaitable[ec]);
			if (ec || m_abort)
				break;

			// 握手期间由 on_udp_packet 处理 Message 1/2,
			// 建立后处理数据帧.
			on_udp_packet(m_remote_udp, std::string_view(
				reinterpret_cast<const char*>(wire.data()), wire.size()));
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
				m_hs_timer.cancel();
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
		if (data.size() < crypto::aead_nonce_size + crypto::aead_tag_size)
			return false;

		std::string_view nonce(data.data(), crypto::aead_nonce_size);
		std::string_view ciphertext(
			data.data() + crypto::aead_nonce_size,
			data.size() - crypto::aead_nonce_size);

		// 用本会话接收密钥尝试解密, 仅判断认证是否成功.
		return !crypto::aead_decrypt(recv_key(), nonce, ciphertext).empty();
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
		m_hs_timer.cancel();
		m_tick_timer.cancel();

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
