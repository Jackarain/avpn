//
// avpn_datapath.cpp
// ~~~~~~~~~~~~~~~~~
//
// Copyright (C) 2025 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#include "libavpn/avpn_datapath.hpp"

#include <cstring>

namespace libavpn {

	namespace {

		// 小端读 32 位计数器.
		inline uint32_t read_u32(const uint8_t* p)
		{
			return static_cast<uint32_t>(p[0]) |
				(static_cast<uint32_t>(p[1]) << 8) |
				(static_cast<uint32_t>(p[2]) << 16) |
				(static_cast<uint32_t>(p[3]) << 24);
		}

		inline void write_u32(uint8_t* p, uint32_t v)
		{
			p[0] = static_cast<uint8_t>(v & 0xff);
			p[1] = static_cast<uint8_t>((v >> 8) & 0xff);
			p[2] = static_cast<uint8_t>((v >> 16) & 0xff);
			p[3] = static_cast<uint8_t>((v >> 24) & 0xff);
		}

		// 小端读 16 位长度 (压缩条目的长度字段).
		inline uint16_t read_len16(const uint8_t* p)
		{
			return static_cast<uint16_t>(p[0]) |
				static_cast<uint16_t>(p[1] << 8);
		}

	} // namespace

	datapath::datapath() = default;
	datapath::~datapath() = default;

	void datapath::configure(std::string master,
		const session_params& params, bool local_is_client)
	{
		m_params = params;
		m_local_is_client = local_is_client;
		m_ready = master.size() == crypto::x25519_key_size;

		m_keys.clear();
		if (m_ready)
		{
			m_keys.set_master(master);
			m_ready = m_keys.ready();
		}

		m_tx_aead_epoch_valid = false;
		m_rx_aead_epoch_valid = false;
		m_tx_epoch = 0;
		m_tx_has_last = false;
		m_rx_epoch = 0;
		m_rx_h_last = 0;
		m_rx_has_last = false;

		m_replay.reset();

		// 压缩算法由握手谈定; 只压 IP 包, 压不小就还发原始包.
		m_compressor.set_type(static_cast<compress_type>(params.compress));
		m_cmp_buf.clear();

		m_fec_tx.configure(params.fec_total, params.fec_data,
			static_cast<uint32_t>(params.shard_limit()),
			params.group_abandon_ms, params.early_close_ms);
		m_fec_tx.reset(0);

		m_fec_rx.configure(params.fec_total, params.fec_data,
			params.early_close_ms != 0, params.group_cache_ms);

		m_roam = false;
		m_cookie_window.clear();
		if (m_ready)
			ensure_send_key(m_tx_epoch);
	}

	void datapath::set_roam_cookie(const std::array<uint8_t, 8>& cookie)
	{
		m_cookie_window.set(cookie);
		m_roam = !m_cookie_window.empty();
	}

	uint32_t datapath::send_counter() const
	{
		return m_fec_tx.group_base() + m_fec_tx.used();
	}

	bool datapath::set_send_position(uint32_t epoch, uint32_t counter)
	{
		if (!m_ready)
			return false;

		m_tx_epoch = epoch;
		m_tx_has_last = false;
		m_fec_tx.reset(counter);
		return ensure_send_key(epoch);
	}

	bool datapath::ensure_send_key(uint32_t epoch)
	{
		if (m_tx_aead_epoch_valid && m_tx_aead_epoch == epoch)
			return true;

		const std::string& key = m_keys.key(epoch, send_c2s());
		if (key.size() != crypto::x25519_key_size)
			return false;

		m_tx_aead.set_tag_len(m_params.tag_len);
		if (!m_tx_aead.init(key))
			return false;

		m_tx_aead_epoch = epoch;
		m_tx_aead_epoch_valid = true;
		return true;
	}

	bool datapath::ensure_recv_key(uint32_t epoch)
	{
		if (m_rx_aead_epoch_valid && m_rx_aead_epoch == epoch)
			return true;

		const std::string& key = m_keys.key(epoch, recv_c2s());
		if (key.size() != crypto::x25519_key_size)
			return false;

		m_rx_aead.set_tag_len(m_params.tag_len);
		if (!m_rx_aead.init(key))
			return false;

		m_rx_aead_epoch = epoch;
		m_rx_aead_epoch_valid = true;
		return true;
	}

	std::string datapath::encrypt_with(std::string_view plaintext,
		uint32_t counter, std::string_view aad)
	{
		if (!m_tx_aead.ready())
			return {};

		const auto nonce = make_frame_nonce(counter);
		m_tx_scratch.resize(plaintext.size() + m_params.tag_len);

		std::size_t written = 0;
		if (!m_tx_aead.encrypt(
			std::string_view(reinterpret_cast<const char*>(nonce.data()),
				nonce.size()),
			plaintext, aad,
			reinterpret_cast<uint8_t*>(m_tx_scratch.data()),
			m_tx_scratch.size(), written))
		{
			return {};
		}

		std::string frame;
		if (!aad.empty())
			frame.append(aad);
		frame.resize(frame.size() + frame_header_size);
		write_u32(reinterpret_cast<uint8_t*>(&frame[frame.size() -
			frame_header_size]), counter);
		frame.append(m_tx_scratch.data(), written);
		return frame;
	}

	bool datapath::compress_payload(std::string_view plaintext, std::string& out)
	{
		out.clear();
		if (!m_compressor.enabled() ||
			classify_payload(plaintext) != frame_kind::ip)
		{
			return false;
		}

		// 太短或一眼看上去压不动 (随机数据、已加密、压过的媒体流) 就别压了.
		if (!looks_compressible(plaintext))
			return false;

		if (!m_compressor.compress(plaintext, m_cmp_buf))
			return false;

		// 压后数据加 3 字节条目头还不见得比原包小, 那就不值得压.
		if (m_cmp_buf.size() + control_header_size >= plaintext.size())
			return false;

		out.reserve(control_header_size + m_cmp_buf.size());
		out.push_back(static_cast<char>(compressed_marker));
		out.push_back(static_cast<char>(m_cmp_buf.size() & 0xff));
		out.push_back(static_cast<char>((m_cmp_buf.size() >> 8) & 0xff));
		out.append(reinterpret_cast<const char*>(m_cmp_buf.data()),
			m_cmp_buf.size());
		return true;
	}

	bool datapath::decompress_payload(std::string_view plaintext,
		std::string& out)
	{
		out.clear();
		if (plaintext.size() < control_header_size)
			return false;

		const std::size_t len = read_len16(
			reinterpret_cast<const uint8_t*>(plaintext.data()) + 1);
		if (control_header_size + len > plaintext.size())
			return false;

		// 解压后最多是一个满长包, 防止对端拿"解压炸弹"撑爆内存.
		if (!m_compressor.decompress(
			plaintext.substr(control_header_size, len), m_cmp_buf,
			m_params.shard_limit()))
		{
			return false;
		}

		out.assign(reinterpret_cast<const char*>(m_cmp_buf.data()),
			m_cmp_buf.size());
		return !out.empty();
	}

	std::vector<std::string> datapath::seal(std::string_view plaintext,
		uint64_t now_ms, bool roam)
	{
		std::vector<std::string> out;
		if (!m_ready || plaintext.empty())
			return out;

		// 先看能不能压小; 压不小就发原始包.
		std::string packed;
		std::string_view payload = plaintext;
		if (compress_payload(plaintext, packed))
			payload = packed;

		std::vector<fec_shard> shards;
		if (!m_fec_tx.push(payload, now_ms, shards))
			return out;

		for (auto& s : shards)
		{
			// 计数器回绕: 换下一个次代和下一把密钥, 绝不拿旧密钥用过的计数器.
			if (m_tx_has_last && s.counter < m_tx_last)
			{
				m_tx_epoch++;
				m_tx_has_last = false;
				if (!ensure_send_key(m_tx_epoch))
					return out;
			}
			m_tx_last = s.counter;
			m_tx_has_last = true;

			const std::string_view aad = (roam && m_roam)
				? std::string_view(
					reinterpret_cast<const char*>(m_cookie_window.current().data()),
					m_cookie_window.current().size())
				: std::string_view();
			auto frame = encrypt_with(s.payload, s.counter, aad);
			if (frame.empty())
				return out;
			out.push_back(std::move(frame));
		}

		return out;
	}

	std::vector<std::string> datapath::tick(uint64_t now_ms)
	{
		std::vector<std::string> out;

		std::vector<fec_shard> shards;
		m_fec_tx.tick(now_ms, shards);
		for (auto& s : shards)
		{
			if (m_tx_has_last && s.counter < m_tx_last)
			{
				m_tx_epoch++;
				m_tx_has_last = false;
				if (!ensure_send_key(m_tx_epoch))
					return out;
			}
			m_tx_last = s.counter;
			m_tx_has_last = true;

			auto frame = encrypt_with(s.payload, s.counter, std::string_view());
			if (frame.empty())
				return out;
			out.push_back(std::move(frame));
		}

		m_fec_rx.tick(now_ms);
		return out;
	}

	bool datapath::decrypt_with(uint32_t epoch, uint32_t counter,
		std::string_view body, std::string_view aad,
		std::string& plaintext)
	{
		if (!ensure_recv_key(epoch))
			return false;

		const std::string_view ciphertext = body.substr(frame_header_size);
		if (ciphertext.size() < m_params.tag_len)
			return false;

		const auto nonce = make_frame_nonce(counter);
		const std::size_t plain_size = ciphertext.size() - m_params.tag_len;
		if (m_rx_scratch.size() < plain_size)
			m_rx_scratch.resize(plain_size);

		std::size_t written = 0;
		if (!m_rx_aead.decrypt(
			std::string_view(reinterpret_cast<const char*>(nonce.data()),
				nonce.size()),
			ciphertext, aad,
			reinterpret_cast<uint8_t*>(m_rx_scratch.data()),
			m_rx_scratch.size(), written))
		{
			return false;
		}

		plaintext.assign(m_rx_scratch.data(), written);
		return true;
	}

	std::vector<std::string> datapath::on_frame(std::string_view frame,
		uint64_t now_ms)
	{
		std::vector<std::string> out;
		if (!m_ready)
			return out;

		const std::size_t least = frame_header_size + m_params.tag_len;
		if (frame.size() < least)
			return out;

		// 漫游帧: 最前面 8 字节 cookie, 并且它是 AEAD 的附加校验数据.
		// 轮换后的重叠期内, 旧凭证也认 (memcmp 由窗口负责).
		std::string_view body = frame;
		std::string_view aad;
		if (m_roam && frame_has_roam_cookie(frame, now_ms) &&
			frame.size() >= roam_cookie_size + least)
		{
			aad = frame.substr(0, roam_cookie_size);
			body = frame.substr(roam_cookie_size);
		}

		uint32_t counter = 0;
		uint32_t epoch = 0;
		bool ok = false;

		for (int attempt = 0; attempt < 2 && !ok; attempt++)
		{
			// 第一次按 (cookie?) 的判法解; 第二次换个判法再试一次.
			std::string_view try_body = body;
			std::string_view try_aad = aad;
			if (attempt == 1)
			{
				if (aad.empty() && !m_roam)
					break;
				try_body = frame;
				try_aad = std::string_view();
			}
			if (try_body.size() < least)
				continue;

			counter = read_u32(
				reinterpret_cast<const uint8_t*>(try_body.data()));

			// 次代不写在报文里: 按 e_last / h_last 挑候选, 一个一个试.
			// 常规最多试两个 (e_last 与 e_last + 1); 都不行时再往前一个次代
			// 试一次, 兜住"正好跨次代时晚到的旧帧".
			uint32_t cand[3];
			int count = 0;
			if (m_rx_has_last)
			{
				if (counter > m_rx_h_last)
				{
					cand[count++] = m_rx_epoch;
					cand[count++] = m_rx_epoch + 1;
				}
				else
				{
					cand[count++] = m_rx_epoch + 1;
					cand[count++] = m_rx_epoch;
				}
				if (m_rx_epoch > 0)
					cand[count++] = m_rx_epoch - 1;
			}
			else
			{
				cand[count++] = m_rx_epoch;
			}

			for (int i = 0; i < count && !ok; i++)
			{
				if (i > 0 && cand[i] == cand[0] && count == 1)
					break;
				if (decrypt_with(cand[i], counter, try_body, try_aad,
					m_rx_plain))
				{
					epoch = cand[i];
					ok = true;
				}
			}
		}

		if (!ok)
			return out;

		m_rx_epoch = epoch;
		m_rx_h_last = counter;
		m_rx_has_last = true;

		// 防重放: 次代与计数器合成一个只增不减的全局序号.
		const uint64_t seq = global_seq(epoch, counter);
		if (!m_replay.check_and_update(seq))
			return out;

		std::vector<std::string_view> delivered;
		if (!m_fec_rx.on_shard(seq, m_rx_plain, now_ms, delivered))
			return out;

		out.reserve(delivered.size());
		for (auto v : delivered)
		{
			// 压缩条目: 解出来再投递; 解不开就丢掉这一片.
			if (m_compressor.enabled() && v.size() >= 1 &&
				static_cast<uint8_t>(v[0]) == compressed_marker)
			{
				std::string real;
				if (decompress_payload(v, real))
					out.push_back(std::move(real));
				continue;
			}
			out.emplace_back(v);
		}
		return out;
	}

} // namespace libavpn
