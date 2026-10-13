//
// avpn_fec_v2.cpp
// ~~~~~~~~~~~~~~~
//
// Copyright (C) 2025 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#include "libavpn/avpn_fec_v2.hpp"
#include "libavpn/avpn_frame.hpp"

#include <algorithm>
#include <cstring>

namespace libavpn {

	namespace {

		// 小端读 16 位.
		inline uint16_t read_u16(const uint8_t* p)
		{
			return static_cast<uint16_t>(p[0] | (p[1] << 8));
		}

		// 一片内容自己声明的长度: IP 包看 IP 头里的总长, 容器看到底用了多少
		// 字节, 控制消息看它自己的长度字段. 返回 0 表示这片不合法.
		std::size_t content_length(std::string_view pad)
		{
			if (pad.empty())
				return 0;

			const uint8_t first = static_cast<uint8_t>(pad[0]);
			if ((first >> 4) == 4 || (first >> 4) == 6)
			{
				return ip_packet_size(
					reinterpret_cast<const uint8_t*>(pad.data()), pad.size());
			}
			if (first == container_marker)
				return container_size(pad);
			if (!valid_control_code(first) || pad.size() < control_header_size)
				return 0;

			const std::size_t len = read_u16(
				reinterpret_cast<const uint8_t*>(pad.data()) + 1);
			if (control_header_size + len > pad.size())
				return 0;
			return control_header_size + len;
		}

		// 从 from 开始是否全是 0 (参与纠错运算时补的零).
		bool tail_is_zero(std::string_view pad, std::size_t from)
		{
			for (std::size_t i = from; i < pad.size(); i++)
			{
				if (pad[i] != 0)
					return false;
			}
			return true;
		}

		// 剥掉补零, 得到片真正的内容; 不合法返回空.
		std::string_view strip_padding(std::string_view pad)
		{
			const std::size_t len = content_length(pad);
			if (len == 0 || !tail_is_zero(pad, len))
				return std::string_view();
			return pad.substr(0, len);
		}

		// 补零到 s 字节, 用来参与纠错运算.
		std::vector<uint8_t> pad_to(std::string_view content, std::size_t s)
		{
			std::vector<uint8_t> v(s, 0);
			std::memcpy(v.data(), content.data(),
				std::min(s, content.size()));
			return v;
		}

	} // namespace

	// ---------------------------------------------------------------
	// 发送端
	// ---------------------------------------------------------------

	void fec_sender::configure(uint32_t total, uint32_t data,
		uint32_t shard_limit, uint64_t abandon_ms, uint64_t close_ms)
	{
		m_total = total >= 1 ? total : 1;
		m_data = data >= 1 ? data : 1;
		if (m_data > m_total)
			m_data = m_total;
		// 开纠错时至少留一片冗余, 否则数据片能直接全收到, 冗余没有意义.
		if (m_total > 1 && m_data == m_total)
			m_data = m_total - 1;

		m_limit = shard_limit >= 1 ? shard_limit : 1;
		m_abandon_ms = abandon_ms >= 1 ? abandon_ms : 1;
		m_close_ms = close_ms;

		m_rs.reset();
		if (m_total > m_data)
		{
			m_rs = std::make_unique<reedsolomon>(static_cast<int>(m_data),
				static_cast<int>(m_total - m_data));
		}

		m_used = 0;
		m_kept.clear();
	}

	void fec_sender::reset(uint32_t base_counter)
	{
		m_base = base_counter;
		m_used = 0;
		m_kept.clear();
	}

	void fec_sender::finish_group()
	{
		m_base += m_total;
		m_used = 0;
		m_kept.clear();
	}

	bool fec_sender::push(std::string_view payload, uint64_t now_ms,
		std::vector<fec_shard>& out)
	{
		if (payload.empty() || payload.size() > m_limit)
			return false;

		fec_shard shard;
		shard.counter = m_base + m_used;
		shard.redundant = false;
		shard.payload.assign(payload);
		out.push_back(std::move(shard));
		m_last_ms = now_ms;

		if (m_total == 1)
		{
			// 整帧模式: 一个包一帧, 计数器一路往下走.
			m_base += 1;
			return true;
		}

		m_kept.emplace_back(payload);
		m_used++;
		if (m_used == m_data)
			emit_parity(out);

		return true;
	}

	void fec_sender::tick(uint64_t now_ms, std::vector<fec_shard>& out)
	{
		if (m_total == 1 || m_used == 0)
			return;

		const uint64_t idle = now_ms - m_last_ms;
		if (m_close_ms != 0 && idle >= m_close_ms)
		{
			emit_parity(out);
			return;
		}
		// 一组一直凑不满就放弃: 不发冗余片, 直接把计数器推到下一组.
		if (idle >= m_abandon_ms)
			finish_group();
	}

	void fec_sender::emit_parity(std::vector<fec_shard>& out)
	{
		if (!m_rs || m_kept.empty())
		{
			finish_group();
			return;
		}

		// 片长 S = 本组最长数据片的长度, 短的补零.
		std::size_t s = 0;
		for (const auto& k : m_kept)
			s = std::max(s, k.size());

		std::vector<std::vector<uint8_t>> data(m_data,
			std::vector<uint8_t>(s, 0));
		for (std::size_t i = 0; i < m_kept.size(); i++)
			std::memcpy(data[i].data(), m_kept[i].data(), m_kept[i].size());

		std::vector<std::vector<uint8_t>> parity;
		if (!m_rs->encode(data, parity))
		{
			finish_group();
			return;
		}

		for (std::size_t i = 0; i < parity.size(); i++)
		{
			fec_shard shard;
			shard.counter = m_base + m_data + static_cast<uint32_t>(i);
			shard.redundant = true;
			// 提前关组时多带 1 字节实际数据片数, 让接收端知道剩下的片是全零.
			if (m_close_ms != 0)
				shard.payload.push_back(static_cast<char>(m_used));
			shard.payload.append(
				reinterpret_cast<const char*>(parity[i].data()),
				parity[i].size());
			out.push_back(std::move(shard));
		}

		finish_group();
	}

	// ---------------------------------------------------------------
	// 接收端
	// ---------------------------------------------------------------

	void fec_receiver::configure(uint32_t total, uint32_t data,
		bool early_close, uint64_t cache_ms)
	{
		m_total = total >= 1 ? total : 1;
		m_data = data >= 1 ? data : 1;
		if (m_data > m_total)
			m_data = m_total;
		if (m_total > 1 && m_data == m_total)
			m_data = m_total - 1;
		if (m_total == 1)
			m_data = 1;

		m_early_close = early_close;
		m_cache_ms = cache_ms >= 1 ? cache_ms : 1;
		reset();
	}

	void fec_receiver::reset()
	{
		m_groups.clear();
		m_recovered.clear();
	}

	fec_receiver::group* fec_receiver::find_or_create(uint64_t gid,
		uint64_t now_ms)
	{
		auto it = m_groups.find(gid);
		if (it != m_groups.end())
			return &it->second;

		// 留的组数封顶, 免得异常流量把内存吃光; 组号小的就是旧的.
		constexpr std::size_t max_groups = 256;
		while (m_groups.size() >= max_groups)
			m_groups.erase(m_groups.begin());

		group g;
		g.shards.resize(m_total);
		g.last_ms = now_ms;
		return &m_groups.emplace(gid, std::move(g)).first->second;
	}

	bool fec_receiver::on_shard(uint64_t seq, std::string_view payload,
		uint64_t now_ms, std::vector<std::string_view>& out)
	{
		m_recovered.clear();
		if (payload.empty())
			return false;

		if (m_total == 1)
		{
			// 整帧模式: 一帧就是全部内容, 直接投递.
			out.push_back(payload);
			return true;
		}

		const uint64_t gid = seq / m_total;
		const uint32_t index = static_cast<uint32_t>(seq % m_total);
		const bool redundant = index >= m_data;

		group* g = find_or_create(gid, now_ms);
		if (g->done)
			return false;  // 这一组已经处理完, 晚到的片没什么用了.
		g->last_ms = now_ms;

		if (redundant)
		{
			if (m_early_close)
			{
				// 冗余片多带的 1 字节: 本组实际发了几个数据片.
				if (payload.size() < 1)
					return false;
				const uint32_t actual = static_cast<uint8_t>(payload[0]);
				if (actual < 1 || actual > m_data)
					return false;
				g->actual_data = static_cast<int>(actual);
				payload.remove_prefix(1);
			}
			if (payload.empty())
				return false;

			const std::size_t s = payload.size();
			if (g->shard_size == 0)
			{
				g->shard_size = s;
				// 拿到 S 之后回头校验已经收到的数据片: 长度不能超过 S.
				for (const auto& c : g->shards)
				{
					if (!c.empty() && c.size() > s)
					{
						finish(*g);
						return false;
					}
				}
			}
			else if (g->shard_size != s)
			{
				// 同组的冗余片推出不同的 S: 整组丢掉.
				finish(*g);
				return false;
			}
		}
		else
		{
			// 数据片: 长度不能超过已知的 S, 内容要自洽.
			if (g->shard_size != 0 && payload.size() > g->shard_size)
				return false;
			if (strip_padding(payload).empty())
				return false;
		}

		if (!g->shards[index].empty())
			return false;  // 重复片.

		g->shards[index] = std::string(payload);
		g->received++;

		if (!redundant)
		{
			// 数据片立刻投递, 不用等整组.
			m_recovered.emplace_back(g->shards[index]);
			out.push_back(m_recovered.back());
		}

		// 本组该发的数据片都收到了, 留的那份没用了.
		const uint32_t expect = (m_early_close && g->actual_data >= 0)
			? static_cast<uint32_t>(g->actual_data) : m_data;
		if (count_data(*g) == expect)
		{
			finish(*g);  // 该收的数据片都收到了, 留的那份没用了.
			return true;
		}

		if (g->shard_size == 0)
			return true;  // 还不知道 S, 等冗余片.

		// 已知的片 (收到的 + 确定是全零的) 够 ds 片就能把缺的片解出来.
		const uint32_t zeros = (m_early_close && g->actual_data >= 0 &&
			static_cast<uint32_t>(g->actual_data) < m_data)
			? m_data - static_cast<uint32_t>(g->actual_data) : 0;
		if (g->received + zeros < m_data)
			return true;

		try_decode(*g, out);
		return true;
	}

	void fec_receiver::tick(uint64_t now_ms)
	{
		m_recovered.clear();
		for (auto it = m_groups.begin(); it != m_groups.end();)
		{
			if (now_ms - it->second.last_ms >= m_cache_ms)
				it = m_groups.erase(it);
			else
				++it;
		}
	}

	std::size_t fec_receiver::group_count() const
	{
		std::size_t n = 0;
		for (const auto& kv : m_groups)
		{
			if (!kv.second.done)
				n++;
		}
		return n;
	}

	void fec_receiver::finish(group& g)
	{
		g.done = true;
		g.shard_size = 0;
		g.received = 0;
		g.actual_data = -1;
		std::vector<std::string>().swap(g.shards);
	}

	void fec_receiver::try_decode(group& g,
		std::vector<std::string_view>& out)
	{
		const std::size_t s = g.shard_size;
		std::vector<std::vector<uint8_t>> shards(m_total);
		// 提前关组的组里, 片号 >= actual_data 的数据片是全零, 不是丢掉的片.
		const int zeros_from = (m_early_close && g.actual_data >= 0)
			? g.actual_data : -1;

		int missing = 0;
		for (uint32_t i = 0; i < m_total; i++)
		{
			if (!g.shards[i].empty())
			{
				shards[i] = pad_to(g.shards[i], s);
				continue;
			}
			if (zeros_from >= 0 && i >= static_cast<uint32_t>(zeros_from) &&
				i < m_data)
			{
				shards[i].assign(s, 0);  // 确定是全零的数据片.
				continue;
			}
			missing++;
		}

		if (missing == 0 || missing > static_cast<int>(m_total - m_data))
		{
			finish(g);
			return;
		}

		reedsolomon rs(static_cast<int>(m_data),
			static_cast<int>(m_total - m_data));
		if (!rs.reconstruct(shards, s))
		{
			finish(g);
			return;
		}

		// 只有本来就该有内容的片才投递; 全零占位的数据片不算内容.
		const uint32_t limit = zeros_from >= 0
			? static_cast<uint32_t>(zeros_from) : m_data;
		for (uint32_t i = 0; i < limit; i++)
		{
			if (!g.shards[i].empty())
				continue;  // 收到的那份已经投递过了.

			std::string_view pad(
				reinterpret_cast<const char*>(shards[i].data()), s);
			const std::string_view content = strip_padding(pad);
			if (content.empty())
				continue;  // 这片不合法, 只丢这一片.

			m_recovered.emplace_back(content);
			out.push_back(m_recovered.back());
		}

		finish(g);
	}

	std::size_t fec_receiver::count_data(const group& g) const
	{
		std::size_t n = 0;
		for (uint32_t i = 0; i < m_data && i < g.shards.size(); i++)
		{
			if (!g.shards[i].empty())
				n++;
		}
		return n;
	}

} // namespace libavpn
