//
// avpn_fec_v2.hpp
// ~~~~~~~~~~~~~~~
//
// v2 的纠错分组 (见 doc/protocol_v2.md 2.4):
//   * 发送端: 收到一个包就立刻发出去, 同时留一份; 凑够 ds 片就补上 ps 片冗余.
//   * 接收端: 数据片立刻投递, 同时留一份; 收到任意 ds 片就把缺的片还回来.
//
// 片号 / 组号都由计数器算出, 不写进报文; 帧头里的计数器由调用方加进帧里.
//
// Copyright (C) 2025 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#ifndef INCLUDE__2026_10_14__AVPN_FEC_V2_HPP
#define INCLUDE__2026_10_14__AVPN_FEC_V2_HPP

#include "libavpn/avpn_rs.hpp"

#include <cstdint>
#include <cstddef>
#include <deque>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace libavpn {

	// 一片: 数据片装原始内容, 冗余片装算出来的 S 字节.
	struct fec_shard
	{
		uint32_t counter{ 0 };    // 帧头里的计数器.
		bool redundant{ false };  // true = 冗余片.
		std::string payload;      // 要发出去的那份内容.
	};

	// 发送端: 一边发一边留, 凑够数据片就算冗余片.
	//
	// 组结束 (凑满 / 放弃 / 提前关组) 时, 组的基地址自动跳到 T 的下一个整数倍,
	// 所以调用方只要把返回的 counter 写进帧头就行.
	class fec_sender
	{
	public:
		// total: 一组总片数 T, data: 数据片数 ds; T = 1 表示不开纠错.
		// shard_limit: 单片内容上限 (线缆 MTU 减去帧头与认证标签).
		// abandon_ms: 一组多久没有新片就放弃 (放弃时不算冗余).
		// close_ms: 一组多久没有新片就提前关组 (按现有片数算冗余), 0 表示不提前关.
		void configure(uint32_t total, uint32_t data, uint32_t shard_limit,
			uint64_t abandon_ms, uint64_t close_ms);
		void reset(uint32_t base_counter = 0);

		uint32_t total() const { return m_total; }
		uint32_t data_shards() const { return m_data; }
		uint32_t parity_shards() const { return m_total - m_data; }

		// 本组已经用掉几个数据片; 0 表示当前没有半满的组.
		uint32_t used() const { return m_used; }

		// 收一个数据片, 把这次该发的片追加到 out: 先是它自己, 凑够时再跟 ps 片冗余.
		// 内容超过单片上限返回 false (调用方应丢掉这个包).
		bool push(std::string_view payload, uint64_t now_ms,
			std::vector<fec_shard>& out);

		// 计时: 到点了就放弃半满的组, 或提前关组 (把冗余片追加到 out).
		void tick(uint64_t now_ms, std::vector<fec_shard>& out);

	private:
		void emit_parity(std::vector<fec_shard>& out);
		void finish_group();

		uint32_t m_total{ 1 };
		uint32_t m_data{ 1 };
		uint32_t m_limit{ 1380 };
		uint64_t m_abandon_ms{ 1000 };
		uint64_t m_close_ms{ 0 };
		uint32_t m_base{ 0 };
		uint32_t m_used{ 0 };
		uint64_t m_last_ms{ 0 };
		std::vector<std::string> m_kept;
		std::unique_ptr<reedsolomon> m_rs;
	};

	// 接收端: 数据片立刻投递, 同时留一份; 够 ds 片就解出缺的片再投递.
	//
	// out 里的 string_view 指向本对象内部缓冲, 只能用到下一次调用之前.
	class fec_receiver
	{
	public:
		// total / data 同发送端; early_close 表示对端开了提前关组 (冗余片多带
		// 1 字节实际数据片数); cache_ms: 一组留多久没动静就扔掉.
		void configure(uint32_t total, uint32_t data, bool early_close,
			uint64_t cache_ms);
		void reset();

		uint32_t total() const { return m_total; }
		uint32_t data_shards() const { return m_data; }

		// 收一片. seq 是帧头计数器加上次代算出的全局序号, 组号 / 片号由它算出.
		// 可以投递的内容追加到 out; 返回 false 表示这片被丢弃.
		bool on_shard(uint64_t seq, std::string_view payload, uint64_t now_ms,
			std::vector<std::string_view>& out);

		// 计时: 扔掉留太久的组.
		void tick(uint64_t now_ms);

		// 还在攒片的组数 (已经处理完的组不算在内, 测试用).
		std::size_t group_count() const;

	private:
		struct group
		{
			std::vector<std::string> shards;   // 长度 T, 空 = 还没收到.
			std::size_t shard_size{ 0 };       // S, 0 表示还不知道.
			uint32_t received{ 0 };
			int actual_data{ -1 };             // 提前关组时冗余片给出的实际数据片数.
			uint64_t last_ms{ 0 };
			bool done{ false };                // 本组已经处理完, 后来的片直接丢.
		};

		group* find_or_create(uint64_t gid, uint64_t now_ms);
		std::size_t count_data(const group& g) const;
		void finish(group& g);
		void try_decode(group& g, std::vector<std::string_view>& out);

		uint32_t m_total{ 1 };
		uint32_t m_data{ 1 };
		bool m_early_close{ false };
		uint64_t m_cache_ms{ 2000 };
		std::map<uint64_t, group> m_groups;
		std::deque<std::string> m_recovered;  // 还原出来的片, 供 out 引用.
	};

} // namespace libavpn

#endif // INCLUDE__2026_10_14__AVPN_FEC_V2_HPP
