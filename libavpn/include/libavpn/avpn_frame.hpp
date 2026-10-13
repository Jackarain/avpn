//
// avpn_frame.hpp
// ~~~~~~~~~~~~~~
//
// v2 协议的数据面与握手报文格式:
//   * 4 字节帧头 (32 位计数器) 与次代/组号/片号的算术.
//   * 明文内容判定 (IP 包 / 容器 / 控制消息).
//   * 容器与控制消息的编解码 (严格校验).
//   * 握手报文的明文编解码, 以及会话参数的 TLV 编解码.
//
// Copyright (C) 2025 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#ifndef INCLUDE__2026_10_14__AVPN_FRAME_HPP
#define INCLUDE__2026_10_14__AVPN_FRAME_HPP

#include <cstdint>
#include <cstddef>
#include <array>
#include <string>
#include <string_view>
#include <vector>

#include <boost/asio/ip/address_v6.hpp>

#include "libavpn/avpn_protocol.hpp"
#include "libavpn/avpn_obfuscate.hpp"

namespace libavpn {

	namespace net = boost::asio;

	// 协议版本.
	inline constexpr uint16_t avpn_protocol_v2 = 2;

	// 帧头大小 (32 位计数器, 小端).
	inline constexpr std::size_t frame_header_size = 4;

	// 帧 AEAD nonce 大小 (计数器 4 字节 + 8 字节 0).
	inline constexpr std::size_t frame_nonce_size = 12;

	// 默认的认证标签长度 (字节); 也可协商成 12.
	inline constexpr std::size_t frame_default_tag_len = 16;

	// 一个次代的帧数.
	inline constexpr uint64_t frame_counter_space = uint64_t{ 1 } << 32;

	// 线缆 MTU 上限 (含帧头与认证标签).
	inline constexpr std::size_t max_wire_mtu = 1500;

	// 一个帧装进 UDP 报文后, 还要加上 IP 头 (20 字节) 和 UDP 头 (8 字节).
	inline constexpr std::size_t wire_outer_overhead = 28;

	// 一片 (一个数据帧的载荷) 的长度上限: 线缆 MTU 减去外层 IP/UDP 头、帧头
	// 和认证标签; 开混淆再减去混淆层的开销, 保证套上混淆后外层报文仍不超过
	// 线缆 MTU, 不会被 IP 分片.
	inline std::size_t wire_payload_limit(std::size_t tag_len, bool obfuscate)
	{
		std::size_t limit = max_wire_mtu - wire_outer_overhead -
			frame_header_size - tag_len;
		if (obfuscate)
			limit -= obfuscate_max_overhead;
		return limit;
	}

	// 明文里装的东西.
	enum class frame_kind : uint8_t
	{
		ip = 0,          // IP 包 (首字节 0x4x / 0x6x).
		container = 1,   // 容器 (首字节 0x00).
		control = 2,     // 控制消息.
	};

	// 容器标记.
	inline constexpr uint8_t container_marker = 0x00;

	// 容器头部: 标记(1) + 条目数(1).
	inline constexpr std::size_t container_header_size = 2;

	// 一个容器最多装多少个条目 (条目数只有 1 字节).
	inline constexpr std::size_t container_max_entries = 255;

	// 控制消息码.
	inline constexpr uint8_t control_keepalive = 0x02;
	inline constexpr uint8_t control_keepalive_reply = 0x03;
	inline constexpr uint8_t control_disconnect = 0x04;

	// 压缩载荷标记: 明文 = [ 标记(1) , 压后长度(2, 小端) , 压后数据 ].
	// 压后数据解压出来是一个 IP 包; 长度字段用来在纠错模式里剥掉补零.
	inline constexpr uint8_t compressed_marker = 0x01;

	// 压缩协商: 客户端想要的和网关配置的是同一个算法才启用. 当前只实现了
	// deflate, 别的算法一律谈成不压缩.
	compress_type negotiate_compress(compress_type wish, compress_type have);

	// 控制消息头部: 消息码(1) + 长度(2, 小端).
	inline constexpr std::size_t control_header_size = 3;

	// 保活消息体: 8 字节时间戳 (小端毫秒).
	inline constexpr std::size_t keepalive_body_size = 8;

	// 明文首字节判定内容类型.
	frame_kind classify_payload(std::string_view plaintext);

	// 控制消息码是否合法 (0x00 留给容器, 0x4x/0x6x 会与 IP 包混淆).
	bool valid_control_code(uint8_t code);

	// 从 IP 头读出这个包的总长; 不合法返回 0.
	std::size_t ip_packet_size(const uint8_t* data, std::size_t size);

	// 控制消息编解码.
	void append_control_message(std::string& out, uint8_t code,
		std::string_view body);
	bool parse_control_message(std::string_view plaintext, uint8_t& code,
		std::string_view& body);

	// 容器编解码. entries 里每一项都是一段独立内容 (IP 包或控制消息).
	void append_container(std::string& out,
		const std::vector<std::string_view>& entries);
	// 同上, 但只取 [from, from + count) 这一段 (机会性聚合时省一次拷贝).
	void append_container(std::string& out,
		const std::vector<std::string_view>& entries,
		std::size_t from, std::size_t count);
	// 机会性聚合: 从 packets[from] 起, 把能塞进一帧的包按容器装进 out,
	// 返回装进去的包数; 只装得下 1 个包时不做容器封装 (省下容器头).
	// 这里只处理已经拿在手里的包, 不为攒包等待 (见 doc/protocol_v2.md 2.4).
	std::size_t pack_packets(const std::vector<std::string_view>& packets,
		std::size_t from, std::size_t payload_limit, std::string& out);
	// 严格解析: 任何一处不合法都返回 false, 由调用方丢弃整帧.
	bool parse_container(std::string_view plaintext,
		std::vector<std::string_view>& entries);
	// 容器真正占用的字节数 (末尾的补零不算); 不合法返回 0.
	std::size_t container_size(std::string_view plaintext);

	// 次代 / 计数器 / 组号 / 片号.
	inline uint64_t global_seq(uint32_t epoch, uint32_t counter)
	{
		return (static_cast<uint64_t>(epoch) << 32) |
			static_cast<uint64_t>(counter);
	}
	inline uint32_t seq_epoch(uint64_t seq)
	{
		return static_cast<uint32_t>(seq >> 32);
	}
	inline uint32_t seq_counter(uint64_t seq)
	{
		return static_cast<uint32_t>(seq & 0xffffffffull);
	}
	inline uint64_t group_of(uint64_t seq, uint32_t total)
	{
		return seq / total;
	}
	inline uint32_t shard_of(uint32_t counter, uint32_t total)
	{
		return counter % total;
	}

	// 会话参数 (握手时一次谈定).
	struct session_params
	{
		uint16_t version{ avpn_protocol_v2 };

		// 认证标签长度.
		uint8_t tag_len{ static_cast<uint8_t>(frame_default_tag_len) };

		// 纠错: 一组的总片数 / 数据片数; 1 表示不开纠错.
		uint8_t fec_total{ 1 };
		uint8_t fec_data{ 1 };

		// 保活间隔 (秒).
		uint16_t keepalive_sec{ 30 };

		// 一组多久没有新包就放弃 (毫秒).
		uint16_t group_abandon_ms{ 1000 };

		// 接收端多久没动静就丢掉一组留的片 (毫秒).
		uint16_t group_cache_ms{ 2000 };

		// 提前关组 (毫秒), 0 表示关闭.
		uint16_t early_close_ms{ 0 };

		// 内层虚拟网卡 MTU.
		uint16_t mtu{ 1380 };

		// 网关分配/确认的虚拟地址与前缀长度.
		uint32_t vaddr{ 0 };
		uint8_t prefix_len{ 0 };

		// IPv6 内网参数.
		uint8_t v6_prefix{ 64 };
		net::ip::address_v6 v6_net{};

		// 下发给客户端的路由.
		std::vector<std::string> routes;

		// 压缩算法与流量混淆开关.
		uint8_t compress{ 0 };
		bool obfuscate{ false };

		// 混淆密钥串的指纹 (4 字节, 0 表示没配); 两端不一致就没法谈成混淆.
		uint32_t obfuscate_key_hash{ 0 };

		// 漫游凭证.
		std::array<uint8_t, 8> roam_cookie{};

		// 每多少个数据帧顺带一次 cookie, 0 表示关闭.
		uint16_t cookie_beacon_k{ 64 };

		// 传输类型: 0 = UDP, 1 = TCP.
		uint8_t transport{ 0 };

		// 网关推给客户端的 dns (虚拟网络内可用).
		uint32_t pushdns{ 0 };

		// 是否默认把全部流量都走这条隧道.
		bool passbyvpn{ false };

		// 取值是否自洽.
		bool valid() const;

		// 数据片长度上限 (= 线缆 MTU - 帧头 - 认证标签, 开混淆时更小).
		std::size_t shard_limit() const
		{
			return wire_payload_limit(tag_len, obfuscate);
		}
	};

	// 会话参数的 TLV 编解码.
	void append_params(std::string& out, const session_params& params);
	bool parse_params(std::string_view data, session_params& params);

	// 握手请求最前面的 hint: 客户端静态公钥的哈希前缀, 放在密文外面,
	// 让网关一步就查到白名单项. 8 字节全 0 表示不带.
	inline constexpr std::size_t handshake_hint_size = 8;
	std::array<uint8_t, handshake_hint_size> make_handshake_hint(
		std::string_view static_pub);
	inline bool hint_absent(
		const std::array<uint8_t, handshake_hint_size>& hint)
	{
		for (auto b : hint)
		{
			if (b != 0)
				return false;
		}
		return true;
	}

	// 握手请求线格式: [ hint(8) , 随机数(12) , 密文 ].
	// 明文 = [ 版本(2) , 临时公钥(32) , 时间戳(8) , 客户端标识(16) ,
	//          期望虚拟地址(4) , 参数长度(2) , 参数 ].
	struct handshake_req
	{
		uint16_t version{ avpn_protocol_v2 };
		std::array<uint8_t, 32> ephemeral_pub{};
		uint64_t timestamp{ 0 };
		std::array<uint8_t, 16> client_id{};
		uint32_t requested_vaddr{ 0 };

		session_params params;

		std::string serialize() const;
	};
	bool parse_handshake_req(std::string_view data, handshake_req& req);

	// 握手回复明文 (网关 -> 客户端).
	struct handshake_resp
	{
		std::array<uint8_t, 32> ephemeral_pub{};
		session_params params;

		std::string serialize() const;
	};
	bool parse_handshake_resp(std::string_view data, handshake_resp& resp);

	// 握手报文的固定字段大小.
	inline constexpr std::size_t handshake_req_fixed_size =
		2 + 32 + 8 + 16 + 4;
	inline constexpr std::size_t handshake_resp_fixed_size = 32;

} // namespace libavpn

#endif // INCLUDE__2026_10_14__AVPN_FRAME_HPP
