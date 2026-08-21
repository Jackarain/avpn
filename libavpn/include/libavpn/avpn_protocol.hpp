//
// avpn_protocol.hpp
// ~~~~~~~~~~~~~~~~~
//
// Copyright (C) 2025 Jack.
//
// Author: jack
// Email:  jack.wgm at gmail dot com
//

#ifndef INCLUDE__2025_11_20__AVPN_PROTOCOL_HPP
#define INCLUDE__2025_11_20__AVPN_PROTOCOL_HPP

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <memory>

#include <boost/asio/ip/udp.hpp>
#include <boost/asio/ip/tcp.hpp>

namespace libavpn {

	namespace net = boost::asio;

	// 协议版本号.
	inline constexpr uint16_t avpn_protocol_version = 1;

	// 密钥大小.
	inline constexpr std::size_t avpn_key_size = 32;

	// 客户端身份 ID 大小.
	inline constexpr std::size_t avpn_client_id_size = 32;

	// 握手加密后载荷中临时公钥大小.
	inline constexpr std::size_t avpn_ephemeral_key_size = 32;

	// 最大 tun mtu.
	inline constexpr std::size_t avpn_max_mtu = 1500;

	// 最大网络数据包大小(含加密与协议开销).
	inline constexpr std::size_t avpn_max_packet_size = 2048;

	// 握手包在网络上的大小 (12 字节 nonce + 密文).
	inline constexpr std::size_t avpn_handshake_packet_size =
		12 + 16 + avpn_ephemeral_key_size + 8 + avpn_client_id_size;

	// 压缩算法.
	enum class compress_type : uint8_t
	{
		none = 0,
		deflate = 1,
		lz4 = 2,
		zstd = 3,
	};

	// 加密数据通道中的消息类型 (位于加密体内的首字节, 不暴露在网络中).
	enum class msg_type : uint8_t
	{
		data = 0x01,               // 数据消息 (可含 fec 分片).
		keepalive = 0x02,          // 保活消息.
		keepalive_reply = 0x03,    // 保活回复.
		disconnect = 0x04,         // 断开消息.
		ack = 0x05,                // 数据确认消息(预留).
	};

	// 握手 Message 1 明文载荷:
	//   [TPubC(32)]
	//   [timestamp(8, 小端, 单位毫秒, 防重放)]
	//   [client_id(32)]
	//   [requested_vaddr(4, 小端, 0 表示不请求, 可选: 老版本无此字段)]
	struct handshake_msg1
	{
		std::array<uint8_t, avpn_ephemeral_key_size> ephemeral_pub{};
		uint64_t timestamp{ 0 };
		std::array<uint8_t, avpn_client_id_size> client_id{};
		uint32_t requested_vaddr{ 0 };
	};

	// 握手 Message 2 中协商的会话配置.
	struct session_config
	{
		// 压缩算法.
		compress_type compress{ compress_type::none };

		// fec 数据分片数.
		uint8_t data_shards{ 1 };

		// fec 冗余分片数.
		uint8_t parity_shards{ 0 };

		// 保活间隔(秒).
		uint16_t keepalive{ 60 };

		// tun mtu.
		uint16_t mtu{ 1450 };

		// gateway 分配给 client 的虚拟地址.
		uint32_t vaddr{ 0 };

		// 子网前缀长度.
		uint8_t prefix_length{ 0 };

		// IPv6 内网前缀长度 (默认 64).
		uint8_t v6_prefix{ 64 };

		// IPv6 内网网络地址 (默认 fd00:8888::).
		net::ip::address_v6 v6_net{};

		// 是否默认通过 gateway 作为全局出口.
		bool passbyvpn{ false };

		// gateway 推送的 dns.
		uint32_t pushdns{ 0 };

		// gateway 推送的路由.
		std::vector<std::string> routes;

		// 数据特征混淆 (traffic obfuscation), 握手时协商.
		// 开启后数据帧外层附加随机垃圾数据以打乱包长特征.
		bool obfuscate{ false };
	};

	// 握手 Message 2 明文载荷:
	//   [TPubS(32)]
	//   [session_config ...]
	struct handshake_msg2
	{
		std::array<uint8_t, avpn_ephemeral_key_size> ephemeral_pub{};
		session_config config;
	};

	// 序列化握手 Message 1 明文.
	std::string serialize_handshake_msg1(const handshake_msg1& msg);

	// 反序列化握手 Message 1 明文, 失败返回 false.
	bool deserialize_handshake_msg1(std::string_view data, handshake_msg1& msg);

	// 序列化握手 Message 2 明文.
	std::string serialize_handshake_msg2(const handshake_msg2& msg);

	// 反序列化握手 Message 2 明文, 失败返回 false.
	bool deserialize_handshake_msg2(std::string_view data, handshake_msg2& msg);

	// 将服务配置转换为握手 Message 2 中的会话配置.
	session_config make_session_config(const struct service_config& config,
		uint32_t vaddr, uint8_t prefix_length);

	// 将压缩算法字符串转换为 compress_type.
	compress_type compress_type_from_string(std::string_view name);
	std::string_view compress_type_to_string(compress_type type);

	// 解析 "ip:port" 形式的地址为 udp/tcp endpoint.
	bool parse_endpoint(std::string_view addr, net::ip::udp::endpoint& ep);
	bool parse_endpoint(std::string_view addr, net::ip::tcp::endpoint& ep);

	// 将 endpoint 转换为字符串.
	std::string endpoint_to_string(const net::ip::udp::endpoint& ep);
	std::string endpoint_to_string(const net::ip::tcp::endpoint& ep);

	// 小端读写工具.
	namespace byteorder {
		inline void put_u16(std::string& out, uint16_t v)
		{
			out.push_back(static_cast<char>(v & 0xff));
			out.push_back(static_cast<char>((v >> 8) & 0xff));
		}
		inline void put_u32(std::string& out, uint32_t v)
		{
			out.push_back(static_cast<char>(v & 0xff));
			out.push_back(static_cast<char>((v >> 8) & 0xff));
			out.push_back(static_cast<char>((v >> 16) & 0xff));
			out.push_back(static_cast<char>((v >> 24) & 0xff));
		}
		inline void put_u16_into(std::vector<uint8_t>& out, uint16_t v)
		{
			out.push_back(static_cast<uint8_t>(v & 0xff));
			out.push_back(static_cast<uint8_t>((v >> 8) & 0xff));
		}
		inline void put_u32_into(std::vector<uint8_t>& out, uint32_t v)
		{
			out.push_back(static_cast<uint8_t>(v & 0xff));
			out.push_back(static_cast<uint8_t>((v >> 8) & 0xff));
			out.push_back(static_cast<uint8_t>((v >> 16) & 0xff));
			out.push_back(static_cast<uint8_t>((v >> 24) & 0xff));
		}
		inline void put_u64_into(std::vector<uint8_t>& out, uint64_t v)
		{
			for (int i = 0; i < 8; i++)
				out.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xff));
		}
		inline uint32_t get_u32_le(const uint8_t* p)
		{
			return static_cast<uint32_t>(p[0]) |
				(static_cast<uint32_t>(p[1]) << 8) |
				(static_cast<uint32_t>(p[2]) << 16) |
				(static_cast<uint32_t>(p[3]) << 24);
		}
		inline uint16_t get_u16_le(const uint8_t* p)
		{
			return static_cast<uint16_t>(p[0]) |
				(static_cast<uint16_t>(p[1]) << 8);
		}
		inline void put_u64(std::string& out, uint64_t v)
		{
			for (int i = 0; i < 8; i++)
				out.push_back(static_cast<char>((v >> (i * 8)) & 0xff));
		}
		inline bool get_u16(std::string_view in, std::size_t& pos, uint16_t& v)
		{
			if (pos + 2 > in.size())
				return false;
			v = static_cast<uint16_t>(
				static_cast<unsigned char>(in[pos]) |
				(static_cast<unsigned char>(in[pos + 1]) << 8));
			pos += 2;
			return true;
		}
		inline bool get_u32(std::string_view in, std::size_t& pos, uint32_t& v)
		{
			if (pos + 4 > in.size())
				return false;
			v = static_cast<uint32_t>(
				static_cast<unsigned char>(in[pos]) |
				(static_cast<unsigned char>(in[pos + 1]) << 8) |
				(static_cast<unsigned char>(in[pos + 2]) << 16) |
				(static_cast<unsigned char>(in[pos + 3]) << 24));
			pos += 4;
			return true;
		}
		inline bool get_u64(std::string_view in, std::size_t& pos, uint64_t& v)
		{
			if (pos + 8 > in.size())
				return false;
			v = 0;
			for (int i = 0; i < 8; i++)
				v |= static_cast<uint64_t>(
					static_cast<unsigned char>(in[pos + i])) << (i * 8);
			pos += 8;
			return true;
		}
		inline bool get_u8(std::string_view in, std::size_t& pos, uint8_t& v)
		{
			if (pos + 1 > in.size())
				return false;
			v = static_cast<uint8_t>(in[pos]);
			pos += 1;
			return true;
		}
	}

} // namespace libavpn

#endif // INCLUDE__2025_11_20__AVPN_PROTOCOL_HPP
