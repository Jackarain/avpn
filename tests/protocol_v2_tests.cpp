#define BOOST_TEST_MODULE avpn_protocol_v2_tests
#include <boost/test/unit_test.hpp>

// 直接包含实现, 便于在一个翻译单元里测试内部细节.
#include "../libavpn/src/avpn_frame.cpp"
#include "../libavpn/src/avpn_keys.cpp"
#include "../libavpn/src/avpn_crypto.cpp"
#include "../libavpn/src/avpn_rs.cpp"
#include "../libavpn/src/avpn_fec_v2.cpp"
#include "../libavpn/src/avpn_obfuscate.cpp"
#include "libavpn/avpn_replay.hpp"
#include "libavpn/avpn_roam_cookie.hpp"

#include <boost/asio/ip/address.hpp>

#include <cstring>
#include <set>

using namespace libavpn;

namespace {

	// 造一个合法的 IPv4 包 (总长 total).
	std::string make_ipv4(std::size_t total)
	{
		std::string s(total, '\0');
		s[0] = static_cast<char>(0x45);
		// IP 头里的长度字段按网络字节序 (大端) 写.
		s[2] = static_cast<char>((total >> 8) & 0xff);
		s[3] = static_cast<char>(total & 0xff);
		return s;
	}

	// 造一个合法的 IPv6 包 (总长 40 + payload).
	std::string make_ipv6(std::size_t payload)
	{
		std::string s(40 + payload, '\0');
		s[0] = static_cast<char>(0x60);
		s[4] = static_cast<char>((payload >> 8) & 0xff);
		s[5] = static_cast<char>(payload & 0xff);
		return s;
	}

	std::string rand_key()
	{
		return crypto::random_bytes(crypto::x25519_key_size);
	}

} // namespace

BOOST_AUTO_TEST_SUITE(protocol_v2)

BOOST_AUTO_TEST_CASE(classify_payload_kinds)
{
	BOOST_CHECK(classify_payload(make_ipv4(20)) == frame_kind::ip);
	BOOST_CHECK(classify_payload(make_ipv6(0)) == frame_kind::ip);
	BOOST_CHECK(classify_payload(std::string("\x4f", 1)) == frame_kind::ip);
	BOOST_CHECK(classify_payload(std::string("\x6f", 1)) == frame_kind::ip);
	BOOST_CHECK(classify_payload(std::string("\x00", 1)) ==
		frame_kind::container);
	BOOST_CHECK(classify_payload(std::string("\x02", 1)) ==
		frame_kind::control);
	BOOST_CHECK(classify_payload(std::string("\xff", 1)) ==
		frame_kind::control);
	// 空明文不能当 IP 包, 也不配当容器.
	BOOST_CHECK(classify_payload(std::string_view()) == frame_kind::control);
}

BOOST_AUTO_TEST_CASE(control_codes_reject_ip_and_container)
{
	BOOST_CHECK(!valid_control_code(0x00));
	BOOST_CHECK(!valid_control_code(0x01));
	BOOST_CHECK(!valid_control_code(0x45));
	BOOST_CHECK(!valid_control_code(0x60));
	BOOST_CHECK(valid_control_code(0x02));
	BOOST_CHECK(valid_control_code(0x04));
}

BOOST_AUTO_TEST_CASE(ip_packet_size_bounds)
{
	const auto v4 = make_ipv4(40);
	BOOST_CHECK_EQUAL(ip_packet_size(
		reinterpret_cast<const uint8_t*>(v4.data()), v4.size()), 40);
	// 报文比头里的总长还短: 不可信.
	BOOST_CHECK_EQUAL(ip_packet_size(
		reinterpret_cast<const uint8_t*>(v4.data()), 30), 0);
	// 总长字段小于最小头长: 不可信.
	auto bad = make_ipv4(40);
	bad[2] = 0;
	bad[3] = static_cast<char>(4);
	BOOST_CHECK_EQUAL(ip_packet_size(
		reinterpret_cast<const uint8_t*>(bad.data()), bad.size()), 0);
	// 长度不够一个 IP 头.
	BOOST_CHECK_EQUAL(ip_packet_size(
		reinterpret_cast<const uint8_t*>(v4.data()), 10), 0);

	const auto v6 = make_ipv6(100);
	BOOST_CHECK_EQUAL(ip_packet_size(
		reinterpret_cast<const uint8_t*>(v6.data()), v6.size()), 140);
	BOOST_CHECK_EQUAL(ip_packet_size(
		reinterpret_cast<const uint8_t*>(v6.data()), 139), 0);
}

BOOST_AUTO_TEST_CASE(control_message_roundtrip)
{
	std::string body = crypto::random_bytes(64);
	std::string wire;
	append_control_message(wire, control_keepalive, body);
	BOOST_CHECK_EQUAL(wire.size(), control_header_size + body.size());

	uint8_t code = 0;
	std::string_view parsed;
	BOOST_REQUIRE(parse_control_message(wire, code, parsed));
	BOOST_CHECK_EQUAL(code, control_keepalive);
	BOOST_CHECK(parsed == body);

	// 长度字段和实际长度不符: 拒绝.
	std::string bad = wire;
	bad[1] = static_cast<char>(bad[1] + 1);
	BOOST_CHECK(!parse_control_message(bad, code, parsed));
	// 太短: 拒绝.
	BOOST_CHECK(!parse_control_message(wire.substr(0, 2), code, parsed));
	// 消息码是 IP 签名: 拒绝.
	std::string ipcode = wire;
	ipcode[0] = static_cast<char>(0x45);
	BOOST_CHECK(!parse_control_message(ipcode, code, parsed));
	// 消息码是压缩载荷标记: 拒绝 (这个位置只留给压缩载荷).
	std::string cmpcode = wire;
	cmpcode[0] = static_cast<char>(compressed_marker);
	BOOST_CHECK(!parse_control_message(cmpcode, code, parsed));

	// 漫游凭证更新: 内容就是 8 字节新凭证.
	std::string cookie(roam_cookie_size, '\0');
	for (std::size_t i = 0; i < cookie.size(); i++)
		cookie[i] = static_cast<char>(i + 1);
	std::string update;
	append_control_message(update, control_cookie_update, cookie);
	BOOST_REQUIRE(parse_control_message(update, code, parsed));
	BOOST_CHECK_EQUAL(code, control_cookie_update);
	BOOST_CHECK(parsed == cookie);
}

BOOST_AUTO_TEST_CASE(container_roundtrip_and_strictness)
{
	const auto ip1 = make_ipv4(28);
	const auto ip2 = make_ipv6(12);
	std::string ctrl;
	append_control_message(ctrl, control_keepalive_reply, "ping");

	std::vector<std::string_view> in{ ip1, ctrl, ip2 };
	std::string wire;
	append_container(wire, in);
	BOOST_CHECK_EQUAL(static_cast<uint8_t>(wire[0]), container_marker);
	BOOST_CHECK_EQUAL(static_cast<uint8_t>(wire[1]), 3);

	std::vector<std::string_view> out;
	BOOST_REQUIRE(parse_container(wire, out));
	BOOST_REQUIRE_EQUAL(out.size(), 3);
	BOOST_CHECK(out[0] == ip1);
	BOOST_CHECK(out[1] == ctrl);
	BOOST_CHECK(out[2] == ip2);

	// 声明 4 个条目却只有 3 个: 整帧丢弃.
	std::string short_count = wire;
	short_count[1] = 4;
	BOOST_CHECK(!parse_container(short_count, out));

	// 条目数比实际少: 尾部多出的字节被忽略 (定义如此).
	std::string fewer = wire;
	fewer[1] = 1;
	BOOST_CHECK(parse_container(fewer, out));
	BOOST_CHECK_EQUAL(out.size(), 1);

	// IP 包总长超过剩余字节: 整帧丢弃.
	std::string bad_ip = wire;
	bad_ip[2 + 2] = static_cast<char>(0x7f);
	bad_ip[2 + 3] = static_cast<char>(0xff);
	BOOST_CHECK(!parse_container(bad_ip, out));

	// 控制条目长度越界: 整帧丢弃.
	std::string bad_ctrl;
	bad_ctrl.push_back(static_cast<char>(container_marker));
	bad_ctrl.push_back(1);
	bad_ctrl.push_back(static_cast<char>(control_keepalive));
	bad_ctrl.push_back(static_cast<char>(0xff));
	bad_ctrl.push_back(static_cast<char>(0x00));
	bad_ctrl.push_back('x');
	BOOST_CHECK(!parse_container(bad_ctrl, out));

	// 标记字节不对, 空内容: 拒绝.
	BOOST_CHECK(!parse_container(std::string_view(), out));
	BOOST_CHECK(!parse_container(std::string("\x01\x00", 2), out));
}

BOOST_AUTO_TEST_CASE(pack_packets_opportunistic_aggregation)
{
	const auto p40 = make_ipv4(40);
	const auto p60 = make_ipv4(60);
	const auto p1200 = make_ipv4(1200);
	std::vector<std::string_view> packets{ p40, p60, p1200 };

	std::string out;
	// 一片只装得下两个: 容器 = 头 2 + 40 + 60.
	BOOST_CHECK_EQUAL(pack_packets(packets, 0, 102, out), 2u);
	BOOST_CHECK_EQUAL(out.size(), 102u);
	std::vector<std::string_view> entries;
	BOOST_REQUIRE(parse_container(out, entries));
	BOOST_REQUIRE_EQUAL(entries.size(), 2u);
	BOOST_CHECK(entries[0] == p40);
	BOOST_CHECK(entries[1] == p60);

	// 少 1 字节就只装得下第一个: 单包不做容器封装, 一个字节都不多花.
	BOOST_CHECK_EQUAL(pack_packets(packets, 0, 101, out), 1u);
	BOOST_CHECK(out == p40);

	// 从中间开始装.
	BOOST_CHECK_EQUAL(pack_packets(packets, 1, 62, out), 1u);
	BOOST_CHECK(out == p60);

	// 第一个包就超过一片: 原样交出去, 由上层按老路径丢掉.
	BOOST_CHECK_EQUAL(pack_packets(packets, 2, 1000, out), 1u);
	BOOST_CHECK(out == p1200);

	// 起点越界 / 空输入.
	BOOST_CHECK_EQUAL(pack_packets(packets, 3, 1500, out), 0u);
	BOOST_CHECK(out.empty());

	// 一批包按顺序被切成若干帧: 顺序不变, 一个不丢.
	std::size_t pos = 0;
	std::size_t frames = 0;
	std::vector<std::string> restored;
	while (pos < packets.size())
	{
		const std::size_t used = pack_packets(packets, pos, 102, out);
		BOOST_REQUIRE(used > 0);
		if (used == 1)
		{
			// 只装得下一个包时不做容器封装, 出来就是那个包.
			restored.emplace_back(out);
		}
		else
		{
			std::vector<std::string_view> got;
			BOOST_REQUIRE(parse_container(out, got));
			for (auto v : got)
				restored.emplace_back(v);
		}
		pos += used;
		frames++;
	}
	BOOST_CHECK_EQUAL(frames, 2u);  // 前两个合成一帧, 大包自己一帧.
	BOOST_REQUIRE_EQUAL(restored.size(), 3u);
	BOOST_CHECK(restored[0] == p40);
	BOOST_CHECK(restored[1] == p60);
	BOOST_CHECK(restored[2] == p1200);

	// 条目数只有 1 字节: 一次最多装 255 个.
	std::vector<std::string> tiny(300, make_ipv4(20));
	std::vector<std::string_view> many;
	for (auto& t : tiny)
		many.push_back(t);
	BOOST_CHECK_EQUAL(pack_packets(many, 0, 20 * 300 + 2, out),
		container_max_entries);
	BOOST_CHECK_EQUAL(static_cast<uint8_t>(out[1]),
		static_cast<uint8_t>(container_max_entries));
}

BOOST_AUTO_TEST_CASE(seq_arithmetic_across_wrap)
{
	BOOST_CHECK_EQUAL(global_seq(0, 5), 5u);
	BOOST_CHECK_EQUAL(global_seq(1, 0), uint64_t{ 1 } << 32);
	BOOST_CHECK_EQUAL(seq_epoch(global_seq(3, 7)), 3u);
	BOOST_CHECK_EQUAL(seq_counter(global_seq(3, 7)), 7u);

	// 计数器回绕: 次代加一, 计数器归零, 全局序号仍然严格递增.
	const uint32_t last = 0xffffffffu;
	const uint64_t a = global_seq(0, last);
	const uint64_t b = global_seq(1, 0);
	BOOST_CHECK_EQUAL(b, a + 1);

	// 组号 / 片号.
	BOOST_CHECK_EQUAL(group_of(0, 16), 0u);
	BOOST_CHECK_EQUAL(group_of(15, 16), 0u);
	BOOST_CHECK_EQUAL(group_of(16, 16), 1u);
	BOOST_CHECK_EQUAL(shard_of(16, 16), 0u);
	BOOST_CHECK_EQUAL(shard_of(31, 16), 15u);
	// T 整除 2^32, 一组不会跨次代.
	BOOST_CHECK_EQUAL((uint64_t{ 1 } << 32) % 16, 0u);
}

BOOST_AUTO_TEST_CASE(params_roundtrip)
{
	session_params p;
	p.tag_len = 12;
	p.fec_total = 16;
	p.fec_data = 12;
	p.keepalive_sec = 45;
	p.group_abandon_ms = 900;
	p.group_cache_ms = 1800;
	p.early_close_ms = 200;
	p.mtu = 1300;
	p.vaddr = 0x0a000002;
	p.prefix_len = 24;
	p.v6_prefix = 64;
	p.v6_net = net::ip::make_address_v6("fd00::1");
	p.routes = { "10.0.0.0/8", "192.168.0.0/16" };
	p.compress = 1;
	p.obfuscate = true;
	p.obfuscate_key_hash = 0x1234abcd;
	p.roam_cookie = { { 1, 2, 3, 4, 5, 6, 7, 8 } };
	p.cookie_beacon_k = 32;
	p.transport = 1;
	p.pushdns = 0x0a090035;   // 10.9.0.53
	p.passbyvpn = true;

	std::string wire;
	append_params(wire, p);
	BOOST_CHECK(wire.size() > 8);

	session_params q;
	BOOST_REQUIRE(parse_params(wire, q));
	BOOST_CHECK_EQUAL(q.version, p.version);
	BOOST_CHECK_EQUAL(int(q.tag_len), int(p.tag_len));
	BOOST_CHECK_EQUAL(int(q.fec_total), int(p.fec_total));
	BOOST_CHECK_EQUAL(int(q.fec_data), int(p.fec_data));
	BOOST_CHECK_EQUAL(q.keepalive_sec, p.keepalive_sec);
	BOOST_CHECK_EQUAL(q.group_abandon_ms, p.group_abandon_ms);
	BOOST_CHECK_EQUAL(q.group_cache_ms, p.group_cache_ms);
	BOOST_CHECK_EQUAL(q.early_close_ms, p.early_close_ms);
	BOOST_CHECK_EQUAL(q.mtu, p.mtu);
	BOOST_CHECK_EQUAL(q.vaddr, p.vaddr);
	BOOST_CHECK_EQUAL(int(q.prefix_len), int(p.prefix_len));
	BOOST_CHECK_EQUAL(int(q.v6_prefix), int(p.v6_prefix));
	BOOST_CHECK(q.v6_net == p.v6_net);
	BOOST_REQUIRE_EQUAL(q.routes.size(), p.routes.size());
	BOOST_CHECK_EQUAL(q.routes[0], p.routes[0]);
	BOOST_CHECK_EQUAL(q.routes[1], p.routes[1]);
	BOOST_CHECK_EQUAL(int(q.compress), int(p.compress));
	BOOST_CHECK_EQUAL(q.obfuscate, p.obfuscate);
	BOOST_CHECK_EQUAL(q.obfuscate_key_hash, p.obfuscate_key_hash);
	BOOST_CHECK(q.roam_cookie == p.roam_cookie);
	BOOST_CHECK_EQUAL(q.cookie_beacon_k, p.cookie_beacon_k);
	BOOST_CHECK_EQUAL(int(q.transport), int(p.transport));
	BOOST_CHECK_EQUAL(q.pushdns, p.pushdns);
	BOOST_CHECK_EQUAL(q.passbyvpn, p.passbyvpn);

	// 默认参数也要能编解码.
	session_params d;
	std::string dw;
	append_params(dw, d);
	session_params dd;
	BOOST_REQUIRE(parse_params(dw, dd));
	BOOST_CHECK_EQUAL(dd.mtu, d.mtu);
	BOOST_CHECK_EQUAL(int(dd.fec_total), 1);
}

BOOST_AUTO_TEST_CASE(tag_len_negotiation)
{
	// 客户端在握手里表达愿望, 网关按规则定夺: 要 12 就给 12, 其余一律 16.
	BOOST_CHECK_EQUAL(int(negotiate_tag_len(12)), 12);
	BOOST_CHECK_EQUAL(int(negotiate_tag_len(16)), 16);
	BOOST_CHECK_EQUAL(int(negotiate_tag_len(0)), 16);
	BOOST_CHECK_EQUAL(int(negotiate_tag_len(8)), 16);
	BOOST_CHECK_EQUAL(int(negotiate_tag_len(255)), 16);

	// 短标签每帧少 4 字节, 片长上限相应宽 4 字节.
	BOOST_CHECK_EQUAL(wire_payload_limit(12, false),
		wire_payload_limit(16, false) + 4);

	// 谈成的 tag_len 只有 12 / 16 两个合法取值, 参数能原样往返.
	session_params p;
	p.tag_len = negotiate_tag_len(12);
	std::string wire;
	append_params(wire, p);
	session_params q;
	BOOST_REQUIRE(parse_params(wire, q));
	BOOST_CHECK_EQUAL(int(q.tag_len), 12);
}

BOOST_AUTO_TEST_CASE(pushdns_value_parsing)
{
	// 点分写法与整数写法都要认, 结果都是地址的主机字节序数值.
	const uint32_t want = net::ip::make_address_v4("10.9.0.53").to_uint();

	uint32_t v = 0;
	BOOST_REQUIRE(parse_ipv4("10.9.0.53", v));
	BOOST_CHECK_EQUAL(v, want);

	BOOST_REQUIRE(parse_ipv4("168362037", v));
	BOOST_CHECK_EQUAL(v, want);

	BOOST_REQUIRE(parse_ipv4("0.0.0.0", v));
	BOOST_CHECK_EQUAL(v, 0u);

	// 空、越界、带掩码、IPv6 都要拒绝.
	BOOST_CHECK(!parse_ipv4("", v));
	BOOST_CHECK(!parse_ipv4("10.9.0.256", v));
	BOOST_CHECK(!parse_ipv4("4294967296", v));
	BOOST_CHECK(!parse_ipv4("10.9.0.53/24", v));
	BOOST_CHECK(!parse_ipv4("::1", v));
	BOOST_CHECK(!parse_ipv4("10.9.0.53 ", v));
}

BOOST_AUTO_TEST_CASE(compression_negotiation)
{
	using ct = compress_type;

	// 两端要的是同一个算法才启用.
	BOOST_CHECK(negotiate_compress(ct::deflate, ct::deflate) == ct::deflate);
	BOOST_CHECK(negotiate_compress(ct::none, ct::deflate) == ct::none);
	BOOST_CHECK(negotiate_compress(ct::deflate, ct::none) == ct::none);
	BOOST_CHECK(negotiate_compress(ct::deflate, ct::zstd) == ct::none);

	// deflate / lz4 都谈得成, 还没实现的算法不能谈成启用.
	BOOST_CHECK(negotiate_compress(ct::lz4, ct::lz4) == ct::lz4);
	BOOST_CHECK(negotiate_compress(ct::lz4, ct::deflate) == ct::none);
	BOOST_CHECK(negotiate_compress(ct::zstd, ct::zstd) == ct::none);

	// zstd 是协议里的保留值: 名字认得出, 但还没实现, 配置里写了它直接拒绝.
	BOOST_CHECK(compress_type_from_string("zstd") == ct::zstd);
	BOOST_CHECK(!compress_supported(ct::zstd));
	BOOST_CHECK(compress_type_from_string("lz4") == ct::lz4);
	BOOST_CHECK(compress_supported(ct::lz4));
	BOOST_CHECK(compress_supported(ct::deflate));
	BOOST_CHECK(!compress_supported(ct::none));
	// 不认识的名字当成不压缩.
	BOOST_CHECK(compress_type_from_string("gzip") == ct::none);

	// 压缩条目的首字节不能和 IP 包 / 容器撞车.
	BOOST_CHECK(compressed_marker != container_marker);
	BOOST_CHECK(classify_payload(std::string(1,
		static_cast<char>(compressed_marker))) == frame_kind::control);
}

BOOST_AUTO_TEST_CASE(params_reject_bad_values)
{
	// 不支持 tag_len.
	session_params p;
	p.tag_len = 8;
	std::string wire;
	append_params(wire, p);
	session_params q;
	BOOST_CHECK(!parse_params(wire, q));

	// T 不是 2 的幂.
	p = session_params();
	p.fec_total = 3;
	p.fec_data = 2;
	wire.clear();
	append_params(wire, p);
	BOOST_CHECK(!parse_params(wire, q));

	// ds 必须小于 T.
	p = session_params();
	p.fec_total = 8;
	p.fec_data = 8;
	wire.clear();
	append_params(wire, p);
	BOOST_CHECK(!parse_params(wire, q));

	// ds 至少 2 片: 只有一片数据时冗余片就是重复发包, v2 不这么做.
	p = session_params();
	p.fec_total = 4;
	p.fec_data = 1;
	wire.clear();
	append_params(wire, p);
	BOOST_CHECK(!parse_params(wire, q));

	// 不开纠错时 ds 必须是 1.
	p = session_params();
	p.fec_data = 4;
	wire.clear();
	append_params(wire, p);
	BOOST_CHECK(!parse_params(wire, q));

	// 内层 MTU 放不进一片.
	p = session_params();
	p.tag_len = 16;
	p.mtu = 1481;
	wire.clear();
	append_params(wire, p);
	BOOST_CHECK(!parse_params(wire, q));

	// 版本对不上 (v1 或别的版本): 双方没谈成一致, 直接判失败.
	p = session_params();
	p.version = 1;
	wire.clear();
	append_params(wire, p);
	BOOST_CHECK(!parse_params(wire, q));
}

BOOST_AUTO_TEST_CASE(params_tlv_edge_cases)
{
	// 重复参数: 拒绝.
	std::string wire;
	append_params(wire, session_params());
	auto dup = wire;
	dup.push_back(static_cast<char>(0x02));
	dup.push_back(1);
	dup.push_back(static_cast<char>(16));
	session_params q;
	BOOST_CHECK(!parse_params(dup, q));

	// 不认识的参数号: 按长度跳过.
	auto unknown = wire;
	unknown.push_back(static_cast<char>(0x40));
	unknown.push_back(2);
	unknown.push_back(0);
	unknown.append("ab");
	BOOST_REQUIRE(parse_params(unknown, q));

	// 长度字段越界: 拒绝.
	auto bad_len = wire;
	bad_len[1] = static_cast<char>(0xff);
	bad_len[2] = static_cast<char>(0xff);
	BOOST_CHECK(!parse_params(bad_len, q));

	// 尾部只有半个 TLV 头: 拒绝.
	auto half = wire;
	half.push_back(static_cast<char>(0x02));
	BOOST_CHECK(!parse_params(half, q));

	// 固定长度参数给错长度: 拒绝.
	auto bad_fixed = wire;
	bad_fixed[1] = 1;
	bad_fixed[2] = 0;
	BOOST_CHECK(!parse_params(bad_fixed, q));

	// 空参数段本身不是合法参数集 (缺默认 tag_len 等), 但取值都是默认值.
	BOOST_CHECK(parse_params(std::string_view(), q));
}

BOOST_AUTO_TEST_CASE(handshake_req_roundtrip)
{
	handshake_req req;
	req.version = avpn_protocol_v2;
	req.ephemeral_pub = { { 9 } };
	req.timestamp = 0x1122334455667788ull;
	req.client_id = { { 7 } };
	req.requested_vaddr = 0x0a000005;
	req.params.tag_len = 12;
	req.params.fec_total = 4;
	req.params.fec_data = 3;

	const std::string wire = req.serialize();
	// 明文 = 固定字段 + 参数长度(2) + 参数.
	const std::size_t params_len =
		static_cast<uint8_t>(wire[handshake_req_fixed_size]) |
		(static_cast<std::size_t>(static_cast<uint8_t>(
			wire[handshake_req_fixed_size + 1])) << 8);
	BOOST_CHECK_EQUAL(handshake_req_fixed_size + 2 + params_len, wire.size());

	handshake_req out;
	BOOST_REQUIRE(parse_handshake_req(wire, out));
	BOOST_CHECK_EQUAL(out.version, req.version);
	BOOST_CHECK(out.ephemeral_pub == req.ephemeral_pub);
	BOOST_CHECK_EQUAL(out.timestamp, req.timestamp);
	BOOST_CHECK(out.client_id == req.client_id);
	BOOST_CHECK_EQUAL(out.requested_vaddr, req.requested_vaddr);
	BOOST_CHECK_EQUAL(int(out.params.tag_len), 12);
	BOOST_CHECK_EQUAL(int(out.params.fec_total), 4);
	BOOST_CHECK_EQUAL(int(out.params.fec_data), 3);

	// 截断: 拒绝.
	for (std::size_t cut = 1; cut < wire.size(); cut++)
		BOOST_CHECK(!parse_handshake_req(wire.substr(0, cut), out));

	// 参数长度字段和实际不符: 拒绝.
	auto bad = wire;
	bad[handshake_req_fixed_size] =
		static_cast<char>(bad[handshake_req_fixed_size] + 1);
	BOOST_CHECK(!parse_handshake_req(bad, out));
}

BOOST_AUTO_TEST_CASE(handshake_resp_roundtrip)
{
	handshake_resp resp;
	resp.ephemeral_pub = { { 3 } };
	resp.params.mtu = 1300;
	resp.params.roam_cookie = { { 8, 7, 6, 5, 4, 3, 2, 1 } };

	const std::string wire = resp.serialize();
	handshake_resp out;
	BOOST_REQUIRE(parse_handshake_resp(wire, out));
	BOOST_CHECK(out.ephemeral_pub == resp.ephemeral_pub);
	BOOST_CHECK_EQUAL(out.params.mtu, 1300);
	BOOST_CHECK(out.params.roam_cookie == resp.params.roam_cookie);

	for (std::size_t cut = 1; cut < wire.size(); cut++)
		BOOST_CHECK(!parse_handshake_resp(wire.substr(0, cut), out));
}

BOOST_AUTO_TEST_CASE(handshake_hint_deterministic)
{
	const std::string pub = rand_key();
	const auto h1 = make_handshake_hint(pub);
	const auto h2 = make_handshake_hint(pub);
	BOOST_CHECK(h1 == h2);
	BOOST_CHECK(!hint_absent(h1));

	const auto other = make_handshake_hint(rand_key());
	BOOST_CHECK(!(h1 == other));

	// 长度不对时视为不带 hint.
	const auto bad = make_handshake_hint(pub.substr(0, 31));
	BOOST_CHECK(hint_absent(bad));

	std::array<uint8_t, handshake_hint_size> zero{};
	BOOST_CHECK(hint_absent(zero));
}

BOOST_AUTO_TEST_CASE(master_key_agrees_from_both_sides)
{
	const auto as = crypto::x25519_generate_keypair();
	const auto ae = crypto::x25519_generate_keypair();
	const auto bs = crypto::x25519_generate_keypair();
	const auto be = crypto::x25519_generate_keypair();

	std::string ka, kb;
	BOOST_REQUIRE(derive_master_key(as.first, ae.first, bs.second, be.second, ka));
	BOOST_REQUIRE(derive_master_key(bs.first, be.first, as.second, ae.second, kb));
	BOOST_CHECK_EQUAL(ka.size(), crypto::x25519_key_size);
	BOOST_CHECK(ka == kb);

	// 换一把临时公钥, 主密钥必须变.
	std::string kc;
	const auto ce = crypto::x25519_generate_keypair();
	BOOST_REQUIRE(derive_master_key(as.first, ae.first,
		bs.second, ce.second, kc));
	BOOST_CHECK(kc != ka);

	// 入参长度不对: 失败.
	BOOST_CHECK(!derive_master_key(as.first, ae.first, "short", be.second, kc));
}

BOOST_AUTO_TEST_CASE(epoch_keys_and_nonce)
{
	const std::string master = rand_key();
	std::string k0c, k0s, k1c;
	BOOST_REQUIRE(derive_epoch_key(master, 0, true, k0c));
	BOOST_REQUIRE(derive_epoch_key(master, 0, false, k0s));
	BOOST_REQUIRE(derive_epoch_key(master, 1, true, k1c));
	BOOST_CHECK(k0c != k0s);
	BOOST_CHECK(k0c != k1c);

	std::string again;
	BOOST_REQUIRE(derive_epoch_key(master, 0, true, again));
	BOOST_CHECK(again == k0c);

	// 主密钥长度不对: 失败.
	BOOST_CHECK(!derive_epoch_key("short", 0, true, again));

	const auto nonce = make_frame_nonce(0x01020304);
	BOOST_CHECK_EQUAL(int(nonce[0]), 0x04);
	BOOST_CHECK_EQUAL(int(nonce[1]), 0x03);
	BOOST_CHECK_EQUAL(int(nonce[2]), 0x02);
	BOOST_CHECK_EQUAL(int(nonce[3]), 0x01);
	for (std::size_t i = 4; i < nonce.size(); i++)
		BOOST_CHECK_EQUAL(int(nonce[i]), 0);
}

BOOST_AUTO_TEST_CASE(epoch_key_cache_caches)
{
	epoch_key_cache cache;
	BOOST_CHECK(!cache.ready());
	BOOST_CHECK(cache.key(0, true).empty());

	const std::string master = rand_key();
	cache.set_master(master);
	BOOST_CHECK(cache.ready());

	const std::string& a = cache.key(0, true);
	BOOST_REQUIRE_EQUAL(a.size(), crypto::x25519_key_size);
	const std::string& b = cache.key(0, true);
	BOOST_CHECK(&a == &b);

	std::string direct;
	BOOST_REQUIRE(derive_epoch_key(master, 1, true, direct));
	BOOST_CHECK(direct == cache.key(1, true));

	// 收发方向与不同次代各自独立.
	BOOST_CHECK(cache.key(0, false) != cache.key(0, true));
	BOOST_CHECK(cache.key(1, true) != cache.key(0, true));

	cache.clear();
	BOOST_CHECK(!cache.ready());
	BOOST_CHECK(cache.key(0, true).empty());
}

BOOST_AUTO_TEST_CASE(seq_window_replay_and_wrap)
{
	seq_window w(64);
	BOOST_CHECK(w.check_and_update(1000));
	BOOST_CHECK(w.check_and_update(1001));
	// 重放: 拒绝.
	BOOST_CHECK(!w.check_and_update(1000));
	// 窗口内的乱序包: 接受一次.
	BOOST_CHECK(w.check_and_update(999));
	BOOST_CHECK(!w.check_and_update(999));
	// 太旧: 拒绝.
	BOOST_CHECK(!w.check_and_update(500));

	// 跨次代连续: 次代 0 的最后一帧与次代 1 的第一帧相邻.
	seq_window v(64);
	BOOST_CHECK(v.check_and_update(global_seq(0, 0xffffffffu)));
	BOOST_CHECK(v.check_and_update(global_seq(1, 0)));
	BOOST_CHECK(v.check_and_update(global_seq(1, 1)));
	BOOST_CHECK(!v.check_and_update(global_seq(0, 0xffffffffu)));

	// 大幅跳跃后窗口整体前移.
	seq_window u(16);
	BOOST_CHECK(u.check_and_update(0));
	BOOST_CHECK(u.check_and_update(uint64_t{ 1 } << 40));
	BOOST_CHECK(u.check_and_update((uint64_t{ 1 } << 40) - 1));
	BOOST_CHECK(!u.check_and_update(0));

	u.reset();
	BOOST_CHECK(u.check_and_update(0));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(tcp_framing)

namespace {

	// 按 TCP 线格式给一帧加上 2 字节大端长度前缀.
	std::string tcp_pack(const std::string& frame)
	{
		const uint16_t len = static_cast<uint16_t>(frame.size());
		std::string out;
		out.push_back(static_cast<char>((len >> 8) & 0xff));
		out.push_back(static_cast<char>(len & 0xff));
		out.append(frame);
		return out;
	}

	// 喂一段字节进去, 收走这次切出来的帧.
	std::vector<std::string> tcp_take(tcp_frame_reader& reader,
		const std::string& bytes)
	{
		std::vector<std::string> frames;
		reader.push(reinterpret_cast<const uint8_t*>(bytes.data()),
			bytes.size(),
			[&frames](std::string_view frame)
			{
				frames.emplace_back(frame);
			});
		return frames;
	}

} // namespace

BOOST_AUTO_TEST_CASE(tcp_frame_reader_merges_and_splits)
{
	tcp_frame_reader reader;

	// 一次读到两帧 (TCP 会把多次发送合并到一起).
	auto frames = tcp_take(reader, tcp_pack("hello") + tcp_pack("world!"));
	BOOST_REQUIRE_EQUAL(frames.size(), 2);
	BOOST_CHECK_EQUAL(frames[0], "hello");
	BOOST_CHECK_EQUAL(frames[1], "world!");
	BOOST_CHECK_EQUAL(reader.pending(), 0);

	// 一次发送被拆开投递: 逐字节喂进去, 凑齐才出帧.
	const std::string wire = tcp_pack("abcdef");
	std::size_t got = 0;
	for (char c : wire)
		got += tcp_take(reader, std::string(1, c)).size();
	BOOST_CHECK_EQUAL(got, 1);
	BOOST_CHECK_EQUAL(reader.pending(), 0);

	// 长度前缀到了、内容没到: 先留着等下一段.
	const std::string full = tcp_pack("0123456789");
	frames = tcp_take(reader, full.substr(0, 5));
	BOOST_CHECK(frames.empty());
	BOOST_CHECK_EQUAL(reader.pending(), 5);
	frames = tcp_take(reader, full.substr(5));
	BOOST_REQUIRE_EQUAL(frames.size(), 1);
	BOOST_CHECK_EQUAL(frames[0], "0123456789");
	BOOST_CHECK_EQUAL(reader.pending(), 0);

	// 最长的一帧 (65535 字节) 也要能切出来.
	frames = tcp_take(reader, tcp_pack(std::string(65535, 'z')));
	BOOST_REQUIRE_EQUAL(frames.size(), 1);
	BOOST_CHECK_EQUAL(frames[0].size(), 65535u);
}

BOOST_AUTO_TEST_CASE(tcp_frame_reader_resyncs_after_zero_length)
{
	tcp_frame_reader reader;

	// 长度 0 表示这一路字节流已经对不上帧边界: 整段丢掉重新找.
	const std::string bad = std::string(2, '\0');
	auto frames = tcp_take(reader, bad + tcp_pack("x"));
	BOOST_CHECK(frames.empty());
	BOOST_CHECK_EQUAL(reader.pending(), 0);

	// 丢掉之后, 重新对齐的帧照常切出来.
	frames = tcp_take(reader, tcp_pack("ok"));
	BOOST_REQUIRE_EQUAL(frames.size(), 1);
	BOOST_CHECK_EQUAL(frames[0], "ok");
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(fec_v2)

namespace {

	// 造一个内容明显不同的 IPv4 包, 便于比对还原结果.
	std::string ipv4_payload(std::size_t total, uint8_t seed)
	{
		std::string s = make_ipv4(total);
		for (std::size_t i = 4; i < s.size(); i++)
			s[i] = static_cast<char>(seed + i);
		return s;
	}

	// 把发送端吐出来的片全部喂给接收端, drop 里的下标跳过 (模拟丢包).
	void feed(fec_receiver& rx, const std::vector<fec_shard>& shards,
		const std::set<std::size_t>& drop, uint64_t now,
		std::vector<std::string>& got)
	{
		std::vector<std::string_view> out;
		for (std::size_t i = 0; i < shards.size(); i++)
		{
			if (drop.count(i) != 0)
				continue;
			out.clear();
			rx.on_shard(shards[i].counter, shards[i].payload, now, out);
			for (auto v : out)
				got.emplace_back(v);
		}
	}

} // namespace

BOOST_AUTO_TEST_CASE(sender_whole_frame_mode)
{
	fec_sender tx;
	tx.configure(1, 1, 1380, 1000, 0);

	std::vector<fec_shard> out;
	BOOST_REQUIRE(tx.push("aaa", 0, out));
	BOOST_REQUIRE(tx.push("bbb", 1, out));
	BOOST_REQUIRE(tx.push("ccc", 2, out));

	BOOST_REQUIRE_EQUAL(out.size(), 3);
	for (std::size_t i = 0; i < out.size(); i++)
	{
		BOOST_CHECK_EQUAL(out[i].counter, i);
		BOOST_CHECK(!out[i].redundant);
	}
	BOOST_CHECK(out[0].payload == "aaa");
	BOOST_CHECK(out[2].payload == "ccc");
	// 整帧模式没有半满的组, 计时器也不做事.
	out.clear();
	tx.tick(100000, out);
	BOOST_CHECK(out.empty());
}

BOOST_AUTO_TEST_CASE(sender_group_fills_and_wraps)
{
	fec_sender tx;
	tx.configure(16, 12, 1380, 1000, 0);

	std::vector<fec_shard> shards;
	for (int i = 0; i < 12; i++)
	{
		std::vector<fec_shard> out;
		BOOST_REQUIRE(tx.push(ipv4_payload(20 + i, static_cast<uint8_t>(i)),
			static_cast<uint64_t>(i), out));
		for (auto& s : out)
			shards.push_back(std::move(s));
	}

	BOOST_REQUIRE_EQUAL(shards.size(), 16);
	for (std::size_t i = 0; i < 12; i++)
		if (i < 12)
		{
			BOOST_CHECK_EQUAL(shards[i].counter, i);
			BOOST_CHECK(!shards[i].redundant);
		}
	for (std::size_t i = 12; i < 16; i++)
	{
		BOOST_CHECK_EQUAL(shards[i].counter, i);
		BOOST_CHECK(shards[i].redundant);
		// S = 本组最长的那片 (20 + 11).
		BOOST_CHECK_EQUAL(shards[i].payload.size(), 31);
	}

	// 下一组从 T 的下一个整数倍开始.
	std::vector<fec_shard> next;
	BOOST_REQUIRE(tx.push(ipv4_payload(20, 0x40), 100, next));
	BOOST_REQUIRE_EQUAL(next.size(), 1);
	BOOST_CHECK_EQUAL(next[0].counter, 16);
	BOOST_CHECK_EQUAL(tx.used(), 1);
}

BOOST_AUTO_TEST_CASE(sender_abandons_half_group)
{
	fec_sender tx;
	tx.configure(16, 12, 1380, 1000, 0);

	std::vector<fec_shard> out;
	BOOST_REQUIRE(tx.push(ipv4_payload(20, 1), 0, out));
	BOOST_REQUIRE(tx.push(ipv4_payload(20, 2), 1, out));
	BOOST_CHECK_EQUAL(tx.used(), 2);

	// 时间没到: 什么都不做.
	out.clear();
	tx.tick(999, out);
	BOOST_CHECK(out.empty());
	BOOST_CHECK_EQUAL(tx.used(), 2);

	// 超时: 放弃这一组, 不发冗余片.
	tx.tick(1001, out);
	BOOST_CHECK(out.empty());
	BOOST_CHECK_EQUAL(tx.used(), 0);

	// 下一个包从下一组开始.
	BOOST_REQUIRE(tx.push(ipv4_payload(20, 3), 1002, out));
	BOOST_REQUIRE_EQUAL(out.size(), 1);
	BOOST_CHECK_EQUAL(out[0].counter, 16);
}

BOOST_AUTO_TEST_CASE(sender_early_close_marks_real_count)
{
	fec_sender tx;
	tx.configure(16, 12, 1380, 1000, 100);

	std::vector<fec_shard> out;
	BOOST_REQUIRE(tx.push(ipv4_payload(30, 1), 0, out));
	BOOST_REQUIRE(tx.push(ipv4_payload(40, 2), 10, out));
	BOOST_REQUIRE_EQUAL(out.size(), 2);

	out.clear();
	tx.tick(111, out);
	BOOST_REQUIRE_EQUAL(out.size(), 4);  // ps = 16 - 12
	for (std::size_t i = 0; i < out.size(); i++)
	{
		BOOST_CHECK(out[i].redundant);
		BOOST_CHECK_EQUAL(out[i].counter, 12 + i);
		// 提前关组: 明文 = 实际数据片数(1) + 冗余片(S).
		BOOST_CHECK_EQUAL(out[i].payload.size(), 1 + 40);
		BOOST_CHECK_EQUAL(static_cast<uint8_t>(out[i].payload[0]), 2);
	}
	BOOST_CHECK_EQUAL(tx.used(), 0);

	// 关组后下一个包从下一组开始.
	out.clear();
	BOOST_REQUIRE(tx.push(ipv4_payload(20, 3), 200, out));
	BOOST_REQUIRE_EQUAL(out[0].counter, 16);
}

BOOST_AUTO_TEST_CASE(receiver_recovers_lost_shards)
{
	fec_sender tx;
	tx.configure(16, 12, 1380, 1000, 0);
	fec_receiver rx;
	rx.configure(16, 12, false, 2000);

	std::vector<std::string> sent;
	std::vector<fec_shard> shards;
	for (int i = 0; i < 12; i++)
	{
		std::string p = ipv4_payload(40 + i * 3, static_cast<uint8_t>(i));
		sent.push_back(p);
		std::vector<fec_shard> out;
		BOOST_REQUIRE(tx.push(p, static_cast<uint64_t>(i), out));
		for (auto& s : out)
			shards.push_back(std::move(s));
	}
	BOOST_REQUIRE_EQUAL(shards.size(), 16);

	// 丢掉 4 片数据 (正好等于冗余片数), 剩下的应该全都能还原.
	std::set<std::size_t> drop{ 1, 5, 9, 11 };
	std::vector<std::string> got;
	feed(rx, shards, drop, 10, got);

	BOOST_REQUIRE_EQUAL(got.size(), sent.size());
	std::multiset<std::string> got_set(got.begin(), got.end());
	for (const auto& p : sent)
		BOOST_CHECK_EQUAL(got_set.count(p), 1);

	// 全部还原完, 留的组应该清空了.
	BOOST_CHECK_EQUAL(rx.group_count(), 0);
}

BOOST_AUTO_TEST_CASE(receiver_gives_up_when_too_many_lost)
{
	fec_sender tx;
	tx.configure(16, 12, 1380, 1000, 0);
	fec_receiver rx;
	rx.configure(16, 12, false, 2000);

	std::vector<std::string> sent;
	std::vector<fec_shard> shards;
	for (int i = 0; i < 12; i++)
	{
		std::string p = ipv4_payload(40, static_cast<uint8_t>(i));
		sent.push_back(p);
		std::vector<fec_shard> out;
		tx.push(p, static_cast<uint64_t>(i), out);
		for (auto& s : out)
			shards.push_back(std::move(s));
	}

	// 丢 5 片数据, 超过 4 片冗余的能力, 缺的还原不回来.
	std::set<std::size_t> drop{ 0, 1, 2, 3, 4 };
	std::vector<std::string> got;
	feed(rx, shards, drop, 10, got);
	BOOST_CHECK_EQUAL(got.size(), 7);

	// 留的组过一会儿会被丢掉.
	BOOST_CHECK_EQUAL(rx.group_count(), 1);
	rx.tick(10 + 2000);
	BOOST_CHECK_EQUAL(rx.group_count(), 0);
}

BOOST_AUTO_TEST_CASE(receiver_early_close_recovers_short_group)
{
	fec_sender tx;
	tx.configure(16, 12, 1380, 1000, 100);
	fec_receiver rx;
	rx.configure(16, 12, true, 2000);

	std::vector<std::string> sent;
	std::vector<fec_shard> shards;
	for (int i = 0; i < 3; i++)
	{
		std::string p = ipv4_payload(60 + i, static_cast<uint8_t>(i));
		sent.push_back(p);
		std::vector<fec_shard> out;
		tx.push(p, static_cast<uint64_t>(i), out);
		for (auto& s : out)
			shards.push_back(std::move(s));
	}
	std::vector<fec_shard> close;
	tx.tick(150, close);
	for (auto& s : close)
		shards.push_back(std::move(s));
	BOOST_REQUIRE_EQUAL(shards.size(), 3 + 4);

	// 丢中间那片数据: 剩下 2 片 + 4 片冗余, 靠"其余数据片是全零"把这片补回来.
	std::set<std::size_t> drop{ 1 };
	std::vector<std::string> got;
	feed(rx, shards, drop, 200, got);

	BOOST_REQUIRE_EQUAL(got.size(), 3);
	std::multiset<std::string> got_set(got.begin(), got.end());
	for (const auto& p : sent)
		BOOST_CHECK_EQUAL(got_set.count(p), 1);
}

BOOST_AUTO_TEST_CASE(receiver_rejects_dishonest_shard_size)
{
	fec_sender tx;
	tx.configure(8, 6, 1380, 1000, 0);
	fec_receiver rx;
	rx.configure(8, 6, false, 2000);

	std::vector<fec_shard> shards;
	for (int i = 0; i < 6; i++)
	{
		std::vector<fec_shard> out;
		tx.push(ipv4_payload(40, static_cast<uint8_t>(i)),
			static_cast<uint64_t>(i), out);
		for (auto& s : out)
			shards.push_back(std::move(s));
	}
	BOOST_REQUIRE_EQUAL(shards.size(), 8);

	std::vector<std::string_view> out;
	std::vector<std::string> got;
	// 先把数据片喂进去.
	for (std::size_t i = 0; i < 2; i++)
	{
		out.clear();
		rx.on_shard(shards[i].counter, shards[i].payload, 1, out);
	}
	// 一片冗余给出一个 S, 另一片给出不同的 S: 整组丢掉.
	shards[6].payload.push_back('x');
	rx.on_shard(shards[6].counter, shards[6].payload, 2, out);
	out.clear();
	rx.on_shard(shards[7].counter, shards[7].payload, 3, out);
	BOOST_CHECK_EQUAL(rx.group_count(), 0);

	// 数据片长度超过 S: 只丢这一片.
	BOOST_CHECK(!rx.on_shard(shards[0].counter + 8,
		std::string(5000, 'i'), 4, out));
}

BOOST_AUTO_TEST_CASE(receiver_delivers_in_arrival_order_and_ignores_dups)
{
	fec_sender tx;
	tx.configure(4, 3, 1380, 1000, 0);
	fec_receiver rx;
	rx.configure(4, 3, false, 2000);

	std::vector<std::string> sent;
	std::vector<fec_shard> shards;
	for (int i = 0; i < 3; i++)
	{
		std::string p = ipv4_payload(20 + i, static_cast<uint8_t>(i));
		sent.push_back(p);
		std::vector<fec_shard> out;
		tx.push(p, static_cast<uint64_t>(i), out);
		for (auto& s : out)
			shards.push_back(std::move(s));
	}
	BOOST_REQUIRE_EQUAL(shards.size(), 4);

	std::vector<std::string_view> out;
	std::vector<std::string> got;
	// 乱序到达, 数据片照样立刻投递.
	const int order[] = { 2, 0 };
	for (int idx : order)
	{
		out.clear();
		BOOST_CHECK(rx.on_shard(shards[idx].counter, shards[idx].payload,
			1, out));
		for (auto v : out)
			got.emplace_back(v);
	}
	BOOST_REQUIRE_EQUAL(got.size(), 2);
	BOOST_CHECK(got[0] == sent[2]);
	BOOST_CHECK(got[1] == sent[0]);

	// 重复片: 丢掉, 不重复投递.
	out.clear();
	BOOST_CHECK(!rx.on_shard(shards[2].counter, shards[2].payload, 2, out));
	BOOST_CHECK(out.empty());

	// 补上最后一片数据: 数据收全, 不需要冗余.
	out.clear();
	BOOST_CHECK(rx.on_shard(shards[1].counter, shards[1].payload, 3, out));
	BOOST_REQUIRE_EQUAL(out.size(), 1);
	BOOST_CHECK(out[0] == sent[1]);
	BOOST_CHECK_EQUAL(rx.group_count(), 0);
}

BOOST_AUTO_TEST_CASE(receiver_whole_frame_mode_passes_through)
{
	fec_receiver rx;
	rx.configure(1, 1, false, 2000);

	std::vector<std::string_view> out;
	BOOST_CHECK(rx.on_shard(0, "hello", 1, out));
	BOOST_REQUIRE_EQUAL(out.size(), 1);
	BOOST_CHECK(out[0] == "hello");
	BOOST_CHECK(!rx.on_shard(1, std::string_view(), 1, out));
}

BOOST_AUTO_TEST_CASE(obfuscate_roundtrip)
{
	const std::string key = "a-shared-obfuscate-key";
	const std::string frame = "0123456789abcdef(this is one frame)";
	obfuscate_rand rand;
	rand.seed("seed-for-tests");

	const std::size_t padding = obfuscate_padding_for(frame.size());
	BOOST_CHECK_GE(padding, obfuscate_min_padding);
	BOOST_CHECK_LE(padding, obfuscate_max_padding);

	std::string wire = obfuscate_frame(rand, key, frame);
	BOOST_REQUIRE(!wire.empty());

	// 外面多出来的就是 salt + 长度字段 + 16~64 字节垃圾.
	const std::size_t extra = wire.size() - frame.size();
	BOOST_CHECK(extra >= obfuscate_fixed_overhead + obfuscate_min_padding);
	BOOST_CHECK(extra <= obfuscate_max_overhead);

	std::string_view got;
	BOOST_REQUIRE(deobfuscate_frame(key, wire, got));
	BOOST_CHECK(got == frame);

	// 换个密钥串就剥不出原来的帧 (垃圾长度算不对).
	std::string_view wrong;
	if (deobfuscate_frame("another-key", wire, wrong))
		BOOST_CHECK(wrong != frame && !wrong.empty());

	// 帧长不同的包, 套出来的长度也不同 (垃圾长度跟着帧长走).
	std::set<std::size_t> sizes;
	for (int i = 0; i < 64; i++)
	{
		std::string w = obfuscate_frame(rand, key,
			frame + std::string(static_cast<std::size_t>(i), 'x'));
		BOOST_REQUIRE(!w.empty());
		std::string_view inner;
		BOOST_REQUIRE(deobfuscate_frame(key, w, inner));
		BOOST_CHECK(inner == frame + std::string(
			static_cast<std::size_t>(i), 'x'));
		sizes.insert(w.size());
	}
	BOOST_CHECK_GT(sizes.size(), 8);

	// 等长帧套出来一定等长: 内核的合并优化 (GRO / GSO) 靠这个.
	BOOST_CHECK_EQUAL(obfuscate_frame(rand, key, frame).size(),
		obfuscate_frame(rand, key, frame).size());
	BOOST_CHECK_EQUAL(obfuscate_padding_for(1430),
		obfuscate_padding_for(1430));

	// 空密钥串 / 空帧不套.
	BOOST_CHECK(obfuscate_frame(rand, "", frame).empty());
	BOOST_CHECK(obfuscate_frame(rand, key, "").empty());
	BOOST_CHECK(!deobfuscate_frame("", wire, wrong));
	BOOST_CHECK(!deobfuscate_frame(key, frame, wrong));  // 太短, 剥不了
}

BOOST_AUTO_TEST_CASE(obfuscate_shrinks_shard_limit)
{
	// 一片的长度上限 = 线缆 MTU 减去外层 IP/UDP 头、帧头和认证标签.
	session_params plain;
	BOOST_CHECK_EQUAL(plain.shard_limit(),
		wire_payload_limit(plain.tag_len, false));
	BOOST_CHECK(plain.shard_limit() + frame_header_size + plain.tag_len +
		wire_outer_overhead <= max_wire_mtu);

	// 开混淆: 片长上限要让出最坏情况下的混淆开销, 套完垃圾再装进 UDP
	// 报文, 仍然不超过线缆 MTU (不会被 IP 分片).
	session_params obf;
	obf.obfuscate = true;
	BOOST_CHECK_EQUAL(obf.shard_limit(),
		plain.shard_limit() - obfuscate_max_overhead);
	BOOST_CHECK(obf.shard_limit() + frame_header_size + obf.tag_len +
		obfuscate_max_overhead + wire_outer_overhead <= max_wire_mtu);
	BOOST_CHECK(obf.valid());

	// 内层 MTU 的粗校验按不含混淆开销的上限来 (开不开混淆由应答方定).
	obf.mtu = static_cast<uint16_t>(obf.shard_limit());
	BOOST_CHECK(obf.valid());
	obf.mtu = static_cast<uint16_t>(plain.shard_limit() + 1);
	BOOST_CHECK(!obf.valid());
}

BOOST_AUTO_TEST_CASE(mtu_is_clamped_to_shard_limit)
{
	// 不含混淆: 上限是 1452, 恰好等于片长, 不用收.
	session_params plain;
	plain.mtu = static_cast<uint16_t>(plain.shard_limit());
	clamp_mtu_to_shard_limit(plain);
	BOOST_CHECK_EQUAL(plain.mtu, plain.shard_limit());

	// 开混淆: 片长让出混淆开销, 收到的大 MTU 得跟着收到片长上.
	session_params obf;
	obf.obfuscate = true;
	obf.mtu = static_cast<uint16_t>(wire_payload_limit(obf.tag_len, false));
	clamp_mtu_to_shard_limit(obf);
	BOOST_CHECK_EQUAL(obf.mtu, obf.shard_limit());
	BOOST_CHECK_EQUAL(obf.mtu,
		plain.shard_limit() - obfuscate_max_overhead);

	// 比上限小的值不动.
	session_params small;
	small.mtu = 1300;
	clamp_mtu_to_shard_limit(small);
	BOOST_CHECK_EQUAL(small.mtu, 1300);
}

BOOST_AUTO_TEST_CASE(fec_is_off_on_reliable_transport)
{
	// UDP 上按配置开纠错.
	session_params udp;
	negotiate_fec(false, 12, 4, udp);
	BOOST_CHECK_EQUAL(int(udp.fec_total), 16);
	BOOST_CHECK_EQUAL(int(udp.fec_data), 12);
	BOOST_CHECK(udp.valid());

	// TCP 自带重传, 补冗余片只是白占带宽.
	session_params tcp;
	negotiate_fec(true, 12, 4, tcp);
	BOOST_CHECK_EQUAL(int(tcp.fec_total), 1);
	BOOST_CHECK_EQUAL(int(tcp.fec_data), 1);
	BOOST_CHECK(tcp.valid());

	// 总片数只能取 2 / 4 / 8 / 16, 数据片至少 2 片, 冗余片至少 1 片.
	struct
	{
		int ds;
		int ps;
		int total;
		int data;
	} cases[] = {
		{ 12, 4, 16, 12 },
		{ 2, 0, 1, 1 },     // 没有冗余片, 不开.
		{ 1, 1, 1, 1 },     // 只有一片数据, 不开.
		{ 1, 3, 1, 1 },     // 退化成一比多的放大发包, v2 不支持.
		{ 12, 3, 1, 1 },    // 总片数 15 不是 2 的幂, 不开.
		{ 3, 1, 4, 3 },
		{ 6, 2, 8, 6 },
		{ 8, 8, 16, 8 },
		{ 7, 1, 8, 7 },
		{ 15, 1, 16, 15 },
	};

	for (const auto& c : cases)
	{
		session_params p;
		negotiate_fec(false, c.ds, c.ps, p);
		BOOST_CHECK_EQUAL(int(p.fec_total), c.total);
		BOOST_CHECK_EQUAL(int(p.fec_data), c.data);
		BOOST_CHECK(p.valid());
	}
}

BOOST_AUTO_TEST_CASE(obfuscate_rejects_broken_length)
{
	const std::string key = "a-shared-obfuscate-key";
	const std::string frame = "0123456789abcdef";
	obfuscate_rand rand;
	rand.seed("seed-for-tests");
	const std::string wire = obfuscate_frame(rand, key, frame);
	BOOST_REQUIRE(!wire.empty());

	// 垃圾还没读全就剥不了 (帧本身的完整性由 AEAD 兜底, 不在这里管).
	std::string_view got;
	BOOST_CHECK(!deobfuscate_frame(key,
		std::string_view(wire).substr(0,
			obfuscate_fixed_overhead + obfuscate_min_padding - 1), got));

	// 长度字段被改: 算出来的垃圾长度要么越界, 要么对不上, 反正不能
	// 得到原来的帧.
	for (std::size_t i = obfuscate_salt_size;
		i < obfuscate_salt_size + obfuscate_len_field_size; i++)
	{
		std::string bad = wire;
		bad[i] = static_cast<char>(bad[i] ^ 0xff);
		std::string_view inner;
		if (deobfuscate_frame(key, bad, inner))
			BOOST_CHECK(inner != frame);
	}

	// 掩码: 同一个 salt 结果稳定, 换个 salt 基本都会变.
	const std::string salt = "abcd";
	BOOST_CHECK_EQUAL(obfuscate_mask(key, salt),
		obfuscate_mask(key, salt));
	BOOST_CHECK_EQUAL(obfuscate_mask("", salt), obfuscate_mask("", salt));

	// 密钥指纹: 配了才有值, 两端一致才谈得成.
	BOOST_CHECK_EQUAL(obfuscate_key_hash(""), 0u);
	BOOST_CHECK_NE(obfuscate_key_hash(key), 0u);
	BOOST_CHECK_EQUAL(obfuscate_key_hash(key), obfuscate_key_hash(key));
	BOOST_CHECK_NE(obfuscate_key_hash(key),
		obfuscate_key_hash("another-key"));
}

BOOST_AUTO_TEST_SUITE_END()
