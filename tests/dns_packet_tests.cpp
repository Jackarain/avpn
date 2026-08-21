#define BOOST_TEST_MODULE avpn_dns_packet_tests
#include <boost/test/unit_test.hpp>

#include "libavpn/dns_packet.hpp"

#include <cstring>
#include <vector>

using namespace libavpn;

namespace {

	// 构建 IPv4 UDP/53 DNS 查询包 (源 10.0.0.1:12345 -> 8.8.8.8:53).
	std::vector<uint8_t> make_dns_query_packet()
	{
		std::vector<uint8_t> pkt;

		// IPv4 头 (20 字节).
		pkt = {
			0x45, 0x00, 0x00, 0x38, 0x12, 0x34, 0x00, 0x00,
			0x40, 0x11, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01,
			0x08, 0x08, 0x08, 0x08,
		};
		// UDP 头 (8 字节).
		pkt.insert(pkt.end(), { 0x30, 0x39, 0x00, 0x35, 0x00, 0x24, 0x00, 0x00 });
		// DNS 查询: id=0x1234, RD, qdcount=1, example.com A IN.
		pkt.insert(pkt.end(), {
			0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
			0x03, 'c', 'o', 'm',
			0x00, 0x00, 0x01, 0x00, 0x01,
		});
		return pkt;
	}

	// 简单 DNS 回复消息 (>= 12 字节).
	std::vector<uint8_t> make_dns_reply()
	{
		return {
			0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01,
			0x00, 0x00, 0x00, 0x00,
			0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
			0x03, 'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00, 0x01,
			0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
			0x00, 0x3c, 0x00, 0x04, 0x5d, 0xb8, 0xd8, 0x22,
		};
	}

	// 校验 IP 头校验和字段是否与头内容一致 (重算应得 0).
	bool ip_checksum_ok(const std::vector<uint8_t>& pkt)
	{
		if (pkt.size() < 20)
			return false;
		std::size_t ihl = (pkt[0] & 0x0f) * 4;
		return dns_packet::internet_checksum(pkt.data(), ihl) == 0;
	}

	// 校验 IPv4 UDP 校验和 (伪头 + UDP + 数据重算应得 0, 校验和字段为 0 时跳过).
	bool udp_checksum_ok(const std::vector<uint8_t>& pkt)
	{
		if (pkt.size() < 28)
			return false;
		std::size_t ihl = (pkt[0] & 0x0f) * 4;
		if (pkt[ihl + 6] == 0 && pkt[ihl + 7] == 0)
			return true;
		uint16_t udp_len = (static_cast<uint16_t>(pkt[ihl + 4]) << 8)
			| pkt[ihl + 5];
		uint32_t sum = 0;
		for (int i = 0; i < 4; i += 2)
			sum += (static_cast<uint32_t>(pkt[12 + i]) << 8) | pkt[13 + i];
		for (int i = 0; i < 4; i += 2)
			sum += (static_cast<uint32_t>(pkt[16 + i]) << 8) | pkt[17 + i];
		sum += 17;
		sum += udp_len;
		return dns_packet::internet_checksum(pkt.data() + ihl,
			udp_len, sum) == 0;
	}

} // namespace

BOOST_AUTO_TEST_CASE(parse_qname_basic)
{
	auto pkt = make_dns_query_packet();
	const uint8_t* dns = nullptr;
	std::size_t dns_len = 0;
	BOOST_REQUIRE(dns_packet::locate_udp53(pkt, dns, dns_len));

	std::string qname;
	BOOST_REQUIRE(dns_packet::parse_qname(dns, dns_len, qname));
	BOOST_CHECK_EQUAL(qname, "example.com");
}

BOOST_AUTO_TEST_CASE(parse_qname_uppercase)
{
	// 构造大写域名查询.
	std::vector<uint8_t> pkt = make_dns_query_packet();
	// 将 DNS 中的 e/x/a/m/p/l/e 大写化.
	std::size_t qoff = 20 + 8 + 12 + 1;
	for (std::size_t i = 0; i < 7; i++)
		pkt[qoff + i] = static_cast<uint8_t>(pkt[qoff + i] - 32);

	const uint8_t* dns = nullptr;
	std::size_t dns_len = 0;
	BOOST_REQUIRE(dns_packet::locate_udp53(pkt, dns, dns_len));
	std::string qname;
	BOOST_REQUIRE(dns_packet::parse_qname(dns, dns_len, qname));
	BOOST_CHECK_EQUAL(qname, "example.com");
}

BOOST_AUTO_TEST_CASE(locate_udp53_filters)
{
	// 非 53 端口不命中.
	auto pkt = make_dns_query_packet();
	pkt[20 + 2] = 0x00;
	pkt[20 + 3] = 0x50; // dst port = 80.
	const uint8_t* dns = nullptr;
	std::size_t dns_len = 0;
	BOOST_CHECK(!dns_packet::locate_udp53(pkt, dns, dns_len));

	// TCP (proto=6) 不命中.
	pkt = make_dns_query_packet();
	pkt[9] = 6;
	BOOST_CHECK(!dns_packet::locate_udp53(pkt, dns, dns_len));

	// IPv6 UDP/53 命中.
	std::vector<uint8_t> v6(40 + 8 + 12 + 15, 0);
	v6[0] = 0x60; // IPv6.
	v6[6] = 17;   // UDP.
	v6[8] = 0x20; v6[9] = 0x01; v6[10] = 0x0d; v6[11] = 0xb8;
	v6[24] = 0x20; v6[25] = 0x01; v6[26] = 0x48; v6[27] = 0x60;
	v6[40 + 2] = 0x00; v6[40 + 3] = 0x35; // dst port 53.
	v6[40 + 4] = 0x00; v6[40 + 5] = 0x23; // udp len 35.
	BOOST_CHECK(dns_packet::locate_udp53(v6, dns, dns_len));

	// IPv4 分片包不命中.
	pkt = make_dns_query_packet();
	pkt[6] = 0x00; pkt[7] = 0x01; // frag offset = 1.
	BOOST_CHECK(!dns_packet::locate_udp53(pkt, dns, dns_len));
}

BOOST_AUTO_TEST_CASE(build_reply_ipv4)
{
	auto req = make_dns_query_packet();
	auto reply = make_dns_reply();

	std::vector<uint8_t> out;
	BOOST_REQUIRE(dns_packet::build_reply(req, reply.data(), reply.size(), out));

	// 源/目的 IP 互换: 原请求 src=10.0.0.1, dst=8.8.8.8, 回复应反向.
	BOOST_CHECK_EQUAL(out[12], 8);
	BOOST_CHECK_EQUAL(out[13], 8);
	BOOST_CHECK_EQUAL(out[14], 8);
	BOOST_CHECK_EQUAL(out[15], 8);
	BOOST_CHECK_EQUAL(out[16], 10);
	BOOST_CHECK_EQUAL(out[17], 0);
	BOOST_CHECK_EQUAL(out[18], 0);
	BOOST_CHECK_EQUAL(out[19], 1);

	// UDP 端口互换: 回复 src=53, dst=12345.
	std::size_t ihl = 20;
	BOOST_CHECK_EQUAL(out[ihl + 0], 0);
	BOOST_CHECK_EQUAL(out[ihl + 1], 53);
	BOOST_CHECK_EQUAL(out[ihl + 2], 0x30);
	BOOST_CHECK_EQUAL(out[ihl + 3], 0x39);

	// DNS 消息被替换为回复.
	std::size_t qoff = ihl + 8;
	BOOST_CHECK(std::memcmp(out.data() + qoff, reply.data(), reply.size()) == 0);

	// IP total length = 20 + 8 + reply.size().
	uint16_t total = (static_cast<uint16_t>(out[2]) << 8) | out[3];
	BOOST_CHECK_EQUAL(total, 20 + 8 + reply.size());

	// 校验和正确.
	BOOST_CHECK(ip_checksum_ok(out));
	BOOST_CHECK(udp_checksum_ok(out));
}

BOOST_AUTO_TEST_CASE(build_reply_ipv6)
{
	// IPv6 请求包.
	std::vector<uint8_t> v6(40 + 8 + 12 + 15, 0);
	v6[0] = 0x60;
	v6[4] = 0x00; v6[5] = 0x2f; // payload length 47.
	v6[6] = 17;                  // UDP.
	v6[8] = 0x20; v6[9] = 0x01; v6[10] = 0x0d; v6[11] = 0xb8;
	v6[12] = 0; v6[13] = 0; v6[14] = 0; v6[15] = 1;
	v6[24] = 0x20; v6[25] = 0x01; v6[26] = 0x48; v6[27] = 0x60;
	v6[28] = 0; v6[29] = 0; v6[30] = 0; v6[31] = 1;
	v6[40 + 0] = 0x30; v6[40 + 1] = 0x39; // src port.
	v6[40 + 2] = 0x00; v6[40 + 3] = 0x35; // dst port 53.
	v6[40 + 4] = 0x00; v6[40 + 5] = 0x23; // udp len 35.

	auto reply = make_dns_reply();
	std::vector<uint8_t> out;
	BOOST_REQUIRE(dns_packet::build_reply(v6, reply.data(), reply.size(), out));

	// 源/目的互换.
	BOOST_CHECK_EQUAL(out[8], 0x20);
	BOOST_CHECK_EQUAL(out[9], 0x01);
	BOOST_CHECK_EQUAL(out[10], 0x48);
	BOOST_CHECK_EQUAL(out[11], 0x60);
	BOOST_CHECK_EQUAL(out[24], 0x20);
	BOOST_CHECK_EQUAL(out[25], 0x01);
	BOOST_CHECK_EQUAL(out[26], 0x0d);
	BOOST_CHECK_EQUAL(out[27], 0xb8);

	// 端口互换.
	BOOST_CHECK_EQUAL(out[40 + 0], 0);
	BOOST_CHECK_EQUAL(out[40 + 1], 53);
	BOOST_CHECK_EQUAL(out[40 + 2], 0x30);
	BOOST_CHECK_EQUAL(out[40 + 3], 0x39);

	// payload length 更新.
	uint16_t payload = (static_cast<uint16_t>(out[4]) << 8) | out[5];
	BOOST_CHECK_EQUAL(payload, 8 + reply.size());

	// IPv6 UDP 校验和必须非零且正确.
	BOOST_CHECK(!(out[40 + 6] == 0 && out[40 + 7] == 0));
	uint16_t udp_len = (static_cast<uint16_t>(out[40 + 4]) << 8) | out[40 + 5];
	uint32_t sum = 0;
	for (int i = 0; i < 16; i += 2)
		sum += (static_cast<uint32_t>(out[8 + i]) << 8) | out[9 + i];
	for (int i = 0; i < 16; i += 2)
		sum += (static_cast<uint32_t>(out[24 + i]) << 8) | out[25 + i];
	sum += udp_len;
	sum += 17;
	BOOST_CHECK_EQUAL(
		dns_packet::internet_checksum(out.data() + 40, udp_len, sum), 0);
}
