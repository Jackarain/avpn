#define BOOST_TEST_MODULE avpn_obfuscate_tests
#include <boost/test/unit_test.hpp>

// 直接包含混淆实现, 以访问内部函数与常量.
#include "../libavpn/src/avpn_obfuscate.cpp"

#include <cstring>
#include <random>
#include <set>

using namespace libavpn;

namespace {

	std::string random_bytes(std::size_t n)
	{
		std::string s(n, '\0');
		static std::mt19937 rng(0x5eed);
		for (auto& c : s)
			c = static_cast<char>(rng() & 0xff);
		return s;
	}

	std::string build_wire(const obfuscate_head& head, std::string_view frame)
	{
		std::string wire;
		wire.reserve(obfuscate_fixed_overhead + head.garbage.size() + frame.size());
		wire.append(reinterpret_cast<const char*>(head.salt.data()),
			head.salt.size());
		wire.append(reinterpret_cast<const char*>(head.len_field.data()),
			head.len_field.size());
		wire.append(head.garbage);
		wire.append(frame.data(), frame.size());
		return wire;
	}

}

BOOST_AUTO_TEST_CASE(roundtrip)
{
	std::string key = random_bytes(32);
	std::string frame = random_bytes(100);

	for (int i = 0; i < 256; i++)
	{
		obfuscate_head head;
		BOOST_REQUIRE(make_obfuscate_head(key, head));
		BOOST_REQUIRE(head.garbage.size() >= obfuscate_min_padding);
		BOOST_REQUIRE(head.garbage.size() <= obfuscate_max_padding);

		std::string wire = build_wire(head, frame);

		std::string_view payload, len_field;
		BOOST_REQUIRE(deobfuscate_packet(key, wire, payload, len_field));
		BOOST_REQUIRE_EQUAL(payload.size(), frame.size());
		BOOST_REQUIRE(std::memcmp(payload.data(), frame.data(), frame.size()) == 0);
		BOOST_REQUIRE_EQUAL(len_field.size(), obfuscate_len_field_size);
		BOOST_REQUIRE(std::memcmp(len_field.data(), head.len_field.data(),
			head.len_field.size()) == 0);
	}
}

BOOST_AUTO_TEST_CASE(dynamic_mask)
{
	std::string key = random_bytes(32);
	std::string frame = random_bytes(64);

	// 不同 salt 应产生不同掩码/长度字段, 即掩码是每包动态的.
	std::set<uint16_t> masks;
	for (int i = 0; i < 512; i++)
	{
		obfuscate_head head;
		BOOST_REQUIRE(make_obfuscate_head(key, head));
		std::string_view salt(reinterpret_cast<const char*>(head.salt.data()),
			head.salt.size());
		masks.insert(obfuscate_mask(key, salt));
	}
	BOOST_REQUIRE(masks.size() > 1);

	// 不同密钥对同一 salt 应产生不同掩码.
	std::string salt = random_bytes(4);
	std::string key2 = random_bytes(32);
	BOOST_REQUIRE(obfuscate_mask(key, salt) != obfuscate_mask(key2, salt));
}

BOOST_AUTO_TEST_CASE(tamper_detection)
{
	std::string key = random_bytes(32);
	std::string frame = random_bytes(100);

	obfuscate_head head;
	BOOST_REQUIRE(make_obfuscate_head(key, head));
	std::string wire = build_wire(head, frame);

	// 翻转垃圾数据不影响剥离结果.
	auto wire2 = wire;
	wire2[obfuscate_salt_size + obfuscate_len_field_size] ^= 0xff;
	std::string_view payload, len_field;
	BOOST_REQUIRE(deobfuscate_packet(key, wire2, payload, len_field));
	BOOST_REQUIRE_EQUAL(payload.size(), frame.size());

	// 篡改长度字段会导致剥离出的 AAD 字节变化, AEAD 认证将失败.
	// 此处验证解出的长度字段与原始不同.
	auto wire3 = wire;
	wire3[obfuscate_salt_size] ^= 0x01;
	if (deobfuscate_packet(key, wire3, payload, len_field))
	{
		BOOST_REQUIRE(std::memcmp(len_field.data(), head.len_field.data(),
			head.len_field.size()) != 0);
	}
	// 篡改 salt 后, 解出的 padding 极可能越界而直接拒绝.
	bool rejected = false;
	for (int i = 0; i < 64; i++)
	{
		auto wire4 = wire;
		wire4[i % obfuscate_salt_size] ^= static_cast<char>(1 + i);
		if (!deobfuscate_packet(key, wire4, payload, len_field))
		{
			rejected = true;
			break;
		}
	}
	BOOST_REQUIRE(rejected);
}

BOOST_AUTO_TEST_CASE(invalid_input)
{
	std::string key = random_bytes(32);
	std::string_view payload, len_field;

	// 空密钥串非法.
	obfuscate_head head0;
	BOOST_REQUIRE(!make_obfuscate_head("", head0));
	BOOST_REQUIRE(!deobfuscate_packet("", "", payload, len_field));

	// 数据过短.
	BOOST_REQUIRE(!deobfuscate_packet(key, random_bytes(8), payload, len_field));

	// 构造 padding 越界的包: 任意伪造长度字段, 掩码未对齐时几乎必然越界.
	obfuscate_head head;
	BOOST_REQUIRE(make_obfuscate_head(key, head));
	head.len_field = { 0x00, 0x00 };
	std::string wire = build_wire(head, "x");
	// 伪造 len_field 后, 解出的 padding 应拒绝或与声明不符.
	if (deobfuscate_packet(key, wire, payload, len_field))
		BOOST_REQUIRE_EQUAL(payload.size(), std::string_view("x").size());
}
