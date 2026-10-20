
#define BOOST_TEST_MODULE avpn_core_util_tests
#include <boost/test/unit_test.hpp>

// 直接包含实现, 便于在一个翻译单元里测试.
#include "libavpn/src/avpn_protocol.cpp"
#include "libavpn/src/io_context_pool.cpp"
#include "libavpn/avpn_replay.hpp"

#include <boost/asio/post.hpp>

#include <atomic>
#include <chrono>
#include <stdexcept>
#include <string>
#include <thread>

using namespace libavpn;

BOOST_AUTO_TEST_SUITE(protocol_util)

BOOST_AUTO_TEST_CASE(parse_ipv4_accepts_dotted_and_integer)
{
	uint32_t dotted = 0;
	BOOST_REQUIRE(parse_ipv4("10.9.0.53", dotted));
	BOOST_CHECK_EQUAL(dotted, 0x0a090035u);

	uint32_t integer = 0;
	BOOST_REQUIRE(parse_ipv4("168362037", integer));
	BOOST_CHECK_EQUAL(integer, dotted);

	uint32_t zero = 1;
	BOOST_REQUIRE(parse_ipv4("0.0.0.0", zero));
	BOOST_CHECK_EQUAL(zero, 0u);

	uint32_t all_ones = 0;
	BOOST_REQUIRE(parse_ipv4("255.255.255.255", all_ones));
	BOOST_CHECK_EQUAL(all_ones, 0xffffffffu);

	// 十进制整数写法同样支持上界, 且不能溢出.
	uint32_t max_int = 0;
	BOOST_REQUIRE(parse_ipv4("4294967295", max_int));
	BOOST_CHECK_EQUAL(max_int, 0xffffffffu);
}

BOOST_AUTO_TEST_CASE(parse_ipv4_rejects_invalid)
{
	uint32_t out = 0;
	BOOST_CHECK(!parse_ipv4("", out));
	BOOST_CHECK(!parse_ipv4("abc", out));
	BOOST_CHECK(!parse_ipv4("10.9.0.256", out));
	BOOST_CHECK(!parse_ipv4("10.9.0.53x", out));
	BOOST_CHECK(!parse_ipv4(" 10.9.0.53", out));
	BOOST_CHECK(!parse_ipv4("10.9.0.53 ", out));
	BOOST_CHECK(!parse_ipv4("4294967296", out));
	BOOST_CHECK(!parse_ipv4("99999999999999999999", out));
}

BOOST_AUTO_TEST_CASE(parse_endpoint_ipv4_and_ipv6)
{
	net::ip::udp::endpoint udp;
	BOOST_REQUIRE(parse_endpoint("1.2.3.4:53", udp));
	BOOST_CHECK_EQUAL(udp.address().to_string(), "1.2.3.4");
	BOOST_CHECK_EQUAL(udp.port(), 53);

	net::ip::udp::endpoint zero;
	BOOST_REQUIRE(parse_endpoint("0.0.0.0:0", zero));
	BOOST_CHECK_EQUAL(zero.port(), 0);

	net::ip::udp::endpoint max_port;
	BOOST_REQUIRE(parse_endpoint("1.2.3.4:65535", max_port));
	BOOST_CHECK_EQUAL(max_port.port(), 65535);

	// IPv6 字面量 (无方括号): 由最后一个冒号切出端口.
	net::ip::udp::endpoint v6;
	BOOST_REQUIRE(parse_endpoint("::1:53", v6));
	BOOST_CHECK(v6.address().is_v6());
	BOOST_CHECK(v6.address().to_v6().is_loopback());
	BOOST_CHECK_EQUAL(v6.port(), 53);

	net::ip::tcp::endpoint tcp;
	BOOST_REQUIRE(parse_endpoint("2001:db8::1:443", tcp));
	BOOST_CHECK(tcp.address().is_v6());
	BOOST_CHECK_EQUAL(tcp.port(), 443);
}

BOOST_AUTO_TEST_CASE(parse_endpoint_rejects_invalid)
{
	net::ip::udp::endpoint udp;
	BOOST_CHECK(!parse_endpoint("", udp));
	BOOST_CHECK(!parse_endpoint("1.2.3.4", udp));
	BOOST_CHECK(!parse_endpoint("1.2.3.4:", udp));
	BOOST_CHECK(!parse_endpoint("1.2.3.4:abc", udp));
	BOOST_CHECK(!parse_endpoint("1.2.3.4:-1", udp));
	BOOST_CHECK(!parse_endpoint("1.2.3.4:65536", udp));
	BOOST_CHECK(!parse_endpoint("1.2.3.4:4294967296", udp));
	BOOST_CHECK(!parse_endpoint(":53", udp));
	BOOST_CHECK(!parse_endpoint("not-an-ip:53", udp));
}

BOOST_AUTO_TEST_CASE(endpoint_to_string_roundtrip)
{
	net::ip::udp::endpoint udp;
	BOOST_REQUIRE(parse_endpoint("1.2.3.4:53", udp));
	BOOST_CHECK_EQUAL(endpoint_to_string(udp), "1.2.3.4:53");

	net::ip::tcp::endpoint tcp;
	BOOST_REQUIRE(parse_endpoint("::1:53", tcp));
	BOOST_CHECK_EQUAL(endpoint_to_string(tcp), "::1:53");
}

BOOST_AUTO_TEST_CASE(compress_type_names)
{
	BOOST_CHECK(compress_type_from_string("deflate") == compress_type::deflate);
	BOOST_CHECK(compress_type_from_string("DeFlAtE") == compress_type::deflate);
	BOOST_CHECK(compress_type_from_string("lz4") == compress_type::lz4);
	BOOST_CHECK(compress_type_from_string("LZ4") == compress_type::lz4);
	BOOST_CHECK(compress_type_from_string("zstd") == compress_type::zstd);
	BOOST_CHECK(compress_type_from_string("none") == compress_type::none);
	BOOST_CHECK(compress_type_from_string("") == compress_type::none);
	BOOST_CHECK(compress_type_from_string("snappy") == compress_type::none);

	BOOST_CHECK(compress_type_to_string(compress_type::deflate) == "deflate");
	BOOST_CHECK(compress_type_to_string(compress_type::lz4) == "lz4");
	BOOST_CHECK(compress_type_to_string(compress_type::zstd) == "zstd");
	BOOST_CHECK(compress_type_to_string(compress_type::none) == "none");
	BOOST_CHECK(compress_type_to_string(
		static_cast<compress_type>(99)) == "none");

	BOOST_CHECK(compress_supported(compress_type::deflate));
	BOOST_CHECK(compress_supported(compress_type::lz4));
	BOOST_CHECK(!compress_supported(compress_type::zstd));
	BOOST_CHECK(!compress_supported(compress_type::none));
	BOOST_CHECK(!compress_supported(static_cast<compress_type>(99)));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(seq_window_edge_cases)

BOOST_AUTO_TEST_CASE(single_slot_window)
{
	seq_window w(1);
	BOOST_CHECK(w.check_and_update(5));
	BOOST_CHECK(!w.check_and_update(5));
	BOOST_CHECK(w.check_and_update(6));
	BOOST_CHECK(!w.check_and_update(5));
}

BOOST_AUTO_TEST_CASE(zero_window_size_is_clamped_to_one)
{
	seq_window w(0);
	BOOST_CHECK(w.check_and_update(1));
	BOOST_CHECK(!w.check_and_update(1));
	BOOST_CHECK(w.check_and_update(2));
	BOOST_CHECK(!w.check_and_update(1));
}

BOOST_AUTO_TEST_CASE(non_multiple_of_word_window)
{
	// 65 位窗口: 最后一位 (offset 64) 有效, offset 65 越界.
	seq_window w(65);
	BOOST_CHECK(w.check_and_update(100));
	BOOST_CHECK(!w.check_and_update(35));
	BOOST_CHECK(w.check_and_update(36));
	BOOST_CHECK(!w.check_and_update(36));

	BOOST_CHECK(w.check_and_update(101));
	BOOST_CHECK(!w.check_and_update(36));
	BOOST_CHECK(w.check_and_update(37));
	BOOST_CHECK(!w.check_and_update(0));
}

BOOST_AUTO_TEST_CASE(bits_survive_small_shifts)
{
	// 连续收 0..64 之后, 每来一个更大的序号窗口只挪一位, 旧位仍然记得.
	seq_window w(65);
	for (uint64_t s = 0; s <= 64; s++)
		BOOST_CHECK(w.check_and_update(s));

	BOOST_CHECK(!w.check_and_update(0));
	BOOST_CHECK(w.check_and_update(65));
	BOOST_CHECK(!w.check_and_update(1)); // 仍在窗口内, 但已收过.
	BOOST_CHECK(!w.check_and_update(0)); // 已被挤出窗口.
}

BOOST_AUTO_TEST_CASE(large_jump_clears_window)
{
	seq_window w(128);
	BOOST_CHECK(w.check_and_update(0));
	BOOST_CHECK(w.check_and_update(1000));
	BOOST_CHECK(!w.check_and_update(1000));
	BOOST_CHECK(w.check_and_update(999));

	// 1000 - 128 = 872 越界, 873 恰好是窗口最旧的一位.
	BOOST_CHECK(!w.check_and_update(872));
	BOOST_CHECK(w.check_and_update(873));
}

BOOST_AUTO_TEST_CASE(reset_allows_reuse)
{
	seq_window w(64);
	BOOST_CHECK(w.check_and_update(7));
	BOOST_CHECK(!w.check_and_update(7));
	w.reset();
	BOOST_CHECK(w.check_and_update(7));
	BOOST_CHECK(w.check_and_update(6));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(io_context_pool_test)

BOOST_AUTO_TEST_CASE(rejects_zero_size)
{
	BOOST_CHECK_THROW(
		{
			io_context_pool pool(0);
		}, std::runtime_error);
}

BOOST_AUTO_TEST_CASE(round_robin_and_main_context)
{
	io_context_pool pool(3);
	BOOST_CHECK_EQUAL(pool.size(), 3u);

	auto* first = &pool.get_io_context();
	auto* second = &pool.get_io_context();
	auto* third = &pool.get_io_context();
	auto* fourth = &pool.get_io_context();

	BOOST_CHECK_NE(first, second);
	BOOST_CHECK_NE(second, third);
	BOOST_CHECK_NE(first, third);
	BOOST_CHECK_EQUAL(first, fourth);

	auto& main = pool.main_io_context();
	BOOST_CHECK(&main != first);
	BOOST_CHECK(&main != second);
	BOOST_CHECK(&main != third);
}

BOOST_AUTO_TEST_CASE(run_processes_tasks_and_stops)
{
	io_context_pool pool(2);
	std::atomic<int> pool_done{ 0 };
	std::atomic<bool> main_running{ false };

	net::post(pool.get_io_context(), [&] { ++pool_done; });
	net::post(pool.get_io_context(), [&] { ++pool_done; });
	net::post(pool.main_io_context(), [&]
	{
		main_running = true;
		const auto deadline = std::chrono::steady_clock::now() +
			std::chrono::seconds(5);
		while (pool_done.load() < 2 &&
			std::chrono::steady_clock::now() < deadline)
			std::this_thread::yield();
		pool.stop();
	});

	std::thread worker([&] { pool.run(); });
	worker.join();

	BOOST_CHECK(main_running.load());
	BOOST_CHECK_EQUAL(pool_done.load(), 2);
}

BOOST_AUTO_TEST_SUITE_END()
