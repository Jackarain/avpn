#define BOOST_TEST_MODULE avpn_datapath_tests
#include <boost/test/unit_test.hpp>

// 直接包含实现, 便于在一个翻译单元里测试.
#include "../libavpn/src/avpn_rs.cpp"
#include "../libavpn/src/avpn_frame.cpp"
#include "../libavpn/src/avpn_keys.cpp"
#include "../libavpn/src/avpn_crypto.cpp"
#include "../libavpn/src/avpn_fec_v2.cpp"
#include "../libavpn/src/avpn_datapath.cpp"

#include <cstring>
#include <set>

using namespace libavpn;

namespace {

	std::string ipv4_payload(std::size_t total, uint8_t seed)
	{
		std::string s(total, '\0');
		s[0] = static_cast<char>(0x45);
		s[2] = static_cast<char>((total >> 8) & 0xff);
		s[3] = static_cast<char>(total & 0xff);
		for (std::size_t i = 4; i < s.size(); i++)
			s[i] = static_cast<char>(seed + i);
		return s;
	}

	// 一对数据面: 客户端和网关, 用同一个主密钥.
	struct pipe_pair
	{
		datapath client;
		datapath gateway;

		void start(const session_params& params)
		{
			const std::string master = crypto::random_bytes(32);
			client.configure(master, params, true);
			gateway.configure(master, params, false);
		}
	};

	// 从客户端发一个明文给网关, 返回网关投递出来的明文.
	std::vector<std::string> pass(pipe_pair& p, std::string_view plaintext,
		uint64_t now_ms = 0, bool roam = false)
	{
		std::vector<std::string> got;
		for (auto& frame : p.client.seal(plaintext, now_ms, roam))
		{
			for (auto& d : p.gateway.on_frame(frame, now_ms))
				got.push_back(std::move(d));
		}
		return got;
	}

} // namespace

BOOST_AUTO_TEST_SUITE(datapath_v2)

BOOST_AUTO_TEST_CASE(whole_frame_roundtrip)
{
	session_params params;  // 默认: T = 1, tag_len = 16.
	pipe_pair p;
	p.start(params);

	const std::string payload = ipv4_payload(1400, 7);
	auto got = pass(p, payload);
	BOOST_REQUIRE_EQUAL(got.size(), 1);
	BOOST_CHECK(got[0] == payload);

	// 帧开销 = 4 + tag_len.
	const auto frames = p.client.seal(payload, 1);
	BOOST_REQUIRE_EQUAL(frames.size(), 1);
	BOOST_CHECK_EQUAL(frames[0].size(),
		payload.size() + frame_header_size + params.tag_len);

	// 小 tag_len 也能用.
	session_params small;
	small.tag_len = 12;
	pipe_pair q;
	q.start(small);
	auto got2 = pass(q, payload);
	BOOST_REQUIRE_EQUAL(got2.size(), 1);
	BOOST_CHECK(got2[0] == payload);
}

BOOST_AUTO_TEST_CASE(wrong_key_delivers_nothing)
{
	session_params params;
	datapath client;
	datapath gateway;
	client.configure(crypto::random_bytes(32), params, true);
	gateway.configure(crypto::random_bytes(32), params, false);

	auto frames = client.seal(ipv4_payload(60, 1), 0);
	BOOST_REQUIRE_EQUAL(frames.size(), 1);
	BOOST_CHECK(gateway.on_frame(frames[0], 0).empty());

	// 方向反了也不行 (客户端拿客户端方向的密钥去解).
	datapath other_client;
	other_client.configure(crypto::random_bytes(32), params, true);
	BOOST_CHECK(other_client.on_frame(frames[0], 0).empty());
}

BOOST_AUTO_TEST_CASE(tampering_is_dropped)
{
	session_params params;
	pipe_pair p;
	p.start(params);

	auto frames = p.client.seal(ipv4_payload(80, 3), 0);
	BOOST_REQUIRE_EQUAL(frames.size(), 1);

	for (std::size_t i = 0; i < frames[0].size(); i += 7)
	{
		std::string bad = frames[0];
		bad[i] = static_cast<char>(bad[i] ^ 0x5a);
		BOOST_CHECK(p.gateway.on_frame(bad, 0).empty());
	}

	// 截断了也解不开.
	BOOST_CHECK(p.gateway.on_frame(
		frames[0].substr(0, frames[0].size() - 1), 0).empty());
	BOOST_CHECK(p.gateway.on_frame(std::string_view(), 0).empty());
}

BOOST_AUTO_TEST_CASE(replay_is_rejected)
{
	session_params params;
	pipe_pair p;
	p.start(params);

	auto frames = p.client.seal(ipv4_payload(60, 4), 0);
	BOOST_REQUIRE_EQUAL(frames.size(), 1);
	BOOST_REQUIRE_EQUAL(p.gateway.on_frame(frames[0], 0).size(), 1);
	// 同样的帧再发一次: 重放窗口挡掉.
	BOOST_CHECK(p.gateway.on_frame(frames[0], 1).empty());

	// 乱序但没来过的帧仍然接受.
	auto f0 = p.client.seal(ipv4_payload(60, 5), 1);
	auto f1 = p.client.seal(ipv4_payload(60, 6), 2);
	BOOST_REQUIRE_EQUAL(f1.size(), 1);
	BOOST_REQUIRE_EQUAL(f0.size(), 1);
	BOOST_CHECK_EQUAL(p.gateway.on_frame(f1[0], 2).size(), 1);
	BOOST_CHECK_EQUAL(p.gateway.on_frame(f0[0], 2).size(), 1);
	// 再补一次顺序反过来: 又是重放.
	BOOST_CHECK(p.gateway.on_frame(f0[0], 2).empty());
}

BOOST_AUTO_TEST_CASE(counter_wrap_switches_epoch)
{
	session_params params;
	pipe_pair p;
	p.start(params);

	// 把客户端摆在次代 0 的最后两帧上.
	BOOST_REQUIRE(p.client.set_send_position(0, 0xfffffffeu));
	BOOST_CHECK_EQUAL(p.client.send_epoch(), 0u);
	BOOST_CHECK_EQUAL(p.client.send_counter(), 0xfffffffeu);

	const std::string a = ipv4_payload(60, 10);
	const std::string b = ipv4_payload(60, 11);
	const std::string c = ipv4_payload(60, 12);

	auto fa = p.client.seal(a, 0);
	BOOST_REQUIRE_EQUAL(fa.size(), 1);
	BOOST_CHECK_EQUAL(static_cast<uint8_t>(fa[0][0]), 0xfe);
	BOOST_CHECK_EQUAL(static_cast<uint8_t>(fa[0][1]), 0xff);
	BOOST_CHECK_EQUAL(static_cast<uint8_t>(fa[0][2]), 0xff);
	BOOST_CHECK_EQUAL(static_cast<uint8_t>(fa[0][3]), 0xff);

	auto fb = p.client.seal(b, 1);
	BOOST_REQUIRE_EQUAL(fb.size(), 1);
	BOOST_CHECK_EQUAL(p.client.send_epoch(), 0u);

	// 计数器回绕: 换到次代 1, 计数器回到 0.
	auto fc = p.client.seal(c, 2);
	BOOST_REQUIRE_EQUAL(fc.size(), 1);
	BOOST_CHECK_EQUAL(p.client.send_epoch(), 1u);
	BOOST_CHECK_EQUAL(p.client.send_counter(), 1u);
	BOOST_CHECK_EQUAL(static_cast<uint8_t>(fc[0][0]), 0x00);

	// 网关这边: 前三帧照收, 跨次代的那一帧也能认出来.
	BOOST_REQUIRE_EQUAL(p.gateway.on_frame(fa[0], 0).size(), 1);
	BOOST_CHECK_EQUAL(p.gateway.recv_epoch(), 0u);
	BOOST_REQUIRE_EQUAL(p.gateway.on_frame(fb[0], 1).size(), 1);
	BOOST_CHECK_EQUAL(p.gateway.recv_epoch(), 0u);
	BOOST_REQUIRE_EQUAL(p.gateway.on_frame(fc[0], 2).size(), 1);
	BOOST_CHECK_EQUAL(p.gateway.recv_epoch(), 1u);

	// 回绕前的旧帧再发一次: 全局序号已经用过, 挡掉.
	BOOST_CHECK(p.gateway.on_frame(fb[0], 3).empty());

	// 换钥之后继续发, 网关照样能收.
	auto fd = p.client.seal(ipv4_payload(60, 13), 4);
	BOOST_REQUIRE_EQUAL(fd.size(), 1);
	BOOST_REQUIRE_EQUAL(p.gateway.on_frame(fd[0], 4).size(), 1);
}

BOOST_AUTO_TEST_CASE(late_frame_from_previous_epoch_is_usable)
{
	session_params params;
	pipe_pair p;
	p.start(params);

	// 客户端在次代 0 的最后两帧, 接着是次代 1 的第一帧.
	BOOST_REQUIRE(p.client.set_send_position(0, 0xfffffffeu));
	auto fa = p.client.seal(ipv4_payload(60, 20), 0);
	auto fb = p.client.seal(ipv4_payload(60, 21), 1);
	BOOST_CHECK_EQUAL(p.client.send_epoch(), 0u);
	auto fc = p.client.seal(ipv4_payload(60, 22), 2);
	BOOST_CHECK_EQUAL(p.client.send_epoch(), 1u);
	BOOST_REQUIRE_EQUAL(fa.size(), 1);
	BOOST_REQUIRE_EQUAL(fb.size(), 1);
	BOOST_REQUIRE_EQUAL(fc.size(), 1);

	// 网关先收下次代 0 的第二帧, 于是它认为当前是次代 0.
	BOOST_REQUIRE_EQUAL(p.gateway.on_frame(fa[0], 0).size(), 1);
	BOOST_CHECK_EQUAL(p.gateway.recv_epoch(), 0u);

	// 次代 1 的第一帧抢先到 (计数器比 h_last 小) -> 换次代试出来.
	BOOST_REQUIRE_EQUAL(p.gateway.on_frame(fc[0], 1).size(), 1);
	BOOST_CHECK_EQUAL(p.gateway.recv_epoch(), 1u);

	// 次代 0 的最后一帧晚到 (计数器比 h_last 大) -> 再往前一个次代试出来.
	BOOST_REQUIRE_EQUAL(p.gateway.on_frame(fb[0], 2).size(), 1);
	// 这次解密成功的是次代 0, 所以 e_last 跟着回到 0.
	BOOST_CHECK_EQUAL(p.gateway.recv_epoch(), 0u);

	// 晚到的那帧再发一次: 全局序号已经用过, 挡掉.
	BOOST_CHECK(p.gateway.on_frame(fb[0], 3).empty());
	BOOST_CHECK(p.gateway.on_frame(fa[0], 3).empty());

	// 客户端接着发新次代的下一帧, 照样能收下.
	auto fd = p.client.seal(ipv4_payload(60, 23), 4);
	BOOST_REQUIRE_EQUAL(fd.size(), 1);
	BOOST_REQUIRE_EQUAL(p.gateway.on_frame(fd[0], 4).size(), 1);
	BOOST_CHECK_EQUAL(p.gateway.recv_epoch(), 1u);
}

BOOST_AUTO_TEST_CASE(fec_mode_recovers_lost_shards)
{
	session_params params;
	params.fec_total = 16;
	params.fec_data = 12;
	pipe_pair p;
	p.start(params);

	std::vector<std::string> sent;
	std::vector<std::string> frames;
	for (int i = 0; i < 12; i++)
	{
		std::string payload = ipv4_payload(40 + i * 5, static_cast<uint8_t>(i));
		sent.push_back(payload);
		auto fs = p.client.seal(payload, static_cast<uint64_t>(i));
		BOOST_REQUIRE(!fs.empty());
		for (auto& f : fs)
			frames.push_back(std::move(f));
	}
	BOOST_REQUIRE_EQUAL(frames.size(), 16);  // 12 片数据 + 4 片冗余.

	// 丢 4 片数据, 网关应该靠冗余片把 12 个明文都还原出来.
	const std::set<std::size_t> drop{ 0, 3, 7, 11 };
	std::vector<std::string> got;
	for (std::size_t i = 0; i < frames.size(); i++)
	{
		if (drop.count(i) != 0)
			continue;
		for (auto& d : p.gateway.on_frame(frames[i], i))
			got.push_back(std::move(d));
	}

	BOOST_REQUIRE_EQUAL(got.size(), sent.size());
	std::multiset<std::string> got_set(got.begin(), got.end());
	for (const auto& payload : sent)
		BOOST_CHECK_EQUAL(got_set.count(payload), 1);
}

BOOST_AUTO_TEST_CASE(fec_mode_data_shard_is_delivered_at_once)
{
	session_params params;
	params.fec_total = 8;
	params.fec_data = 6;
	pipe_pair p;
	p.start(params);

	// 只发 3 个包: 每个都该立刻出来, 不用等整组.
	for (int i = 0; i < 3; i++)
	{
		const std::string payload = ipv4_payload(50 + i, static_cast<uint8_t>(i));
		auto fs = p.client.seal(payload, static_cast<uint64_t>(i));
		BOOST_REQUIRE_EQUAL(fs.size(), 1);
		auto got = p.gateway.on_frame(fs[0], static_cast<uint64_t>(i));
		BOOST_REQUIRE_EQUAL(got.size(), 1);
		BOOST_CHECK(got[0] == payload);
	}
}

BOOST_AUTO_TEST_CASE(roaming_frames_are_bound_to_cookie)
{
	session_params params;
	pipe_pair p;
	p.start(params);

	const std::array<uint8_t, 8> cookie{ { 1, 2, 3, 4, 5, 6, 7, 8 } };
	p.client.set_roam_cookie(cookie);
	p.gateway.set_roam_cookie(cookie);
	BOOST_CHECK(p.client.has_roam_cookie());

	const std::string payload = ipv4_payload(120, 30);
	auto frames = p.client.seal(payload, 0, true);
	BOOST_REQUIRE_EQUAL(frames.size(), 1);
	// 漫游帧 = cookie(8) + 帧头(4) + 密文.
	BOOST_CHECK_EQUAL(frames[0].size(),
		cookie.size() + frame_header_size + payload.size() + params.tag_len);

	auto got = p.gateway.on_frame(frames[0], 0);
	BOOST_REQUIRE_EQUAL(got.size(), 1);
	BOOST_CHECK(got[0] == payload);

	// 普通帧 (不带 cookie) 照样能收.
	auto plain = p.client.seal(ipv4_payload(120, 31), 1, false);
	BOOST_REQUIRE_EQUAL(plain.size(), 1);
	BOOST_REQUIRE_EQUAL(p.gateway.on_frame(plain[0], 1).size(), 1);

	// cookie 被改动过: AEAD 校验不过.
	auto tampered = frames[0];
	tampered[2] = static_cast<char>(tampered[2] ^ 0x11);
	BOOST_CHECK(p.gateway.on_frame(tampered, 2).empty());

	// 对端不知道 cookie 时, 漫游帧收不了.
	datapath stranger;
	stranger.configure(crypto::random_bytes(32), params, false);
	BOOST_CHECK(stranger.on_frame(frames[0], 2).empty());

	// 另一对数据面用不同的 cookie: 认不出, 也解不开.
	pipe_pair q;
	q.start(params);
	const std::array<uint8_t, 8> other{ { 8, 7, 6, 5, 4, 3, 2, 1 } };
	q.client.set_roam_cookie(cookie);
	q.gateway.set_roam_cookie(other);
	BOOST_CHECK(q.gateway.on_frame(frames[0], 2).empty());
}

BOOST_AUTO_TEST_CASE(sender_tick_abandons_and_closes_group)
{
	session_params params;
	params.fec_total = 16;
	params.fec_data = 12;
	params.group_abandon_ms = 1000;
	params.early_close_ms = 100;
	pipe_pair p;
	p.start(params);

	const std::string payload = ipv4_payload(200, 40);
	auto data = p.client.seal(payload, 0);
	BOOST_REQUIRE_EQUAL(data.size(), 1);

	// 还没到提前关组的时间: 不加时什么都不发.
	BOOST_CHECK(p.client.tick(50).empty());

	// 到点了: 补出 4 片冗余, 并且带上实际数据片数.
	auto extra = p.client.tick(200);
	BOOST_REQUIRE_EQUAL(extra.size(), 4);
	for (const auto& frame : extra)
		BOOST_CHECK_EQUAL(frame.size(),
			frame_header_size + params.tag_len + 1 + payload.size());

	// 数据片正常到达: 立刻投递, 冗余片到了不用再重复投递.
	auto got = p.gateway.on_frame(data[0], 0);
	BOOST_REQUIRE_EQUAL(got.size(), 1);
	BOOST_CHECK(got[0] == payload);
	got.clear();
	for (const auto& frame : extra)
	{
		for (auto& d : p.gateway.on_frame(frame, 200))
			got.push_back(std::move(d));
	}
	BOOST_CHECK(got.empty());

	// 数据片丢了也不要紧: 4 片冗余足以把这一片算回来.
	pipe_pair r;
	r.start(params);
	BOOST_REQUIRE_EQUAL(r.client.seal(payload, 0).size(), 1);  // 这一帧丢掉.
	auto extra2 = r.client.tick(200);
	BOOST_REQUIRE_EQUAL(extra2.size(), 4);
	std::vector<std::string> recovered;
	for (const auto& frame : extra2)
	{
		for (auto& d : r.gateway.on_frame(frame, 200))
			recovered.push_back(std::move(d));
	}
	BOOST_REQUIRE_EQUAL(recovered.size(), 1);
	BOOST_CHECK(recovered[0] == payload);
}

BOOST_AUTO_TEST_SUITE_END()
