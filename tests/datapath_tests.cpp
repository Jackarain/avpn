#define BOOST_TEST_MODULE avpn_datapath_tests
#include <boost/test/unit_test.hpp>

// 直接包含实现, 便于在一个翻译单元里测试.
#include "../libavpn/src/avpn_rs.cpp"
#include "../libavpn/src/avpn_frame.cpp"
#include "../libavpn/src/avpn_keys.cpp"
#include "../libavpn/src/avpn_crypto.cpp"
#include "../libavpn/src/avpn_fec_v2.cpp"
#include "../libavpn/src/avpn_compress.cpp"
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

	// 一个随机内容 (压不动) 的 IPv4 包.
	std::string random_ipv4_payload(std::size_t total)
	{
		std::string s = crypto::random_bytes(total);
		s[0] = static_cast<char>(0x45);
		s[2] = static_cast<char>((total >> 8) & 0xff);
		s[3] = static_cast<char>(total & 0xff);
		return s;
	}

	// 一个像文本 / 协议头那样有结构 (压得动) 的 IPv4 包.
	std::string text_ipv4_payload(std::size_t total)
	{
		static constexpr char text[] =
			"GET /index.html HTTP/1.1\r\nHost: example.com\r\n"
			"Accept: text/html,application/xhtml+xml\r\n\r\n";
		std::string s = ipv4_payload(total, 0);
		for (std::size_t i = 20; i < s.size(); i++)
			s[i] = text[(i - 20) % (sizeof(text) - 1)];
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

BOOST_AUTO_TEST_CASE(container_aggregation_survives_fec_loss)
{
	session_params params;
	params.fec_total = 16;
	params.fec_data = 12;
	pipe_pair p;
	p.start(params);

	// 每个数据片装一个容器 (3 个小包); 容器长短不一, 组里短的片会被补零.
	constexpr std::size_t per_container = 3;
	std::vector<std::string> originals;
	std::vector<std::string> frames;

	for (std::size_t g = 0; g < params.fec_data; g++)
	{
		std::vector<std::string> members;
		std::vector<std::string_view> entries;
		for (std::size_t k = 0; k < per_container; k++)
		{
			members.push_back(ipv4_payload(
				60 + g * 7 + k * 11, static_cast<uint8_t>(g + k)));
			originals.push_back(members.back());
		}
		for (auto& m : members)
			entries.push_back(m);

		std::string container;
		append_container(container, entries);

		// 最后一片凑满一组时会连冗余片一起出来.
		auto fs = p.client.seal(container, g);
		BOOST_REQUIRE(!fs.empty());
		for (auto& f : fs)
			frames.push_back(std::move(f));
	}
	BOOST_REQUIRE_EQUAL(frames.size(), params.fec_total);

	// 丢 4 片数据 (正好是冗余片的数), 剩下的靠冗余片还原.
	std::vector<std::string> got;
	for (std::size_t i = 0; i < frames.size(); i++)
	{
		if (i < params.fec_data && i % 3 == 0)
			continue;
		for (auto& d : p.gateway.on_frame(frames[i], i))
			got.push_back(std::move(d));
	}
	BOOST_REQUIRE_EQUAL(got.size(), params.fec_data);

	// 每片解出来是一个容器, 按容器规则拆回原来的小包.
	std::multiset<std::string> delivered;
	for (auto& plain : got)
	{
		std::vector<std::string_view> entries;
		BOOST_REQUIRE(parse_container(plain, entries));
		BOOST_CHECK_EQUAL(entries.size(), per_container);
		for (auto v : entries)
			delivered.emplace(v);
	}
	BOOST_REQUIRE_EQUAL(delivered.size(), originals.size());
	for (const auto& o : originals)
		BOOST_CHECK_EQUAL(delivered.count(o), 1);
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

BOOST_AUTO_TEST_CASE(roam_cookie_window_rotation)
{
	const std::array<uint8_t, roam_cookie_size> c1{ { 1, 1, 1, 1, 1, 1, 1, 1 } };
	const std::array<uint8_t, roam_cookie_size> c2{ { 2, 2, 2, 2, 2, 2, 2, 2 } };
	const std::array<uint8_t, roam_cookie_size> c3{ { 3, 3, 3, 3, 3, 3, 3, 3 } };

	// 帧: 凭证 + 若干字节.
	const auto frame_with = [](const std::array<uint8_t, roam_cookie_size>& c,
		char tail)
	{
		std::string s(reinterpret_cast<const char*>(c.data()), c.size());
		s.push_back(tail);
		return s;
	};

	roam_cookie_window w;
	BOOST_CHECK(w.empty());
	// 没有凭证时什么都不认.
	BOOST_CHECK(!w.accepts(frame_with(c1, 'x'), 0));
	// 短于凭证长度的帧也认不了.
	BOOST_CHECK(!w.accepts(std::string_view("abc"), 0));

	w.set(c1);
	BOOST_CHECK(!w.empty());
	BOOST_CHECK(w.accepts(frame_with(c1, 'x'), 0));
	// 全 0 视为没有凭证.
	w.set(std::array<uint8_t, roam_cookie_size>{});
	BOOST_CHECK(w.empty());

	w.set(c1);
	// 轮换: 被顶出去的是上一把 (第一次轮换时还没有上一把, 返回全 0).
	auto dropped = w.rotate(c2, 100);
	BOOST_CHECK(!w.accepts(frame_with(dropped, 'x'), 100));
	BOOST_CHECK(w.accepts(frame_with(c2, 'x'), 100));
	// 重叠期内旧凭证还认.
	BOOST_CHECK(w.accepts(frame_with(c1, 'x'),
		100 + roam_cookie_grace_ms - 1));
	// 过了重叠期就不认了.
	BOOST_CHECK(!w.accepts(frame_with(c1, 'x'),
		100 + roam_cookie_grace_ms));

	// 再轮换一次: 顶出去的是更早那把, 上一把 (c1) 仍在重叠期内.
	dropped = w.rotate(c3, 200);
	BOOST_CHECK(dropped == c1);
	BOOST_CHECK(w.accepts(frame_with(c2, 'x'),
		200 + roam_cookie_grace_ms - 1));
	BOOST_CHECK(w.accepts(frame_with(c3, 'x'), 200));
	// c1 已经被顶出窗口.
	BOOST_CHECK(!w.accepts(frame_with(c1, 'x'), 200));

	// 握手重谈: set 会把上一把一起丢掉.
	w.set(c2);
	BOOST_CHECK(!w.accepts(frame_with(c3, 'x'), 300));
	BOOST_CHECK(w.accepts(frame_with(c2, 'x'), 300));

	// clear 之后什么都不认.
	w.clear();
	BOOST_CHECK(w.empty());
	BOOST_CHECK(!w.accepts(frame_with(c2, 'x'), 300));
}

BOOST_AUTO_TEST_CASE(roaming_survives_cookie_rotation)
{
	session_params params;
	pipe_pair p;
	p.start(params);

	const std::array<uint8_t, roam_cookie_size> c1{ { 1, 2, 3, 4, 5, 6, 7, 8 } };
	const std::array<uint8_t, roam_cookie_size> c2{ { 9, 10, 11, 12, 13, 14, 15, 16 } };
	p.client.set_roam_cookie(c1);
	p.gateway.set_roam_cookie(c1);

	// 轮换前客户端发出的漫游帧 (两帧: 第二帧留着验证重叠期之后).
	const std::string payload = ipv4_payload(140, 40);
	auto before = p.client.seal(payload, 0, true);
	BOOST_REQUIRE_EQUAL(before.size(), 1);
	BOOST_CHECK(std::memcmp(before[0].data(), c1.data(), c1.size()) == 0);
	auto before2 = p.client.seal(ipv4_payload(140, 42), 0, true);
	BOOST_REQUIRE_EQUAL(before2.size(), 1);

	// 网关轮换到新凭证, 客户端跟着换.
	const auto dropped = p.gateway.rotate_roam_cookie(c2, 100);
	BOOST_CHECK(!p.gateway.frame_has_roam_cookie(
		std::string_view(reinterpret_cast<const char*>(dropped.data()),
			dropped.size()), 100));
	p.client.rotate_roam_cookie(c2, 100);
	BOOST_CHECK(p.gateway.roam_cookie() == c2);
	BOOST_CHECK(p.client.roam_cookie() == c2);

	// 轮换之后发的漫游帧带新凭证.
	auto after = p.client.seal(ipv4_payload(140, 41), 100, true);
	BOOST_REQUIRE_EQUAL(after.size(), 1);
	BOOST_CHECK(std::memcmp(after[0].data(), c2.data(), c2.size()) == 0);
	BOOST_REQUIRE_EQUAL(p.gateway.on_frame(after[0], 100).size(), 1);

	// 重叠期内, 轮换之前发出的旧凭证帧仍然收得下.
	BOOST_CHECK(p.gateway.frame_has_roam_cookie(before[0], 100));
	auto got = p.gateway.on_frame(before[0], 100);
	BOOST_REQUIRE_EQUAL(got.size(), 1);
	BOOST_CHECK(got[0] == payload);

	// 重叠期过后, 旧凭证帧不再认 (客户端这时早已换成新的).
	const uint64_t late = 100 + roam_cookie_grace_ms;
	BOOST_CHECK(!p.gateway.frame_has_roam_cookie(before2[0], late));
	BOOST_CHECK(p.gateway.on_frame(before2[0], late).empty());
	// 新凭证的帧一直认.
	auto late_frame = p.client.seal(ipv4_payload(140, 43), late, true);
	BOOST_REQUIRE_EQUAL(late_frame.size(), 1);
	BOOST_CHECK(p.gateway.frame_has_roam_cookie(late_frame[0], late));
	BOOST_REQUIRE_EQUAL(p.gateway.on_frame(late_frame[0], late).size(), 1);
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

BOOST_AUTO_TEST_CASE(compression_shrinks_ip_packet)
{
	session_params params;
	params.compress = static_cast<uint8_t>(compress_type::deflate);
	pipe_pair p;
	p.start(params);

	// 内容有结构: 压得动, 线上帧应该明显变小, 投递出来的还是原始包.
	const std::string payload = text_ipv4_payload(1400);
	auto frames = p.client.seal(payload, 0);
	BOOST_REQUIRE_EQUAL(frames.size(), 1);
	BOOST_CHECK_LT(frames[0].size(),
		payload.size() + frame_header_size + params.tag_len);

	auto got = p.gateway.on_frame(frames[0], 0);
	BOOST_REQUIRE_EQUAL(got.size(), 1);
	BOOST_CHECK(got[0] == payload);

	// 内容随机: 压不小, 直接发原始包, 帧开销还是 4 + tag_len.
	const std::string noise = random_ipv4_payload(600);
	auto noise_frames = p.client.seal(noise, 1);
	BOOST_REQUIRE_EQUAL(noise_frames.size(), 1);
	BOOST_CHECK_EQUAL(noise_frames[0].size(),
		noise.size() + frame_header_size + params.tag_len);
	auto noise_got = p.gateway.on_frame(noise_frames[0], 1);
	BOOST_REQUIRE_EQUAL(noise_got.size(), 1);
	BOOST_CHECK(noise_got[0] == noise);
}

BOOST_AUTO_TEST_CASE(compression_gate_skips_random_and_tiny_packets)
{
	// 预判: 随机数据不值得压, 有结构的数据值得压, 太短的也不值得.
	BOOST_CHECK(!looks_compressible(random_ipv4_payload(1400)));
	BOOST_CHECK(looks_compressible(text_ipv4_payload(1400)));
	BOOST_CHECK(!looks_compressible(std::string(32, 'a')));

	session_params params;
	params.compress = static_cast<uint8_t>(compress_type::deflate);
	pipe_pair p;
	p.start(params);

	// 随机的大包不压: 帧开销还是 4 + tag_len.
	const std::string noise = random_ipv4_payload(1400);
	auto frames = p.client.seal(noise, 0);
	BOOST_REQUIRE_EQUAL(frames.size(), 1);
	BOOST_CHECK_EQUAL(frames[0].size(),
		noise.size() + frame_header_size + params.tag_len);
	auto got = p.gateway.on_frame(frames[0], 0);
	BOOST_REQUIRE_EQUAL(got.size(), 1);
	BOOST_CHECK(got[0] == noise);

	// 有结构的大包会压: 线上帧明显比原包小, 解出来还原.
	const std::string text = text_ipv4_payload(1400);
	auto text_frames = p.client.seal(text, 1);
	BOOST_REQUIRE_EQUAL(text_frames.size(), 1);
	BOOST_CHECK_LT(text_frames[0].size(), text.size());
	auto text_got = p.gateway.on_frame(text_frames[0], 1);
	BOOST_REQUIRE_EQUAL(text_got.size(), 1);
	BOOST_CHECK(text_got[0] == text);
}

BOOST_AUTO_TEST_CASE(compression_keeps_control_messages_raw)
{
	session_params params;
	params.compress = static_cast<uint8_t>(compress_type::deflate);
	pipe_pair p;
	p.start(params);

	std::string msg;
	append_control_message(msg, control_keepalive, std::string(8, '\0'));
	auto got = pass(p, msg);
	BOOST_REQUIRE_EQUAL(got.size(), 1);
	BOOST_CHECK(got[0] == msg);

	// 开着压缩也不动漫游帧里的保活消息.
	pipe_pair r;
	r.start(params);
	r.client.set_roam_cookie({ 1, 2, 3, 4, 5, 6, 7, 8 });
	r.gateway.set_roam_cookie({ 1, 2, 3, 4, 5, 6, 7, 8 });
	auto roam = pass(r, msg, 0, true);
	BOOST_REQUIRE_EQUAL(roam.size(), 1);
	BOOST_CHECK(roam[0] == msg);
}

BOOST_AUTO_TEST_CASE(compression_in_fec_mode_recovers_loss)
{
	session_params params;
	params.compress = static_cast<uint8_t>(compress_type::deflate);
	params.fec_total = 16;
	params.fec_data = 12;
	pipe_pair p;
	p.start(params);

	std::vector<std::string> sent;
	std::vector<std::string> frames;
	for (int i = 0; i < 12; i++)
	{
		std::string payload = ipv4_payload(40 + i * 40, static_cast<uint8_t>(i));
		sent.push_back(payload);
		auto fs = p.client.seal(payload, static_cast<uint64_t>(i));
		BOOST_REQUIRE(!fs.empty());
		for (auto& f : fs)
			frames.push_back(std::move(f));
	}
	BOOST_REQUIRE_EQUAL(frames.size(), 16);

	// 丢 4 片数据, 冗余片上的内容也是压过的, 解出来要还原成原始包.
	const std::set<std::size_t> drop{ 1, 4, 9, 14 };
	std::multiset<std::string> got;
	for (std::size_t i = 0; i < frames.size(); i++)
	{
		if (drop.count(i) != 0)
			continue;
		for (auto& d : p.gateway.on_frame(frames[i], i))
			got.insert(std::move(d));
	}

	BOOST_REQUIRE_EQUAL(got.size(), sent.size());
	for (const auto& payload : sent)
		BOOST_CHECK_EQUAL(got.count(payload), 1);
}

BOOST_AUTO_TEST_CASE(lz4_codec_roundtrip_and_limits)
{
	compressor comp(compress_type::lz4);
	BOOST_CHECK(comp.enabled());
	BOOST_CHECK(comp.type() == compress_type::lz4);

	// 有结构的载荷压得动, 解出来和原样一字不差.
	const std::string text = text_ipv4_payload(1400);
	std::vector<uint8_t> packed;
	BOOST_REQUIRE(comp.compress(text, packed));
	BOOST_CHECK_LT(packed.size(), text.size());

	const auto view = [](const std::vector<uint8_t>& v)
	{
		return std::string_view(reinterpret_cast<const char*>(v.data()),
			v.size());
	};

	std::vector<uint8_t> restored;
	BOOST_REQUIRE(comp.decompress(view(packed), restored, 2048));
	BOOST_CHECK(std::string(restored.begin(), restored.end()) == text);

	// 输出上限比真实结果小: 当成解压炸弹丢掉.
	BOOST_CHECK(!comp.decompress(view(packed), restored, text.size() - 1));

	// 截断的数据解不开.
	BOOST_CHECK(!comp.decompress(view(packed).substr(0, packed.size() / 2),
		restored, 2048));

	// 压不动的数据照样能压能解 (发不发由调用方比大小决定).
	const std::string noise = random_ipv4_payload(600);
	std::vector<uint8_t> noise_packed;
	BOOST_REQUIRE(comp.compress(noise, noise_packed));
	BOOST_REQUIRE(comp.decompress(view(noise_packed), restored, 2048));
	BOOST_CHECK(std::string(restored.begin(), restored.end()) == noise);

	// 换了算法要把 lz4 的结果当坏数据丢掉, 不能投递乱码.
	comp.set_type(compress_type::deflate);
	std::vector<uint8_t> cross;
	BOOST_CHECK(!comp.decompress(view(packed), cross, 2048));
}

BOOST_AUTO_TEST_CASE(lz4_negotiated_ip_packet_shrinks)
{
	session_params params;
	params.compress = static_cast<uint8_t>(compress_type::lz4);
	pipe_pair p;
	p.start(params);

	// 压得动的包: 线上帧明显比原包小, 投递出来还是原包.
	const std::string payload = text_ipv4_payload(1400);
	auto frames = p.client.seal(payload, 0);
	BOOST_REQUIRE_EQUAL(frames.size(), 1);
	BOOST_CHECK_LT(frames[0].size(),
		payload.size() + frame_header_size + params.tag_len);
	auto got = p.gateway.on_frame(frames[0], 0);
	BOOST_REQUIRE_EQUAL(got.size(), 1);
	BOOST_CHECK(got[0] == payload);

	// 压不动的照旧发原始包, 帧开销还是 4 + tag_len.
	const std::string noise = random_ipv4_payload(600);
	auto noise_frames = p.client.seal(noise, 1);
	BOOST_REQUIRE_EQUAL(noise_frames.size(), 1);
	BOOST_CHECK_EQUAL(noise_frames[0].size(),
		noise.size() + frame_header_size + params.tag_len);
	BOOST_CHECK(p.gateway.on_frame(noise_frames[0], 1)[0] == noise);

	// 两端谈的算法不一致 (对端按 deflate 解): 解不开就丢, 不会投递乱码.
	session_params other;
	other.compress = static_cast<uint8_t>(compress_type::deflate);
	pipe_pair q;
	q.start(other);

	compressor comp(compress_type::lz4);
	std::vector<uint8_t> packed;
	BOOST_REQUIRE(comp.compress(payload, packed));
	std::string entry;
	entry.push_back(static_cast<char>(compressed_marker));
	entry.push_back(static_cast<char>(packed.size() & 0xff));
	entry.push_back(static_cast<char>((packed.size() >> 8) & 0xff));
	entry.append(reinterpret_cast<const char*>(packed.data()), packed.size());
	BOOST_CHECK(pass(q, entry).empty());
}

BOOST_AUTO_TEST_CASE(decompression_bomb_is_dropped)
{
	// deflate / lz4 都要挡住解压炸弹.
	for (compress_type algo : { compress_type::deflate, compress_type::lz4 })
	{
		session_params params;
		params.compress = static_cast<uint8_t>(algo);
		pipe_pair p;
		p.start(params);

		// 造一个"解压炸弹": 压后很小, 解出来远超一个满长包.
		compressor comp(algo);
		std::vector<uint8_t> bomb;
		BOOST_REQUIRE(comp.compress(std::string(200000, 'a'), bomb));
		std::string entry;
		entry.push_back(static_cast<char>(compressed_marker));
		entry.push_back(static_cast<char>(bomb.size() & 0xff));
		entry.push_back(static_cast<char>((bomb.size() >> 8) & 0xff));
		entry.append(reinterpret_cast<const char*>(bomb.data()), bomb.size());

		// 首字节是压缩标记, 所以封包时按原样发出去; 网关解不开, 必须丢.
		auto frames = p.client.seal(entry, 0);
		BOOST_REQUIRE_EQUAL(frames.size(), 1);
		BOOST_CHECK(p.gateway.on_frame(frames[0], 0).empty());

		// 长度字段被改坏 (超过实际数据) 也要丢.
		std::string broken = entry;
		broken[1] = static_cast<char>(0xff);
		broken[2] = static_cast<char>(0x7f);
		auto broken_frames = p.client.seal(broken, 1);
		BOOST_REQUIRE_EQUAL(broken_frames.size(), 1);
		BOOST_CHECK(p.gateway.on_frame(broken_frames[0], 1).empty());
	}
}

BOOST_AUTO_TEST_CASE(compression_off_delivers_compressed_entry_as_is)
{
	// 对端没谈压缩时, 压缩条目当作不认识的控制消息忽略, 不会被当成 IP 包.
	session_params params;
	pipe_pair p;
	p.start(params);

	std::string entry;
	append_control_message(entry, compressed_marker, std::string(4, '\0'));
	auto got = pass(p, entry);
	BOOST_REQUIRE_EQUAL(got.size(), 1);
	BOOST_CHECK(got[0] == entry);
	BOOST_CHECK(classify_payload(got[0]) == frame_kind::control);
}

// 随机丢包下按线损比例统计纠错的实际效果: 一组 16 片丢 4 片以内都能还原,
// 残留丢包只剩"整组补不回来"的那部分.
static double fec_loss_experiment(uint32_t ds, uint32_t ps, double drop)
{
	session_params params;
	params.fec_total = static_cast<uint8_t>(ds + ps);
	params.fec_data = static_cast<uint8_t>(ds);

	pipe_pair p;
	p.start(params);

	// 固定种子的 LCG: 测试结果可重复.
	uint32_t rng = 0x12345678u;
	auto next_random = [&rng]()
	{
		rng = rng * 1664525u + 1013904223u;
		return (rng >> 8) & 0xffffffu;
	};

	const std::size_t total = 12000;
	const std::size_t threshold = static_cast<std::size_t>(
		drop * 16777216.0);
	std::size_t sent = 0;
	std::size_t delivered = 0;

	for (std::size_t i = 0; i < total; i++)
	{
		std::string payload = ipv4_payload(1228, static_cast<uint8_t>(i));
		payload[20] = static_cast<char>(i & 0xff);
		payload[21] = static_cast<char>((i >> 8) & 0xff);

		for (auto& frame : p.client.seal(payload, i))
		{
			if (next_random() < threshold)
				continue;  // 线路上丢了这一帧.
			for (auto& d : p.gateway.on_frame(frame, i))
			{
				(void)d;
				delivered++;
			}
		}
		sent++;
	}

	return 1.0 - static_cast<double>(delivered) /
		static_cast<double>(sent);
}

BOOST_AUTO_TEST_CASE(fec_recovers_random_wire_loss)
{
	// 线损固定 10%: 12/4 要一组里丢超过 4 片才补不回来 (残留约 0.8%),
	// 8/8 要丢超过 8 片 (残留近乎为零), 都该比不开纠错时低一个数量级.
	const double plain = fec_loss_experiment(0, 0, 0.10);
	const double loss_12_4 = fec_loss_experiment(12, 4, 0.10);
	const double loss_8_8 = fec_loss_experiment(8, 8, 0.10);

	BOOST_TEST_MESSAGE("loss plain = " << plain);
	BOOST_TEST_MESSAGE("loss 12/4 = " << loss_12_4);
	BOOST_TEST_MESSAGE("loss 8/8  = " << loss_8_8);

	BOOST_CHECK_GT(plain, 0.09);  // 不开纠错时丢多少就是多少.
	BOOST_CHECK_LT(loss_12_4, plain / 5);
	BOOST_CHECK_LT(loss_8_8, plain / 20);
}

// 一直收到凑不满的组时, 留在手里的组数要有上限, 不能随包数一路涨.
BOOST_AUTO_TEST_CASE(fec_open_group_backlog_is_bounded)
{
	fec_receiver rx;
	rx.configure(16, 8, false, 2000);

	// 每组只喂一个冗余片: 组永远凑不满, 也不会自己消失.
	const std::string shard(1200, '\0');
	std::vector<std::string_view> out;
	for (uint64_t g = 0; g < 1000; g++)
		rx.on_shard(g * 16 + 8, shard, 0, out);

	BOOST_CHECK_LE(rx.group_count(), 300);
}

BOOST_AUTO_TEST_SUITE_END()
