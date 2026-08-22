#define BOOST_TEST_MODULE avpn_gfwlist_tests
#include <boost/test/unit_test.hpp>

#include "libavpn/dns_proxy.hpp"
#include "libavpn/avpn_crypto.hpp"

#include <string>
#include <unordered_set>

using namespace libavpn;

namespace {

	bool has(const std::unordered_set<std::string>& s, const std::string& v)
	{
		return s.find(v) != s.end();
	}

	// 官方 gfwlist 格式: 规则文本先 base64 编码后分发.
	std::string official_body(const std::string& rules)
	{
		return crypto::base64_encode(rules);
	}

}

// 自建纯文本列表 (如 http://192.168.1.1:8080/gfwlist 提供的内容).
BOOST_AUTO_TEST_CASE(plain_text_list)
{
	const std::string content =
		"! 自建规则列表\n"
		"! 注释行不参与匹配\n"
		"||example.com^\n"
		"||google-analytics.com\n"
		"@@||safe.example.com^\n"
		"|http://plainhttp.com\n"
		"|https://securehttp.org\n"
		"*wildcard.example.net\n"
		".facebook.com\n"
		"cn.bing.com\n"
		"/^https?:\\/\\/([^/]+\\.)?github\\.com/\n"
		"http://withproto.example.org/path\n"
		"|http://trailing.dot.example.com.^\n";

	std::unordered_set<std::string> rules;
	std::unordered_set<std::string> exceptions;
	parse_gfwlist_rules(content, rules, exceptions);

	BOOST_CHECK(has(rules, "example.com"));
	BOOST_CHECK(has(rules, "google-analytics.com"));
	BOOST_CHECK(has(rules, "plainhttp.com"));
	BOOST_CHECK(has(rules, "securehttp.org"));
	BOOST_CHECK(has(rules, "wildcard.example.net"));
	BOOST_CHECK(has(rules, "facebook.com"));
	BOOST_CHECK(has(rules, "cn.bing.com"));
	// /regex/ 与带路径/协议前缀的域名均归一化为裸域名.
	BOOST_CHECK(has(rules, "github.com"));
	BOOST_CHECK(has(rules, "withproto.example.org"));
	BOOST_CHECK(has(rules, "trailing.dot.example.com"));

	// 例外规则进入独立集合.
	BOOST_CHECK(has(exceptions, "safe.example.com"));
	BOOST_CHECK(!has(rules, "safe.example.com"));
	BOOST_CHECK(!has(exceptions, "example.com"));
}

// 官方 base64 编码列表 (如 raw.githubusercontent.com 的 gfwlist.txt).
BOOST_AUTO_TEST_CASE(official_base64_list)
{
	const std::string rules =
		"[AutoProxy 0.2.9]\n"
		"! Updated: 2026-08-22\n"
		"||google.com^\n"
		"||youtube.com^\n"
		"||twitter.com\n"
		"@@||google.cn^\n"
		"/^(https?:\\/\\/)?([^/]*\\.)?archive\\.org\\//\n"
		"|https://vimeo.com\n"
		".wikipedia.org\n";

	// 下载内容为 base64 编码文本, 解码后与纯文本解析路径一致.
	const std::string body = official_body(rules);
	auto decoded = crypto::base64_decode(body);
	BOOST_REQUIRE(!decoded.empty());

	std::unordered_set<std::string> parsed_rules;
	std::unordered_set<std::string> exceptions;
	parse_gfwlist_rules(decoded, parsed_rules, exceptions);

	BOOST_CHECK(has(parsed_rules, "google.com"));
	BOOST_CHECK(has(parsed_rules, "youtube.com"));
	BOOST_CHECK(has(parsed_rules, "twitter.com"));
	BOOST_CHECK(has(parsed_rules, "archive.org"));
	BOOST_CHECK(has(parsed_rules, "vimeo.com"));
	BOOST_CHECK(has(parsed_rules, "wikipedia.org"));

	BOOST_CHECK(has(exceptions, "google.cn"));
	BOOST_CHECK(!has(parsed_rules, "google.cn"));
}

// 空内容/纯注释: 不产生任何规则.
BOOST_AUTO_TEST_CASE(empty_and_comment_only)
{
	{
		std::unordered_set<std::string> rules;
		std::unordered_set<std::string> exceptions;
		parse_gfwlist_rules("", rules, exceptions);
		BOOST_CHECK(rules.empty());
		BOOST_CHECK(exceptions.empty());
	}
	{
		std::unordered_set<std::string> rules;
		std::unordered_set<std::string> exceptions;
		parse_gfwlist_rules("! only comment\n\n! another\n", rules, exceptions);
		BOOST_CHECK(rules.empty());
		BOOST_CHECK(exceptions.empty());
	}
}

// 非法/不完整条目被过滤, 不影响其余规则.
BOOST_AUTO_TEST_CASE(invalid_lines_filtered)
{
	const std::string content =
		"||good.example.com^\n"
		"||\n"
		"not a domain with spaces\n"
		"@@||\n"
		"||bad^domain.com\n";

	std::unordered_set<std::string> rules;
	std::unordered_set<std::string> exceptions;
	parse_gfwlist_rules(content, rules, exceptions);

	BOOST_CHECK(has(rules, "good.example.com"));
	BOOST_CHECK(rules.size() == 1);
	BOOST_CHECK(exceptions.empty());
}
