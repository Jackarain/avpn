#define BOOST_TEST_MODULE avpn_resolv_conf_tests
#include <boost/test/unit_test.hpp>

#include "libavpn/resolv_conf.hpp"

#include <cstdio>
#include <fstream>
#include <string>

using namespace libavpn;

namespace {

	std::string tmp_path(const std::string& tag)
	{
		return "/tmp/avpn-resolv-" + tag + ".conf";
	}

	void write_file(const std::string& path, const std::string& text)
	{
		std::ofstream out(path, std::ios::binary | std::ios::trunc);
		out << text;
	}

	std::string read_file(const std::string& path)
	{
		std::ifstream in(path, std::ios::binary);
		return std::string(std::istreambuf_iterator<char>(in),
			std::istreambuf_iterator<char>());
	}

} // namespace

BOOST_AUTO_TEST_SUITE(resolv_conf)

BOOST_AUTO_TEST_CASE(merge_puts_pushed_dns_first)
{
	// 空文件: 直接写一条 nameserver.
	BOOST_CHECK_EQUAL(resolv_conf_merge("", "10.9.0.53"),
		"nameserver 10.9.0.53\n");

	// 原来的 nameserver 与其它指令都留在后面 / 原位.
	const std::string original =
		"# generated\nsearch lan\nnameserver 192.168.1.1\noptions timeout:2\n";
	const std::string merged = resolv_conf_merge(original, "10.9.0.53");
	BOOST_CHECK_EQUAL(merged,
		"# generated\nsearch lan\nnameserver 10.9.0.53\n"
		"nameserver 192.168.1.1\noptions timeout:2\n");

	// 合并结果再合并一次不再变 (重连时重复应用不出错).
	BOOST_CHECK_EQUAL(resolv_conf_merge(merged, "10.9.0.53"), merged);
	BOOST_CHECK_EQUAL(resolv_conf_merge(merged, "10.9.0.54"),
		"# generated\nsearch lan\nnameserver 10.9.0.54\n"
		"nameserver 10.9.0.53\n"
		"nameserver 192.168.1.1\noptions timeout:2\n");
}

BOOST_AUTO_TEST_CASE(merge_handles_odd_files)
{
	// 没有 nameserver 行: 追加在最后.
	BOOST_CHECK_EQUAL(resolv_conf_merge("search lan\n", "10.9.0.53"),
		"search lan\nnameserver 10.9.0.53\n");

	// 结尾没有换行也要能处理.
	BOOST_CHECK_EQUAL(resolv_conf_merge("nameserver 1.1.1.1", "10.9.0.53"),
		"nameserver 10.9.0.53\nnameserver 1.1.1.1\n");

	// 制表符分隔、行首空白都认; 原来那行按原样留下.
	BOOST_CHECK_EQUAL(resolv_conf_merge("  nameserver\t1.1.1.1\n", "10.9.0.53"),
		"nameserver 10.9.0.53\n  nameserver\t1.1.1.1\n");

	// 同样的地址出现在后面: 挪到最前面, 不留重复项.
	BOOST_CHECK_EQUAL(resolv_conf_merge(
		"nameserver 1.1.1.1\nnameserver 10.9.0.53\n", "10.9.0.53"),
		"nameserver 10.9.0.53\nnameserver 1.1.1.1\n");

	// 空 dns 不动文件.
	BOOST_CHECK_EQUAL(resolv_conf_merge("nameserver 1.1.1.1\n", ""),
		"nameserver 1.1.1.1\n");

	// 注释里的 nameserver 不当作配置项.
	BOOST_CHECK_EQUAL(resolv_conf_merge("# nameserver 1.1.1.1\n", "10.9.0.53"),
		"# nameserver 1.1.1.1\nnameserver 10.9.0.53\n");
}

BOOST_AUTO_TEST_CASE(read_write_roundtrip)
{
	const std::string path = tmp_path("roundtrip");
	const std::string original = "nameserver 192.168.1.1\n";
	write_file(path, original);

	std::string text;
	std::string err;
	BOOST_REQUIRE_MESSAGE(resolv_conf_read(path, text, err), err);
	BOOST_CHECK_EQUAL(text, original);

	const std::string merged = resolv_conf_merge(text, "10.9.0.53");
	BOOST_REQUIRE_MESSAGE(resolv_conf_write(path, merged, err), err);
	BOOST_CHECK_EQUAL(read_file(path), merged);

	// 还原成原样.
	BOOST_REQUIRE_MESSAGE(resolv_conf_write(path, text, err), err);
	BOOST_CHECK_EQUAL(read_file(path), original);

	std::remove(path.c_str());
}

BOOST_AUTO_TEST_CASE(read_missing_file_reports_error)
{
	std::string text;
	std::string err;
	BOOST_CHECK(!resolv_conf_read(tmp_path("no-such-file"), text, err));
	BOOST_CHECK(!err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
