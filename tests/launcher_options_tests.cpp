#define BOOST_TEST_MODULE avpn_launcher_options_tests
#include <boost/test/unit_test.hpp>

#include "apps/launcher/options.hpp"

#include <fstream>
#include <regex>
#include <set>
#include <sstream>
#include <string>

#ifndef AVPN_SOURCE_DIR
#error AVPN_SOURCE_DIR must point at the repository root
#endif

namespace {

	// 从 avpn 的命令行定义里抠出选项名: main.cpp 里的
	// desc.add_options()("name", ...) 一段.
	std::set<std::string> cli_option_names()
	{
		std::ifstream in(std::string(AVPN_SOURCE_DIR) +
			"/apps/avpn/avpn/main.cpp");
		BOOST_REQUIRE_MESSAGE(in.good(), "cannot open main.cpp");

		std::stringstream buf;
		buf << in.rdbuf();
		const std::string text = buf.str();

		const std::size_t begin = text.find("desc.add_options()");
		BOOST_REQUIRE_MESSAGE(begin != std::string::npos,
			"desc.add_options() not found in main.cpp");
		const std::size_t end = text.find("\n\t;\n", begin);
		BOOST_REQUIRE_MESSAGE(end != std::string::npos,
			"end of desc.add_options() not found in main.cpp");

		const std::string block = text.substr(begin, end - begin);
		std::set<std::string> names;
		// 每个选项都写成一行, 行首是 ("name" 或 ("name,短名" 的形式;
		// 行内的 value_name("...") 不算选项名.
		const std::regex re(R"(^\s*\(\s*"([a-z_0-9]+)[",])");
		std::istringstream lines(block);
		for (std::string line; std::getline(lines, line);)
		{
			std::smatch m;
			if (std::regex_search(line, m, re))
				names.insert(m[1].str());
		}
		return names;
	}

} // namespace

BOOST_AUTO_TEST_SUITE(launcher_options_v2)

// 注册表是 WebUI 与启动参数的单一事实来源, 名字不能重复.
BOOST_AUTO_TEST_CASE(option_names_are_unique)
{
	std::set<std::string> seen;
	for (const auto& o : launcher::all_options())
	{
		BOOST_CHECK_MESSAGE(seen.insert(o.name_).second,
			"duplicate option: " << o.name_);
	}
}

// 命令行支持的选项, launcher 注册表里都得有, 否则 WebUI 配不了.
BOOST_AUTO_TEST_CASE(every_cli_option_is_registered)
{
	std::size_t checked = 0;
	for (const auto& name : cli_option_names())
	{
		BOOST_CHECK_MESSAGE(launcher::find_option(name) != nullptr,
			"option " << name << " is missing from the launcher registry");
		checked++;
	}
	BOOST_CHECK(checked > 30);
}

// 注册表里非隐藏的选项都必须是 avpn 真的认得的选项.
BOOST_AUTO_TEST_CASE(every_visible_option_exists_on_the_cli)
{
	const auto names = cli_option_names();
	for (const auto& o : launcher::all_options())
	{
		if (o.hidden_)
			continue;
		BOOST_CHECK_MESSAGE(names.count(o.name_) != 0,
			"registry option " << o.name_ << " is not a cli option");
	}
}

BOOST_AUTO_TEST_SUITE_END()
