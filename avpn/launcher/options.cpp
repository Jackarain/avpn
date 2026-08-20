//
// options.cpp
// ~~~~~~~~~~~
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// avpn 全部命令行选项的单一事实来源：供 WebUI 配置表单、新建实例默认
// 配置、启动参数生成共用，保证 WebUI 覆盖的功能与 avpn 命令行一致。
//

#include "options.hpp"

#include <algorithm>
#include <cstdlib>

namespace launcher {

namespace {

namespace json = boost::json;

// 全部可配置项（名称/类型/帮助/默认值/隐藏/重启/常用/提示/分组）。
const option k_options[] = {
	// 内部/隐藏选项：不参与 WebUI 表单，由 launcher 在拉起 avpn 时传入。
	{ "help", option_kind::boolean, "显示帮助信息并退出。", false, false, 0, "", {}, true, false, false, "", "其他" },
	{ "config", option_kind::string, "从指定配置文件加载参数选项。", false, false, 0, "", {}, true, false, false, "", "其他" },
	{ "genkey", option_kind::boolean, "生成新的密钥对并输出到 stdout。", false, false, 0, "", {}, true, false, false, "", "其他" },
	{ "controller", option_kind::string, "控制服务地址（内部使用，由 launcher 传入）。", false, false, 0, "", {}, true, false, false, "", "其他" },
	{ "pid_file", option_kind::string, "把进程 PID 写入指定文件（内部使用，由 launcher 传入）。", false, false, 0, "", {}, true, false, false, "", "其他" },
	{ "console_logs", option_kind::boolean, "强制控制台日志并关闭 ANSI 颜色（内部使用，由 launcher 传入）。", false, false, 0, "", {}, true, false, false, "", "其他" },
	{ "ptun_fd", option_kind::integer, "外部传入的 tun 设备文件描述符（内部使用）。", false, false, 0, "", {}, true, false, false, "", "其他" },
	{ "utun_fd", option_kind::integer, "tun 设备 IPC 文件描述符（内部使用）。", false, false, 0, "", {}, true, false, false, "", "其他" },

	// 常用配置。
	{ "nexthop", option_kind::string, "目标 vpn 服务器地址（客户端模式）。", false, false, 0, "", {}, false, false, true,
	  "客户端模式：指向远端 vpn 网关的地址，格式 ip:port；留空则为网关模式。", "连接" },
	{ "udp_listen", option_kind::string_list, "UDP 监听地址（网关模式，可重复添加）。", false, false, 0, "", {}, false, false, true,
	  "网关模式：UDP 监听地址（可添加多条），如 0.0.0.0:51820；客户端模式下留空。", "连接" },
	{ "tcp_listen", option_kind::string_list, "TCP 监听地址（网关模式，可重复添加）。", false, false, 0, "", {}, false, false, true,
	  "网关模式：TCP 监听地址（可添加多条），如 0.0.0.0:51820；客户端模式下留空。", "连接" },
	{ "ifdev", option_kind::string, "tun 设备名称。", false, false, 0, "", {}, false, false, false,
	  "虚拟网卡名称，如 tun0；留空自动选择。", "网络" },
	{ "mtu_size", option_kind::integer, "tun mtu 大小。", true, false, 1450, "", {}, false, false, false,
	  "虚拟网卡 MTU 大小，默认 1450。", "网络" },
	{ "keepalive", option_kind::integer, "保活间隔（秒）。", true, false, 60, "", {}, false, false, false,
	  "与对端之间的保活消息间隔（秒），默认 60。", "网络" },
	{ "subnet", option_kind::string, "vpn 子网。", true, false, 0, "10.8.0.0/16", {}, false, false, false,
	  "网关模式：vpn 虚拟子网，默认 10.8.0.0/16。", "网络" },
	{ "v6_subnet", option_kind::string, "vpn IPv6 子网。", true, false, 0, "fd00:8888::/64", {}, false, false, false,
	  "网关模式：IPv6 虚拟子网，默认 fd00:8888::/64。", "网络" },
	{ "c2c", option_kind::boolean, "允许客户端之间通信。", false, false, 0, "", {}, false, false, false,
	  "网关模式：允许不同客户端之间直接互通。", "网络" },
	{ "passbyvpn", option_kind::boolean, "使用网关作为默认路由。", false, false, 0, "", {}, false, false, false,
	  "客户端模式：把默认路由指向 vpn 网关（需网关侧 NAT 配置）。", "路由" },
	{ "ignore_push", option_kind::boolean, "忽略推送的路由/DNS。", false, false, 0, "", {}, false, false, false,
	  "客户端模式：忽略网关推送的路由与 DNS 配置。", "路由" },
	{ "pushroutes", option_kind::string_list, "推送给客户端的路由（可重复添加）。", false, false, 0, "", {}, false, false, false,
	  "网关模式：推送给客户端的路由（可添加多条），格式 ip/cidr 或域名。", "路由" },
	{ "bypassroutes", option_kind::string_list, "绕过 vpn 走物理线路的目标（可重复添加）。", false, false, 0, "", {}, false, false, false,
	  "客户端模式：这些目标不走 vpn（可添加多条），格式 ip/cidr 或域名。", "路由" },
	{ "pushdns", option_kind::integer, "推送给客户端的 DNS。", true, false, 0, "", {}, false, false, false,
	  "网关模式：推送给客户端的 DNS 服务器地址（IPv4 整数形式），0 表示不推送。", "路由" },
	{ "pre_up", option_kind::string, "在 tun 接口启用前执行的命令。", false, false, 0, "", {}, false, false, false,
	  "钩子：接口启用前通过 shell 执行，支持 %i 替换为接口名。", "钩子" },
	{ "post_up", option_kind::string, "在 tun 接口配置完成后执行的命令。", false, false, 0, "", {}, false, false, false,
	  "钩子：接口配置完成后通过 shell 执行，支持 %i 替换为接口名。", "钩子" },
	{ "pre_down", option_kind::string, "在 tun 接口拆除前执行的命令。", false, false, 0, "", {}, false, false, false,
	  "钩子：接口拆除前通过 shell 执行，支持 %i 替换为接口名。", "钩子" },
	{ "post_down", option_kind::string, "在 tun 接口拆除后执行的命令。", false, false, 0, "", {}, false, false, false,
	  "钩子：接口拆除后通过 shell 执行，支持 %i 替换为接口名。", "钩子" },
	{ "private_key", option_kind::string, "本端私钥（base64）。", false, false, 0, "", {}, false, false, false,
	  "本端静态私钥，base64 编码；可运行 avpn --genkey 生成。", "密钥" },
	{ "public_key", option_kind::string, "本端公钥（base64）。", false, false, 0, "", {}, false, false, false,
	  "本端静态公钥，base64 编码。", "密钥" },
	{ "pkl", option_kind::string_list, "对端公钥白名单（base64，可重复添加）。", false, false, 0, "", {}, false, false, false,
	  "对端静态公钥白名单（可添加多条），base64 编码。", "密钥" },
	{ "obfuscate_key", option_kind::string, "数据特征混淆密钥串。", false, false, 0, "", {}, false, false, false,
	  "非空时启用流量混淆：加密帧外层填充随机垃圾数据打乱包长。两端必须配置相同密钥串，留空关闭。", "密钥" },
	{ "data_shards", option_kind::integer, "FEC 数据分片数。", true, false, 0, "", {}, false, false, false,
	  "FEC 数据分片数。大于 1 时启用 FEC 恢复；为 1 时按 parity_shards 倍数发包；0 关闭 FEC。", "FEC" },
	{ "parity_shards", option_kind::integer, "FEC 冗余分片数。", true, false, 0, "", {}, false, false, false,
	  "FEC 冗余分片数。data_shards 大于 1 时为可容忍丢失的数据包数；data_shards 为 1 时为发包倍数（0-5）。", "FEC" },
	{ "compress", option_kind::string, "压缩算法。", false, false, 0, "", {}, false, false, false,
	  "数据压缩算法：deflate / lz4 / zstd，留空不压缩。", "压缩" },
	{ "logs_path", option_kind::string, "日志文件输出目录。", false, false, 0, "", {}, false, false, false,
	  "指定日志文件输出目录；留空仅控制台输出。", "日志" },
	{ "disable_logs", option_kind::boolean, "禁用日志输出。", true, false, 0, "", {}, false, false, false,
	  "禁用全部日志输出（launcher 管理下日志经 stdout/stderr 采集，建议保持关闭）。", "日志" },
};

const std::vector<option>& all_options_impl()
{
	static const std::vector<option> all(std::begin(k_options), std::end(k_options));
	return all;
}

// 判断配置值是否与注册表默认值相同（相同则无需显式传入命令行）。
bool equals_default(const option& o, const json::value& val)
{
	const bool has_def = o.has_default_;
	const auto kind = o.kind_;

	// 无默认值：仅当值等于该类型的零值时视为"未设置"。
	auto is_zero_value = [kind](const json::value& v) -> bool {
		switch (kind) {
		case option_kind::boolean:
			return v.is_bool() && !v.as_bool();
		case option_kind::integer:
			return v.is_int64() ? v.as_int64() == 0
				: (v.is_uint64() ? v.as_uint64() == 0 : (v.is_double() && v.as_double() == 0));
		case option_kind::string:
			return v.is_string() ? v.as_string().empty() : (v.is_null() || v.is_bool());
		case option_kind::string_list:
			return v.is_array() ? v.as_array().empty()
				: (v.is_string() ? v.as_string().empty() : v.is_null());
		}
		return false;
	};

	if (!has_def)
		return is_zero_value(val);

	switch (kind) {
	case option_kind::boolean: {
		bool b = val.is_bool() ? val.as_bool() : false;
		return b == o.def_bool_;
	}
	case option_kind::integer: {
		std::int64_t v = to_int_value(val);
		return v == o.def_int_;
	}
	case option_kind::string:
		return to_string_value(val) == o.def_str_;
	case option_kind::string_list: {
		std::vector<std::string> list = to_string_list(val);
		if (list.size() != o.def_list_.size())
			return false;
		for (std::size_t i = 0; i < list.size(); i++)
			if (list[i] != o.def_list_[i])
				return false;
		return true;
	}
	}
	return false;
}

} // namespace

// 兼容 int / int64 / float64 的整数取值。
std::int64_t to_int_value(const json::value& v)
{
	if (v.is_int64())
		return v.as_int64();
	if (v.is_uint64())
		return static_cast<std::int64_t>(v.as_uint64());
	if (v.is_double())
		return static_cast<std::int64_t>(v.as_double());
	if (v.is_string()) {
		// std::from_chars 的浮点重载在 macOS 上不可用（macOS 26 才引入），
		// 改用 strtod 实现相同语义：解析出有效数字即视为成功。
		const auto& s = v.as_string();
		char* end = nullptr;
		const double f = std::strtod(s.data(), &end);
		if (end != s.data())
			return static_cast<std::int64_t>(f);
	}
	return 0;
}

std::string to_string_value(const json::value& v)
{
	if (v.is_string())
		return std::string(v.as_string());
	if (v.is_bool())
		return v.as_bool() ? "true" : "false";
	if (v.is_int64())
		return std::to_string(v.as_int64());
	if (v.is_uint64())
		return std::to_string(v.as_uint64());
	if (v.is_double())
		return json::serialize(v);
	return {};
}

// stringlist 值统一转为 []string。
std::vector<std::string> to_string_list(const json::value& v)
{
	std::vector<std::string> out;
	if (v.is_array()) {
		for (const auto& e : v.as_array())
			out.push_back(to_string_value(e));
	} else if (v.is_string()) {
		if (!v.as_string().empty())
			out.push_back(std::string(v.as_string()));
	}
	return out;
}

const std::vector<option>& all_options()
{
	return all_options_impl();
}

const option* find_option(const std::string& name)
{
	for (const auto& o : all_options_impl())
		if (o.name_ == name)
			return &o;
	return nullptr;
}

const char* kind_type_name(option_kind kind)
{
	switch (kind) {
	case option_kind::boolean: return "bool";
	case option_kind::integer: return "int";
	case option_kind::string_list: return "stringlist";
	default: return "string";
	}
}

json::object default_config()
{
	json::object cfg;
	for (const auto& o : all_options_impl()) {
		if (o.hidden_)
			continue;
		if (!o.has_default_) {
			switch (o.kind_) {
			case option_kind::string_list: cfg[o.name_] = json::array(); break;
			case option_kind::integer: cfg[o.name_] = std::int64_t{0}; break;
			case option_kind::boolean: cfg[o.name_] = false; break;
			default: cfg[o.name_] = "";
			}
			continue;
		}
		switch (o.kind_) {
		case option_kind::string_list: {
			json::array arr;
			for (const auto& s : o.def_list_)
				arr.emplace_back(s);
			cfg[o.name_] = std::move(arr);
			break;
		}
		case option_kind::boolean:
			cfg[o.name_] = o.def_bool_;
			break;
		case option_kind::integer:
			cfg[o.name_] = o.def_int_;
			break;
		default:
			cfg[o.name_] = o.def_str_;
			break;
		}
	}
	return cfg;
}

std::vector<std::string> args_for(const json::object& cfg)
{
	// 按名称排序。
	std::vector<std::string> names;
	names.reserve(cfg.size());
	for (const auto& kv : cfg)
		names.push_back(std::string(kv.key()));
	std::sort(names.begin(), names.end());

	std::vector<std::string> args;
	for (const auto& name : names) {
		const option* o = find_option(name);
		if (o == nullptr || o->hidden_)
			continue;
		const json::value& val = cfg.at(name);
		// 跳过与注册表默认值相同的选项。
		if (equals_default(*o, val))
			continue;
		switch (o->kind_) {
		case option_kind::string_list: {
			// avpn 没有注册表默认值，空列表直接跳过；
			// 传 "--name \"\"" 会让 avpn 把空串当作列表项。
			auto items = to_string_list(val);
			for (const auto& item : items) {
				args.push_back("--" + name);
				args.push_back(item);
			}
			break;
		}
		case option_kind::boolean: {
			bool b = false;
			if (val.is_bool())
				b = val.as_bool();
			else if (val.is_string()) {
				const auto& s = val.as_string();
				b = (s == "true" || s == "1" || s == "yes" || s == "on");
			} else if (val.is_int64())
				b = val.as_int64() != 0;
			else if (val.is_double())
				b = val.as_double() != 0;
			args.push_back("--" + name + "=" + (b ? "true" : "false"));
			break;
		}
		default:
			args.push_back("--" + name);
			args.push_back(to_string_value(val));
			break;
		}
	}
	return args;
}

std::string validate_config(json::object& cfg)
{
	for (const auto& kv : cfg) {
		const option* o = find_option(std::string(kv.key()));
		if (o == nullptr)
			return "unknown option: " + std::string(kv.key());
		if (o->hidden_)
			return "internal option cannot be set: " + std::string(kv.key());
	}
	return {};
}

} // namespace launcher
