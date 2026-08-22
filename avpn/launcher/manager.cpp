//
// manager.cpp
// ~~~~~~~~~~~
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include "manager.hpp"

#include <algorithm>
#include <cstdio>
#include <fstream>
#include <sstream>

#include <openssl/rand.h>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/filesystem.hpp>

#include "options.hpp"

namespace launcher {

namespace fs = boost::filesystem;
namespace json = boost::json;

// 进程启动后等待控制通道接入的告警阈值。
inline constexpr std::chrono::seconds kConnectWarnInterval{ 15 };
// 崩溃自动重启参数。
inline constexpr std::chrono::seconds kCrashWindow{ 60 };
inline constexpr int kMaxCrashes = 3;

namespace {

const char* kInstancesFile = "instances.json";

// 任意值转 int64。
std::int64_t as_int64(const json::value& v)
{
	if (v.is_int64())
		return v.as_int64();
	if (v.is_uint64())
		return static_cast<std::int64_t>(v.as_uint64());
	if (v.is_double())
		return static_cast<std::int64_t>(v.as_double());
	if (v.is_bool())
		return v.as_bool() ? 1 : 0;
	if (v.is_string()) {
		try {
			return std::stoll(std::string(v.as_string()));
		} catch (...) {}
	}
	return 0;
}

// 任意值转字符串。
std::string as_string(const json::value& v)
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

// 随机 hex 字符串（crypto 强度，跨平台：OpenSSL RAND_bytes）。
std::string random_hex(std::size_t bytes)
{
	std::string out;
	out.resize(bytes * 2);
	std::vector<unsigned char> buf(bytes);
	if (RAND_bytes(buf.data(), static_cast<int>(bytes)) != 1) {
		// 随机源失败时回退：实例 ID/令牌可预测，认证形同虚设，直接终止。
		std::fprintf(stderr, "crypto random failed\n");
		std::abort();
	}
	static const char* hex = "0123456789abcdef";
	for (std::size_t i = 0; i < bytes; i++) {
		out[i * 2] = hex[buf[i] >> 4];
		out[i * 2 + 1] = hex[buf[i] & 0xf];
	}
	return out;
}

// 取配置中的 stringlist。
std::vector<std::string> config_list(const json::object& cfg, const char* key)
{
	std::vector<std::string> out;
	auto it = cfg.find(key);
	if (it == cfg.end())
		return out;
	if (it->value().is_array()) {
		for (const auto& v : it->value().as_array())
			out.push_back(as_string(v));
	} else if (it->value().is_string()) {
		out.push_back(std::string(it->value().as_string()));
	}
	return out;
}

// 2 空格缩进的 JSON 序列化, 便于阅读与跨端调试一致.
std::string serialize_pretty(const json::value& v, int indent = 0)
{
	std::string out;
	switch (v.kind()) {
	case json::kind::object: {
		out += "{\n";
		bool first = true;
		for (const auto& [k, val] : v.as_object()) {
			if (!first)
				out += ",\n";
			first = false;
			out += std::string(indent + 2, ' ') + json::serialize(json::value(k)) + ": " +
				serialize_pretty(val, indent + 2);
		}
		out += "\n" + std::string(indent, ' ') + "}";
		break;
	}
	case json::kind::array: {
		out += "[\n";
		bool first = true;
		for (const auto& val : v.as_array()) {
			if (!first)
				out += ",\n";
			first = false;
			out += std::string(indent + 2, ' ') + serialize_pretty(val, indent + 2);
		}
		out += "\n" + std::string(indent, ' ') + "]";
		break;
	}
	default:
		out += json::serialize(v);
		break;
	}
	return out;
}

} // namespace

manager::manager(std::string data_dir, std::string avpn_path, std::string work_dir)
	: m_data_dir_(std::move(data_dir))
	, m_avpn_path_(std::move(avpn_path))
	, m_work_dir_(std::move(work_dir))
{}

void manager::set_ws_addr(const std::string& host, int port, bool https)
{
	std::lock_guard<std::mutex> lock(m_mu_);
	m_host_ = host;
	m_port_ = port;
	m_https_ = https;
}

std::string manager::persist_path() const
{
	return (fs::path(m_data_dir_) / kInstancesFile).string();
}

std::string manager::pid_file_path(const std::string& id) const
{
	return (fs::path(m_data_dir_) / "pid" / (id + ".pid")).string();
}

// 控制通道连接应使用的 host。
static std::string control_host(const std::string& host)
{
	std::string h = host;
	if (h.size() >= 2 && h.front() == '[' && h.back() == ']')
		h = h.substr(1, h.size() - 2);
	if (h.empty() || h == "0.0.0.0" || h == "::")
		return "127.0.0.1";
	if (h == "::1")
		return "[::1]";
	if (h.find(':') != std::string::npos)
		return "[" + h + "]";
	return h;
}

std::string manager::ws_url(const instance_ptr& in) const
{
	std::string scheme = m_https_ ? "wss" : "ws";
	return scheme + "://" + control_host(m_host_) + ":" + std::to_string(m_port_) +
		"/rpc?instance=" + in->id_ + "&token=" + in->token_;
}

bool manager::load()
{
	if (!load_from_disk())
		return false;
	for (const auto& id : ids()) {
		instance_ptr in = find_instance(id);
		if (in && in->autostart_) {
			std::string err;
			if (!start(id, err))
				std::fprintf(stderr, "[warn] autostart instance %s failed: %s\n", id.c_str(), err.c_str());
		}
	}
	return true;
}

bool manager::load_from_disk()
{
	std::string path = persist_path();
	std::ifstream ifs(path);
	if (!ifs) {
		// 文件不存在视为正常。
		if (!fs::exists(path))
			return true;
		return false;
	}
	std::stringstream ss;
	ss << ifs.rdbuf();
	boost::system::error_code ec;
	auto jv = json::parse(ss.str(), ec);
	if (ec || !jv.is_array())
		return false;

	std::lock_guard<std::mutex> lock(m_mu_);
	for (const auto& item : jv.as_array()) {
		if (!item.is_object())
			continue;
		const auto& obj = item.as_object();
		auto id_it = obj.find("id");
		if (id_it == obj.end() || !id_it->value().is_string())
			continue;
		auto in = std::make_shared<instance>();
		in->id_ = std::string(id_it->value().as_string());
		if (in->id_.empty())
			continue;
		in->name_ = obj.if_contains("name") && obj.at("name").is_string()
			? std::string(obj.at("name").as_string()) : "";
		in->autostart_ = obj.if_contains("autostart") && obj.at("autostart").is_bool()
			? obj.at("autostart").as_bool() : false;
		in->token_ = obj.if_contains("token") && obj.at("token").is_string()
			? std::string(obj.at("token").as_string()) : "";
		if (in->token_.empty())
			in->token_ = random_hex(16);
		if (auto c = obj.if_contains("config"); c && c->is_object())
			in->config_ = c->as_object();
		if (in->config_.empty())
			in->config_ = json::object();
		if (auto t = obj.if_contains("created_at"); t && t->is_string()) {
			time_point tp;
			if (rfc3339_parse(std::string(t->as_string()), tp))
				in->created_at_ = tp;
		}
		if (in->created_at_ == zero_time())
			in->created_at_ = now_time();
		in->logs_ = std::make_shared<ringbuf>(2000);
		m_instances_[in->id_] = in;
	}
	return true;
}

std::vector<std::string> manager::ids()
{
	std::lock_guard<std::mutex> lock(m_mu_);
	std::vector<std::string> out;
	out.reserve(m_instances_.size());
	for (const auto& [id, _] : m_instances_)
		out.push_back(id);
	return out;
}

bool manager::save()
{
	std::vector<std::pair<instance_ptr, json::object>> list;
	{
		std::lock_guard<std::mutex> lock(m_mu_);
		list.reserve(m_instances_.size());
		for (const auto& [_, in] : m_instances_) {
			// 深拷贝 map：锁外序列化期间其他线程可能在锁内就地修改 config_。
			list.emplace_back(in, json::object(in->config_));
		}
	}
	json::array arr;
	for (auto& [in, cfg] : list) {
		json::object item;
		item["id"] = in->id_;
		item["name"] = in->name_;
		item["config"] = std::move(cfg);
		item["autostart"] = in->autostart_;
		item["token"] = in->token_;
		item["created_at"] = rfc3339_format(in->created_at_);
		arr.emplace_back(std::move(item));
	}

	std::string data = serialize_pretty(arr);
	{
		std::lock_guard<std::mutex> lock(m_save_mu_);
		boost::system::error_code ec;
		fs::create_directories(m_data_dir_, ec);
		if (ec)
			return false;
		std::string tmp = persist_path() + ".tmp";
		{
			std::ofstream ofs(tmp, std::ios::binary | std::ios::trunc);
			if (!ofs)
				return false;
			ofs << data;
			ofs.flush();
			if (!ofs)
				return false;
		}
		fs::rename(tmp, persist_path(), ec);
		return !ec;
	}
}

instance_ptr manager::find_instance(const std::string& id)
{
	std::lock_guard<std::mutex> lock(m_mu_);
	auto it = m_instances_.find(id);
	return it == m_instances_.end() ? nullptr : it->second;
}

// 持锁状态下的实例查找（调用者须已持有 m_mu_）。
instance_ptr manager::find_instance_unlocked(const std::string& id) const
{
	auto it = m_instances_.find(id);
	return it == m_instances_.end() ? nullptr : it->second;
}

instance_ptr manager::get(const std::string& id)
{
	return find_instance(id);
}

instance_ptr manager::create(const std::string& name, json::object config, std::string& err)
{
	if (config.empty())
		config = default_config();
	err = validate_config(config);
	if (!err.empty())
		return nullptr;

	auto in = std::make_shared<instance>();
	in->id_ = random_hex(8);
	in->name_ = name.empty() ? in->id_ : name;
	in->config_ = std::move(config);
	in->created_at_ = now_time();
	in->token_ = random_hex(16);
	in->logs_ = std::make_shared<ringbuf>(2000);

	{
		std::lock_guard<std::mutex> lock(m_mu_);
		m_instances_[in->id_] = in;
	}
	if (!save())
		err = "save instances failed";
	return in;
}

net::awaitable<bool> manager::del(const std::string& id, std::string& err)
{
	if (!find_instance(id)) {
		err = "instance not found";
		co_return false;
	}
	co_await stop(id, err);
	{
		std::lock_guard<std::mutex> lock(m_mu_);
		m_instances_.erase(id);
	}
	// 清理实例残留的 pid 文件。
	boost::system::error_code ec;
	fs::remove(pid_file_path(id), ec);
	save();
	co_return true;
}

bool manager::update(const std::string& id, const std::string& name,
	const std::optional<bool>& autostart, std::string& err)
{
	auto in = find_instance(id);
	if (!in) {
		err = "instance not found";
		return false;
	}
	{
		std::lock_guard<std::mutex> lock(m_mu_);
		if (!name.empty() && name != in->name_)
			in->name_ = name;
		if (autostart)
			in->autostart_ = *autostart;
	}
	save();
	return true;
}

bool manager::start(const std::string& id, std::string& err)
{
	auto in = find_instance(id);
	if (!in) {
		err = "instance not found";
		return false;
	}
	{
		std::lock_guard<std::mutex> lock(m_mu_);
		in->stopping_ = false;
		in->restart_count_ = 0;
		in->last_exit_ = time_point{};
	}
	return start_internal(id, err);
}

bool manager::start_internal(const std::string& id, std::string& err)
{
	std::vector<std::string> args;
	std::string avpn_path, work_dir, launcher_url, pid_path;
	{
		auto in = find_instance(id);
		if (!in) {
			err = "instance not found";
			return false;
		}
		std::lock_guard<std::mutex> lock(m_mu_);
		if (in->stopping_) {
			err = "instance " + id + " is stopping";
			return false;
		}
		if (in->proc_ && in->proc_->alive_) {
			err = "instance " + id + " already running";
			return false;
		}
		args = args_for(in->config_);
		launcher_url = ws_url(in);
		pid_path = pid_file_path(id);
		args.push_back("--launcher");
		args.push_back(launcher_url);
		args.push_back("--pid_file");
		args.push_back(pid_path);
		// launcher 管理下经控制通道日志上报采集日志 (logger_tag 钩子),
		// 无需强制控制台输出.
		avpn_path = m_avpn_path_;
		work_dir = m_work_dir_;
	}

	// 确保 pid 文件目录存在（avpn 写入 pid 文件前不会自行创建父目录）。
	{
		boost::system::error_code pec;
		fs::create_directories(fs::path(pid_path).parent_path(), pec);
	}

	// 按 pid 文件终止上次运行残留的进程（锁外执行，可能阻塞）。
	kill_by_pid_file(id);

	{
		auto in = find_instance(id);
		if (!in) {
			err = "instance not found";
			return false;
		}
		std::lock_guard<std::mutex> lock(m_mu_);
		// 自动重启与 Stop 并发时：kill 残留进程期间用户可能点了停止。
		if (in->stopping_) {
			err = "instance " + id + " is stopping";
			return false;
		}
		if (in->proc_ && in->proc_->alive_) {
			err = "instance " + id + " already running";
			return false;
		}

		auto logs = std::make_shared<ringbuf>(2000);
		// 捕获 manager 的 shared_ptr，保证监控线程回调期间对象存活。
		auto self = shared_from_this();
		auto p = spawn_proc(avpn_path, args, work_dir, logs,
			[self, id]() { self->wait_exit(id); });
		if (!p) {
			err = "spawn avpn failed";
			return false;
		}
		in->proc_ = p;
		in->logs_ = logs;
	}

	// 记录 pid（供日志）。
	{
		std::lock_guard<std::mutex> lock(m_mu_);
		auto in = find_instance_unlocked(id);
		if (in && in->proc_)
			std::fprintf(stderr, "[info] instance %s pid=%d\n", id.c_str(), in->proc_->pid_);
	}
	// 诊断：进程启动后若长时间未连上控制通道，打印明确告警。
	std::thread([self = shared_from_this(), id]() {
			std::this_thread::sleep_for(kConnectWarnInterval);
		bool no_conn = false;
		{
			std::lock_guard<std::mutex> lock(self->m_mu_);
			auto in = self->find_instance_unlocked(id);
			if (in && !in->online() && in->proc_ && in->proc_->alive_)
				no_conn = true;
		}
		if (no_conn)
			std::fprintf(stderr,
				"[warn] instance %s: avpn did not connect to launcher within %llds; "
				"check the avpn binary supports --launcher and the control channel URL\n",
				id.c_str(), (long long)kConnectWarnInterval.count());
	}).detach();
	return true;
}

void manager::wait_exit(const std::string& id)
{
	{
		std::lock_guard<std::mutex> lock(m_mu_);
		auto in = find_instance_unlocked(id);
		if (!in)
			return;
		if (in->proc_)
			in->proc_ = nullptr;
		if (!in->online())
			in->last_seen_ = now_time();
	}
	save();

	instance_ptr in = find_instance(id);
	if (in && should_auto_restart(in)) {
		std::string err;
		if (!start_internal(id, err))
			std::fprintf(stderr, "[warn] instance %s auto-restart failed: %s\n", id.c_str(), err.c_str());
	}
}

bool manager::should_auto_restart(const instance_ptr& in)
{
	std::lock_guard<std::mutex> lock(m_mu_);
	if (in->stopping_)
		return false;
	if (!m_instances_.count(in->id_))
		return false;
	if (in->proc_ && in->proc_->alive_)
		return false;
	auto now = now_time();
	// 距上次崩溃超过窗口：进程此前已稳定运行，重置连续崩溃计数。
	if (now - in->last_exit_ > kCrashWindow)
		in->restart_count_ = 0;
	in->last_exit_ = now;
	in->restart_count_++;
	if (in->restart_count_ > kMaxCrashes) {
		std::fprintf(stderr,
			"[warn] instance %s: crashed %d times within %llds, stop auto-restarting\n",
			in->id_.c_str(), in->restart_count_, (long long)kCrashWindow.count());
		in->restart_count_ = 0;
		in->last_exit_ = time_point{};
		return false;
	}
	return true;
}

void manager::kill_by_pid_file(const std::string& id)
{
	std::string path = pid_file_path(id);
	std::ifstream ifs(path);
	if (!ifs)
		return;
	std::string data((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
	process_id pid = 0;
	try {
		pid = static_cast<process_id>(std::stoll(data));
	} catch (...) {
		return;
	}	if (pid <= 0)
		return;
	if (!process_alive(pid)) {
		// 进程已退出：仅清理陈旧 pid 文件。
		boost::system::error_code ec;
		fs::remove(path, ec);
		return;
	}
	// 防御 pid 复用：确认该进程确实以本实例的 pid 文件参数启动。
	if (!process_matches_pid_file(pid, path)) {
		std::fprintf(stderr,
			"[warn] instance %s: pid %d in pid file %s is not this instance's process, skip killing\n",
			id.c_str(), pid, path.c_str());
		boost::system::error_code ec;
		fs::remove(path, ec);
		return;
	}
	std::fprintf(stderr, "[info] instance %s: killing leftover process %d from pid file %s\n",
		id.c_str(), pid, path.c_str());
	stop_pid(pid);
	boost::system::error_code ec;
	fs::remove(path, ec);
}

net::awaitable<bool> manager::stop(const std::string& id, std::string& err)
{
	std::shared_ptr<proc> proc;
	jsonrpc_session sess;
	process_id orphan_pid = 0;
	{
		auto in = find_instance(id);
		if (!in) {
			err = "instance not found";
			co_return false;
		}
		std::lock_guard<std::mutex> lock(m_mu_);
		in->stopping_ = true;
		proc = in->proc_;
		sess = in->channel_;
	}

	if (proc == nullptr) {
		// 孤儿实例（launcher 崩溃后残留）：按 register 上报的 PID 终止。
		{
			std::lock_guard<std::mutex> lock(m_mu_);
			auto in = find_instance_unlocked(id);
			if (in) {
				orphan_pid = in->reg_pid_;
				in->reg_pid_ = 0;
			}
		}
		if (orphan_pid > 0)
			stop_pid(orphan_pid);
		if (sess.valid())
			sess.stop();
		co_return true;
	}

	// 先 RPC shutdown 优雅退出（异步，不阻塞 io_context 线程）。
	if (sess.valid())
		(void)co_await sess.async_call("shutdown", json::value(), std::chrono::seconds(3));
	stop_proc(proc, 5);
	if (sess.valid())
		sess.stop();
	co_return true;
}

net::awaitable<bool> manager::restart(const std::string& id, std::string& err)
{
	std::shared_ptr<proc> proc;
	jsonrpc_session sess;
	{
		auto in = find_instance(id);
		if (!in) {
			err = "instance not found";
			co_return false;
		}
		std::lock_guard<std::mutex> lock(m_mu_);
		in->stopping_ = true;
		proc = in->proc_;
		sess = in->channel_;
	}

	// 直接杀死子进程（不等优雅退出），实现快速重启。
	if (proc)
		stop_proc(proc, 0);
	if (sess.valid())
		sess.stop();

	// 等待监控线程完成退出处理（proc_ 清空、不再自动重启），
	// 避免紧接着 start 时与 wait_exit 竞争导致新进程句柄被清空。
	auto ex = co_await net::this_coro::executor;
	net::steady_timer timer(ex);
	for (int i = 0; i < 50; i++) {
		{
			auto in = find_instance(id);
			std::lock_guard<std::mutex> lock(m_mu_);
			if (!in || in->proc_ == nullptr)
				break;
		}
		timer.expires_after(std::chrono::milliseconds(50));
		boost::system::error_code tec;
		co_await timer.async_wait(net::redirect_error(net::use_awaitable, tec));
	}
	co_return start(id, err);
}

net::awaitable<bool> manager::apply_config(const std::string& id, json::object config,
	json::value& result, std::string& err)
{
	err = validate_config(config);
	if (!err.empty())
		co_return false;

	instance_ptr in = find_instance(id);
	if (!in) {
		err = "instance not found";
		co_return false;
	}

	// avpn 不支持运行期热改配置：计算变更的选项，提示重启生效。
	json::array changed;
	{
		std::lock_guard<std::mutex> lock(m_mu_);
		auto cur = in->config_;
		for (const auto& kv : config) {
			auto it = cur.find(kv.key());
			if (it == cur.end() || it->value() != kv.value())
				changed.emplace_back(std::string(kv.key()));
		}
	}
	bool online = in->online();

	{
		std::lock_guard<std::mutex> lock(m_mu_);
		auto in = find_instance_unlocked(id);
		if (in)
			in->config_ = std::move(config);
	}
	save();

	json::object out;
	out["applied"] = json::array();
	if (online && !changed.empty()) {
		out["needs_restart"] = std::move(changed);
	} else {
		out["needs_restart"] = json::array();
	}
	out["errors"] = json::object();
	result = std::move(out);
	co_return true;
}

boost::json::value manager::summaries()
{
	std::lock_guard<std::mutex> lock(m_mu_);
	std::vector<summary> items;
	items.reserve(m_instances_.size());
	for (const auto& [_, in] : m_instances_) {
		summary s;
		s.id_ = in->id_;
		s.name_ = in->name_;
		s.state_ = in->state();
		s.online_ = in->online();
		s.pid_ = in->pid();
		s.autostart_ = in->autostart_;
		s.created_at_ = in->created_at_;
		// 列表展示的监听/对端地址：网关取 tcp/udp 监听，客户端取 nexthop。
		s.listen_ = config_list(in->config_, "tcp_listen");
		auto udp = config_list(in->config_, "udp_listen");
		s.listen_.insert(s.listen_.end(), udp.begin(), udp.end());
		if (s.listen_.empty()) {
			auto nh = config_list(in->config_, "nexthop");
			s.listen_ = nh;
		}
		if (in->last_report_.is_object()) {
			const auto& rep = in->last_report_.as_object();
			if (auto t = rep.if_contains("ts"); t && t->is_int64() && t->as_int64() != 0) {
				if (auto a = rep.if_contains("active_connections"); a)
					s.active_ = static_cast<int>(as_int64(*a));
				if (auto r = rep.if_contains("rates"); r && r->is_object()) {
					if (auto rx = r->as_object().if_contains("rx_rate_bps"); rx && rx->is_double())
						s.rx_rate_ = rx->as_double();
					if (auto tx = r->as_object().if_contains("tx_rate_bps"); tx && tx->is_double())
						s.tx_rate_ = tx->as_double();
				}
			}
		}
		items.push_back(std::move(s));
	}
	// 按创建顺序（升序）显示；同时刻创建时按 ID 稳定排序兜底。
	std::stable_sort(items.begin(), items.end(), [](const summary& a, const summary& b) {
		if (a.created_at_ == b.created_at_)
			return a.id_ < b.id_;
		return a.created_at_ < b.created_at_;
	});

	json::array out;
	for (const auto& s : items) {
		json::object o;
		o["id"] = s.id_;
		o["name"] = s.name_;
		o["state"] = s.state_;
		o["online"] = s.online_;
		o["pid"] = s.pid_;
		o["autostart"] = s.autostart_;
		if (!s.listen_.empty()) {
			json::array arr;
			for (const auto& l : s.listen_)
				arr.emplace_back(l);
			o["listen"] = std::move(arr);
		}
		o["active"] = s.active_;
		o["rx_rate_bps"] = s.rx_rate_;
		o["tx_rate_bps"] = s.tx_rate_;
		out.emplace_back(std::move(o));
	}
	return out;
}

bool manager::view(const std::string& id, launcher::view& out)
{
	std::lock_guard<std::mutex> lock(m_mu_);
	auto in = find_instance_unlocked(id);
	if (!in)
		return false;
	out.id_ = in->id_;
	out.name_ = in->name_;
	out.state_ = in->state();
	out.online_ = in->online();
	out.pid_ = in->pid();
	out.autostart_ = in->autostart_;
	out.config_ = json::object(in->config_);
	out.created_at_ = in->created_at_;
	out.last_report_ = in->last_report_;
	out.last_seen_ = in->last_seen_;
	return true;
}

bool manager::status_view(const std::string& id, json::value& out)
{
	std::lock_guard<std::mutex> lock(m_mu_);
	auto in = find_instance_unlocked(id);
	if (!in)
		return false;
	json::object o;
	o["online"] = in->online();
	o["state"] = in->state();
	o["pid"] = in->pid();
	o["last_seen"] = rfc3339_format(in->last_seen_);
	o["report"] = in->last_report_.is_object() ? in->last_report_ : json::value(json::object_kind);
	out = std::move(o);
	return true;
}

bool manager::logs(const std::string& id, std::int64_t since, json::value& out) {
	std::lock_guard<std::mutex> lock(m_mu_);
	auto in = find_instance_unlocked(id);
	if (!in)
		return false;
	if (!in->logs_)
		return false;

	std::vector<std::string> l;
	std::vector<std::int64_t> s;
	std::int64_t next = 0;
	json::array lines;
	json::array seqs;
	if (since < 0)
		in->logs_->tail_next(2000, l, s, next);
	else
		in->logs_->since_next(since, l, s, next);
	for (std::size_t i = 0; i < l.size(); i++) {
		lines.emplace_back(l[i]);
		seqs.emplace_back(s[i]);
	}
	json::object o;
	o["lines"] = std::move(lines);
	o["seqs"] = std::move(seqs);
	o["next"] = next;
	o["gen"] = in->logs_->generation();
	out = std::move(o);
	return true;
}

instance_ptr manager::ws_auth(const std::string& id, const std::string& token)
{
	std::lock_guard<std::mutex> lock(m_mu_);
	auto in = find_instance_unlocked(id);
	if (!in)
		return nullptr;
	if (in->token_.empty() || in->token_ != token)
		return nullptr;
	return in;
}

void manager::ws_attached(const instance_ptr& in, jsonrpc_session sess)
{
	// 存入实例并关闭旧连接（若存在）。
	jsonrpc_session old;
	{
		std::lock_guard<std::mutex> lock(m_mu_);
		old = in->channel_;
		in->channel_ = std::move(sess);
		in->online_ = true;
	}
	if (old.valid())
		old.stop();
}

// 处理控制通道通知（register/status/log）。由 http_server 直接用
// jsonrpc::jsonrpc_session 绑定通知回调后转发到本方法。
void manager::handle_notify(const instance_ptr& in, const std::string& method,
	const json::value& params)
{
	if (method == "register") {
		std::lock_guard<std::mutex> lock(m_mu_);
		if (params.is_object()) {
			if (auto p = params.as_object().if_contains("pid"); p && p->is_int64())
				in->reg_pid_ = static_cast<process_id>(p->as_int64());
			else if (p && p->is_uint64())
				in->reg_pid_ = static_cast<process_id>(p->as_uint64());
		}
		in->last_seen_ = now_time();
		return;
	}

	if (method == "status") {
		std::lock_guard<std::mutex> lock(m_mu_);
		in->last_report_ = params;
		in->last_seen_ = now_time();
		return;
	}

	if (method == "log") {
		std::lock_guard<std::mutex> lock(m_mu_);
		if (in->logs_ && params.is_object()) {
			if (auto l = params.as_object().if_contains("lines"); l && l->is_array()) {
				for (const auto& line : l->as_array())
					in->logs_->add(as_string(line));
			}
		}
		return;
	}
}

void manager::ws_detached(const instance_ptr& in, std::uint64_t gen)
{
	std::lock_guard<std::mutex> lock(m_mu_);
	// 已有新连接接入时不清空实例会话。
	if (gen != in->chan_gen_.load())
		return;
	in->channel_ = jsonrpc_session{};
	in->online_ = false;
	in->last_seen_ = now_time();
}

} // namespace launcher
