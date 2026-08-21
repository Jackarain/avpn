//
// main.cpp
// ~~~~~~~~
//
// Copyright (c) 2023 Jack (jack dot wgm at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifdef _MSC_VER
# pragma warning(push)
# pragma warning(disable: 4005)
#endif // _MSC_VER

#ifdef USE_SNMALLOC
# ifdef NDEBUG
#  define SNMALLOC_STATIC_LIBRARY_PREFIX sn_
#  include "src/snmalloc/override/malloc.cc"
#  include "src/snmalloc/override/new.cc"
# endif
#endif // USE_SNMALLOC

#ifdef _MSC_VER
# pragma warning(pop)
#endif

#include "libavpn/logging.hpp"
#include "libavpn/io_context_pool.hpp"

#include "libavpn/use_awaitable.hpp"
#include "libavpn/ipip.hpp"
#include "libavpn/avpn.hpp"
#include "libavpn/avpn_crypto.hpp"

#include "main.hpp"

#include <boost/asio/io_context.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/signal_set.hpp>

#include <boost/nowide/args.hpp>
#include <boost/algorithm/string/join.hpp>
#include <boost/program_options.hpp>
namespace po = boost::program_options;

#include <boost/filesystem.hpp>
namespace fs = boost::filesystem;

#include <fstream>
#include <limits>
#include <cstdint>
#ifndef _WIN32
# include <unistd.h>
#endif

namespace net = boost::asio;

#ifdef _MSC_VER
# pragma warning(disable: 4244)
#endif

using namespace libavpn;

namespace {

// 跨平台获取当前进程 PID.
long long current_process_id()
{
#ifdef _WIN32
	return static_cast<long long>(::GetCurrentProcessId());
#else
	return static_cast<long long>(::getpid());
#endif
}

} // namespace


//////////////////////////////////////////////////////////////////////////

namespace std
{
	std::ostream& operator<<(std::ostream &os, const std::vector<std::string> &users)
	{
		for (auto it = users.begin(); it != users.end();)
		{
			os << *it;
			if (++it == users.end())
				break;
			os << " ";
		}

		return os;
	}
}

int main(int argc, char** argv)
{
	[[maybe_unused]]boost::nowide::args a(argc, argv);
	platform_init();

	std::string config;
	std::string log_dir;
	bool disable_logs = false;
	std::string pid_file;

	service_config cfg{};

	po::options_description desc("Options");
	desc.add_options()
		("help,h", "Help message.")
		("config", po::value<std::string>(&config)->value_name("config.conf"), "Load configuration options from specified file.")
		("logs_path", po::value<std::string>(&log_dir)->value_name(""), "Specify directory for log files.")
		("disable_logs", po::value<bool>(&disable_logs)->value_name("")->default_value(false), "Disable logging.")
		("ifdev", po::value<std::string>(&cfg.ifdev_)->value_name("tun0"), "Tun device name.")
		("ptun_fd", po::value<int>(&cfg.ptun_fd_)->value_name("fd"), "Tun device fd passed in from outside.")
		("utun_fd", po::value<int>(&cfg.utun_fd_)->value_name("fd"), "Tun device fd for IPC.")
		("controller", po::value<std::string>(&cfg.controller_)->value_name("ws://ip:port"), "Control service address.")
		("nexthop", po::value<std::string>(&cfg.nexthop_)->value_name("ip:port"), "Next hop vpn server address.")
		("tcp_listen", po::value<std::vector<std::string>>(&cfg.tcp_listens_)->value_name("ip:port"), "TCP listen address.")
		("udp_listen", po::value<std::vector<std::string>>(&cfg.udp_listens_)->value_name("ip:port"), "UDP listen address.")
		("genkey", "Generate a new keypair, print private and public keys to stdout.")
		("private_key", po::value<std::string>(&cfg.private_key_)->value_name("key"), "Local private key (base64).")
		("public_key", po::value<std::string>(&cfg.public_key_)->value_name("key"), "Local public key (base64).")
		("pkl", po::value<std::vector<std::string>>(&cfg.pkl_)->value_name("key"), "Peer public key (base64).")
		("mtu_size", po::value<int>(&cfg.mtu_size_)->value_name("mtu"), "Tun mtu size.")
		("keepalive", po::value<int>(&cfg.keepalive_)->value_name("seconds"), "Keepalive interval in seconds.")
		("pushroutes", po::value<std::vector<std::string>>(&cfg.pushroutes_)->value_name("route"), "Routes pushed to client.")
		("bypassroutes", po::value<std::vector<std::string>>(&cfg.bypassroutes_)->value_name("route"), "Routes bypassing vpn on client (ip/cidr or hostname).")
		("pushdns", po::value<uint32_t>(&cfg.pushdns_)->value_name("ip"), "DNS pushed to client.")
		("passbyvpn", po::value<bool>(&cfg.passbyvpn_)->value_name("bool"), "Use gateway as default route.")
		("ignore_push", po::value<bool>(&cfg.ignore_push_)->value_name("bool"), "Ignore pushed routes/dns.")
		("c2c", po::value<bool>(&cfg.c2c_)->value_name("bool"), "Allow client to client communication.")
		("subnet", po::value<std::string>(&cfg.subnet_)->value_name("10.8.0.0/16"), "Vpn subnet.")
		("v6_subnet", po::value<std::string>(&cfg.v6_subnet_)->value_name("fd00:8888::/64"), "Vpn ipv6 subnet.")
		("data_shards", po::value<int>(&cfg.data_shards_)->value_name("n"), "Fec data shards.")
		("parity_shards", po::value<int>(&cfg.parity_shards_)->value_name("n"), "Fec parity shards.")
		("compress", po::value<std::string>(&cfg.compress_)->value_name("deflate|lz4|zstd"), "Compression algorithm.")
		("obfuscate_key", po::value<std::string>(&cfg.obfuscate_key_)->value_name("string"), "Obfuscation key string (both ends must set the same key).")
		("pre_up", po::value<std::string>(&cfg.pre_up_)->value_name("cmd"), "Shell command run before tun is brought up (%i = interface name).")
		("post_up", po::value<std::string>(&cfg.post_up_)->value_name("cmd"), "Shell command run after tun is configured (%i = interface name).")
		("pre_down", po::value<std::string>(&cfg.pre_down_)->value_name("cmd"), "Shell command run before tun is torn down (%i = interface name).")
		("post_down", po::value<std::string>(&cfg.post_down_)->value_name("cmd"), "Shell command run after tun is torn down (%i = interface name).")
		("pid_file", po::value<std::string>(&pid_file)->value_name("path"), "Write process PID to this file (internal, set by launcher).")
	;

	// 解析命令行.
	po::variables_map vm;

	try {
		po::store(
			po::command_line_parser(argc, argv)
			.options(desc)
			.style(po::command_line_style::unix_style
				| po::command_line_style::allow_long_disguise)
			.run()
			, vm);
		po::notify(vm);
	}
	catch (const po::error& e)
	{
		std::cerr << "Error parsing command line: " << e.what() << "\n";
		return EXIT_FAILURE;
	}

	// 帮助输出.
	if (vm.count("help") || argc == 1)
	{
		version_info();
		std::cout << desc
				  << "\n"
				  << R"(Email bug reports, questions, discussions to <jack.wgm@gmail.com>
and/or open issues at https://github.com/Jackarain/proxy)"
				  << "\n";
		return EXIT_SUCCESS;
	}

	// 生成密钥对并退出.
	if (vm.count("genkey"))
	{
		auto kp = crypto::x25519_generate_keypair();
		auto priv = crypto::base64_encode(kp.first);
		auto pub = crypto::base64_encode(kp.second);
		std::cout << "private: " << priv << "\n";
		std::cout << "public: " << pub << "\n";
		return EXIT_SUCCESS;
	}

	// 解析配置文件.
	if (vm.count("config"))
	{
		if (!fs::exists(config))
		{
			std::cerr << "No such config file: " << config << std::endl;
			return EXIT_FAILURE;
		}

		auto cfg_file = po::parse_config_file(config.c_str(), desc, false);
		po::store(cfg_file, vm);
		po::notify(vm);
	}

	if (disable_logs && log_dir.empty())
	{
		xlogger::turnoff_logging();
	}
	else
	{
		if (log_dir.empty())
			xlogger::toggle_write_logging(false);
		else
			xlogger::init_logging(log_dir);

		if (disable_logs)
			xlogger::toggle_console_logging(false);
	}

	// launcher 管理下日志经控制通道上报采集（logger_tag 钩子），
	// 关闭控制台输出，避免调试构建下 stdout 与控制通道双路写入
	// 导致日志重复。
	if (!cfg.controller_.empty())
		xlogger::toggle_console_logging(false);

	// 创建 io_context 池.
	io_context_pool io_pool(std::max<std::size_t>(4, std::thread::hardware_concurrency()));
	net::io_context& ioc = io_pool.main_io_context();

	// 创建并配置服务对象.
	auto service = avpn_service::create_service(io_pool, cfg);

	// 创建 signal_set 以捕获终止信号.
	net::signal_set terminator_signal(ioc);
	terminator_signal.add(SIGINT);
	terminator_signal.add(SIGTERM);
#ifdef __linux__
	signal(SIGPIPE, SIG_IGN);
#endif
#if defined(SIGQUIT)
	terminator_signal.add(SIGQUIT);
#endif // defined(SIGQUIT)

	// 等待终止( CTRL+C )信号.
	terminator_signal.async_wait(
		[&](const boost::system::error_code&, int sig) mutable
			{
				XLOG_INFO << "Received termination signal " << sig << ", shutting down...";
				service->stop();
				io_pool.stop();
				terminator_signal.remove(sig);
			});

	// 启动服务.
	service->start();

	// 写入 pid 文件 (供 launcher 重启后据此清理残余进程); 正常退出时删除.
	if (!pid_file.empty())
	{
		std::ofstream ofs(pid_file, std::ios::trunc);
		if (ofs)
		{
			ofs << current_process_id() << "\n";
			ofs.flush();
		}
		else
		{
			std::cerr << "Failed to write pid file: " << pid_file << std::endl;
		}
	}

	// 运行 io_context 池.
	io_pool.run();

	if (!pid_file.empty())
		fs::remove(pid_file);

	return EXIT_SUCCESS;
}
