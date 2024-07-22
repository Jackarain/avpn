//
// main.cpp
// ~~~~~~~~
//
// Copyright (c) 2019 Jack (jack dot wgm at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include "avpn/version.hpp"
#include "avpn/avpn.hpp"
#include "avpn/vpn_controller.hpp"

#include "utils/misc.hpp"
#include "proxy/socks_client.hpp"

#include <iostream>
#include <iterator>
#include <algorithm>
#include <functional>

#include <tuple>
#include <utility>
#include <array>
#include <streambuf>
#include <fstream>

#ifdef __linux__
#  include <sys/resource.h>
//#  include <systemd/sd-daemon.h>

# ifndef HAVE_UNAME
#  define HAVE_UNAME
# endif

#elif _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <fcntl.h>
#  include <io.h>
#  include <windows.h>
#  include <objbase.h>

#pragma data_seg("avpn.windows.lean.mean")
bool g_avpn_windows_lean_mean = false;
#pragma data_seg()
#pragma comment(linker, "/Section:avpn.windows.lean.mean,RWS")

#pragma comment(lib, "Ole32.lib")

#endif // _WIN32

#ifdef HAVE_UNAME
#  include <sys/utsname.h>
#endif

#include <boost/nowide/args.hpp>
#include <boost/algorithm/string/join.hpp>
#include <boost/program_options.hpp>
namespace po = boost::program_options;

#include "avpn/protocol.hpp"
#include "utils/crypto.hpp"

int platform_init()
{
#if defined(WIN32) || defined(_WIN32)
	CoInitialize(NULL);
	/* Disable the "application crashed" popup. */
	SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX |
		SEM_NOOPENFILEERRORBOX);

#if defined(DEBUG) ||defined(_DEBUG)
	//	_CrtDumpMemoryLeaks();
	// 	int flags = _CrtSetDbgFlag(_CRTDBG_REPORT_FLAG);
	// 	flags |= _CRTDBG_LEAK_CHECK_DF;
	// 	_CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE);
	// 	_CrtSetReportFile(_CRT_WARN, _CRTDBG_FILE_STDOUT);
	// 	_CrtSetDbgFlag(flags);
#endif

#if !defined(__MINGW32__)
	_CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_DEBUG);
	_CrtSetReportMode(_CRT_ERROR, _CRTDBG_MODE_DEBUG);
#endif

	_setmode(0, _O_BINARY);
	_setmode(1, _O_BINARY);
	_setmode(2, _O_BINARY);

	/* Disable stdio output buffering. */
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	/* Enable minidump when application crashed. */
#elif defined(__linux__)
	rlimit of = { 50000, 100000 };
	setrlimit(RLIMIT_NOFILE, &of);

	struct rlimit core_limit;
	core_limit.rlim_cur = RLIM_INFINITY;
	core_limit.rlim_max = RLIM_INFINITY;
	setrlimit(RLIMIT_CORE, &core_limit);

	/* Set the stack size programmatically with setrlimit */
	rlimit rl;
	int result = getrlimit(RLIMIT_STACK, &rl);
	if (result == 0)
	{
		const rlim_t stack_size = 100 * 1024 * 1024;
		if (rl.rlim_cur < stack_size)
		{
			rl.rlim_cur = stack_size;
			setrlimit(RLIMIT_STACK, &rl);
		}
	}
#endif

	std::ios::sync_with_stdio(false);

	return 0;
}

std::string version_info()
{
	std::string os_name;

#ifdef _WIN32
#ifdef _WIN64
	os_name = "Windows (64bit)";
#else
	os_name = "Windows (32bit)";
#endif // _WIN64

#elif defined(HAVE_UNAME)
	utsname un;
	uname(&un);
	os_name = un.sysname;
	os_name += " ";
	os_name += un.release;

	// extract_linux_version from un.release;
	int ma_ver, mi_ver, patch_ver;
	sscanf(un.release, "%d.%d.%d", &ma_ver, &mi_ver, &patch_ver);

	if (std::string(un.sysname) == "Linux" && ma_ver < 4)
	{
		std::cerr << "WARNING: kernel too old, "
			<< "please upgrade your system!" << std::endl;
	}

#elif defined(__APPLE__)
	os_name = "Drawin";
#else
	os_name = "unknow";
#endif // _WIN32

	std::ostringstream oss;
	oss << "Version: v" << AVPN_VERSION
		<< ", " << AVPN_GIT_REVISION
		<< "\nBuilt on " << __DATE__
		<< " " << __TIME__
		<< " runs on " << os_name
		<< ", " << BOOST_COMPILER
		<< ", boost " << BOOST_LIB_VERSION;
	std::cerr << oss.str() << "\n";

	return oss.str();
}

void print_args(int argc, char** argv,
	const po::variables_map& vm)
{
	XLOG_INFO << "Current directory: "
		<< std::filesystem::current_path().string();

	if (!vm.count("config"))
	{
		std::vector<std::string> print_args;
		print_args.assign(argv, argv + argc);
		XLOG_INFO << "Run: "
			<< boost::algorithm::join(print_args, " ");

		return;
	}

	for (const auto& cfg : vm)
	{
		if (cfg.second.empty() || cfg.first == "config")
			continue;

		auto& var = cfg.second.value();
		try {
			const auto& s = boost::any_cast<std::string>(var);
			XLOG_INFO << cfg.first
				<< " = "
				<< s;
			continue;
		}
		catch (const std::exception&) {}

		try {
			const auto& v = boost::any_cast<bool>(var);
			XLOG_INFO << cfg.first
				<< " = "
				<< v;
			continue;
		}
		catch (const std::exception&) {}

		try {
			const auto& v = boost::any_cast<int>(var);
			XLOG_INFO << cfg.first
				<< " = "
				<< v;
			continue;
		}
		catch (const std::exception&) {}
	}
}

int main(int argc, char** argv)
{
	platform_init();

	std::vector<std::string> upstreams;
	std::vector<std::string> tcp_listens;
	std::vector<std::string> udp_listens;
	int data_shards;
	int parity_shards;
	int mtu_size;
	int mode;
	int keepalive;
	int matrix_cache;
	std::string compress;
	std::string subnet;
	std::string ifdev;
	std::string ptun;
	std::string utun;
	std::string identity;
	std::string config;
	std::string controller;
	std::string proxy;

	std::string post_up_script;
	std::string log_directory;

	std::vector<std::string> routes;
	std::string pushdns;
	bool passbyvpn = false;
	bool c2c = true;
	bool noroute = false;
	bool disable_logs = false;
	bool ipv6 = false;
	std::string writepid_file;
	std::string ignored_param;

	std::string privatekey;
	std::string publickey;

	std::string ssl_certificate_dir;

	[[maybe_unused]] boost::nowide::args _(argc, argv);

	po::options_description desc("Options");
	desc.add_options()
		("help,h", "Show this help message.")
		("version", "Display the current version.")

		("config", po::value<std::string>(&config)->value_name("config.conf"), "Load configuration options from the specified file.")

		("identity", po::value<std::string>(&identity)->default_value("client")->value_name("client/server"), "Specify the identity of the instance as 'client' or 'server'.")

		("tun", po::value<std::string>(&ifdev)->value_name("tun"), "Specify the TUN device driver name, such as wintun, tun9, or vtun.")

		("ptun", po::value<std::string>(&ptun)->value_name("unix domain socket path"), "Send TUN file descriptor over a Unix domain socket.")
		("utun", po::value<std::string>(&utun)->value_name("unix domain socket path"), "Send TUN packets over a Unix domain socket.")

		("mtu", po::value<int>(&mtu_size)->default_value(1450)->value_name("mtu"), "Set the MTU size for the TUN device (default: 1450).")

		("upstream", po::value<std::vector<std::string>>(&upstreams)->multitoken()->value_name("url [urls ...]"), "List of upstream servers.")

		("genkey", "Generate a new private key and print it to stdout.")

		("privatekey", po::value<std::string>(&privatekey)->value_name("privatekey"), "Specify the private key for secure communication.")
		("publickey", po::value<std::string>(&publickey)->value_name("publickey"), "Specify the public key for secure communication.")

		("tcp", po::value<std::vector<std::string>>(&tcp_listens)->multitoken()->value_name("ip:port [ip:port ...]"), "Set the TCP listen addresses for the WebSocket server.")
		("udp", po::value<std::vector<std::string>>(&udp_listens)->multitoken()->value_name("ip:port [ip:port ...]"), "Set the UDP listen addresses for the WebSocket server.")

		("proxy", po::value<std::string>(&proxy)->value_name("proxy"), "Specify a proxy server to use in the format [protocol://]host[:port], supporting socks, http, and haproxy protocols.")

		("data_shards,d", po::value<int>(&data_shards)->default_value(8)->value_name("N"), "Set the number of data shards for Reed-Solomon encoding.")
		("parity_shards,p", po::value<int>(&parity_shards)->default_value(4)->value_name("N"), "Set the number of parity shards for Reed-Solomon encoding.")

		("matrix_cache", po::value<int>(&matrix_cache)->default_value(256)->value_name("N"), "Specify the cache size for the Reed-Solomon Vandermonde matrix.")

		("mode", po::value<int>(&mode)->default_value(0)->value_name("mode"), "Set the data transmission mode: 0 for UDP only, 1 for TCP/UDP mix, 2 for TCP only.")
		("compress", po::value<std::string>(&compress)->value_name("deflate/lz4/zstd"), "Enable a compression algorithm (deflate, lz4, or zstd).")

		("keepalive", po::value<int>(&keepalive)->default_value(10000)->value_name("ms"), "Set the keepalive interval in milliseconds for TCP and UDP connections.")

		("noroute", po::value<bool>(&noroute)->value_name(""), "Ignore routes and DNS settings pushed by the server.")
		("pushroute", po::value<std::vector<std::string>>(&routes)->multitoken()->value_name("routes"), "Push specified routes to the client.")
		("pushdns", po::value<std::string>(&pushdns)->value_name("ip"), "Push the specified DNS nameserver to the client.")
		("passbyvpn", po::value<bool>(&passbyvpn)->value_name(""), "Allow all IP network traffic originating on client machines to pass through the server.")

		("subnet", po::value<std::string>(&subnet)->default_value("10.0.0.1/16")->value_name("net/mask"), "Set the VPN subnet.")
		("c2c", po::value<bool>(&c2c)->default_value(true, "true")->value_name("true/false"), "Allow clients to see each other (client-to-client communication).")

		("controller", po::value<std::string>(&controller)->value_name("ip:port"), "Specify the local controller server's IP and port.")

		("disable_logs", po::value<bool>(&disable_logs)->value_name(""), "Disable logging.")
		("logs_path", po::value<std::string>(&log_directory)->value_name(""), "Specify the directory for log files.")

		("writepid", po::value<std::string>(&writepid_file)->value_name("pidfile"), "Write the process ID to the specified file.")

		("post_up", po::value<std::string>(&post_up_script)->value_name("cmd"), "Specify a command to run after the TUN device is up.")
	;

	// 以下参数是为了保持和 openvpn 兼容, 这样可以直接把 avpn 替换掉 openvpn 的二进制, 从而大幅简化 ERX 上的配置.
	if (std::filesystem::path(argv[0]).filename() == "openvpn")
	{
		desc.add_options()
			("daemon", "daemon")
			("status", po::value<std::string>(&ignored_param)->value_name("file"), "output status to file")
			("verb", po::value<std::string>(&ignored_param)->value_name("N"), "verbose log")
			("dev-type", po::value<std::string>(&ignored_param)->value_name("tun/tap"), "device type, must be tun")
		;
	}

	try
	{
		// 解析命令行.
		po::variables_map vm;
		po::store(
			po::command_line_parser(argc, argv)
			.options(desc)
			.style(po::command_line_style::unix_style
				| po::command_line_style::allow_long_disguise)
			.run()
			, vm);
		po::notify(vm);

		if (disable_logs)
		{
			xlogger::turnoff_logging();
			xlogger::toggle_write_logging(true);
		}

		// 生成私钥.
		if (vm.count("genkey"))
		{
			auto key = base64_encode(crypto_util::ecdh_keygen());
			std::cout << "private: " << key << "\n";
			std::cout << "public: " << base64_encode(crypto_util::ecdh_public(key)) << "\n";
			return EXIT_SUCCESS;
		}

#if 0
		if (vm.count("pubkey"))
		{
			std::string pkey;

			for (std::string line; std::getline(std::cin, line);)
				pkey += line;

			auto priv_key = base64_decode(pkey);
			if (priv_key.size() != 32)
			{
				std::cerr << "Key is not the correct length or format\n";
				return EXIT_FAILURE;
			}

			std::cout << base64_encode(crypto_util::ecdh_public(pkey)) << "\n";

			return EXIT_SUCCESS;
		}
#endif

		if (vm.count("config"))
		{
			if (!std::filesystem::exists(config))
			{
				std::cerr << "No such config file: " << config << std::endl;
				return EXIT_FAILURE;
			}

			auto cfg = po::parse_config_file(config.c_str(), desc, false);
			po::store(cfg, vm);
			po::notify(vm);

			if (disable_logs)
				xlogger::toggle_write_logging(true);
		}

		// 设置日志输出目录.
		xlogger::init_logging(log_directory);

		// 输出版本信息.
		XLOG_FILE << version_info();

		// 帮助输出.
		if (vm.count("help") || argc == 1)
		{
			std::cout << desc
				<< "\nWritten by jackarain"
				<< "\nReport bugs to: jack.wgm@gmail.com"
				<< "\n";
			return EXIT_SUCCESS;
		}

		if (!config.empty())
			XLOG_DBG << "Load config file: " << config;

		// 输出参数信息.
		print_args(argc, argv, vm);

		// test subnet address.
		{
			auto net = net::ip::make_network_v4(subnet);
			net.address().to_string();
		}

		#ifdef BOOST_POSIX_API
			if (vm.count("daemon"))
				daemon(0, 0);
		#endif
	}
	catch (const std::exception& e)
	{
		std::cerr << "exception: " << e.what() << std::endl;
		return EXIT_FAILURE;
	}

	net::io_context ioc{ 1 };

	net::signal_set terminator_signal(ioc);
	terminator_signal.add(SIGINT);
	terminator_signal.add(SIGTERM);
#ifdef __linux__
	signal(SIGPIPE, SIG_IGN);
#endif
#if defined(SIGQUIT)
	terminator_signal.add(SIGQUIT);
#endif // defined(SIGQUIT)

	avpn::service_config cfg;

	cfg.upstreams_ = upstreams;

	cfg.tcp_listens_ = tcp_listens;
	cfg.udp_listens_ = udp_listens;

	cfg.proxy_ = proxy;

	cfg.ifdev_ = ifdev;
	if (ifdev.empty())
	{
		if (!utun.empty())
		{
			cfg.utun_fd_  = avpn_recv_fd(utun);
			if (cfg.utun_fd_ == -1)
			{
				XLOG_ERR << "Recv utun fd from: " << utun << " failed!";
				return EXIT_FAILURE;
			}
		}
		else if (!ptun.empty())
		{
			cfg.ptun_fd_ = avpn_recv_fd(ptun);
			if (cfg.ptun_fd_ == -1)
			{
				XLOG_ERR << "Recv ptun fd from: " << ptun << " failed!";
				return EXIT_FAILURE;
			}
		}
	}

	cfg.controller_ = controller;
	cfg.private_key_ = privatekey;
	cfg.public_key_ = publickey;
	cfg.ssl_certificate_dir_ = ssl_certificate_dir;

	cfg.post_up_script_ = post_up_script;

	cfg.mtu_size_ = mtu_size;
	cfg.using_ipv6_ = ipv6;

	auto& params = cfg.tunnel_params_;
	params.data_shards_ = data_shards;
	params.parity_shards_ = parity_shards;
	params.mode_ = static_cast<avpn::Proto>(mode);
	params.matrix_cache_ = matrix_cache;
	params.compress_ = compress;
	params.keepalive_ = keepalive < 1000 ? 1000 : keepalive;
	if (!pushdns.empty())
	{
		auto dns = net::ip::address_v4::from_string(pushdns);
		params.pushdns_ = dns.to_uint();
	}
	params.pushroutes_ = routes;
	params.passbyvpn_ = passbyvpn;
	params.ignore_push_ = noroute;
	params.c2c_ = c2c;
	params.subnet_ = subnet;

	if (data_shards + parity_shards > 256)
	{
		XLOG_ERR << "Sum of data and parity shards cannot exceed 256";
		return EXIT_FAILURE;
	}
	if (identity == "server")
		cfg.identity_ = avpn::Identity::avpn_server;
	else if (identity == "client")
		cfg.identity_ = avpn::Identity::avpn_client;
	else
	{
		XLOG_DBG << "Identity not set, default is client.";
		cfg.identity_ = avpn::Identity::avpn_client;
	}

	if (cfg.identity_ == avpn::Identity::avpn_client)
	{
		if (cfg.upstreams_.empty())
		{
			XLOG_ERR << "Missing upstream...";
			return EXIT_FAILURE;
		}

		// 检查upstream是否有ipv6, 如果有v6地址, mtu则需要减少20
		// 这样避免在udp中发送ip包时, 超过物理mtu大小则拆包.
		for (auto& stream : cfg.upstreams_)
		{
			auto url = boost::url_view(stream);
			udp::resolver resolver{ ioc };
			boost::system::error_code ec;
			auto results = resolver.resolve(url.host(), url.port(), ec);
			for (auto endp : results)
			{
				if (endp.endpoint().address().is_v6())
				{
					cfg.using_ipv6_ = ipv6 = true;
					cfg.mtu_size_  = mtu_size = std::min(1430, mtu_size);
					break;
				}
			}

			if (ipv6)
				break;
		}

		// 重新计算packet及mtu等大小.
		if (!avpn::recompute_mtu(mtu_size, ipv6))
		{
			XLOG_ERR << "MTU mismatch";
			return EXIT_FAILURE;
		}
	}
	else
	{
		if (!avpn::recompute_mtu(mtu_size, ipv6))
		{
			XLOG_ERR << "MTU mismatch";
			return EXIT_FAILURE;
		}
	}

#ifdef _WIN32
	if (g_avpn_windows_lean_mean)
	{
		auto pid = (DWORD)check_pid(ifdev);
		HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
		if (handle == INVALID_HANDLE_VALUE)
			return EXIT_FAILURE;
		TerminateProcess(handle, EXIT_SUCCESS);
	}

	g_avpn_windows_lean_mean = true;
#endif

	// 创建pid文件.
	if (writepid_file.empty())
		create_pid(ifdev);
	else
	 	create_pid(ifdev, std::filesystem::path(writepid_file));

	auto io_run = [&ioc]() mutable
	{
		while (ioc.run_one())
		{
			while (ioc.poll_one())
				;
		}
	};

	if (controller.empty())
	{
		using  avpn::avpn_service;
		auto avpn_srv = avpn_service::make_avpn_service(ioc, cfg);
		auto& srv = *avpn_srv;

		srv.start();

		// 处理中止信号.
		terminator_signal.async_wait(
			[&ioc, &srv, &terminator_signal]
			(const boost::system::error_code&, int sig) mutable
			{
				XLOG_DBG << "terminator is called!";
				terminator_signal.remove(sig);

				srv.stop();
				ioc.stop();
			});

		io_run();
	}
	else
	{
		// 构造vpn_controller对象, 在内部发起对controller的连接.
		avpn::vpn_controller control{ ioc, cfg };
		control.start();

		io_run();
	}

	XLOG_DBG << "avpn system exiting...";
	return EXIT_SUCCESS;
}

