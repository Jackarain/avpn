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

#include <iostream>
#include <iterator>
#include <algorithm>
#include <functional>

#include <tuple>
#include <utility>
#include <array>
#include <streambuf>
#include <fstream>
#include <bitset>

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

#pragma data_seg("avpn.windows.lean.mean")
bool g_avpn_windows_lean_mean = false;
#pragma data_seg()
#pragma comment(linker, "/Section:avpn.windows.lean.mean,RWS")

#endif // _WIN32

#ifdef HAVE_UNAME
#  include <sys/utsname.h>
#endif

#include <boost/nowide/args.hpp>
#include <boost/algorithm/string/join.hpp>
#include <boost/program_options.hpp>
namespace po = boost::program_options;

#include <boost/multiprecision/cpp_dec_float.hpp>

#include "avpn/version.hpp"
#include "avpn/internal.hpp"
#include "avpn/io_context_pool.hpp"
#include "avpn/avpn.hpp"
#include "avpn/reedsolomon.hpp"
#include "avpn/controller.hpp"

#include "utils/fileop.hpp"


void create_pid(std::string ifdev)
{
	// 创建临时avpn文件夹.
	auto avpn_tmp_dir = std::filesystem::temp_directory_path() / "avpn";
	std::error_code ignore_ec;
	std::filesystem::create_directories(avpn_tmp_dir, ignore_ec);

	std::ostringstream oss;
	oss << get_process_id();

	// 先删除存在的pid文件.
	auto pid = avpn_tmp_dir / std::format("avpn-{}.pid", ifdev);
	std::filesystem::remove(pid, ignore_ec);

	// 创建avpn.pid文件.
	fileop::write(pid, oss.str());
}

uint64_t check_pid(std::string ifdev)
{
	auto avpn_tmp_dir = std::filesystem::temp_directory_path() / "avpn";
	if (!std::filesystem::exists(avpn_tmp_dir))
		return 0;

	std::string bufs(128, 0);
	auto bytes = fileop::read(avpn_tmp_dir / std::format("avpn-{}.pid", ifdev), bufs);
	bufs.resize(bytes);

	return (uint64_t)std::atoll(bufs.c_str());
}

int platform_init()
{
#if defined(WIN32) || defined(_WIN32)
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
	if (setrlimit(RLIMIT_NOFILE, &of) < 0)
	{
		perror("setrlimit for nofile");
	}
	struct rlimit core_limit;
	core_limit.rlim_cur = RLIM_INFINITY;
	core_limit.rlim_max = RLIM_INFINITY;
	if (setrlimit(RLIMIT_CORE, &core_limit) < 0)
	{
		perror("setrlimit for coredump");
	}

	/* Set the stack size programmatically with setrlimit */
	rlimit rl;
	int result = getrlimit(RLIMIT_STACK, &rl);
	if (result == 0)
	{
		const rlim_t stack_size = 100 * 1024 * 1024;
		if (rl.rlim_cur < stack_size)
		{
			rl.rlim_cur = stack_size;
			result = setrlimit(RLIMIT_STACK, &rl);
			if (result != 0)
				perror("setrlimit for stack size");
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

	if (std::string(un.sysname) == "Linux" && ma_ver < 3)
	{
		std::cerr << "you are running a very very OLD kernel. please upgrade your system" << std::endl;
	}

#elif defined(__APPLE__)
	os_name = "Drawin";
#else
	os_name = "unknow";
#endif // _WIN32

	std::ostringstream oss;
	oss << "avpn version: v" << AVPN_VERSION << ", " << AVPN_GIT_REVISION
		<< " built on " << __DATE__ << " " << __TIME__ << " runs on " << os_name << ", " << BOOST_COMPILER;
	std::cerr << oss.str() << "\n";

	return oss.str();
}

int main(int argc, char** argv)
{
	platform_init();

	std::vector<std::string> upstreams;
	std::vector<std::string> tcp_listens;
	std::vector<std::string> udp_listens;
	int data_shards;
	int parity_shards;
	int mode;
	bool compress;
	int fec_delay;
	bool auto_fec;
	int keepalive;
	std::string subnet;
	std::string ifdev;
	std::string identity;
	std::string config;
	int controller_port;

	std::vector<std::string> routes;
	std::string pushdns;
	bool passbyvpn = false;
	bool snat = false;
	bool c2c = true;
	bool disable_logs = false;

	[[maybe_unused]] boost::nowide::args _(argc, argv);

	po::options_description desc("Options");
	desc.add_options()
		("help,h", "Help message.")
		("version", "Current version.")

		("config", po::value<std::string>(&config), "Load config options from file.")

		("identity", po::value<std::string>(&identity)->default_value("client"), "Identity of self, server/client.")

		("tun", po::value<std::string>(&ifdev)->default_value(""), "Tun device.")

		("upstream", po::value<std::vector<std::string>>(&upstreams)->multitoken(), "Upstream servers.")

		("tcp", po::value<std::vector<std::string>>(&tcp_listens)->multitoken(), "For websocket tcp server listen.")
		("udp", po::value<std::vector<std::string>>(&udp_listens)->multitoken(), "For websocket udp server listen.")

		("data_shards,d", po::value<int>(&data_shards)->default_value(8), "Reedsolomon params of data shards.")
		("parity_shards,p", po::value<int>(&parity_shards)->default_value(4), "Reedsolomon params of parity shards.")

		("fec_delay", po::value<int>(&fec_delay)->default_value(20), "Delay(milliseconds) for fec.")

		("autofec", po::value<bool>(&auto_fec)->default_value(false), "Automatic parameterization for fec.")
		("mode", po::value<int>(&mode)->default_value(0), "Data send mode, 0: only udp, 1: tcp/udp mix, 2: only tcp.")
		("compress", po::value<bool>(&compress)->default_value(false), "Enable a compression algorithm.")

		("keepalive", po::value<int>(&keepalive)->default_value(10000), "Keep alive(milliseconds) for tcp and udp.")

		("pushroute", po::value<std::vector<std::string>>(&routes)->multitoken(), "Push routes to client.")
		("pushdns", po::value<std::string>(&pushdns)->default_value(""), "Push nameserver to client.")
		("passbyvpn", po::value<bool>(&passbyvpn)->default_value(false), "All IP network traffic originating on client machines to pass through the server.")
		("snat", po::value<bool>(&snat)->default_value(false), "Source network address translation.")

		("subnet", po::value<std::string>(&subnet)->default_value("10.0.0.1/16"), "VPN subnet.")
		("c2c", po::value<bool>(&c2c)->default_value(true), "Allow different clients to be able to see each other.")

		("controller", po::value<int>(&controller_port)->default_value(-1), "Controller, local controller server port.")

		("disable_logs", po::value<bool>(&disable_logs)->default_value(false), "Disable logs.")
	;

	try
	{
		// 解析命令行.
		po::variables_map vm;
		po::store(
			po::command_line_parser(argc, argv)
			.options(desc)
			.style(po::command_line_style::unix_style | po::command_line_style::allow_long_disguise)
			.run()
			, vm);
		po::notify(vm);

		if (disable_logs)
			util::toggle_write_logging(true);

		// 输出版本信息.
		LOG_FILE << version_info();

		// 帮助输出.
		if (vm.count("help") || argc == 1)
		{
			std::cout << desc;
			return EXIT_SUCCESS;
		}

		std::vector<std::string> print_args;
		print_args.assign(argv, argv + argc);
		LOG_DBG << "Run: " << boost::algorithm::join(print_args, " ");

		if (vm.count("config"))
		{
			if (!std::filesystem::exists(config))
			{
				LOG_ERR << "No such config file: " << config;
				return EXIT_FAILURE;
			}

			LOG_DBG << "Load config file: " << config;
			auto cfg = po::parse_config_file(config.c_str(), desc, false);
			po::store(cfg, vm);
			po::notify(vm);

			if (disable_logs)
				util::toggle_write_logging(true);
		}

		// test subnet address.
		{
			auto net = boost::asio::ip::make_network_v4(subnet);
			net.address().to_string();
		}
	}
	catch (const std::exception& e)
	{
		std::cerr << "exception: " << e.what() << std::endl;
		return EXIT_FAILURE;
	}

	auto concurrency = boost::thread::hardware_concurrency() + 2;
	avpn::io_context_pool ios{concurrency};

	boost::asio::signal_set terminator_signal(ios.get_io_context());
	terminator_signal.add(SIGINT);
	terminator_signal.add(SIGTERM);
#ifdef __linux__
	signal(SIGPIPE, SIG_IGN);
#endif
#if defined(SIGQUIT)
	terminator_signal.add(SIGQUIT);
#endif // defined(SIGQUIT)

	avpn::server_config cfg;

	cfg.upstreams_ = upstreams;

	cfg.tcp_listens_ = tcp_listens;
	cfg.udp_listens_ = udp_listens;

	cfg.ifdev_ = ifdev;
	cfg.snat_ = snat;
	cfg.controller_ = controller_port;

	auto& params = cfg.channel_params_;
	params.data_shards_ = data_shards;
	params.parity_shards_ = parity_shards;
	params.mode_ = mode;
	params.compress_ = compress;
	params.fec_delay_ = fec_delay;
	params.auto_fec_ = auto_fec;
	params.keepalive_ = keepalive;
	params.passbyvpn_ = passbyvpn;
	params.c2c_ = c2c;
	params.subnet_ = subnet;

	if (data_shards + parity_shards > 256)
	{
		LOG_ERR << "sum of data and parity shards cannot exceed 256";
		return EXIT_FAILURE;
	}
	if (identity == "server")
		cfg.identity_ = avpn::Identity::avpn_server;
	else if (identity == "client")
		cfg.identity_ = avpn::Identity::avpn_client;
	else
	{
		LOG_DBG << "identity not set, default is client.";
		cfg.identity_ = avpn::Identity::avpn_client;
	}

	params.routes_ = routes;
	params.pushdns_ = pushdns;
	params.passbyvpn_ = passbyvpn;

	if (cfg.identity_ == avpn::Identity::avpn_client && cfg.upstreams_.empty())
	{
		LOG_ERR << "Missing upstream...";
		return EXIT_FAILURE;
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
	create_pid(ifdev);

	if (controller_port == -1)
	{
		avpn::avpn_service srv{ ios, cfg };
		srv.start();

		// 处理中止信号.
		terminator_signal.async_wait(
			[&ios, &srv](const boost::system::error_code&, int)
			{
				LOG_DBG << "terminator is called!";
				srv.stop();
				ios.stop();
			});

		ios.run();
	}
	else
	{
		// 构造controller对象, 在内部发起对controller的连接.
		avpn::controller control{ ios, cfg };
		control.start();

		ios.run();
	}

	LOG_DBG << "avpn system exiting...";
	return EXIT_SUCCESS;
}

