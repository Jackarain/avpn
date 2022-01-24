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
#endif

#ifdef HAVE_UNAME
#  include <sys/utsname.h>
#endif

#include <gsl/span>

#include <boost/nowide/args.hpp>
#include <boost/algorithm/string/join.hpp>
#include <boost/program_options.hpp>
namespace po = boost::program_options;

#include <boost/multiprecision/cpp_dec_float.hpp>

#include "avpn/version.hpp"
#include "avpn/internal.hpp"
#include "avpn/avpn.hpp"
#include "avpn/simple_http.hpp"

#include "avpn/fileop.hpp"

#include "avpn/reedsolomon.hpp"


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

	return oss.str();
}

int main(int argc, char** argv)
{
	std::vector<std::string> upstreams;
	std::vector<std::string> tcp_listens;
	std::vector<std::string> udp_listens;
	int data_shards;
	int parity_shards;
	int direct_tcp;
	int fec_timeout;
	bool auto_fec;
	std::string ifdev;
	std::string identity;

	boost::nowide::args a(argc, argv);
	boost::ignore_unused(a);

	po::options_description desc("Options");
	desc.add_options()
		("help,h", "Help message.")
		("version", "Current version.")

		("upstream", po::value<std::vector<std::string>>(&upstreams)->multitoken(), "Upstream servers.")
		("tun", po::value<std::string>(&ifdev)->default_value(""), "Tun device.")

		("tcp", po::value<std::vector<std::string>>(&tcp_listens)->multitoken(), "For websocket tcp server listen.")
		("udp", po::value<std::vector<std::string>>(&udp_listens)->multitoken(), "For websocket udp server listen.")

		("data_shards", po::value<int>(&data_shards)->default_value(3), "Reedsolomon params of data shards.")
		("parity_shards", po::value<int>(&parity_shards)->default_value(1), "Reedsolomon params of parity shards.")

		("identity", po::value<std::string>(&identity)->default_value("client"), "Identity of self, server/client.")

		("fec_timeout", po::value<int>(&fec_timeout)->default_value(50), "Timeout(milliseconds) for fec.")
		("fec_delay", po::value<int>(&fec_timeout)->default_value(50), "Timeout(milliseconds) for fec.")

		("autofec", po::value<bool>(&auto_fec)->default_value(false), "Automatic parameterization for fec.")
		("direct_tcp", po::value<int>(&direct_tcp)->default_value(0), "Direct tcp, disable use udp.")
	;

	try
	{
		// 解析命令行.
		po::variables_map vm;
		po::store(po::parse_command_line(argc, argv, desc), vm);
		po::notify(vm);

		// 输出版本信息.
		LOG_INFO << version_info();

		// 帮助输出.
		if (vm.count("help") || argc == 1)
		{
			std::cout << desc;
			return EXIT_SUCCESS;
		}
	}
	catch (const std::exception& e)
	{
		std::cerr << "exception: " << e.what() << std::endl;
		return EXIT_FAILURE;
	}

	auto concurrency = boost::thread::hardware_concurrency() + 2;
	io_context_pool ios{concurrency};

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

	auto& params = cfg.channel_params_;
	params.data_shards_ = data_shards;
	params.parity_shards_ = parity_shards;
	params.direct_tcp_ = direct_tcp;
	params.fec_timeout_ = fec_timeout;
	params.auto_fec_ = auto_fec;
	if (data_shards + parity_shards > 256)
	{
		LOG_ERR << "sum of data and parity shards cannot exceed 256";
		return EXIT_FAILURE;
	}
	if (identity == "server")
		cfg.identity_ = avpn::avpn_server;
	else if (identity == "client")
		cfg.identity_ = avpn::avpn_client;
	else
	{
		LOG_DBG << "identity not set, default is client.";
		cfg.identity_ = avpn::avpn_client;
	}

	avpn::avpn_service dsrv{ios, cfg};

	dsrv.start();

	// 处理中止信号.
	terminator_signal.async_wait([&ios, &dsrv](const boost::system::error_code&, int)
	{
		LOG_DBG << "terminator is called!";
		dsrv.stop();
		ios.stop();
	});

	ios.run(5);

	LOG_DBG << "avpn system exiting...";
	return EXIT_SUCCESS;
}

