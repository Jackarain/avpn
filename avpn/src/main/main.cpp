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

#include "utils/io_context_pool.hpp"
#include "utils/misc.hpp"
#include "socks/socks_server.hpp"
#include "socks/socks_client.hpp"

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

int main(int argc, char** argv)
{
	platform_init();

	std::vector<std::string> upstreams;
	std::vector<std::string> tcp_listens;
	std::vector<std::string> udp_listens;
	std::vector<std::string> socks_listens;
	std::string socks_interface;
	std::string socks_userid;
	std::string socks_passwd;
	std::string socks_next_proxy;
	bool socks_next_proxy_ssl = false;
	int data_shards;
	int parity_shards;
	int mtu_size;
	int mode;
	std::string compress;
	int keepalive;
	std::string subnet;
	std::string ifdev;
	std::string identity;
	std::string config;
	std::string controller;

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
		("help,h", "Help message.")
		("version", "Current version.")

		("config", po::value<std::string>(&config)->value_name("config.conf"), "Load config options from file.")

		("identity", po::value<std::string>(&identity)->default_value("client")->value_name("client/server"), "Identity of self, server/client.")

		("tun", po::value<std::string>(&ifdev)->default_value("")->value_name("tun"), "Tun device driver name, such as wintun/tun9/vtun, etc.")
		("mtu", po::value<int>(&mtu_size)->default_value(0)->value_name("mtu"), "Tun mtu size(default: 0).")

		("upstream", po::value<std::vector<std::string>>(&upstreams)->multitoken()->value_name("url [urls ...]"), "Upstream servers.")

		("privatekey", po::value<std::string>(&privatekey)->default_value("")->value_name("privatekey"), "Communication Security private key.")
		("publickey", po::value<std::string>(&publickey)->default_value("")->value_name("publickey"), "Communication Security public key.")

		("genkey", "Generates a new private key and writes it to stdout.")
		("pubkey", "Calculates a public key and prints it in base64 to standard output from a corresponding private key (generated with genkey) given in base64 on standard input.")

		("socks_server", po::value<std::vector<std::string>>(&socks_listens)->multitoken()->value_name("ip:port [ip:port ...]"), "For socks4/5 server listen.")

		("socks_interface", po::value<std::string>(&socks_interface)->default_value("")->value_name("ifname"), "Bind interface for socks4/5 connection.")
		("socks_userid", po::value<std::string>(&socks_userid)->default_value("adwin")->value_name("userid"), "Socks4/5 auth user id.")
		("socks_passwd", po::value<std::string>(&socks_passwd)->default_value("88w88")->value_name("passwd"), "Socks4/5 auth password.")
		("socks_next_proxy", po::value<std::string>(&socks_next_proxy)->default_value("")->value_name(""), "Next socks4/5 proxy. (e.g: socks5://user:passwd@ip:port)")
		("socks_next_proxy_ssl", po::value<bool>(&socks_next_proxy_ssl)->default_value(false, "false")->value_name(""), "Next socks4/5 proxy with ssl.")

		("ssl_certificate_dir", po::value<std::string>(&ssl_certificate_dir)->default_value("")->value_name("path"), "SSL certificate dir.")

		("tcp", po::value<std::vector<std::string>>(&tcp_listens)->multitoken()->value_name("ip:port [ip:port ...]"), "For websocket tcp server listen.")
		("udp", po::value<std::vector<std::string>>(&udp_listens)->multitoken()->value_name("ip:port [ip:port ...]"), "For websocket udp server listen.")

		("data_shards,d", po::value<int>(&data_shards)->default_value(8)->value_name("N"), "Reedsolomon params of data shards.")
		("parity_shards,p", po::value<int>(&parity_shards)->default_value(4)->value_name("N"), "Reedsolomon params of parity shards.")

		("mode", po::value<int>(&mode)->default_value(0)->value_name("mode"), "Data send mode, 0: only udp, 1: tcp/udp mix, 2: only tcp.")
		("compress", po::value<std::string>(&compress)->value_name("deflate/lz4/zstd"), "Enable a compression algorithm.")

		("keepalive", po::value<int>(&keepalive)->default_value(10000)->value_name("ms"), "Keep alive(milliseconds) for tcp and udp.")

		("noroute", po::value<bool>(&noroute)->value_name(""), "Ignore server pushed routes&dns")
		("pushroute", po::value<std::vector<std::string>>(&routes)->multitoken()->value_name("routes"), "Push routes to client.")
		("pushdns", po::value<std::string>(&pushdns)->value_name("ip"), "Push nameserver to client.")
		("passbyvpn", po::value<bool>(&passbyvpn)->value_name(""), "All IP network traffic originating on client machines to pass through the server.")

		("subnet", po::value<std::string>(&subnet)->default_value("10.0.0.1/16")->value_name("net/mask"), "VPN subnet.")
		("c2c", po::value<bool>(&c2c)->default_value(true, "true")->value_name("true/false"), "Allow different clients to be able to see each other.")

		("controller", po::value<std::string>(&controller)->default_value("")->value_name("ip:port"), "Controller, local controller server port.")

		("disable_logs", po::value<bool>(&disable_logs)->value_name(""), "Disable logs.")
		("writepid", po::value<std::string>(&writepid_file)->value_name("pidfile"), "Write pit to file")
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
			util::toggle_logging();
			util::toggle_write_logging(true);
		}

		// 生成私钥.
		if (vm.count("genkey"))
		{
			std::cout << base64_encode(crypto_util::ecdh_keygen()) << "\n";
			return EXIT_SUCCESS;
		}

		if (vm.count("pubkey"))
		{
			std::string pkey;

			for (std::string line; std::getline(std::cin, line);)
				pkey += line;

			auto priv_key = base64_decode(pkey);
			if (priv_key.size() != 32)
			{
				std::cerr << "Key is not the correct length or format";
				return EXIT_FAILURE;
			}

			std::cout << base64_encode(crypto_util::ecdh_public(pkey)) << "\n";

			return EXIT_SUCCESS;
		}

		// 输出版本信息.
		LOG_FILE << version_info();

		// 帮助输出.
		if (vm.count("help") || argc == 1)
		{
			std::cout << desc
				<< "\nWritten by jackarain"
				<< "\nReport bugs to: jack.wgm@gmail.com"
				<< "\n";
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

	size_t concurrency = 1; // std::thread::hardware_concurrency() + 2;
	util::io_context_pool ios{concurrency};

	net::signal_set terminator_signal(ios.get_io_context());
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

	cfg.ifdev_ = ifdev;
	cfg.controller_ = controller;
	cfg.private_key_ = privatekey;
	cfg.public_key_ = publickey;
	cfg.ssl_certificate_dir_ = ssl_certificate_dir;

	cfg.mtu_size_ = mtu_size;
	cfg.using_ipv6_ = ipv6;

	auto& socks_opt = cfg.socks_opt_;
	socks_opt.usrdid_ = socks_userid;
	socks_opt.passwd_ = socks_passwd;
	socks_opt.bind_addr_ = socks_interface;

	auto& params = cfg.tunnel_params_;
	params.data_shards_ = data_shards;
	params.parity_shards_ = parity_shards;
	params.mode_ = static_cast<avpn::Proto>(mode);
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
		LOG_ERR << "Sum of data and parity shards cannot exceed 256";
		return EXIT_FAILURE;
	}
	if (identity == "server")
		cfg.identity_ = avpn::Identity::avpn_server;
	else if (identity == "client")
		cfg.identity_ = avpn::Identity::avpn_client;
	else
	{
		LOG_DBG << "Identity not set, default is client.";
		cfg.identity_ = avpn::Identity::avpn_client;
	}

	if (cfg.identity_ == avpn::Identity::avpn_client)
	{
		if (cfg.upstreams_.empty())
		{
			LOG_ERR << "Missing upstream...";
			return EXIT_FAILURE;
		}

		// 检查upstream是否有ipv6, 如果有v6地址, mtu则需要减少20
		// 这样避免在udp中发送ip包时, 超过物理mtu大小则拆包.
		for (auto& stream : cfg.upstreams_)
		{
			auto url = urls::url_view(stream);
			udp::resolver resolver{ ios.main_io_context() };
			boost::system::error_code ec;
			auto results = resolver.resolve(url.host(), url.port(), ec);
			for (auto endp : results)
			{
				if (endp.endpoint().address().is_v6())
				{
					cfg.using_ipv6_ = ipv6 = true;
					break;
				}
			}

			if (ipv6)
				break;
		}

		// 重新计算packet及mtu等大小.
		if (!avpn::recompute_mtu(mtu_size, ipv6))
		{
			LOG_ERR << "Mtu set incorrect!!!";
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

	// 如果开启了socks服务, 则listen一个socks服务.
	// 这个socks server 则将在client模式下, 通过server代理出去.
	// 在 server 模式下, 则将是一个单纯的socks server.
	std::vector<std::shared_ptr<socks::socks_server>> socks_servers;
	for (auto& socks : socks_listens)
	{
		boost::system::error_code ec;
		net::ip::tcp::endpoint endp;
		make_listen_endpoint(socks, endp, ec);
		if (ec)
		{
			LOG_WARN << "Socks server param: "
				<< socks << " listen: " << ec.message();
			continue;
		}

		socks::socks_server_option opt;
		opt.usrdid_ = socks_userid;
		opt.passwd_ = socks_passwd;
		opt.bind_addr_ = socks_interface;

		if (cfg.identity_ == avpn::Identity::avpn_client &&
			!socks_next_proxy.empty())
		{
			opt.next_proxy_ = socks_next_proxy;
			opt.next_proxy_use_ssl_ = socks_next_proxy_ssl;

			// 检查 next socks proxy地址格式是否正确.
			// 如果是无效的地址则忽略.
			if (!urls::url_view().parse(socks_next_proxy))
			{
				LOG_WARN << "Next socks server: "
					<< socks_next_proxy << " invalid";
				opt.next_proxy_.clear();
			}
		}

		net::any_io_executor executor =
			ios.get_io_context().get_executor();

		auto server = std::make_shared<socks::socks_server>(
			executor, endp, opt);
		server->start();

		socks_servers.emplace_back(std::move(server));
	}

	if (controller.empty())
	{
		using  avpn::avpn_service;
		auto avpn_srv = avpn_service::make_avpn_service(ios, cfg);
		auto& srv = *avpn_srv;

		srv.start();

		// 处理中止信号.
		terminator_signal.async_wait(
			[&ios, &srv, &socks_servers](const boost::system::error_code&, int)
			{
				LOG_DBG << "terminator is called!";

				for (auto& s : socks_servers)
				{
					if (!s)
						continue;
					s->close();
				}

				srv.stop();
				ios.stop();
			});

		ios.run();
	}
	else
	{
		// 构造vpn_controller对象, 在内部发起对controller的连接.
		avpn::vpn_controller control{ ios, cfg };
		control.start();

		ios.run();
	}

	LOG_DBG << "avpn system exiting...";
	return EXIT_SUCCESS;
}

