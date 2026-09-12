//
// main.hpp
// ~~~~~~~~
//
// Copyright (c) 2023 Jack (jack dot wgm at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef INCLUDE__2023_10_18__MAIN_HPP
#define INCLUDE__2023_10_18__MAIN_HPP


#ifdef __linux__
#  include <sys/resource.h>

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

#endif // _WIN32

#ifdef HAVE_UNAME
#  include <sys/utsname.h>
#endif

#if __has_include("openssl/opensslv.h")
#  include "openssl/opensslv.h"
#else
#  ifndef OPENSSL_VERSION_TEXT
#    define OPENSSL_VERSION_TEXT "NONE"
#  endif
#endif

#include <boost/version.hpp>
#include <boost/config.hpp>

#include <string>
#include <iostream>
#include <sstream>
#include <ios>

//////////////////////////////////////////////////////////////////////////

inline int platform_init()
{
#if defined(WIN32) || defined(_WIN32)
	/* Disable the "application crashed" popup. */
	SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX |
		SEM_NOOPENFILEERRORBOX);

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

	std::ios_base::sync_with_stdio(false);

	return 0;
}


//////////////////////////////////////////////////////////////////////////

inline std::string version_info()
{
	std::ostringstream oss;
	std::string os_name;

#ifdef _WIN32
# ifdef _WIN64
	os_name = "Windows (64bit)";
# else
	os_name = "Windows (32bit)";
# endif
#elif defined(HAVE_UNAME)
	struct utsname un;
	uname(&un);
	os_name = std::string(un.sysname) + " " + un.release;

	int ma_ver, mi_ver, patch_ver;
	sscanf(un.release, "%d.%d.%d", &ma_ver, &mi_ver, &patch_ver);

	if (os_name.find("Linux") != std::string::npos && ma_ver < 4)
		std::cerr << "WARNING: kernel too old, please upgrade your system!" << std::endl;
#else
	os_name = BOOST_PLATFORM;
#endif

	std::string git_version;

#ifdef VERSION_GIT
	git_version = VERSION_GIT;
#else
	git_version = __DATE__ + std::string(" ") + __TIME__;
#endif

	oss << "Built: " << git_version
		<< ", " << os_name
		<< ", " << BOOST_COMPILER
		<< ", Boost " << BOOST_LIB_VERSION
		<< ", SSL: " << OPENSSL_VERSION_TEXT
		;

	std::cerr << oss.str() << "\n";
	return oss.str();
}



#endif // INCLUDE__2023_10_18__MAIN_HPP
