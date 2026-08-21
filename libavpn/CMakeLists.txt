cmake_minimum_required(VERSION 3.16)
project(libavpn)

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -DLOGGER_DBG_VIEW")
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO} -DLOGGER_DBG_VIEW")
set(CMAKE_CXX_FLAGS_MINSIZEREL "${CMAKE_CXX_FLAGS_MINSIZEREL} -DLOGGER_DBG_VIEW")

add_library(libavpn STATIC)

target_sources(libavpn
	PRIVATE
	${CMAKE_CURRENT_SOURCE_DIR}/include/libavpn/async_connect.hpp
	${CMAKE_CURRENT_SOURCE_DIR}/include/libavpn/default_cert.hpp
	${CMAKE_CURRENT_SOURCE_DIR}/include/libavpn/fileop.hpp
	${CMAKE_CURRENT_SOURCE_DIR}/include/libavpn/ipip.hpp
	${CMAKE_CURRENT_SOURCE_DIR}/include/libavpn/logging.hpp
	${CMAKE_CURRENT_SOURCE_DIR}/include/libavpn/socks_io.hpp
	${CMAKE_CURRENT_SOURCE_DIR}/include/libavpn/strutil.hpp
	${CMAKE_CURRENT_SOURCE_DIR}/include/httpc/httpc.hpp
	${CMAKE_CURRENT_SOURCE_DIR}/include/libavpn/use_awaitable.hpp
	${CMAKE_CURRENT_SOURCE_DIR}/include/libavpn/xxhash.hpp
	${CMAKE_CURRENT_SOURCE_DIR}/include/libavpn/avpn.hpp
	${CMAKE_CURRENT_SOURCE_DIR}/include/libavpn/dns_proxy.hpp
	${CMAKE_CURRENT_SOURCE_DIR}/include/libavpn/io_context_pool.hpp
	${CMAKE_CURRENT_SOURCE_DIR}/include/libavpn/launcher_log.hpp
	${CMAKE_CURRENT_SOURCE_DIR}/include/libavpn/vpn_controller.hpp
	${CMAKE_CURRENT_SOURCE_DIR}/include/libavpn/jsonrpc.hpp
	${CMAKE_CURRENT_SOURCE_DIR}/include/libavpn/asio_util.hpp
	${CMAKE_CURRENT_SOURCE_DIR}/include/libavpn/avpn_crypto.hpp
	${CMAKE_CURRENT_SOURCE_DIR}/include/libavpn/avpn_protocol.hpp
	${CMAKE_CURRENT_SOURCE_DIR}/include/libavpn/avpn_compress.hpp
	${CMAKE_CURRENT_SOURCE_DIR}/include/libavpn/avpn_fec.hpp
	${CMAKE_CURRENT_SOURCE_DIR}/include/libavpn/avpn_obfuscate.hpp
	${CMAKE_CURRENT_SOURCE_DIR}/include/libavpn/avpn_session.hpp
	${CMAKE_CURRENT_SOURCE_DIR}/include/libavpn/avpn_tun.hpp
	${CMAKE_CURRENT_SOURCE_DIR}/include/libavpn/avpn_wintun.hpp
	${CMAKE_CURRENT_SOURCE_DIR}/include/libavpn/netlink_route.hpp
	${CMAKE_CURRENT_SOURCE_DIR}/include/libavpn/nat_rule.hpp

	${CMAKE_CURRENT_SOURCE_DIR}/src/httpc.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/src/lib_asio_beast.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/src/logging.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/src/launcher_log.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/src/ipip.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/src/avpn.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/src/dns_proxy.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/src/io_context_pool.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/src/vpn_controller.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/src/avpn_crypto.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/src/avpn_protocol.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/src/avpn_compress.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/src/avpn_fec.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/src/avpn_obfuscate.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/src/avpn_session.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/src/avpn_tun.cpp
	$<$<PLATFORM_ID:Windows>:${CMAKE_CURRENT_SOURCE_DIR}/src/avpn_wintun.cpp>
	${CMAKE_CURRENT_SOURCE_DIR}/src/netlink_route.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/src/nat_rule.cpp
)

target_include_directories(libavpn
	PUBLIC
	${CMAKE_CURRENT_SOURCE_DIR}/include/
	${ZLIB_INCLUDE_DIRS}
	${WINTUN_INCLUDE_DIRS}
)

# Windows 下 wintun 为唯一 tun 后端, 无条件加入头文件路径.
if (WIN32)
	target_include_directories(libavpn PUBLIC
		${CMAKE_SOURCE_DIR}/third_party/wintun/include)
endif()

target_compile_definitions(libavpn
	PUBLIC
	-DXXH_INLINE_ALL
	-DFORCE_USE_FMT_FORMAT
)

# MSVC x64: avpn_fec.cpp 中的 AVX2 intrinsics 需要 /arch:AVX2 编译.
if (MSVC)
	target_compile_options(libavpn PRIVATE /arch:AVX2)
endif()

target_link_libraries(libavpn
	Boost::thread
	Boost::date_time
	Boost::program_options
	Boost::filesystem
	Boost::signals2
	Boost::nowide
	Boost::url
	Boost::json
	Boost::uuid
	Boost::asio
	Boost::beast
	Boost::scope
	Boost::system

	fmt
	${ZLIB_LIBRARIES}
	${OPENSSL_LIBRARIES}
)

#source_group("Header Files\\libvpn" FILES ${libavpn_HEADERS})
#source_group("Source Files" FILES ${libavpn_SRCS})

target_compile_definitions(libavpn PUBLIC -DVERSION_GIT=\"${PVERSION}\")

set_target_properties(libavpn PROPERTIES OUTPUT_NAME avpn PREFIX "lib" CLEAN_DIRECT_OUTPUT 1)

if (MSVC AND CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 19.29.30129 AND CMAKE_VERSION VERSION_GREATER 3.20.3)
	set_property(TARGET libavpn PROPERTY CXX_STANDARD 23)
	message(STATUS "libavpn set cxx standard: C++23")
else()
	set_property(TARGET libavpn PROPERTY CXX_STANDARD 20)
	message(STATUS "libavpn set cxx standard: C++20")
endif()

set(AVPN_INCLUDE_DIRS
	${CMAKE_CURRENT_SOURCE_DIR}/include
	PARENT_SCOPE
)

set(AVPN_LIBRARIES
	libavpn
	PARENT_SCOPE
)
