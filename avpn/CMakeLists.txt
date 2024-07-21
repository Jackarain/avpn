cmake_minimum_required(VERSION 3.16)
if (WIN32)
	configure_file(${CMAKE_CURRENT_SOURCE_DIR}/src/resource/avpn.rc.in
			${CMAKE_CURRENT_SOURCE_DIR}/src/resource/avpn.rc @ONLY NEWLINE_STYLE LF)
endif()

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/include/avpn/version.hpp.in
		${CMAKE_CURRENT_SOURCE_DIR}/include/avpn/version.hpp @ONLY NEWLINE_STYLE LF)

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DENABLE_LOGGER")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -DENABLE_LOGGER -DDISABLE_LOGGER_TO_CONSOLE -DLOGGER_DBG_VIEW")
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO} -DENABLE_LOGGER -DDISABLE_LOGGER_TO_CONSOLE -DLOGGER_DBG_VIEW")
set(CMAKE_CXX_FLAGS_MINSIZEREL "${CMAKE_CXX_FLAGS_MINSIZEREL} -DENABLE_LOGGER -DDISABLE_LOGGER_TO_CONSOLE -DLOGGER_DBG_VIEW")

file(GLOB avpn_WINTUN_SRCS
	include/avpn/wintun_windows_service.hpp
)
file(GLOB avpn_WINDOWS_SRCS
	include/avpn/tuntap_windows_service.hpp
)
file(GLOB avpn_APPLE_SRCS
	include/avpn/tundev_macos_service.hpp
)
file(GLOB avpn_ANDROID_SRCS
	include/avpn/tundev_android_service.hpp
)
file(GLOB avpn_LINUX_SRCS
	include/avpn/tundev_linux_service.hpp
)
file(GLOB avpn_IPC_SRCS
	include/avpn/tundev_ipc_service.hpp
)

file(GLOB avpn_SRCS
	include/avpn/version.hpp
	include/avpn/logging.hpp
	include/avpn/avpn.hpp
	include/avpn/vpn_tunnel.hpp
	include/avpn/reedsolomon.hpp
	include/avpn/vpn_controller.hpp

	include/avpn/basic_tuntap.hpp
	include/avpn/endpoint_pair.hpp
	include/avpn/tundev.hpp
	include/avpn/tun_device.hpp
	include/avpn/tundev_config.hpp
	include/avpn/tundev_common.hpp
	include/avpn/fec_cache.hpp
	include/avpn/protocol.hpp
	include/avpn/vpn_client_table.hpp
	include/avpn/vpn_packet.hpp
	include/avpn/vpn_conntrack.hpp
	include/avpn/vpn_tcp_stream.hpp
	include/avpn/chksum.hpp

	src/lib_asio_beast.cpp

	src/main/avpn.cpp
	src/main/vpn_tunnel.cpp
	src/main/reedsolomon.cpp
	src/main/vpn_controller.cpp
	src/main/fec_cache.cpp
	src/main/protocol.cpp
	src/main/vpn_client_table.cpp
	src/main/vpn_packet.cpp
	src/main/vpn_conntrack.cpp
	src/main/vpn_tcp_stream.cpp
	src/main/tundev_common.cpp
)

if (WIN32)
	if (ENABLE_USE_WINTUN)
		list (APPEND avpn_WINDOWS_SRCS ${avpn_WINTUN_SRCS})
	endif()
	list (APPEND avpn_SRCS ${avpn_WINDOWS_SRCS})
#elseif (UNIX AND NOT APPLE)
	list (APPEND avpn_SRCS ${avpn_LINUX_SRCS})
#elseif (AVPN_ANDROID)
	list (APPEND avpn_SRCS ${avpn_ANDROID_SRCS})
#elseif (APPLE)
	list (APPEND avpn_SRCS ${avpn_APPLE_SRCS})
	if (true)
		list (APPEND avpn_SRCS ${avpn_IPC_SRCS})
	endif()
endif()

add_library(libavpn ${avpn_SRCS})

file(GLOB rc_SRCS)
if (WIN32 AND ENABLE_USE_WINTUN)
	list (APPEND rc_SRCS src/resource/avpn.rc)
endif()

add_executable(avpn
	src/main/main.cpp

	${rc_SRCS}
)

# 其实 target_precompile_headers(avpn PUBLIC stdafx.hpp) 就可以了
# 但是 在 msvc 上不知为何会导致同时产生 C 和 C++ 两个预编译头
# 所以强行用 COMPILE_LANGUAGE:CXX 设定只有 C++
# 这样 msvc 上就只有一个预编译头了.
target_precompile_headers(avpn PRIVATE
  "$<$<COMPILE_LANGUAGE:CXX>:${CMAKE_CURRENT_SOURCE_DIR}/include/stdafx.hpp>"
)
target_precompile_headers(libavpn PRIVATE
  "$<$<COMPILE_LANGUAGE:CXX>:${CMAKE_CURRENT_SOURCE_DIR}/include/stdafx.hpp>"
)

if (ENABLE_MIMALLOC_STATIC)
	target_link_libraries(avpn mimalloc-static)
endif()

if (ENABLE_INTEGRATE_SOCKS_SERVER)
	target_compile_definitions(avpn PUBLIC -DINTEGRATE_SOCKS_SERVER)
	target_compile_definitions(libavpn PUBLIC -DINTEGRATE_SOCKS_SERVER)
endif()

target_link_libraries(avpn
	libavpn
)

if (MINGW)
	target_compile_options(avpn PUBLIC "-O2")
	target_compile_options(avpn PUBLIC "-Wa,-mbig-obj")
	target_compile_options(libavpn PUBLIC "-O2")
	target_compile_options(libavpn PUBLIC "-Wa,-mbig-obj")
endif()

set_target_properties(libavpn PROPERTIES OUTPUT_NAME avpn PREFIX "lib" CLEAN_DIRECT_OUTPUT 1)

set_property(TARGET avpn libavpn PROPERTY CXX_STANDARD 20)
message(STATUS "Avpn set cxx standard: C++20")

set(BASE_SOURCE_DIR
	${CMAKE_BINARY_DIR}
	${CMAKE_CURRENT_SOURCE_DIR}
	${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_include_directories(avpn PUBLIC ${BASE_SOURCE_DIR})
target_include_directories(libavpn PUBLIC ${BASE_SOURCE_DIR})

if (ENABLE_BUILD_WERROR)
	if (MSVC)
		target_compile_options(avpn PRIVATE /W4 /WX)
		target_compile_options(libavpn PRIVATE /W4 /WX)
	elseif (UNIX AND NOT APPLE)
		if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9.1)
			target_compile_options(avpn PRIVATE -Werror -Wall -Wextra -Wno-unknown-pragmas -Wno-deprecated)
			target_compile_options(libavpn PRIVATE -Werror -Wall -Wextra -Wno-unknown-pragmas -Wno-deprecated)
		else()
			target_compile_options(avpn PRIVATE -Werror -Wall -Wextra -Wno-unknown-pragmas -Wno-deprecated -Wno-deprecated-copy -Wno-error=deprecated-copy -Wno-pessimizing-move)
			target_compile_options(libavpn PRIVATE -Werror -Wall -Wextra -Wno-unknown-pragmas -Wno-deprecated -Wno-deprecated-copy -Wno-error=deprecated-copy -Wno-pessimizing-move)
		endif()
	endif()
endif()

if (WIN32 AND NOT MINGW)
	if (REQUIRE_ADMINISTRATOR)
		SET_TARGET_PROPERTIES(avpn PROPERTIES LINK_FLAGS " /MANIFESTUAC:\"level='requireAdministrator'\" /level='requireAdministrator'")
	endif()
endif()

install(TARGETS avpn DESTINATION bin)
install(TARGETS libavpn DESTINATION bin)
