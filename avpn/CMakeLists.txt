
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/include/avpn/version.hpp.in
		${CMAKE_CURRENT_SOURCE_DIR}/include/avpn/version.hpp @ONLY NEWLINE_STYLE LF)

#set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DDEBUG")
add_definitions(-DLOGGING_COMPRESS_LOGS)

file(GLOB avpn_WINDOWS_SRCS
	include/vpncore/tuntap_windows_service.hpp
)
file(GLOB avpn_APPLE_SRCS
	include/vpncore/tuntap_macos_service.hpp
)
file(GLOB avpn_LINUX_SRCS
	include/vpncore/tuntap_linux_service.hpp
)

file(GLOB avpn_SRCS
	include/avpn/version.hpp
	include/avpn/internal.hpp
	include/avpn/io_context_pool.hpp
	include/avpn/logging.hpp
	include/avpn/avpn.hpp
	include/avpn/reedsolomon.hpp

	include/vpncore/basic_tuntap.hpp
	include/vpncore/channel.hpp
	include/vpncore/endpoint_pair.hpp
	include/vpncore/tuntap.hpp
	include/vpncore/tuntap_config.hpp

	include/utils/*.hpp
	src/utils/*.cpp

	src/main/main.cpp
	src/main/avpn.cpp
	src/main/io_context_pool.cpp
	src/main/reedsolomon.cpp
)

if (WIN32)
	list (APPEND avpn_SRCS ${avpn_WINDOWS_SRCS})
elseif (UNIX AND NOT APPLE)
	list (APPEND avpn_SRCS ${avpn_LINUX_SRCS})
elseif (APPLE)
	list (APPEND avpn_SRCS ${avpn_APPLE_SRCS})
endif()

add_executable(avpn ${avpn_SRCS})

target_include_directories(avpn PUBLIC
	${CMAKE_BINARY_DIR}
	${CMAKE_CURRENT_SOURCE_DIR}
	${CMAKE_CURRENT_SOURCE_DIR}/include
)

if(ENABLE_BUILD_WERROR)
	if(MSVC)
		target_compile_options(avpn PRIVATE /W4 /WX)
	elseif(NOT APPLE AND NOT MINGW)
		if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9.1)
			target_compile_options(avpn PRIVATE -Werror -Wall -Wextra -Wno-unknown-pragmas -Wno-deprecated)
		else()
			target_compile_options(avpn PRIVATE -Werror -Wall -Wextra -Wno-unknown-pragmas -Wno-deprecated -Wno-deprecated-copy -Wno-error=deprecated-copy -Wno-pessimizing-move)
		endif()
	endif()
endif()

#if(WIN32)
#	SET_TARGET_PROPERTIES(avpn PROPERTIES LINK_FLAGS " /MANIFESTUAC:\"level='requireAdministrator'\" /level='requireAdministrator'")
#endif()

install(TARGETS avpn DESTINATION bin)
