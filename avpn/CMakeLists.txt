
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/include/avpn/version.hpp.in
		${CMAKE_CURRENT_SOURCE_DIR}/include/avpn/version.hpp @ONLY NEWLINE_STYLE LF)

#set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DDEBUG")
add_definitions(-DLOGGING_COMPRESS_LOGS)

file(GLOB avpn_SRCS
	include/avpn/scoped_exit.hpp
	include/avpn/time_clock.hpp
	include/avpn/url_parser.hpp
	include/avpn/version.hpp
	include/avpn/internal.hpp
	include/avpn/io_context_pool.hpp
	include/avpn/logging.hpp
	include/avpn/misc.hpp
	include/avpn/avpn.hpp
	include/avpn/async_connect.hpp
	include/avpn/simple_http.hpp
	include/avpn/socks_proxy.hpp
	include/avpn/url_parser.hpp
	include/avpn/http_last_modified.hpp
	include/avpn/default_cert.hpp
	include/avpn/io.hpp
	include/avpn/handler_type_check.hpp
	include/avpn/multipart.hpp
	include/avpn/fileop.hpp
	include/avpn/reedsolomon.hpp
	include/avpn/bitfield.hpp

	include/vpncore/*.hpp
	include/utils/*.hpp

	src/main.cpp
	src/avpn.cpp
	src/io_context_pool.cpp
	src/internal.cpp
	src/default_cert.cpp
	src/reedsolomon.cpp
	src/http_last_modified.cpp
)

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

if(WIN32)
	SET_TARGET_PROPERTIES(avpn PROPERTIES LINK_FLAGS " /MANIFESTUAC:\"level='requireAdministrator'\" /level='requireAdministrator'")
endif()

install(TARGETS avpn DESTINATION bin)
