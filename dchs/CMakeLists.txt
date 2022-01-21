
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/include/dchs/version.hpp.in
		${CMAKE_CURRENT_SOURCE_DIR}/include/dchs/version.hpp @ONLY NEWLINE_STYLE LF)

#set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DDEBUG")
add_definitions(-DLOGGING_COMPRESS_LOGS)

file(GLOB dchs_SRCS
	include/dchs/scoped_exit.hpp
	include/dchs/time_clock.hpp
	include/dchs/url_parser.hpp
	include/dchs/version.hpp
	include/dchs/internal.hpp
	include/dchs/io_context_pool.hpp
	include/dchs/logging.hpp
	include/dchs/misc.hpp
	include/dchs/avpn.hpp
	include/dchs/async_connect.hpp
	include/dchs/simple_http.hpp
	include/dchs/socks_proxy.hpp
	include/dchs/url_parser.hpp
	include/dchs/http_last_modified.hpp
	include/dchs/default_cert.hpp
	include/dchs/io.hpp
	include/dchs/handler_type_check.hpp
	include/dchs/multipart.hpp
	include/dchs/fileop.hpp
	include/dchs/reedsolomon.hpp
	include/dchs/bitfield.hpp

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

add_executable(dchs ${dchs_SRCS})

target_include_directories(dchs PUBLIC
	${CMAKE_BINARY_DIR}
	${CMAKE_CURRENT_SOURCE_DIR}
	${CMAKE_CURRENT_SOURCE_DIR}/include
)

if(ENABLE_BUILD_WERROR)
	if(MSVC)
		target_compile_options(dchs PRIVATE /W4 /WX)
	elseif(NOT APPLE AND NOT MINGW)
		if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9.1)
			target_compile_options(dchs PRIVATE -Werror -Wall -Wextra -Wno-unknown-pragmas -Wno-deprecated)
		else()
			target_compile_options(dchs PRIVATE -Werror -Wall -Wextra -Wno-unknown-pragmas -Wno-deprecated -Wno-deprecated-copy -Wno-error=deprecated-copy -Wno-pessimizing-move)
		endif()
	endif()
endif()

if(WIN32)
	SET_TARGET_PROPERTIES(dchs PROPERTIES LINK_FLAGS " /MANIFESTUAC:\"level='requireAdministrator'\" /level='requireAdministrator'")
endif()

install(TARGETS dchs DESTINATION bin)
