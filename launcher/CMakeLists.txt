# launcher
#
# avpn launcher:
# WebUI 实例管理器
# （REST API + WebSocket JSON-RPC 控制通道 + instances.json 持久化）。
# JSON-RPC 基于 libavpn 的 jsonrpc.hpp（与 launcher 控制通道协议一致）。
#
# 并发模型：C++20/23 协程（boost.asio co_spawn/awaitable）。
# 整个服务运行在单个 io_context 的小线程池上，无每连接线程、无 poll。
# WebUI 静态资源在构建期内嵌进可执行文件（webui_embedded.cpp 由
# embed_webui.cmake 生成），运行时直接从内存提供。

# 平台相关的子进程管理实现（创建/采集输出/终止）。
if (WIN32)
	set(LAUNCHER_PROC_SRC proc_windows.cpp)
else()
	set(LAUNCHER_PROC_SRC proc_unix.cpp)
endif()

# 构建期内嵌 WebUI：生成 webui_embedded.cpp（静态资源直接编入可执行文件）。
# CONFIGURE_DEPENDS 使更新 webui 文件后 CMake 自动重新收集列表并重新配置。
set(WEBUI_EMBEDDED_CPP ${CMAKE_CURRENT_BINARY_DIR}/webui_embedded.cpp)
file(GLOB_RECURSE WEBUI_FILES CONFIGURE_DEPENDS RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}/webui
	${CMAKE_CURRENT_SOURCE_DIR}/webui/*)
set(WEBUI_FILE_DEPS)
foreach (f ${WEBUI_FILES})
	list(APPEND WEBUI_FILE_DEPS ${CMAKE_CURRENT_SOURCE_DIR}/webui/${f})
endforeach()
add_custom_command(
	OUTPUT ${WEBUI_EMBEDDED_CPP}
	COMMAND ${CMAKE_COMMAND}
		-DINPUT_DIR=${CMAKE_CURRENT_SOURCE_DIR}/webui
		-DOUTPUT_CPP=${WEBUI_EMBEDDED_CPP}
		-P ${CMAKE_CURRENT_SOURCE_DIR}/embed_webui.cmake
	DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/embed_webui.cmake ${WEBUI_FILE_DEPS}
	COMMENT "Embedding launcher webui assets"
	VERBATIM
)

add_executable(launcher
	main.cpp
	options.cpp
	${LAUNCHER_PROC_SRC}
	manager.cpp
	http_server.cpp
	version.cpp
	webui_embedded.hpp
	${WEBUI_EMBEDDED_CPP}
)

target_link_libraries(launcher
	${OPENSSL_LIBRARIES}
	${AVPN_LIBRARIES}
	${ZLIB_LIBRARIES}
	Boost::program_options
)

# 启用 io_uring 时链接 liburing（与 avpn 一致），
# 否则 asio 的 io_uring_service 会产生未定义符号链接错误。
if (TARGET IOUring::IOUring)
	target_link_libraries(launcher IOUring::IOUring)
endif()

target_include_directories(launcher
	PRIVATE
	${PROJECT_SOURCE_DIR}/libavpn/include
	${CMAKE_CURRENT_SOURCE_DIR}
)

set_property(SOURCE version.cpp PROPERTY COMPILE_DEFINITIONS "VERSION_GIT=\"${PVERSION}\"")
set_property(TARGET launcher PROPERTY FOLDER "launcher")

if (MSVC AND CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 19.29.30129 AND CMAKE_VERSION VERSION_GREATER 3.20.3)
	set_property(TARGET launcher PROPERTY CXX_STANDARD 23)
	message(STATUS "launcher set cxx standard: C++23")
else()
	set_property(TARGET launcher PROPERTY CXX_STANDARD 20)
	message(STATUS "launcher set cxx standard: C++20")
endif()
set_property(TARGET launcher PROPERTY CXX_STANDARD_REQUIRED ON)
set_property(TARGET launcher PROPERTY CXX_EXTENSIONS OFF)

if(ENABLE_BUILD_WERROR)
	if(MSVC)
		target_compile_options(launcher PRIVATE /W4 /WX)
	elseif(UNIX AND NOT APPLE)
		if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9.1)
			target_compile_options(launcher PRIVATE -Werror -Wall -Wextra -Wno-unknown-pragmas -Wno-deprecated)
		else()
			target_compile_options(launcher PRIVATE -Werror -Wall -Wextra -Wno-unknown-pragmas -Wno-deprecated -Wno-deprecated-copy -Wno-error=deprecated-copy -Wno-pessimizing-move)
		endif()
	endif()
endif()
