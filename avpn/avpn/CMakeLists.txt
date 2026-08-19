
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -DLOGGER_DBG_VIEW")
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO} -DLOGGER_DBG_VIEW")
set(CMAKE_CXX_FLAGS_MINSIZEREL "${CMAKE_CXX_FLAGS_MINSIZEREL} -DLOGGER_DBG_VIEW")

if (WIN32)
	set(AVPN_RESOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../src/resource)
	configure_file(${AVPN_RESOURCE_DIR}/avpn.rc.in
		${AVPN_RESOURCE_DIR}/avpn.rc @ONLY NEWLINE_STYLE LF)
endif()

add_executable(avpn
    main.cpp
    main.hpp
)

if (WIN32)
    target_sources(avpn PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../src/resource/avpn.rc)
endif()

target_link_libraries(avpn
    ${AVPN_LIBRARIES}
    ${OPENSSL_LIBRARIES}
)

# 启用 io_uring 时链接 liburing（与 proxy_server 一致），
# 否则 asio 的 io_uring_service 会产生未定义符号链接错误。
if (TARGET IOUring::IOUring)
    target_link_libraries(avpn IOUring::IOUring)
endif()

if (WIN32 AND ENABLE_USE_WINTUN)
    # 拷贝 wintun.dll 到输出目录.
    add_custom_command(TARGET avpn POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${CMAKE_CURRENT_SOURCE_DIR}/../../third_party/wintun/bin/amd64/wintun.dll
            $<TARGET_FILE_DIR:avpn>/wintun.dll
    )
endif()

target_compile_definitions(avpn PUBLIC -DVERSION_GIT=\"${PVERSION}\")

if (MSVC AND CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 19.29.30129 AND CMAKE_VERSION VERSION_GREATER 3.20.3)
	set_property(TARGET avpn PROPERTY CXX_STANDARD 23)
	message(STATUS "avpn set cxx standard: C++23")
else()
	set_property(TARGET avpn PROPERTY CXX_STANDARD 20)
	message(STATUS "avpn set cxx standard: C++20")
endif()

if (ANDROID)
    # 查找 Android log 库.
    find_library(
        log-lib
        log
    )

    # target_link_libraries 目标中链接 log 库.
    target_link_libraries(avpn ${log-lib})
endif()

if(ENABLE_BUILD_WERROR)
	if(MSVC)
		target_compile_options(avpn PRIVATE /W4 /WX)
	elseif(UNIX AND NOT APPLE)
		if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9.1)
			target_compile_options(avpn PRIVATE -Werror -Wall -Wextra -Wno-unknown-pragmas -Wno-deprecated)
		else()
			target_compile_options(avpn PRIVATE -Werror -Wall -Wextra -Wno-unknown-pragmas -Wno-deprecated -Wno-deprecated-copy -Wno-error=deprecated-copy -Wno-pessimizing-move)
		endif()
	endif()
endif()
