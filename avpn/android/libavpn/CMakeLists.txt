cmake_minimum_required(VERSION 3.16)
cmake_policy(SET CMP0078 NEW)
project(avpn_android)

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DENABLE_LOGGER")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -DENABLE_LOGGER -DDISABLE_LOGGER_TO_CONSOLE -DLOGGER_DBG_VIEW")
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO} -DENABLE_LOGGER -DDISABLE_LOGGER_TO_CONSOLE -DLOGGER_DBG_VIEW")
set(CMAKE_CXX_FLAGS_MINSIZEREL "${CMAKE_CXX_FLAGS_MINSIZEREL} -DENABLE_LOGGER -DDISABLE_LOGGER_TO_CONSOLE -DLOGGER_DBG_VIEW")

file(GLOB avpn_android_HEADERS
	${CMAKE_CURRENT_SOURCE_DIR}/xavpn.hpp
)

file(GLOB avpn_android_SRCS
	${CMAKE_CURRENT_SOURCE_DIR}/xavpn.cpp
)

add_library(avpn_android ${avpn_android_SRCS} ${avpn_android_HEADERS})

target_compile_definitions(avpn_android PRIVATE
	-DVERSION_GIT=\"${PVERSION}\"
)

target_link_libraries(avpn_android
	libavpn
	${LOG_LIBRARY}
)

if (MSVC AND CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 19.29.30129
    AND CMAKE_VERSION VERSION_GREATER 3.20.3)
	set_property(TARGET avpn_android PROPERTY CXX_STANDARD 23)
	message(STATUS "avpn_android set cxx standard: C++23")
else()
	set_property(TARGET avpn_android PROPERTY CXX_STANDARD 20)
	message(STATUS "avpn_android set cxx standard: C++20")
endif()

if (SWIG_FOUND)
	# ${SWIG_USE_FILE} 变量在使用 find_package(SWIG) 命令时被设置,
	# 指向 SWIG 的配置文件.
	include(${SWIG_USE_FILE})

	# 设置 SWIG 模块名称, 该名称用于生成的文件名.
	set(SWIG_MODULE_NAME "xavpn")

	# CMAKE_SWIG_FLAGS 用于设置 SWIG 参数, 这里指定生成的 Java 包名.
	set(CMAKE_SWIG_FLAGS -package com.jackarain)

	# include_directories 用于添加头文件搜索路径.
	include_directories(${CMAKE_CURRENT_SOURCE_DIR})

	# set_source_files_properties 设置 xavpn.i 的属性, 指定其为 C++ 源文件.
	set_source_files_properties(xavpn.i PROPERTIES CPLUSPLUS ON)

	# swig_add_library 生成 SWIG 模块, 这里生成了一个名为 xavpn 的模块,
	# 指定其语言为 Java, 源文件为 xavpn.i.
	swig_add_library(${SWIG_MODULE_NAME} LANGUAGE java SOURCES xavpn.i)

	# target_link_libraries 用于链接库文件, 这里链接了 avpn_android 和 log 库.
	target_link_libraries(${SWIG_MODULE_NAME} avpn_android ${LOG_LIBRARY})
endif()
