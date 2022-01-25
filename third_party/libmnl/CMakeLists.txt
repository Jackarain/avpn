# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

cmake_minimum_required(VERSION 3.0)
project(libmnl C)

file(GLOB libmnl_SRC
	include/libmnl/libmnl.h

	src/attr.c
	src/callback.c
	src/nlmsg.c
	src/socket.c
)

add_library(mnl STATIC ${libmnl_SRC})

#target_compile_definitions(mnl PRIVATE -DCONFIG_VERSION="1.0")
target_include_directories(mnl PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(mnl PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

set_target_properties(mnl PROPERTIES FOLDER "third_party")
set_target_properties(mnl PROPERTIES POSITION_INDEPENDENT_CODE ON)
set_target_properties(mnl PROPERTIES OUTPUT_NAME mnl PREFIX "lib" CLEAN_DIRECT_OUTPUT 1)

