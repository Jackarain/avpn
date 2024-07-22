# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

cmake_minimum_required(VERSION 3.16)
project(iproute2 C)

file(GLOB iproute2_SRC
	lib/libnetlink.c
)

add_library(iproute2 STATIC ${iproute2_SRC})

target_include_directories(iproute2 PUBLIC
	${CMAKE_CURRENT_SOURCE_DIR}/include
	${CMAKE_CURRENT_SOURCE_DIR}/include/uapi
)

set_target_properties(iproute2 PROPERTIES FOLDER "third_party")
set_target_properties(iproute2 PROPERTIES POSITION_INDEPENDENT_CODE ON)
set_target_properties(iproute2 PROPERTIES OUTPUT_NAME iproute2 PREFIX "lib" CLEAN_DIRECT_OUTPUT 1)

