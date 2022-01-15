# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

cmake_minimum_required(VERSION 3.0)
project(quickjs C)

file(GLOB quickjs_SRC
		cutils.c
		libbf.c
		libunicode.c
		libregexp.c
		quickjs-libc.c
		quickjs.c
		
		cutils.h
		libbf.h
		libunicode.h
		libunicode-table.h
		unicode_gen_def.h
		libregexp.h
		libregexp-opcode.h
		quickjs.h
		quickjs-atom.h
		quickjs-libc.h
		quickjs-opcode.h
)

add_library(quickjs STATIC ${quickjs_SRC})

target_compile_definitions(quickjs PUBLIC -DCONFIG_BIGNUM)
target_compile_definitions(quickjs PRIVATE -DCONFIG_VERSION="1.0")
target_include_directories(quickjs PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

set_target_properties(quickjs PROPERTIES FOLDER "third_party")
set_target_properties(quickjs PROPERTIES POSITION_INDEPENDENT_CODE ON)
set_target_properties(quickjs PROPERTIES OUTPUT_NAME quickjs PREFIX "lib" CLEAN_DIRECT_OUTPUT 1)
