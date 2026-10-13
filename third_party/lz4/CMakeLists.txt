# lz4 - 极快的无损压缩库 (块格式接口)
#
# 只编译库本体 (lib/lz4.c), 供 libavpn 的压缩器按块调用;
# 上游的 CLI / frame / high-compression 等目标本工程用不到, 不引入.

cmake_minimum_required(VERSION 3.16)

project(lz4
	LANGUAGES C
	VERSION 1.10.0
	HOMEPAGE_URL "https://github.com/lz4/lz4")

add_library(lz4 STATIC lib/lz4.c)

target_include_directories(lz4
	PUBLIC
	${CMAKE_CURRENT_SOURCE_DIR}/lib
)

set_property(TARGET lz4 PROPERTY FOLDER "third_party")
