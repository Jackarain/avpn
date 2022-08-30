cmake_minimum_required(VERSION 3.16)
project(socks)

add_library(socks INTERFACE)

target_sources(socks
	PUBLIC
	${CMAKE_CURRENT_SOURCE_DIR}/include/socks/socks_client.hpp
	${CMAKE_CURRENT_SOURCE_DIR}/include/socks/socks_enums.hpp
	${CMAKE_CURRENT_SOURCE_DIR}/include/socks/socks_error_code.hpp
	${CMAKE_CURRENT_SOURCE_DIR}/include/socks/socks_io.hpp
	${CMAKE_CURRENT_SOURCE_DIR}/include/socks/socks_server.hpp
)

target_include_directories(socks
	INTERFACE
	${CMAKE_CURRENT_SOURCE_DIR}/include/
)

set(SOCKS_INCLUDE_DIRS
	${CMAKE_CURRENT_SOURCE_DIR}/include
	PARENT_SCOPE
)

set(SOCKS_LIBRARIES
	socks
	PARENT_SCOPE
)
