cmake_minimum_required(VERSION 3.16)
project(libproxy)

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DENABLE_LOGGER")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -DENABLE_LOGGER -DDISABLE_LOGGER_TO_CONSOLE -DLOGGER_DBG_VIEW")
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO} -DENABLE_LOGGER -DDISABLE_LOGGER_TO_CONSOLE -DLOGGER_DBG_VIEW")
set(CMAKE_CXX_FLAGS_MINSIZEREL "${CMAKE_CXX_FLAGS_MINSIZEREL} -DENABLE_LOGGER -DDISABLE_LOGGER_TO_CONSOLE -DLOGGER_DBG_VIEW")

add_library(libproxy STATIC
	${CMAKE_CURRENT_SOURCE_DIR}/src/dummy.cpp
)

if (APPLE)
	target_sources(libproxy
		INTERFACE
		${CMAKE_CURRENT_SOURCE_DIR}/include/proxy/http_proxy_client.hpp
		${CMAKE_CURRENT_SOURCE_DIR}/include/proxy/socks_client.hpp
		${CMAKE_CURRENT_SOURCE_DIR}/include/proxy/socks_enums.hpp
		${CMAKE_CURRENT_SOURCE_DIR}/include/proxy/socks_error_code.hpp
		${CMAKE_CURRENT_SOURCE_DIR}/include/proxy/socks_io.hpp

		${CMAKE_CURRENT_SOURCE_DIR}/src/dummy.cpp
	)
else()
	target_sources(libproxy
		PRIVATE
		${CMAKE_CURRENT_SOURCE_DIR}/include/proxy/http_proxy_client.hpp
		${CMAKE_CURRENT_SOURCE_DIR}/include/proxy/socks_client.hpp
		${CMAKE_CURRENT_SOURCE_DIR}/include/proxy/socks_enums.hpp
		${CMAKE_CURRENT_SOURCE_DIR}/include/proxy/socks_error_code.hpp
		${CMAKE_CURRENT_SOURCE_DIR}/include/proxy/socks_io.hpp

		${CMAKE_CURRENT_SOURCE_DIR}/src/dummy.cpp
	)
endif()

target_include_directories(libproxy
	PUBLIC
	${CMAKE_CURRENT_SOURCE_DIR}/include/

	${Boost_INCLUDE_DIRS} # 上层传递的boost依赖库目录.
	${UTILS_INCLUDE_DIRS} # 上层传递的utils依赖库目录.
)

target_link_libraries(libproxy
	Boost::asio
	Boost::beast
	fmt
	${OPENSSL_LIBRARIES}
)

#source_group("Header Files\\proxy" FILES ${libproxy_HEADERS})
#source_group("Source Files" FILES ${libproxy_SRCS})

set_target_properties(libproxy PROPERTIES OUTPUT_NAME proxy PREFIX "lib" CLEAN_DIRECT_OUTPUT 1)

set_property(TARGET libproxy PROPERTY CXX_STANDARD 20)
message(STATUS "libproxy set cxx standard: C++20")

set(PROXY_INCLUDE_DIRS
	${CMAKE_CURRENT_SOURCE_DIR}/include
	PARENT_SCOPE
)

set(PROXY_LIBRARIES
	libproxy
	PARENT_SCOPE
)
