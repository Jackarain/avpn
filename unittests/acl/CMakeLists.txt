
file(GLOB acl_SRCS
	*.cpp
)

add_executable(acl_tests
	${acl_SRCS}
)

if (ENABLE_MIMALLOC_STATIC)
	target_link_libraries(acl_tests mimalloc-static)
endif()

target_link_libraries(acl_tests
	Boost::asio
	libavpn
)

if (MSVC AND CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 19.29.30129 AND CMAKE_VERSION VERSION_GREATER 3.20.3)
	set_property(TARGET acl_tests PROPERTY CXX_STANDARD 23)
	message(STATUS "acl_tests set cxx standard: C++23")
else()
	set_property(TARGET acl_tests PROPERTY CXX_STANDARD 20)
	message(STATUS "acl_tests set cxx standard: C++20")
endif()

target_include_directories(acl_tests PUBLIC
	${CMAKE_BINARY_DIR}
	${CMAKE_CURRENT_SOURCE_DIR}
	${CMAKE_CURRENT_SOURCE_DIR}/include
)

if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
	target_compile_options(acl_tests PRIVATE -fcoroutines)
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
	target_compile_definitions(acl_tests PRIVATE -DBOOST_ASIO_HAS_CO_AWAIT)
endif()

if(ENABLE_BUILD_WERROR)
	if(MSVC)
		target_compile_options(acl_tests PRIVATE /W4 /WX)
	elseif(UNIX AND NOT APPLE)
		if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9.1)
			target_compile_options(acl_tests PRIVATE -Werror -Wall -Wextra -Wno-unknown-pragmas -Wno-deprecated)
		else()
			target_compile_options(acl_tests PRIVATE -Werror -Wall -Wextra -Wno-unknown-pragmas -Wno-deprecated -Wno-deprecated-copy -Wno-error=deprecated-copy -Wno-pessimizing-move)
		endif()
	endif()
endif()

add_test (NAME tun_tests COMMAND acl_tests)
set_target_properties(acl_tests PROPERTIES FOLDER "AVPN tests")
