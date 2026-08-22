if (NOT ENABLE_BUILD_TESTS)
	return()
endif()

add_executable(fec_tests
	fec_tests.cpp
)

add_executable(obfuscate_tests
	obfuscate_tests.cpp
)

add_executable(dns_packet_tests
	dns_packet_tests.cpp
)

add_executable(gfwlist_tests
	gfwlist_tests.cpp
)

target_include_directories(fec_tests PRIVATE
	${CMAKE_SOURCE_DIR}
	${CMAKE_CURRENT_SOURCE_DIR}
)

target_include_directories(obfuscate_tests PRIVATE
	${CMAKE_SOURCE_DIR}
	${CMAKE_CURRENT_SOURCE_DIR}
)

target_include_directories(dns_packet_tests PRIVATE
	${CMAKE_SOURCE_DIR}
	${CMAKE_CURRENT_SOURCE_DIR}
	${CMAKE_SOURCE_DIR}/third_party/boost/libs/test/include
)

target_include_directories(gfwlist_tests PRIVATE
	${CMAKE_SOURCE_DIR}
	${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(gfwlist_tests PRIVATE
	libavpn
	Boost::unit_test_framework
)

target_link_libraries(dns_packet_tests PRIVATE
	Boost::unit_test_framework
	Boost::thread
	Boost::date_time
	Boost::program_options
	Boost::filesystem
	Boost::signals2
	Boost::nowide
	Boost::url
	Boost::json
	Boost::uuid
	Boost::asio
	Boost::beast
	Boost::scope

	fmt
	${ZLIB_LIBRARIES}
	${OPENSSL_LIBRARIES}
)

target_link_libraries(fec_tests PRIVATE
	Boost::unit_test_framework
	Boost::thread
	Boost::date_time
	Boost::program_options
	Boost::filesystem
	Boost::signals2
	Boost::nowide
	Boost::url
	Boost::json
	Boost::uuid
	Boost::asio
	Boost::beast
	Boost::scope

	fmt
	${ZLIB_LIBRARIES}
	${OPENSSL_LIBRARIES}
)

target_link_libraries(obfuscate_tests PRIVATE
	Boost::unit_test_framework
	Boost::thread
	Boost::date_time
	Boost::program_options
	Boost::filesystem
	Boost::signals2
	Boost::nowide
	Boost::url
	Boost::json
	Boost::uuid
	Boost::asio
	Boost::beast
	Boost::scope

	fmt
	${ZLIB_LIBRARIES}
	${OPENSSL_LIBRARIES}
)

if (MSVC AND CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 19.29.30129 AND CMAKE_VERSION VERSION_GREATER 3.20.3)
	set_property(TARGET fec_tests PROPERTY CXX_STANDARD 23)
	set_property(TARGET obfuscate_tests PROPERTY CXX_STANDARD 23)
	set_property(TARGET dns_packet_tests PROPERTY CXX_STANDARD 23)
	set_property(TARGET gfwlist_tests PROPERTY CXX_STANDARD 23)
else()
	set_property(TARGET fec_tests PROPERTY CXX_STANDARD 20)
	set_property(TARGET obfuscate_tests PROPERTY CXX_STANDARD 20)
	set_property(TARGET dns_packet_tests PROPERTY CXX_STANDARD 20)
	set_property(TARGET gfwlist_tests PROPERTY CXX_STANDARD 20)
endif()

add_test(NAME fec_tests COMMAND fec_tests)
add_test(NAME obfuscate_tests COMMAND obfuscate_tests)
add_test(NAME dns_packet_tests COMMAND dns_packet_tests)
add_test(NAME gfwlist_tests COMMAND gfwlist_tests)
