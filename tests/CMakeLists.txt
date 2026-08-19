if (NOT ENABLE_BUILD_TESTS)
	return()
endif()

add_executable(fec_tests
	fec_tests.cpp
)

target_include_directories(fec_tests PRIVATE
	${CMAKE_SOURCE_DIR}
	${CMAKE_CURRENT_SOURCE_DIR}
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

if (MSVC AND CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 19.29.30129 AND CMAKE_VERSION VERSION_GREATER 3.20.3)
	set_property(TARGET fec_tests PROPERTY CXX_STANDARD 23)
else()
	set_property(TARGET fec_tests PROPERTY CXX_STANDARD 20)
endif()

add_test(NAME fec_tests COMMAND fec_tests)
