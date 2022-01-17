cmake_minimum_required(VERSION 3.1)
cmake_policy(SET CMP0091 NEW) # for CMAKE_MSVC_RUNTIME_LIBRARY
set(CMAKE_POLICY_DEFAULT_CMP0077 NEW) # cmake_policy(SET CMP0077 NEW)
set_property(GLOBAL PROPERTY USE_FOLDERS ON)
project(dchs)

string(TIMESTAMP VERSION_YEAR "%Y")
string(TIMESTAMP VERSION_MONTH_YEAR "%m")
string(TIMESTAMP VERSION_DAY_YEAR "%j")

math(EXPR VERSION_MAJOR "${VERSION_YEAR} - 2018")
math(EXPR VERSION_MINOR "${VERSION_MONTH_YEAR}")
math(EXPR VERSION_TINY "${VERSION_DAY_YEAR}")

include(CheckCXXCompilerFlag)
include(CheckLibraryExists)
include(FetchContent)

# 跨平台性定义.
if (WIN32)
	add_definitions(-DAVPN_USE_WINAPI -DAVPN_WINDOWS)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
	add_definitions(-DAVPN_LINUX)
elseif (CMAKE_SYSTEM_NAME MATCHES "FreeBSD")
	add_definitions(-DAVPN_FREEBSD)
endif()

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${PROJECT_SOURCE_DIR}" "${PROJECT_SOURCE_DIR}/cmake")

option(ENABLE_BUILD_WERROR "All warnings being treated as errors" ON)

option(ENABLE_SYSTEM_OPENSSL "Build with system openssl support" OFF)
option(ENABLE_SYSTEM_ZLIB "Build with system zlib support" OFF)
option(ENABLE_SYSTEM_BOOST "Build with system boost support" OFF)

option(ENABLE_TCMALLOC_STATIC "Build with Tcmalloc support" OFF)
option(ENABLE_JEMALLOC_STATIC "Build with Jemalloc support" OFF)

option(ENABLE_GIT_VERSION "Enable git version" ON)


if (ENABLE_GIT_VERSION)
	find_package(Git)
	gitGetVersion(${CMAKE_CURRENT_SOURCE_DIR} dchs)
	set(VERSION_GIT ${dchs_WC_REVISION_HASH})
	string(TIMESTAMP PVERSION "%Y%m%d-${VERSION_GIT}-${CMAKE_SYSTEM_NAME}")
endif()

set(CMAKE_C_STANDARD 11)

if (MSVC)
	set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

	add_definitions(
		-D_CRT_SECURE_NO_DEPRECATE
		-D_CRT_SECURE_NO_WARNINGS
		-D_CRT_NONSTDC_NO_DEPRECATE
		-D_CRT_NONSTDC_NO_WARNINGS
		-D_SCL_SECURE_NO_DEPRECATE
		-D_SCL_SECURE_NO_WARNINGS
	)

	add_definitions(
		-DWIN32_LEAN_AND_MEAN
		-D_WIN32_WINNT=0x0601
		-DNOMINMAX
		-DUNICODE
		-D_UNICODE
		-D_SILENCE_ALL_CXX17_DEPRECATION_WARNINGS
	)

	add_definitions(
		-DBOOST_ALL_STATIC_LINK
		-DBOOST_THREAD_USE_LIB
		-DBOOST_FILESYSTEM_STATIC_LINK
		-DBOOST_USE_WINAPI_VERSION=0x0601
	)

	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /bigobj /MP")
	message(status "Using parallel compiling (/MP)")
	set(CMAKE_CXX_STACK_SIZE "100000000") #set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /STACK:100000000")
	message(status "Set stack size: 100000000")

	if (MSVC_VERSION GREATER_EQUAL "1900")
		CHECK_CXX_COMPILER_FLAG("/std:c++17" HAS_CPP_LATEST_FLAG)
		if (HAS_CPP_LATEST_FLAG)
			set(CMAKE_CXX_STANDARD 17)
			set(CMAKE_CXX_STANDARD_REQUIRED ON)
			MESSAGE(STATUS "Set cxx standard: C++17")
		endif()
	endif()
elseif(WIN32)
	set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

	add_definitions(
		-DWIN32_LEAN_AND_MEAN
		-D_WIN32_WINNT=0x0601
		-DNOMINMAX
		-DUNICODE
		-D_UNICODE
		-D_SILENCE_ALL_CXX17_DEPRECATION_WARNINGS
	)

	add_definitions(
		-DBOOST_ALL_STATIC_LINK
		-DBOOST_THREAD_USE_LIB
		-DBOOST_FILESYSTEM_STATIC_LINK
		-DBOOST_USE_WINAPI_VERSION=0x0601
	)
endif()

CHECK_CXX_COMPILER_FLAG(-fvisibility-inlines-hidden COMPILER_HAS_VISIBILITY_INLINE_HIDDEN)
CHECK_CXX_COMPILER_FLAG(-fvisibility=hidden COMPILER_HAS_VISIBILITY_HIDDEN)
CHECK_CXX_COMPILER_FLAG(-std=c++14 LIBCXX_HAS_STDCXX14_FLAG)
CHECK_CXX_COMPILER_FLAG(-std=c++17 LIBCXX_HAS_STDCXX17_FLAG)
CHECK_CXX_COMPILER_FLAG(-fdiagnostics-color=always COMPILER_HAS_COLOR)

if (${COMPILER_HAS_VISIBILITY_INLINE_HIDDEN})
	SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fvisibility-inlines-hidden")
endif()

if (${COMPILER_HAS_VISIBILITY_HIDDEN})
	SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fvisibility=hidden")
endif()

if (${COMPILER_HAS_COLOR})
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fdiagnostics-color=always")
endif()

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -DENABLE_LOGGER -DDISABLE_LOGGER_TO_CONSOLE -DLOGGER_DBG_VIEW")
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO} -DENABLE_LOGGER -DDISABLE_LOGGER_TO_CONSOLE -DLOGGER_DBG_VIEW")
set(CMAKE_CXX_FLAGS_MINSIZEREL "${CMAKE_CXX_FLAGS_MINSIZEREL} -DENABLE_LOGGER -DDISABLE_LOGGER_TO_CONSOLE -DLOGGER_DBG_VIEW")

if (NOT MSVC)
	if(NOT APPLE)
		if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang" AND WIN32)
			set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS}")
		else()
			set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libstdc++ -static-libgcc")
		endif()
	endif()
	if (ANDROID)
		set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fPIE -pie")
	endif()
	if(LIBCXX_HAS_STDCXX17_FLAG)
		set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17 -O3")
		add_definitions(-DUSE_STD_STRING_VIEW)
	elseif(LIBCXX_HAS_STDCXX14_FLAG)
		set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -O3")
	else()
		message(FATAL_ERROR "need at least GCC 5 or clang 5")
	endif()
endif(NOT MSVC)

#add_definitions(-DJSONRPC_DISABLE_THREADS)
add_subdirectory(third_party/crypto)
set(CRYPTOPP_INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/third_party/crypto/include)

if (ENABLE_SYSTEM_BOOST)
	set(Boost_USE_STATIC_RUNTIME ON)
	find_package(Boost 1.73 REQUIRED COMPONENTS system json date_time regex context coroutine thread filesystem program_options)
else()
	set(Boost_USE_STATIC_LIBS ON)
	set(Boost_USE_STATIC_RUNTIME ON)

	set(Boost_INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/third_party/boost)

	add_definitions(-DBOOST_LOCALE_HIDE_AUTO_PTR)
	add_definitions(-DBOOST_BIND_GLOBAL_PLACEHOLDERS)
	add_definitions(-DBOOST_DISABLE_PRAGMA_MESSAGE)
	add_definitions(-DBOOST_COROUTINES_NO_DEPRECATION_WARNING)
	add_subdirectory(third_party/boost)
endif()

find_package(Threads)
link_libraries(${CMAKE_THREAD_LIBS_INIT} ${CMAKE_DL_LIBS})

if (ENABLE_TCMALLOC_STATIC)
	find_package(Tcmalloc)
	link_libraries(${Tcmalloc_LIBRARY})
endif()

if (ENABLE_JEMALLOC_STATIC)
	find_package(JeMalloc)
	link_libraries(${JEMALLOC_LIBRARIES})
endif()

if (WIN32 OR NOT ENABLE_SYSTEM_ZLIB)
	add_subdirectory(third_party/zlib EXCLUDE_FROM_ALL)
	set(ZLIB_LIBRARIES zlibstatic)
	set(MINIZIP_LIBRARIES minizip)
	set(ZLIB_INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/third_party/zlib ${CMAKE_CURRENT_SOURCE_DIR}/third_party/zlib/contrib/minizip)
else()
	find_package(ZLIB REQUIRED)
	set(MINIZIP_LIBRARIES minizip)
	#find_package(minizip REQUIRED)
endif()

add_subdirectory(third_party/fmt)

include_directories(third_party
	${ZLIB_INCLUDE_DIRS}
	${MINIZIP_INCLUDE_DIRS}
	${CRYPTOPP_INCLUDE_DIRS}
)

if (ENABLE_SYSTEM_OPENSSL)
	find_package(OpenSSL)
else()
	add_subdirectory(third_party/openssl)
	if (NOT MSVC AND NOT APPLE)
		if (NOT (CMAKE_CXX_COMPILER_ID STREQUAL "Clang"))
			set(CMAKE_SHARED_LINKER_FLAGS "-Wl,--exclude-libs,ALL ${CMAKE_SHARED_LINKER_FLAGS}")
			set(CMAKE_MODULE_LINKER_FLAGS "-Wl,--exclude-libs,ALL ${CMAKE_MODULE_LINKER_FLAGS}")
			set(CMAKE_EXE_LINKER_FLAGS "-Wl,--exclude-libs,ALL ${CMAKE_EXE_LINKER_FLAGS}")
		endif()
	endif()
endif()
include_directories(${OPENSSL_INCLUDE_DIR})

set(FLATBUFFERS_BUILD_TESTS OFF CACHE BOOL "Enable the build of tests and samples.")
set(FLATBUFFERS_INSTALL OFF CACHE BOOL "Enable the installation of targets." OFF)
set(FLATBUFFERS_BUILD_FLATHASH OFF CACHE BOOL "Enable the build of flathash" OFF)
set(FLATBUFFERS_BUILD_FLATC OFF CACHE BOOL "Enable the build of the flatbuffers compiler" OFF)
set(FLATBUFFERS_BUILD_CPP17 OFF CACHE BOOL
       "Enable the build of c++17 test target. \"
       Requirements: Clang6, GCC7, MSVC2017 (_MSC_VER >= 1914)  or higher."
	ON)
set(FLATBUFFERS_LIBCXX_WITH_CLANG OFF CACHE BOOL "Force libc++ when using Clang" OFF)
set(FLATBUFFERS_INSTALL OFF CACHE BOOL "Enable the installation of targets." OFF)

add_subdirectory(third_party/flatbuffers EXCLUDE_FROM_ALL)
set(FLATBUFFERS_INCLUDE_DIRS third_party/flatbuffers/include)
set_target_properties(flatbuffers PROPERTIES FOLDER "third_party")
set_target_properties(flatbuffers PROPERTIES POSITION_INDEPENDENT_CODE ON)

set(BUILD_EXAMPLES OFF CACHE BOOL OFF)
set(BUILD_TESTING OFF CACHE BOOL OFF)
add_subdirectory(third_party/libssh2)
set_target_properties(libssh2 PROPERTIES FOLDER "third_party")
set_target_properties(libssh2 PROPERTIES POSITION_INDEPENDENT_CODE ON)

set(LIBSSH2_INCLUDE_DIRS
	${CMAKE_CURRENT_SOURCE_DIR}/third_party/libssh2/include
	${CMAKE_BINARY_DIR}/third_party/libssh2/src
)

include_directories(
	${FLATBUFFERS_INCLUDE_DIRS}
	${LIBSSH2_INCLUDE_DIRS}
)

FetchContent_Declare(GSL
    GIT_REPOSITORY "https://github.com/microsoft/GSL"
    GIT_TAG "v3.1.0"
)

FetchContent_MakeAvailable(GSL)

link_libraries(
		Boost::coroutine
		Boost::context
		Boost::thread
		Boost::date_time
		Boost::filesystem
		Boost::program_options
		Boost::regex
		Boost::json

		libssh2
		GSL
		fmt
		flatbuffers
		cryptopp-static

		${OPENSSL_LIBRARIES}
		${ZLIB_LIBRARIES}
		${MINIZIP_LIBRARIES}
)

if (WIN32)
	link_libraries(
		Secur32.lib
		Bcrypt.lib
		Winmm.lib
		Mswsock.lib
	)
else()
	link_libraries(mnl netlink)
endif()

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

if (WIN32)
	set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG ${CMAKE_BINARY_DIR}/bin/debug)
	set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR}/bin/release)
endif()

add_subdirectory(dchs)

configure_file(dchs.service.in dchs.service)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/dchs.service DESTINATION /usr/lib/systemd/system/)
install(TARGETS dchs DESTINATION bin)
