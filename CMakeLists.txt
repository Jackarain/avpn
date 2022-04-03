cmake_minimum_required(VERSION 3.16)
set(CMAKE_POLICY_DEFAULT_CMP0077 NEW) # cmake_policy(SET CMP0077 NEW)
if (WIN32)
	cmake_policy(SET CMP0091 NEW) # for CMAKE_MSVC_RUNTIME_LIBRARY
endif()
set_property(GLOBAL PROPERTY USE_FOLDERS ON)
project(avpn)

string(TIMESTAMP VERSION_YEAR "%Y")
string(TIMESTAMP VERSION_MONTH_YEAR "%m")
string(TIMESTAMP VERSION_DAY_YEAR "%j")

math(EXPR VERSION_MAJOR "${VERSION_YEAR} - 2018")
math(EXPR VERSION_MINOR "${VERSION_MONTH_YEAR}")
math(EXPR VERSION_TINY "${VERSION_DAY_YEAR}")

include(CheckCXXCompilerFlag)
include(CheckLibraryExists)

# Disable in-source builds to prevent source tree corruption.
if("${CMAKE_CURRENT_SOURCE_DIR}" STREQUAL "${CMAKE_BINARY_DIR}")
  message(FATAL_ERROR "
FATAL: In-source builds are not allowed.
       You should create a separate directory for build files.
")
endif()
message(STATUS "CMAKE Version: ${CMAKE_VERSION}")

message(STATUS "Source Dir: ${CMAKE_CURRENT_SOURCE_DIR}")
message(STATUS "Host System name: ${CMAKE_HOST_SYSTEM_NAME}")

set(default_build_type "Release")

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE "${default_build_type}" CACHE
        STRING "Choose the type of build." FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
                 "Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif()

message(STATUS "System name: ${CMAKE_SYSTEM_NAME}")
message(STATUS "System version: ${CMAKE_SYSTEM_VERSION}")
if (WIN32)
	message(STATUS "Platform version: ${CMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION}")
endif()
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

# 跨平台性定义.
message(STATUS "SYSTEM NAME: ${CMAKE_SYSTEM_NAME}")
if (WIN32)
	cmake_policy(SET CMP0091 NEW) # for CMAKE_MSVC_RUNTIME_LIBRARY
	add_definitions(-DAVPN_USE_WINAPI -DAVPN_WINDOWS)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
	add_definitions(-DAVPN_LINUX)
elseif (CMAKE_SYSTEM_NAME MATCHES "FreeBSD")
	add_definitions(-DAVPN_FREEBSD)
elseif (CMAKE_SYSTEM_NAME MATCHES "Darwin")
	add_definitions(-DAVPN_APPLE)
elseif (CMAKE_SYSTEM_NAME MATCHES "Android")
	add_definitions(-DAVPN_ANDROID)
endif()

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${PROJECT_SOURCE_DIR}" "${PROJECT_SOURCE_DIR}/cmake")

include(CheckCXXLinkerFlag)

option(ENABLE_USE_IO_URING "Enable auto use io_uring" ON)
option(ENABLE_USE_WINTUN "Enable use Wintun instead tap-windows" ON)
option(ENABLE_BUILD_WERROR "All warnings being treated as errors" OFF)

option(ENABLE_SYSTEM_ZLIB "Build with system zlib support" OFF)

option(ENABLE_TCMALLOC_STATIC "Build with Tcmalloc support" OFF)
option(ENABLE_JEMALLOC_STATIC "Build with Jemalloc support" OFF)
option(ENABLE_MIMALLOC_STATIC "Build with Mimalloc support" OFF)

option(ENABLE_GIT_VERSION "Enable git version" ON)
option(ENABLE_SYSTEMD_LOGGING "Build with systemd journal support" OFF)

option(ENABLE_BUILD_WITH_LIBCXX "Build with libc++" OFF)

option(ENABLE_MOLD "build using mold" OFF)
option(ENABLE_LLD "build using lld" OFF)

option(ENABLE_BUILD_TESTS "build avpn's unit tests" OFF)

find_program(MOLD_LINKER mold)
find_program(LLD_LINKER lld)

if (ENABLE_GIT_VERSION)
	find_package(Git)
	gitGetVersion(${CMAKE_CURRENT_SOURCE_DIR} avpn)
	set(VERSION_GIT ${avpn_WC_REVISION_HASH})
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

	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /bigobj /MP /Zc:__cplusplus")
	message(STATUS "Using parallel compiling (/MP)")
	set(CMAKE_CXX_STACK_SIZE "100000000") #set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /STACK:100000000")
	message(STATUS "Set stack size: 100000000 bytes")

	CHECK_CXX_COMPILER_FLAG(/std:c++20 COMPILER_HAS_STD_CXX20)

	if (COMPILER_HAS_STD_CXX20)
		set(CMAKE_CXX_STANDARD 20)
		set(CMAKE_CXX_STANDARD_REQUIRED ON)
		message(STATUS "Set default cxx standard: C++20")
	elseif (MSVC_VERSION GREATER_EQUAL "1900")
		set(CMAKE_CXX_STANDARD 17)
		set(CMAKE_CXX_STANDARD_REQUIRED ON)
		message(STATUS "Set default cxx standard: C++17")
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
	add_compile_options(/utf8)
endif()

CHECK_CXX_COMPILER_FLAG(-fvisibility-inlines-hidden COMPILER_HAS_VISIBILITY_INLINE_HIDDEN)
CHECK_CXX_COMPILER_FLAG(-fvisibility=hidden COMPILER_HAS_VISIBILITY_HIDDEN)
CHECK_CXX_COMPILER_FLAG(-fdiagnostics-color=always COMPILER_HAS_COLOR)
CHECK_CXX_COMPILER_FLAG(-fcoroutines COMPILER_HAS_FCOROUTINES)
CHECK_CXX_COMPILER_FLAG(-std=c++20 COMPILER_HAS_STD_CXX20)

if (${COMPILER_HAS_VISIBILITY_INLINE_HIDDEN})
	SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fvisibility-inlines-hidden")
endif()

if (${COMPILER_HAS_VISIBILITY_HIDDEN})
	SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fvisibility=hidden")
endif()

if (${COMPILER_HAS_COLOR})
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fdiagnostics-color=always")
endif()

if (COMPILER_HAS_FCOROUTINES)
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fcoroutines")
endif()


if (ENABLE_SYSTEMD_LOGGING )
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DUSE_SYSTEMD_LOGGING")
endif()

if (NOT MSVC)
	if(NOT APPLE)
		if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
			if (ENABLE_BUILD_WITH_LIBCXX)
				set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++")
				CHECK_LINKER_FLAG(CXX "-rtlib=compiler-rt" IS_COMPILER_RT_SUPPORTED)

				if (IS_COMPILER_RT_SUPPORTED)
					message(STATUS "clang supports compiler-rt, use it")
					add_link_options(-rtlib=compiler-rt -unwindlib=libunwind)
				endif()
			else()
				set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libstdc++ -static-libgcc")
			endif()
		elseif (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
			set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libstdc++ -static-libgcc")
		endif()
	endif()
	if (ANDROID)
		set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fPIE -pie")
	endif()
	if(COMPILER_HAS_STD_CXX20)
		set(CMAKE_CXX_STANDARD 20)
		add_definitions(-DUSE_STD_STRING_VIEW)
		message(STATUS "Set default cxx standard: C++20")
	else()
		message(FATAL_ERROR "need at least GCC 11 or clang 14")
	endif()

	if (ENABLE_MOLD)
		if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
			if (MOLD_LINKER)
				list(APPEND CMAKE_EXE_LINKER_FLAGS "-fuse-ld=mold")
			endif()
		endif()
	endif()

	if (ENABLE_MOLD)
		if (LLD_LINKER)
			list(APPEND CMAKE_EXE_LINKER_FLAGS "-fuse-ld=lld")
		endif()
	endif()

endif(NOT MSVC)

if (ENABLE_USE_WINTUN)
	add_definitions(-DAVPN_USE_WINTUN)
	set(WINTUN_INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/third_party/wintun/include)
endif()

#add_definitions(-DJSONRPC_DISABLE_THREADS)
add_subdirectory(third_party/crypto)
set(CRYPTOPP_INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/third_party/crypto/include)

if (ENABLE_BUILD_TESTS)
	set(USE_BOOST_TEST ON)
endif()

set(BUILD_ASIO_BEAST ON)

set(Boost_USE_STATIC_LIBS ON)
set(Boost_USE_STATIC_RUNTIME ON)

set(Boost_INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/third_party/boost EXCLUDE_FROM_ALL)

add_definitions(-DBOOST_ASIO_SEPARATE_COMPILATION)
add_definitions(-DBOOST_BEAST_SEPARATE_COMPILATION)

add_definitions(-DBOOST_LOCALE_HIDE_AUTO_PTR)
add_definitions(-DBOOST_BIND_GLOBAL_PLACEHOLDERS)
add_definitions(-DBOOST_DISABLE_PRAGMA_MESSAGE)
add_definitions(-DBOOST_COROUTINES_NO_DEPRECATION_WARNING)
if (ENABLE_USE_IO_URING)
	find_package(IOUring)

	if (IOUring_FOUND)
		message(STATUS "Linux using io_uring...")
		add_definitions(-DBOOST_ASIO_HAS_IO_URING -DBOOST_ASIO_DISABLE_EPOLL)
		link_libraries(${IOUring_LIBRARIES})
	endif()
endif()

if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
	add_definitions(-DBOOST_ASIO_HAS_CO_AWAIT)
endif()

add_subdirectory(third_party/boost EXCLUDE_FROM_ALL)

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

if (ENABLE_MIMALLOC_STATIC)
	add_definitions(-DUSE_MIMALLOC)
	set(mimalloc_DIR ${CMAKE_SOURCE_DIR}/third_party/mimalloc/cmake)

	set(MI_DEBUG_FULL        OFF CACHE BOOL "" FORCE) # Use full internal heap invariant checking in DEBUG mode (expensive)
	set(MI_PADDING           ON  CACHE BOOL "" FORCE) # Enable padding to detect heap block overflow (used only in DEBUG mode)
	if (APPLE)
		set(MI_OVERRIDE        OFF CACHE BOOL "" FORCE) # Override the standard malloc interface (e.g. define entry points for malloc() etc)
	else()
		set(MI_OVERRIDE        ON  CACHE BOOL "" FORCE)
	endif()
	set(MI_XMALLOC           OFF CACHE BOOL "" FORCE) # Enable abort() call on memory allocation failure by default
	set(MI_SHOW_ERRORS       OFF CACHE BOOL "" FORCE) # Show error and warning messages by default (only enabled by default in DEBUG mode)
	set(MI_USE_CXX           ON  CACHE BOOL "" FORCE) # Use the C++ compiler to compile the library (instead of the C compiler)
	set(MI_SEE_ASM           OFF CACHE BOOL "" FORCE) # Generate assembly files
	set(MI_INTERPOSE         ON  CACHE BOOL "" FORCE) # Use interpose to override standard malloc on macOS
	set(MI_OSX_ZONE          ON  CACHE BOOL "" FORCE) # Use malloc zone to override standard malloc on macOS
	set(MI_LOCAL_DYNAMIC_TLS OFF CACHE BOOL "" FORCE) # Use slightly slower, dlopen-compatible TLS mechanism (Unix)
	set(MI_BUILD_SHARED      OFF CACHE BOOL "" FORCE) # Build shared library
	set(MI_BUILD_STATIC      ON  CACHE BOOL "" FORCE) # Build static library
	set(MI_BUILD_OBJECT      OFF CACHE BOOL "" FORCE) # Build object library
	set(MI_BUILD_TESTS       OFF CACHE BOOL "" FORCE) # Build test executables
	set(MI_DEBUG_TSAN        OFF CACHE BOOL "" FORCE) # Build with thread sanitizer (needs clang)
	set(MI_DEBUG_UBSAN       OFF CACHE BOOL "" FORCE) # Build with undefined-behavior sanitizer (needs clang++)
	set(MI_INSTALL_TOPLEVEL  OFF CACHE BOOL "" FORCE) # Install directly into $CMAKE_INSTALL_PREFIX instead of PREFIX/lib/mimalloc-version

	include_directories(third_party/mimalloc/include)
	add_subdirectory(third_party/mimalloc EXCLUDE_FROM_ALL)

	if (MI_OVERRIDE)
		add_definitions(-DMI_OVERRIDE) # For preprocessor checks in our source.
	endif()
endif()

if (ENABLE_SYSTEMD_LOGGING)
	link_libraries(systemd)
endif()

if (WIN32 OR NOT ENABLE_SYSTEM_ZLIB)
	add_subdirectory(third_party/zlib EXCLUDE_FROM_ALL)
	set(ZLIB_LIBRARIES zlibstatic)
	set(ZLIB_INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/third_party/zlib ${CMAKE_CURRENT_SOURCE_DIR}/third_party/zlib/contrib/minizip)
else()
	find_package(ZLIB REQUIRED)
endif()

if (UNIX AND NOT APPLE AND NOT ANDROID)
	add_subdirectory(third_party/iproute2)
	set(IPROUTE2_INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/third_party/iproute2/include)
	set(IPROUTE2_LIBRARIES iproute2)

	include_directories(${IPROUTE2_INCLUDE_DIRS})
endif()

add_subdirectory(third_party/fmt)

include_directories(third_party
	${ZLIB_INCLUDE_DIRS}
	${CRYPTOPP_INCLUDE_DIRS}
	${WINTUN_INCLUDE_DIRS}
)

if (ENABLE_USE_WINTUN)
	include_directories(${WINTUN_INCLUDE_DIRS})
endif()


link_libraries(
		Boost::coroutine
		Boost::context
		Boost::thread
		Boost::date_time
		Boost::program_options
		Boost::regex
		Boost::json

		fmt
		cryptopp-static

		${ZLIB_LIBRARIES}
)

if (WIN32)
	link_libraries(
		Secur32.lib
		Bcrypt.lib
		Winmm.lib
		Mswsock.lib
	)
elseif(UNIX AND NOT APPLE)
	# aviod link std::filesystem fail.
	set(std_fs_workaround "")
	if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9.0)
		set(std_fs_workaround stdc++fs)
	endif()

	link_libraries(
		${std_fs_workaround}
		${IPROUTE2_LIBRARIES}
	)
endif()

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

if (WIN32)
	set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG ${CMAKE_BINARY_DIR}/bin/debug)
	set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR}/bin/release)
endif()

add_subdirectory(avpn)

if (ENABLE_BUILD_TESTS)
	link_libraries(Boost::test)

	enable_testing()
	include_directories(${CMAKE_CURRENT_SOURCE_DIR}/avpn/include)
	add_subdirectory(unittests)
endif()

configure_file(avpn.service.in avpn.service)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/avpn.service DESTINATION /usr/lib/systemd/system/)
