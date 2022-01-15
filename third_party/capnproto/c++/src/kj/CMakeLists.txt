
# kj ===========================================================================

set(kj_sources_lite
  array.c++
  common.c++
  debug.c++
  exception.c++
  io.c++
  memory.c++
  mutex.c++
  string.c++
  hash.c++
  table.c++
  thread.c++
  time.c++
  main.c++
  arena.c++
  test-helpers.c++
  units.c++
  encoding.c++
)
set(kj_sources_heavy
  refcount.c++
  string-tree.c++
  time.c++
  filesystem.c++
  filesystem-disk-unix.c++
  filesystem-disk-win32.c++
  parse/char.c++
)
if(NOT CAPNP_LITE)
  set(kj_sources ${kj_sources_lite} ${kj_sources_heavy})
else()
  set(kj_sources ${kj_sources_lite})
endif()

set(kj_headers
  common.h
  units.h
  memory.h
  refcount.h
  array.h
  vector.h
  string.h
  string-tree.h
  hash.h
  table.h
  map.h
  encoding.h
  exception.h
  debug.h
  arena.h
  io.h
  tuple.h
  one-of.h
  function.h
  mutex.h
  thread.h
  threadlocal.h
  filesystem.h
  time.h
  main.h
  windows-sanity.h
)
set(kj-parse_headers
  parse/common.h
  parse/char.h
)
set(kj-std_headers
  std/iostream.h
)
add_library(kj ${kj_sources})
add_library(CapnProto::kj ALIAS kj)
# TODO(cleanup): Use cxx_std_14 once it's safe to require cmake 3.8.
target_compile_features(kj PUBLIC cxx_generic_lambdas)

if(UNIX AND NOT ANDROID)
  target_link_libraries(kj PUBLIC pthread)
endif()
#make sure the lite flag propagates to all users (internal + external) of this library
target_compile_definitions(kj PUBLIC ${CAPNP_LITE_FLAG})
#make sure external consumers don't need to manually set the include dirs
target_include_directories(kj INTERFACE
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>
  $<INSTALL_INTERFACE:include>
)
# Ensure the library has a version set to match autotools build
set_target_properties(kj PROPERTIES VERSION ${VERSION})
install(TARGETS kj ${INSTALL_TARGETS_DEFAULT_ARGS})
install(FILES ${kj_headers} DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/kj")
install(FILES ${kj-parse_headers} DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/kj/parse")
install(FILES ${kj-std_headers} DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/kj/std")

set(kj-async_sources
  async.c++
  async-unix.c++
  async-win32.c++
  async-io-win32.c++
  async-io.c++
  async-io-unix.c++
  timer.c++
)
set(kj-async_headers
  async-prelude.h
  async.h
  async-inl.h
  async-unix.h
  async-win32.h
  async-io.h
  timer.h
)
if(NOT CAPNP_LITE)
  add_library(kj-async ${kj-async_sources})
  add_library(CapnProto::kj-async ALIAS kj-async)
  target_link_libraries(kj-async PUBLIC kj)
  if(UNIX)
    # external clients of this library need to link to pthreads
    target_compile_options(kj-async INTERFACE "-pthread")
  elseif(WIN32)
    target_link_libraries(kj-async PUBLIC ws2_32)
  endif()
  # Ensure the library has a version set to match autotools build
  set_target_properties(kj-async PROPERTIES VERSION ${VERSION})
  install(TARGETS kj-async ${INSTALL_TARGETS_DEFAULT_ARGS})
  install(FILES ${kj-async_headers} DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/kj")
endif()

# kj-http ======================================================================

set(kj-http_sources
  compat/url.c++
  compat/http.c++
)
set(kj-http_headers
  compat/url.h
  compat/http.h
)
if(NOT CAPNP_LITE)
  add_library(kj-http ${kj-http_sources})
  add_library(CapnProto::kj-http ALIAS kj-http)
  target_link_libraries(kj-http PUBLIC kj-async kj)
  # Ensure the library has a version set to match autotools build
  set_target_properties(kj-http PROPERTIES VERSION ${VERSION})
  install(TARGETS kj-http ${INSTALL_TARGETS_DEFAULT_ARGS})
  install(FILES ${kj-http_headers} DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/kj/compat")
endif()

# kj-tls ======================================================================
set(kj-tls_sources
  compat/readiness-io.c++
  compat/tls.c++
)
set(kj-tls_headers
  compat/readiness-io.h
  compat/tls.h
)
if(NOT CAPNP_LITE)
  add_library(kj-tls ${kj-tls_sources})
  add_library(CapnProto::kj-tls ALIAS kj-tls)
  target_link_libraries(kj-tls PUBLIC kj-async)
  if (WITH_OPENSSL)
    target_compile_definitions(kj-tls PRIVATE KJ_HAS_OPENSSL)
    target_link_libraries(kj-tls PRIVATE OpenSSL::SSL OpenSSL::Crypto)
  endif()
  # Ensure the library has a version set to match autotools build
  set_target_properties(kj-tls PROPERTIES VERSION ${VERSION})
  install(TARGETS kj-tls ${INSTALL_TARGETS_DEFAULT_ARGS})
  install(FILES ${kj-tls_headers} DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/kj/compat")
endif()

# kj-gzip ======================================================================

set(kj-gzip_sources
  compat/gzip.c++
)
set(kj-gzip_headers
  compat/gzip.h
)
if(NOT CAPNP_LITE)
  add_library(kj-gzip ${kj-gzip_sources})
  add_library(CapnProto::kj-gzip ALIAS kj-gzip)

  find_package(ZLIB)
  if(ZLIB_FOUND)
    add_definitions(-D KJ_HAS_ZLIB=1)
    include_directories(${ZLIB_INCLUDE_DIRS})
    target_link_libraries(kj-gzip PUBLIC kj-async kj ${ZLIB_LIBRARIES})
  endif()

  # Ensure the library has a version set to match autotools build
  set_target_properties(kj-gzip PROPERTIES VERSION ${VERSION})
  install(TARGETS kj-gzip ${INSTALL_TARGETS_DEFAULT_ARGS})
  install(FILES ${kj-gzip_headers} DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/kj/compat")
endif()
