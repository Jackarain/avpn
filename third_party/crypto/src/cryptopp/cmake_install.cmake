# Install script for directory: /root/cryptopp-cmake/cryptopp

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr/local")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "Release")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Install shared libraries without execute permission?
if(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)
  set(CMAKE_INSTALL_SO_NO_EXE "0")
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

# Set path to fallback-tool for dependency-resolution.
if(NOT DEFINED CMAKE_OBJDUMP)
  set(CMAKE_OBJDUMP "/usr/bin/objdump")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "cryptopp_dev" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE STATIC_LIBRARY FILES "/root/cryptopp-cmake/build/cryptopp/libcryptopp.a")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "cryptopp_dev" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/cryptopp" TYPE FILE FILES
    "/root/cryptopp-cmake/build/cryptopp/3way.h"
    "/root/cryptopp-cmake/build/cryptopp/adler32.h"
    "/root/cryptopp-cmake/build/cryptopp/adv_simd.h"
    "/root/cryptopp-cmake/build/cryptopp/aes.h"
    "/root/cryptopp-cmake/build/cryptopp/aes_armv4.h"
    "/root/cryptopp-cmake/build/cryptopp/algebra.h"
    "/root/cryptopp-cmake/build/cryptopp/algparam.h"
    "/root/cryptopp-cmake/build/cryptopp/allocate.h"
    "/root/cryptopp-cmake/build/cryptopp/arc4.h"
    "/root/cryptopp-cmake/build/cryptopp/argnames.h"
    "/root/cryptopp-cmake/build/cryptopp/aria.h"
    "/root/cryptopp-cmake/build/cryptopp/arm_simd.h"
    "/root/cryptopp-cmake/build/cryptopp/asn.h"
    "/root/cryptopp-cmake/build/cryptopp/authenc.h"
    "/root/cryptopp-cmake/build/cryptopp/base32.h"
    "/root/cryptopp-cmake/build/cryptopp/base64.h"
    "/root/cryptopp-cmake/build/cryptopp/basecode.h"
    "/root/cryptopp-cmake/build/cryptopp/blake2.h"
    "/root/cryptopp-cmake/build/cryptopp/blowfish.h"
    "/root/cryptopp-cmake/build/cryptopp/blumshub.h"
    "/root/cryptopp-cmake/build/cryptopp/camellia.h"
    "/root/cryptopp-cmake/build/cryptopp/cast.h"
    "/root/cryptopp-cmake/build/cryptopp/cbcmac.h"
    "/root/cryptopp-cmake/build/cryptopp/ccm.h"
    "/root/cryptopp-cmake/build/cryptopp/chacha.h"
    "/root/cryptopp-cmake/build/cryptopp/chachapoly.h"
    "/root/cryptopp-cmake/build/cryptopp/cham.h"
    "/root/cryptopp-cmake/build/cryptopp/channels.h"
    "/root/cryptopp-cmake/build/cryptopp/cmac.h"
    "/root/cryptopp-cmake/build/cryptopp/config.h"
    "/root/cryptopp-cmake/build/cryptopp/config_align.h"
    "/root/cryptopp-cmake/build/cryptopp/config_asm.h"
    "/root/cryptopp-cmake/build/cryptopp/config_cpu.h"
    "/root/cryptopp-cmake/build/cryptopp/config_cxx.h"
    "/root/cryptopp-cmake/build/cryptopp/config_dll.h"
    "/root/cryptopp-cmake/build/cryptopp/config_int.h"
    "/root/cryptopp-cmake/build/cryptopp/config_misc.h"
    "/root/cryptopp-cmake/build/cryptopp/config_ns.h"
    "/root/cryptopp-cmake/build/cryptopp/config_os.h"
    "/root/cryptopp-cmake/build/cryptopp/config_ver.h"
    "/root/cryptopp-cmake/build/cryptopp/cpu.h"
    "/root/cryptopp-cmake/build/cryptopp/crc.h"
    "/root/cryptopp-cmake/build/cryptopp/cryptlib.h"
    "/root/cryptopp-cmake/build/cryptopp/darn.h"
    "/root/cryptopp-cmake/build/cryptopp/default.h"
    "/root/cryptopp-cmake/build/cryptopp/des.h"
    "/root/cryptopp-cmake/build/cryptopp/dh.h"
    "/root/cryptopp-cmake/build/cryptopp/dh2.h"
    "/root/cryptopp-cmake/build/cryptopp/dll.h"
    "/root/cryptopp-cmake/build/cryptopp/dmac.h"
    "/root/cryptopp-cmake/build/cryptopp/donna.h"
    "/root/cryptopp-cmake/build/cryptopp/donna_32.h"
    "/root/cryptopp-cmake/build/cryptopp/donna_64.h"
    "/root/cryptopp-cmake/build/cryptopp/donna_sse.h"
    "/root/cryptopp-cmake/build/cryptopp/drbg.h"
    "/root/cryptopp-cmake/build/cryptopp/dsa.h"
    "/root/cryptopp-cmake/build/cryptopp/eax.h"
    "/root/cryptopp-cmake/build/cryptopp/ec2n.h"
    "/root/cryptopp-cmake/build/cryptopp/eccrypto.h"
    "/root/cryptopp-cmake/build/cryptopp/ecp.h"
    "/root/cryptopp-cmake/build/cryptopp/ecpoint.h"
    "/root/cryptopp-cmake/build/cryptopp/elgamal.h"
    "/root/cryptopp-cmake/build/cryptopp/emsa2.h"
    "/root/cryptopp-cmake/build/cryptopp/eprecomp.h"
    "/root/cryptopp-cmake/build/cryptopp/esign.h"
    "/root/cryptopp-cmake/build/cryptopp/fhmqv.h"
    "/root/cryptopp-cmake/build/cryptopp/files.h"
    "/root/cryptopp-cmake/build/cryptopp/filters.h"
    "/root/cryptopp-cmake/build/cryptopp/fips140.h"
    "/root/cryptopp-cmake/build/cryptopp/fltrimpl.h"
    "/root/cryptopp-cmake/build/cryptopp/gcm.h"
    "/root/cryptopp-cmake/build/cryptopp/gf256.h"
    "/root/cryptopp-cmake/build/cryptopp/gf2_32.h"
    "/root/cryptopp-cmake/build/cryptopp/gf2n.h"
    "/root/cryptopp-cmake/build/cryptopp/gfpcrypt.h"
    "/root/cryptopp-cmake/build/cryptopp/gost.h"
    "/root/cryptopp-cmake/build/cryptopp/gzip.h"
    "/root/cryptopp-cmake/build/cryptopp/hashfwd.h"
    "/root/cryptopp-cmake/build/cryptopp/hc128.h"
    "/root/cryptopp-cmake/build/cryptopp/hc256.h"
    "/root/cryptopp-cmake/build/cryptopp/hex.h"
    "/root/cryptopp-cmake/build/cryptopp/hight.h"
    "/root/cryptopp-cmake/build/cryptopp/hkdf.h"
    "/root/cryptopp-cmake/build/cryptopp/hmac.h"
    "/root/cryptopp-cmake/build/cryptopp/hmqv.h"
    "/root/cryptopp-cmake/build/cryptopp/hrtimer.h"
    "/root/cryptopp-cmake/build/cryptopp/ida.h"
    "/root/cryptopp-cmake/build/cryptopp/idea.h"
    "/root/cryptopp-cmake/build/cryptopp/integer.h"
    "/root/cryptopp-cmake/build/cryptopp/iterhash.h"
    "/root/cryptopp-cmake/build/cryptopp/kalyna.h"
    "/root/cryptopp-cmake/build/cryptopp/keccak.h"
    "/root/cryptopp-cmake/build/cryptopp/lea.h"
    "/root/cryptopp-cmake/build/cryptopp/lsh.h"
    "/root/cryptopp-cmake/build/cryptopp/lubyrack.h"
    "/root/cryptopp-cmake/build/cryptopp/luc.h"
    "/root/cryptopp-cmake/build/cryptopp/mars.h"
    "/root/cryptopp-cmake/build/cryptopp/md2.h"
    "/root/cryptopp-cmake/build/cryptopp/md4.h"
    "/root/cryptopp-cmake/build/cryptopp/md5.h"
    "/root/cryptopp-cmake/build/cryptopp/mdc.h"
    "/root/cryptopp-cmake/build/cryptopp/mersenne.h"
    "/root/cryptopp-cmake/build/cryptopp/misc.h"
    "/root/cryptopp-cmake/build/cryptopp/modarith.h"
    "/root/cryptopp-cmake/build/cryptopp/modes.h"
    "/root/cryptopp-cmake/build/cryptopp/modexppc.h"
    "/root/cryptopp-cmake/build/cryptopp/mqueue.h"
    "/root/cryptopp-cmake/build/cryptopp/mqv.h"
    "/root/cryptopp-cmake/build/cryptopp/naclite.h"
    "/root/cryptopp-cmake/build/cryptopp/nbtheory.h"
    "/root/cryptopp-cmake/build/cryptopp/nr.h"
    "/root/cryptopp-cmake/build/cryptopp/oaep.h"
    "/root/cryptopp-cmake/build/cryptopp/oids.h"
    "/root/cryptopp-cmake/build/cryptopp/osrng.h"
    "/root/cryptopp-cmake/build/cryptopp/ossig.h"
    "/root/cryptopp-cmake/build/cryptopp/padlkrng.h"
    "/root/cryptopp-cmake/build/cryptopp/panama.h"
    "/root/cryptopp-cmake/build/cryptopp/pch.h"
    "/root/cryptopp-cmake/build/cryptopp/pkcspad.h"
    "/root/cryptopp-cmake/build/cryptopp/poly1305.h"
    "/root/cryptopp-cmake/build/cryptopp/polynomi.h"
    "/root/cryptopp-cmake/build/cryptopp/ppc_simd.h"
    "/root/cryptopp-cmake/build/cryptopp/pssr.h"
    "/root/cryptopp-cmake/build/cryptopp/pubkey.h"
    "/root/cryptopp-cmake/build/cryptopp/pwdbased.h"
    "/root/cryptopp-cmake/build/cryptopp/queue.h"
    "/root/cryptopp-cmake/build/cryptopp/rabbit.h"
    "/root/cryptopp-cmake/build/cryptopp/rabin.h"
    "/root/cryptopp-cmake/build/cryptopp/randpool.h"
    "/root/cryptopp-cmake/build/cryptopp/rc2.h"
    "/root/cryptopp-cmake/build/cryptopp/rc5.h"
    "/root/cryptopp-cmake/build/cryptopp/rc6.h"
    "/root/cryptopp-cmake/build/cryptopp/rdrand.h"
    "/root/cryptopp-cmake/build/cryptopp/rijndael.h"
    "/root/cryptopp-cmake/build/cryptopp/ripemd.h"
    "/root/cryptopp-cmake/build/cryptopp/rng.h"
    "/root/cryptopp-cmake/build/cryptopp/rsa.h"
    "/root/cryptopp-cmake/build/cryptopp/rw.h"
    "/root/cryptopp-cmake/build/cryptopp/safer.h"
    "/root/cryptopp-cmake/build/cryptopp/salsa.h"
    "/root/cryptopp-cmake/build/cryptopp/scrypt.h"
    "/root/cryptopp-cmake/build/cryptopp/seal.h"
    "/root/cryptopp-cmake/build/cryptopp/secblock.h"
    "/root/cryptopp-cmake/build/cryptopp/secblockfwd.h"
    "/root/cryptopp-cmake/build/cryptopp/seckey.h"
    "/root/cryptopp-cmake/build/cryptopp/seed.h"
    "/root/cryptopp-cmake/build/cryptopp/serpent.h"
    "/root/cryptopp-cmake/build/cryptopp/serpentp.h"
    "/root/cryptopp-cmake/build/cryptopp/sha.h"
    "/root/cryptopp-cmake/build/cryptopp/sha1_armv4.h"
    "/root/cryptopp-cmake/build/cryptopp/sha256_armv4.h"
    "/root/cryptopp-cmake/build/cryptopp/sha3.h"
    "/root/cryptopp-cmake/build/cryptopp/sha512_armv4.h"
    "/root/cryptopp-cmake/build/cryptopp/shacal2.h"
    "/root/cryptopp-cmake/build/cryptopp/shake.h"
    "/root/cryptopp-cmake/build/cryptopp/shark.h"
    "/root/cryptopp-cmake/build/cryptopp/simeck.h"
    "/root/cryptopp-cmake/build/cryptopp/simon.h"
    "/root/cryptopp-cmake/build/cryptopp/simple.h"
    "/root/cryptopp-cmake/build/cryptopp/siphash.h"
    "/root/cryptopp-cmake/build/cryptopp/skipjack.h"
    "/root/cryptopp-cmake/build/cryptopp/sm3.h"
    "/root/cryptopp-cmake/build/cryptopp/sm4.h"
    "/root/cryptopp-cmake/build/cryptopp/smartptr.h"
    "/root/cryptopp-cmake/build/cryptopp/sosemanuk.h"
    "/root/cryptopp-cmake/build/cryptopp/speck.h"
    "/root/cryptopp-cmake/build/cryptopp/square.h"
    "/root/cryptopp-cmake/build/cryptopp/stdcpp.h"
    "/root/cryptopp-cmake/build/cryptopp/strciphr.h"
    "/root/cryptopp-cmake/build/cryptopp/tea.h"
    "/root/cryptopp-cmake/build/cryptopp/threefish.h"
    "/root/cryptopp-cmake/build/cryptopp/tiger.h"
    "/root/cryptopp-cmake/build/cryptopp/trap.h"
    "/root/cryptopp-cmake/build/cryptopp/trunhash.h"
    "/root/cryptopp-cmake/build/cryptopp/ttmac.h"
    "/root/cryptopp-cmake/build/cryptopp/tweetnacl.h"
    "/root/cryptopp-cmake/build/cryptopp/twofish.h"
    "/root/cryptopp-cmake/build/cryptopp/vmac.h"
    "/root/cryptopp-cmake/build/cryptopp/wake.h"
    "/root/cryptopp-cmake/build/cryptopp/whrlpool.h"
    "/root/cryptopp-cmake/build/cryptopp/words.h"
    "/root/cryptopp-cmake/build/cryptopp/xed25519.h"
    "/root/cryptopp-cmake/build/cryptopp/xtr.h"
    "/root/cryptopp-cmake/build/cryptopp/xtrcrypt.h"
    "/root/cryptopp-cmake/build/cryptopp/xts.h"
    "/root/cryptopp-cmake/build/cryptopp/zdeflate.h"
    "/root/cryptopp-cmake/build/cryptopp/zinflate.h"
    "/root/cryptopp-cmake/build/cryptopp/zlib.h"
    )
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "cryptopp_dev" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/share/cmake/cryptopp/cryptopp-static-targets.cmake")
    file(DIFFERENT _cmake_export_file_changed FILES
         "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/share/cmake/cryptopp/cryptopp-static-targets.cmake"
         "/root/cryptopp-cmake/build/cryptopp/CMakeFiles/Export/b2240bf58d48ab81379cb5dc4149e5db/cryptopp-static-targets.cmake")
    if(_cmake_export_file_changed)
      file(GLOB _cmake_old_config_files "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/share/cmake/cryptopp/cryptopp-static-targets-*.cmake")
      if(_cmake_old_config_files)
        string(REPLACE ";" ", " _cmake_old_config_files_text "${_cmake_old_config_files}")
        message(STATUS "Old export file \"$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/share/cmake/cryptopp/cryptopp-static-targets.cmake\" will be replaced.  Removing files [${_cmake_old_config_files_text}].")
        unset(_cmake_old_config_files_text)
        file(REMOVE ${_cmake_old_config_files})
      endif()
      unset(_cmake_old_config_files)
    endif()
    unset(_cmake_export_file_changed)
  endif()
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/share/cmake/cryptopp" TYPE FILE FILES "/root/cryptopp-cmake/build/cryptopp/CMakeFiles/Export/b2240bf58d48ab81379cb5dc4149e5db/cryptopp-static-targets.cmake")
  if(CMAKE_INSTALL_CONFIG_NAME MATCHES "^([Rr][Ee][Ll][Ee][Aa][Ss][Ee])$")
    file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/share/cmake/cryptopp" TYPE FILE FILES "/root/cryptopp-cmake/build/cryptopp/CMakeFiles/Export/b2240bf58d48ab81379cb5dc4149e5db/cryptopp-static-targets-release.cmake")
  endif()
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "cryptopp_dev" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/share/cmake/cryptopp" TYPE FILE FILES
    "/root/cryptopp-cmake/cryptopp/cryptoppConfig.cmake"
    "/root/cryptopp-cmake/build/cryptopp/cryptoppConfigVersion.cmake"
    )
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "cryptopp_dev" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/share/pkgconfig" TYPE FILE FILES "/root/cryptopp-cmake/build/cryptopp/cryptopp.pc")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/cryptest" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/cryptest")
    file(RPATH_CHECK
         FILE "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/cryptest"
         RPATH "")
  endif()
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/bin" TYPE EXECUTABLE FILES "/root/cryptopp-cmake/build/cryptopp/cryptest")
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/cryptest" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/cryptest")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/usr/bin/strip" "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/bin/cryptest")
    endif()
  endif()
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  include("/root/cryptopp-cmake/build/cryptopp/CMakeFiles/cryptest.dir/install-cxx-module-bmi-Release.cmake" OPTIONAL)
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/share/cryptopp" TYPE DIRECTORY FILES "/root/cryptopp-cmake/build/cryptopp/TestData")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/share/cryptopp" TYPE DIRECTORY FILES "/root/cryptopp-cmake/build/cryptopp/TestVectors")
endif()

