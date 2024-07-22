# CMake generated Testfile for 
# Source directory: /root/cryptopp-cmake/cryptopp
# Build directory: /root/cryptopp-cmake/build/cryptopp
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test([=[cryptopp-build_cryptest]=] "/usr/bin/cmake" "--build" "/root/cryptopp-cmake/build" "--target" "cryptest" "--config" "Release")
set_tests_properties([=[cryptopp-build_cryptest]=] PROPERTIES  FIXTURES_SETUP "cryptest-build" LABELS "cryptopp;cryptopp-cryptest" _BACKTRACE_TRIPLES "/root/cryptopp-cmake/cryptopp/CMakeLists.txt;1465;add_test;/root/cryptopp-cmake/cryptopp/CMakeLists.txt;0;")
add_test([=[cryptopp-cryptest]=] "/root/cryptopp-cmake/build/cryptopp/cryptest" "v")
set_tests_properties([=[cryptopp-cryptest]=] PROPERTIES  FIXTURES_REQUIRED "cryptest-build" LABELS "cryptopp;cryptopp-cryptest" WORKING_DIRECTORY "/root/cryptopp-cmake/build/cryptopp" _BACKTRACE_TRIPLES "/root/cryptopp-cmake/cryptopp/CMakeLists.txt;1478;add_test;/root/cryptopp-cmake/cryptopp/CMakeLists.txt;0;")
add_test([=[cryptopp-cryptest-extensive]=] "/root/cryptopp-cmake/build/cryptopp/cryptest" "tv" "all")
set_tests_properties([=[cryptopp-cryptest-extensive]=] PROPERTIES  FIXTURES_CLEANUP "cryptest-build" LABELS "cryptopp;cryptopp-cryptest" WORKING_DIRECTORY "/root/cryptopp-cmake/build/cryptopp" _BACKTRACE_TRIPLES "/root/cryptopp-cmake/cryptopp/CMakeLists.txt;1490;add_test;/root/cryptopp-cmake/cryptopp/CMakeLists.txt;0;")
