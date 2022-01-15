project(ethash)
set(PROJECT_VERSION 0.5.0-alpha.0)

option(ETHASH_FUZZING "Build with fuzzer instrumentation" OFF)
if(ETHASH_FUZZING)
    set(CMAKE_EXE_LINKER_FLAGS "-fsanitize=fuzzer-no-link ${CMAKE_EXE_LINKER_FLAGS}")
    add_compile_options(-fno-omit-frame-pointer -fsanitize=fuzzer,undefined,integer -fno-sanitize-recover=all)
endif()

add_subdirectory(lib/ethash)
set_target_properties(ethash PROPERTIES FOLDER "third_party")
