add_subdirectory(avpn)
add_subdirectory(launcher)

if (ANDROID)
    # 查找 Android log 库.
    find_library(
        log-lib
        log
    )

    set(LOG_LIBRARY ${log-lib})

    # 设置 swig 输出目录.
    set(CMAKE_SWIG_OUTDIR ${CMAKE_BINARY_DIR}/swig)

    # link_libraries 会在所有目标中链接 log 库.
    link_libraries("${log-lib}")

    # 查找 swig, 并添加 android 子目录.
    find_package(SWIG)
    add_subdirectory(android)
endif()
