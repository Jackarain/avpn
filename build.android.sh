#!/bin/bash
# arm64-v8a   armeabi-v7a    x86         x86_64
#
# 使用方法:
#
# ./build.android.sh <path-to-avpn> <path-to-ndk> [host-tag] [architecture]
# 示例:
# ./build.android.sh ~/Documents/avpn /Users/jack/Library/Android/sdk/ndk/26.1.10909125
# ./build.android.sh ~/Documents/avpn /Users/jack/Library/Android/sdk/ndk/26.1.10909125 darwin-x86_64 arm64-v8a
# ./build.android.sh /root/avpn /root/ndk linux-x86_64 armeabi-v7a
# ./build.android.sh ~/avpn ~/ndk windows-x86_64
#

set -e

AVPN_PATH=$1
NDK_PATH=$2
HOST_TAG=${3:-windows-x86_64}
TARGET_ARCH=$4
BUILD_TYPE="Release"

# 指定了具体架构则只编译该架构, 否则默认编译所有架构.
if [ -n "$TARGET_ARCH" ]; then
    ARCHITECTURES=("$TARGET_ARCH")
else
    ARCHITECTURES=("arm64-v8a" "armeabi-v7a" "x86" "x86_64")
fi

kernel=$(uname -s)

if [ "$kernel" = "Linux" ]; then
    HOST_TAG=linux-x86_64
elif [ "$kernel" = "Darwin" ]; then
    HOST_TAG=darwin-x86_64
elif [ "$kernel" = "MINGW64_NT-10.0" ]; then
    HOST_TAG=windows-x86_64
fi

echo "AVPN_PATH: ${AVPN_PATH}"
echo "NDK_PATH: ${NDK_PATH}"
echo "HOST_TAG: ${HOST_TAG}"
echo "ARCHITECTURES: ${ARCHITECTURES[*]}"

# Android 客户端工程 (Flutter), 存在时把编译产物同步过去.
ANDROID_APP_DIR=${AVPN_PATH}/avpn/android/xavpn/android/app
JAVA_DIR=${ANDROID_APP_DIR}/src/main/java/com/jackarain
# 源码目录的绝对路径, 用于识别其它仓库遗留的构建目录.
AVPN_ABS=$(cd "${AVPN_PATH}" && pwd)

for ARCH in "${ARCHITECTURES[@]}"
do
    # 构建目录来自其它源码路径时 CMake 会配置失败, 先清理再重新生成.
    if [ -f android/$ARCH/CMakeCache.txt ] && ! grep -q "^CMAKE_HOME_DIRECTORY:INTERNAL=${AVPN_ABS}$" android/$ARCH/CMakeCache.txt; then
        echo "clean stale build dir: android/$ARCH"
        rm -rf android/$ARCH
    fi
    cmake -S ${AVPN_PATH} -B android/$ARCH -DCMAKE_TOOLCHAIN_FILE=${NDK_PATH}/build/cmake/android.toolchain.cmake -DANDROID_ABI=${ARCH} -DANDROID_PLATFORM=android-19 -DCMAKE_BUILD_TYPE=${BUILD_TYPE} -DENABLE_USE_OPENSSL=OFF -DENABLE_USE_BORINGSSL=ON -G Ninja
    cmake --build android/$ARCH
    mkdir -p release/$ARCH
    # 桌面端可执行文件 (非 Android 场景).
    if ls android/$ARCH/bin/* >/dev/null 2>&1; then
        ${NDK_PATH}/toolchains/llvm/prebuilt/${HOST_TAG}/bin/llvm-strip android/$ARCH/bin/*
        cp android/$ARCH/bin/* release/$ARCH/
    fi
    # SWIG 库 (libxavpn.so) 与生成的 Java 包装文件.
    ${NDK_PATH}/toolchains/llvm/prebuilt/${HOST_TAG}/bin/llvm-strip android/$ARCH/lib/libxavpn.so
    cp android/$ARCH/lib/libxavpn.so release/$ARCH/
    # 同步 libxavpn.so 到 Android 客户端工程 (Flutter), 避免 APK 编译时缺少 .so.
    if [ -d "${ANDROID_APP_DIR}" ]; then
        mkdir -p ${ANDROID_APP_DIR}/src/main/jniLibs/${ARCH}
        cp android/$ARCH/lib/libxavpn.so ${ANDROID_APP_DIR}/src/main/jniLibs/${ARCH}/libxavpn.so
        echo "copied libxavpn.so -> ${ANDROID_APP_DIR}/src/main/jniLibs/${ARCH}/libxavpn.so"
        # 同步 SWIG 生成的 Java 包装类, 保持与 .so 的 JNI 签名一致.
        if ls android/$ARCH/swig/xavpn*.java >/dev/null 2>&1; then
            mkdir -p ${JAVA_DIR}
            cp android/$ARCH/swig/xavpn*.java ${JAVA_DIR}/
            echo "copied xavpn java -> ${JAVA_DIR}"
        fi
    fi
    mkdir -p outputs/binaries
    if [ -d "android/$ARCH/swig" ]; then
        cp -r android/$ARCH/swig/* outputs/
    fi
    cp -r release/* outputs/binaries/
done

echo "Build finished."
