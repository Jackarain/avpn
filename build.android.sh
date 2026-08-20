#!/bin/bash
# arm64-v8a   armeabi-v7a    x86         x86_64
#
# 使用方法:
#
# ./build.android.sh <path-to-avpn> <path-to-ndk> <host-tag>
# 示例:
# ./build.android.sh ~/Documents/avpn /Users/jack/Library/Android/sdk/ndk/26.1.10909125
# ./build.android.sh ~/Documents/avpn /Users/jack/Library/Android/sdk/ndk/26.1.10909125 darwin-x86_64
# ./build.android.sh /root/avpn /root/ndk linux-x86_64
# ./build.android.sh ~/avpn ~/ndk windows-x86_64
#

ARCHITECTURES=("arm64-v8a" "armeabi-v7a" "x86" "x86_64")

AVPN_PATH=$1
NDK_PATH=$2
HOST_TAG=${3:-windows-x86_64}
BUILD_TYPE="Release"

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

for ARCH in "${ARCHITECTURES[@]}"
do
    cmake -S ${AVPN_PATH} -B android/$ARCH -DCMAKE_TOOLCHAIN_FILE=${NDK_PATH}/build/cmake/android.toolchain.cmake -DANDROID_ABI=${ARCH} -DANDROID_PLATFORM=android-19 -DCMAKE_BUILD_TYPE=${BUILD_TYPE} -G Ninja
    cmake --build android/$ARCH
    mkdir -p release/$ARCH
    cp android/$ARCH/bin/* release/$ARCH/
done

echo "Build finished."
