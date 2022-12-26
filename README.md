aVPN
====


aVPN是目前世界唯一基于 **现代c++** 的企业级虚拟专用网络实现，主要用于解决企业跨区域虚拟专用网络组建，并保证极高的稳定性。aVPN展示了在现代c++的支持下，编写为数不多的代码，即实现一个功能完善且强大并跨各大主流平台的虚拟专用网络，它不仅具有虚拟网络组建的功能，还能在丢包较高的环境下，通过纠错算法，保证通信的可靠，且具有降低延迟等特性。

<br>

***
<br>

### 开发环境要求：

<br>

1. 项目基于 **c++20** 开发，编译器要求gcc-10.3.1或更高，clang-13或更高，msvc-2019或更高。

2. cmake-3.20或更高。

***
<br>

### Linux 平台下编译:

<br>

首先执行git克隆源码

```
git clone <source url>
```

然后进入源码目录，执行如下操作：

```
mkdir build && cd build
```
```
cmake .. -DCMAKE_BUILD_TYPE=Debug
```

上面命令中，CMAKE_BUILD_TYPE=Debug指定了编译为Debug的类型，如果需要更好的性能，则需要编译为Release。

在cmake命令成功执行完成后，开始输入以下命令编译：

```
make
```

通常编译过程不会出现问题，如果出现任何问题，请联系作者，并将完整的错误信息保留并报告给作者。

成功编译后，可执行程序将在bin目录下生成。

avpn的cmake配置了默认编译选项参数，如果有必要，可以参考cmake源文件中的选项开关尝试不同功能，比如可以选择使用mimalloc、tcmalloc等分配器，比如使用更快的mold链接器，比如打开systemd的日志开关，便可将日志记录到systemd.journal中。

***
<br>

### 编译 Android 平台:

<br>

首先执行git克隆源码

```
git clone <source url>
```

然后进入源码目录，执行如下操作：

```
mkdir build && cd build
```
```
cmake \
-DANDROID_NDK=${ANDROID_NDK} \
-DANDROID_ABI=arm64-v8a  \
-DANDROID_ARM_NEON=ON \
-DANDROID_PLATFORM=android-23 \
-DCMAKE_ANDROID_ARCH_ABI=arm64-v8a       \
-DCMAKE_ANDROID_NDK=${ANDROID_NDK} \
-DCMAKE_TOOLCHAIN_FILE=${ANDROID_NDK}/build/cmake/android.toolchain.cmake \
-DCMAKE_BUILD_TYPE=Debug \
-DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
-DCMAKE_SYSTEM_NAME=Android \
-DCMAKE_SYSTEM_VERSION=23 \
-DCMAKE_EXE_LINKER_FLAGS="-static" \
.. \
-G Ninja
```

上面命令中 ${ANDROID_NDK} 替换为 Adnroid NDK 目录，CMAKE_ANDROID_ARCH_ABI、ANDROID_ABI 和 ANDROID_PLATFORM
根据需要设定，CMAKE_BUILD_TYPE=Debug指定了编译为Debug的类型，如果需要更好的性能，则需要编译为Release。

在cmake命令成功执行完成后，开始输入以下命令编译：

```
ninja
```

成功编译后，可执行程序将在bin目录下生成，可在 android 的 termux 中运行，当然同时也需要 root 权限。

***
<br>

### 通过Docker编译构建

<br>
avpn提供了一个更为简单的编译方式，在任何安装有docker环境下，进入avpn源码目录，可以执行如下命令，创建一个docker并编译avpn：

```
docker build -t avpn:v1 .
```
编译完成后，将生成一个无任何系统依赖的avpn可执行程序，因为它使用了静态链接到一个叫作 musl 的 libc，这样编译出来的avpn可执行程序将可运行在无glibc的环境下如 initramfs 中，使用musl的最大好处就是可以无需关心系统上过于古老的glibc而导致无法运行的问题。

***
<br>

### Windows 平台下编译

<br>
同样先执行git克隆源码，上面已经介绍过了，这里略过，在git克隆的源码目录下建立一个build目录，然后执行以下命令：

```
cmake.exe ..
```

成功完成cmake后，cmake将生成vc的项目文件，然后执行以下命令编译avpn：

```
msbuild avpn.sln /p:Configuration="Debug"
```

在完成编译后，同样会生成一个avpn.exe在bin目录，当然也可以直接使用msvc打开avpn.sln项目文件，通过菜单上的编译命令进行编译。

***
<br>

### MinGW 编译

<br>
在安装好MinGW工具链的Linux平台上执行：

```
cmake -DCMAKE_TOOLCHAIN_FILE=../cmake/mingw.cmake .. -DCMAKE_EXE_LINKER_FLAGS="-static" -DCMAKE_BUILD_TYPE=Release -DENABLE_USE_WINTUN=OFF -G Ninja
```

成功完成cmake后，然后执行以下命令编译avpn：

```
ninja
```

在完成编译后，同样会生成一个avpn.exe在bin/release。

***
<br>

### 其它平台交叉编译

<br>
这里以我的 MediaTek MT7621 为例，在 x86_64 linux 平台交叉编译目标为 openwrt mipsel 架构，libc 为 musl，先下载编译工具链：
```
wget https://downloads.openwrt.org/releases/22.03.2/targets/ramips/mt7621/openwrt-sdk-22.03.2-ramips-mt7621_gcc-11.2.0_musl.Linux-x86_64.tar.xz
```
将 toolchain 相关目录添加到 PATH中，以便调用 gcc 编译，我这里执行：

```
export STAGING_DIR=${OPENWRT_SDK}/staging_dir
export PATH=$PATH:${OPENWRT_SDK}/staging_dir/toolchain-mipsel_24kc_gcc-11.2.0_musl/bin
```
${OPENWRT_SDK} 是sdk的解压目录，然后在 avpn 源码目录中创建 build 目录并执行 cmake：
```
ccmake .. -DCOMPILER=mipsel-openwrt-linux -DCMAKE_TOOLCHAIN_FILE=../cmake/mips.cmake -DCMAKE_SYSROOT=${OPENWRT_SDK}/staging_dir/host -DCMAKE_BUILD_WITH_INSTALL_RPATH=ON -DCMAKE_BUILD_TYPE=Release -G Ninja
```
在这个步骤中，一些平台有必要打开一些编译开关，如 ENABLE_LINKE_TO_LIBATOMIC 库，以及关闭 ENABLE_STATIC_LINK_TO_GCC，在完成 cmake 后生成Makefile，然后开始编译：
```
ninja
```
没有问题的话，avpn 将会编译生成在 build 的 bin 目录下，拷贝到 openwrt 机器上就可以运行了。

其它架构平台可以参考 avpn 中的 cmake 目录下的 cross.cmake 进行相关修改。

***
<br>

### 功能参数介绍
<br>

除config、genkey、pubkey参数之外，所有参数均可在命令行或配置文件中，在下面一一解释各参数相关作用

|  参    数      | 用法解释  |
|  --------      | -----    |
| config |		可配置一个参数配置文件，如vpn.conf，配置文件内容以key=value的ini配置文件的方式保存，如identity=server。|
| identity |		指定avpn运行角色是server或client，avpn的客户端和服务器是同一程序，server或是client，主要由这个参数指定avpn的运行身份。|
| tun |		指定tun虚拟网卡名称，在windows上为虚拟网卡的具体名字（有时需要注意空格，比如 "以太网 3" 中间的空格不能丢失），在类unix平台，avpn将会自动创建虚拟网卡，windows平台使用wintun同样也会自动创建虚拟网卡。|
| upstream |		运行身份作为client时，这个参数指定了目标server和端口，目前版本实现由udp/tcp必须同时运行，所以需要同时指定udp和ws的地址和端口。如--upstream ws://example.com:33333 udp://example.com:33333|
| publickey<br>privatekey |		作为server时，指定ecdh的私钥(base64编码)，作为client时，指定为server的ecdh公钥信息(base64编码)。client 本身的密钥对由系统自动随机生成，在握手时通过协议传输公钥到server。server 通过握手协议拿到client的公钥，及本参数指定的密钥对，协商出解密密钥。client 通过本参数指定的server的公钥，及自己生成的密钥对，协商出解密密钥。|
| genkey |		随机生成一个base64编码的密钥（等同wg genkey）。|
| pubkey |		给定的一个私钥，计算它的公钥，私钥以base64编码并从stdin输入，公钥将以base64编码输出stdout，对应的私钥生成可使用genkey（等同wg）。|
| socks_server |		这个参数指定avpn内部运行一个或多个socks server。|
| socks_interface |		内部运行socks server时，指定对外发起连接时，所bind的interface。|
| socks_userid<br>socks_passwd |		指定socks server的userid/passwd。|
| socks_next_proxy |		作为socks server时指定下一个socks server以实现client可跨过2层socks server的目的，这对client来说是无感的。|
| socks_next_proxy_ssl |		指定socks_next_proxy时，与下一层socks server通信时是否采用ssl加密通信。|
| ssl_certificate_dir |		作为socks server时，指定ssl证书目录，固定证书相关文件名为：ssl_crt.pem、ssl_key.pem、ssl_dh.pem、ssl_crt.pwd。|
| tcp |		运行身份作为server时，这个参数指定了监听的tcp地址和端口，一般如--tcp "[::0]:33333"表示tcp监听在ipv6地下::0下的33333端口，再如--tcp "0.0.0.0:33333"表示tcp监听在ipv4地下0.0.0.0下的33333端口。|
| udp |		运行身份作为server时，这个参数指定了监听的udp地址和端口，一般如--udp "[::0]:33333"表示udp监听在ipv6地下::0下的33333端口，再如--udp "0.0.0.0:33333"表示udp监听在ipv4地下0.0.0.0下的33333端口。|
| data_shards <br> parity_shards |		这2个参数是fec参数，主要指定多少份data_shards和多少份parity_shards组成一组fec数据，也就是说，在发送data_shards份数据的同时，携带parity_shards份冗余数据。fec算法可以允许任意最多丢失parity_shards份数据。|
| mode |		数据发送模式，取值0: 只用 udp，1: tcp/udp 混合，2: 只用 tcp主要由这3种模式。如果udp模式，则在延迟上一般远小于tcp，但是在udp丢包特别严重的ISP网络环境中，tcp有时更有效率。|
| compress |		启用数据压缩算法。|
| keepalive |		设置心跳时间间隔，单位ms。|
| pushroute |		推送路由到client，当运行身份为server时，向client推送路由。一般格式为"TARGET MASK GATEWAY METRIC"，其中METRIC可省略，也可以使用CIDR格式，如："TARGET/32 GATEWAY METRIC"。|
| pushdns |		推送DNS到client。|
| passbyvpn |		通过server配置此参数，所有client将默认所有流量将通过server传输。|
| noroute |		推送路由到client的所有路由和DNS将被忽略。|
| subnet |		在服务端上指定虚拟的子网网段，默认为"10.0.0.1/16"。|
| c2c |		是否允许client之间互相通过虚拟子网网络通信，默认是允许。|
| controller |		指定控制器的，控制器是一个用于通过本地websocket服务控制avpn开启或关闭，或者获取网络速率的，比如在flutter中开启一个websocket服务，服务端口为5656，那么启动avpn的时候使用 --controller 5656就可以让avpn自动连接到flutter中的服务，flutter通过websocket连接控制avpn。|
| disable_logs |		关闭日志写入。|
| writepid |		将pid写入指定的文件。|
| post_up |		在虚拟网卡设备就绪后运行一个指定的命令。|

