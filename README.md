aVPN
====


一个使用 C++20 的 VPN 的高性能实现, 基于 Boost.Asio 协程.

aVPN 是目前世界唯一基于**现代 C++** 的企业级虚拟专用网络实现，主要用于解决企业跨区域虚拟专用网络组建，并保证极高的稳定性。aVPN 展示了在现代 C++ 的支持下，编写为数不多的代码，即实现一个功能完善且强大并跨各大主流平台的虚拟专用网络，它不仅具有虚拟网络组建的功能，还能在丢包较高的环境下，通过纠错算法，保证通信的可靠，且具有降低延迟等特性。

## 支持平台

- Linux: /dev/net/tun.
- macOS: utun 内核控制.
- Windows: wintun 驱动 (tun 通过 wintun 实现).

## 开发环境要求

- 项目基于 C++20 开发，编译器要求 gcc-10.3.1 或更高，clang-13 或更高，msvc-2019 或更高。
- cmake-3.16 或更高。

## Linux 平台下编译

首先执行 git 克隆源码：

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

上面命令中，`CMAKE_BUILD_TYPE=Debug` 指定了编译为 Debug 类型，如果需要更好的性能，则需要编译为 Release。

在 cmake 命令成功执行完成后，开始输入以下命令编译：

```
make
```

通常编译过程不会出现问题，如果出现任何问题，请联系作者，并将完整的错误信息保留并报告给作者。

成功编译后，可执行程序将在 `bin` 目录下生成。

avpn 的 cmake 配置了默认编译选项参数，如果有必要，可以参考 cmake 源文件中的选项开关尝试不同功能，比如可以选择使用 mimalloc、tcmalloc 等分配器，比如使用更快的 mold 链接器，比如打开 systemd 的日志开关，便可将日志记录到 systemd.journal 中。

## Windows 平台下编译

在 git 克隆的源码目录下建立一个 build 目录，然后执行以下命令：

```
cmake.exe ..
```

成功完成 cmake 后，cmake 将生成 vc 的项目文件，然后执行以下命令编译 avpn：

```
msbuild avpn.sln /p:Configuration="Debug"
```

在完成编译后，同样会生成一个 `avpn.exe` 在 bin 目录，当然也可以直接使用 msvc 打开 avpn.sln 项目文件，通过菜单上的编译命令进行编译。

## Windows 构建 (MinGW-w64)

```sh
mkdir build && cd build
cmake -G Ninja -DCMAKE_TOOLCHAIN_FILE=../cmake/mingw.cmake \
	-DENABLE_USE_WINTUN=ON -DENABLE_USE_BORINGSSL=ON ..
ninja
```

- `avpn.exe` 内嵌 wintun 驱动 (wintun.sys/inf/cat), 首次运行自动通过 pnputil 安装.
- `wintun.dll` 由构建脚本拷贝到输出目录, 运行时动态加载.
- FEC 在 Windows x64 上使用 SSSE3/AVX2 运行时分派加速 (MinGW 与 MSVC 均支持).
- 在完成编译后，同样会生成一个 `avpn.exe` 在 bin/release。

## 其它平台交叉编译

这里以 MediaTek MT7621 为例，在 x86_64 linux 平台交叉编译目标为 openwrt mipsel 架构，libc 为 musl，先下载编译工具链：

```
wget https://downloads.openwrt.org/releases/22.03.2/targets/ramips/mt7621/openwrt-sdk-22.03.2-ramips-mt7621_gcc-11.2.0_musl.Linux-x86_64.tar.xz
```

将 toolchain 相关目录添加到 PATH 中，以便调用 gcc 编译，这里执行：

```
export STAGING_DIR=${OPENWRT_SDK}/staging_dir
export PATH=$PATH:${OPENWRT_SDK}/staging_dir/toolchain-mipsel_24kc_gcc-11.2.0_musl/bin
```

${OPENWRT_SDK} 是 sdk 的解压目录，然后在 avpn 源码目录中创建 build 目录并执行 cmake：

```
ccmake .. -DCOMPILER=mipsel-openwrt-linux -DCMAKE_SYSTEM_PROCESSOR=mips32 -DCMAKE_TOOLCHAIN_FILE=../cmake/cross.cmake -DCMAKE_BUILD_WITH_INSTALL_RPATH=ON -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DCMAKE_BUILD_TYPE=Release -G Ninja
```

在这个步骤中，一些平台有必要打开一些编译开关，如 `ENABLE_LINKE_TO_LIBATOMIC`，以及关闭 `ENABLE_STATIC_LINK_TO_GCC`，在完成 cmake 后生成构建文件，然后开始编译：

```
ninja
```

没有问题的话，avpn 将会编译生成在 build 的 bin 目录下，拷贝到 openwrt 机器上就可以运行了。

其它架构平台可以参考 avpn 中的 cmake 目录下的 cross.cmake 进行相关修改。

## Docker 构建

当前仓库暂未提供 Dockerfile；如需要容器化构建，可自行编写 Dockerfile，仓库已包含 `.dockerignore`（忽略 build/ 目录）。

## 运行

网关 (Windows):

```sh
avpn.exe --ifdev wintun --subnet 10.9.0.0/16 --udp_listen 0.0.0.0:19090 \
	--private_key <key> --pkl <peer-pubkey> --data_shards 12 --parity_shards 4
```

客户端 (Windows):

```sh
avpn.exe --ifdev wintun --nexthop <server-ip>:19090 \
	--private_key <key> --pkl <peer-pubkey> --data_shards 12 --parity_shards 4
```

Linux 下使用相同的参数，只需将 `--ifdev wintun` 替换为 `--ifdev tun0`。

## Launcher（WebUI 实例管理器）

`launcher` 用于创建并管理多个 `avpn` 实例：通过内置 WebUI 完成实例的
创建/启停/删除、配置修改、状态监控与日志查看，实例配置持久化在
`data_dir/instances.json`，运行效果如下图所示：

<img width="1155" height="710" alt="image" src="https://github.com/user-attachments/assets/646f8254-234b-46fd-8c34-2cae18b14cd8" />


### 构建

WebUI 使用 React/Vite 构建，产物在编译期内嵌进 `launcher` 可执行文件，
因此需先构建 WebUI 再编译 launcher：

```sh
cd webui
npm install
npm run build        # 产物输出到 ../apps/launcher/webui
cd ..

cmake -G Ninja -B build -DCMAKE_BUILD_TYPE=Release
ninja -C build launcher
```

生成的可执行文件在 `build/bin/launcher`。

### 运行

```sh
./build/bin/launcher --avpn ./build/bin/avpn --data_dir /tmp/launcher_data
```

launcher 主要参数:

| 参数 | 说明 |
| --- | --- |
| `--listen addr` | WebUI HTTP 监听地址，默认 `0.0.0.0:18080` |
| `--avpn path` | `avpn` 可执行文件路径，默认当前目录下的 `avpn`，其次在 `$PATH` 中查找 |
| `--data_dir dir` | 实例配置持久化目录，默认 `launcher_data` |
| `--webui_user user` | 可选，WebUI HTTP Basic 认证用户名 |
| `--webui_password pass` | 可选，WebUI HTTP Basic 认证密码 |
| `--ssl_certificate_dir path` | 可选，SSL 证书目录；指定后 WebUI 以 HTTPS 提供服务（证书不可用时自动降级为明文 HTTP） |
| `--no_kill_on_exit` | 退出 launcher 时不停止已启动的 avpn 实例 |

launcher 启动后，浏览器访问 `http://<host>:18080/` 即可打开 WebUI。
launcher 会自动为每个实例生成控制通道 URL（`--launcher ws://.../rpc`），
通过 WebSocket + JSON-RPC 采集实例运行状态与日志，无需手工配置。

## 功能参数介绍

除 genkey 外，所有参数均可在命令行或配置文件（--config）中指定，配置文件以 key=value 的格式保存。下面逐一解释各参数的作用：

| 参数 | 说明 |
| --- | --- |
| `--help` | 显示帮助信息并退出。 |
| `--config <file>` | 从指定配置文件加载选项，配置文件为 key=value 格式。 |
| `--logs_path <dir>` | 指定日志文件目录。 |
| `--disable_logs` | 关闭日志输出。 |
| `--ifdev <dev>` | 指定 tun 虚拟网卡名称，如 tun0；Windows 下使用 wintun 虚拟网卡。 |
| `--ptun_fd <fd>` | 使用外部传入的 tun 设备文件描述符（如通过 SCM_RIGHTS 传递），-1 表示不使用。 |
| `--utun_fd <fd>` | 通过 Unix Domain Datagram Socket 以 IPC 方式读写 tun 设备时的 fd，-1 表示不使用。 |
| `--launcher <ws://ip:port>` | 控制服务地址，avpn 主动连接该 WebSocket 服务并接受控制命令。 |
| `--nexthop <ip:port>` | client 端指定下一跳 VPN 服务器地址和端口，gateway 端为空。 |
| `--tcp_listen <ip:port>` | server 端 TCP 监听地址，可多次指定。 |
| `--udp_listen <ip:port>` | server 端 UDP 监听地址，可多次指定。 |
| `--genkey` | 生成一个新的密钥对，将私钥和公钥输出到 stdout。 |
| `--private_key <key>` | 本机私钥（base64 编码）。 |
| `--public_key <key>` | 本机公钥（base64 编码）。 |
| `--pkl <key>` | 远端公钥列表（base64 编码），可多次指定。 |
| `--mtu_size <mtu>` | Tun MTU 大小，默认为 1450。 |
| `--udp_pacing_mbps <n>` | 外层 UDP 发送限速，单位 Mbit/s，0 表示不限速。发送端内核出口 qdisc 为 `fq` 时通过 `SO_MAX_PACING_RATE` 生效，用于在无拥塞控制的外层避免把瓶颈链路打满。 |
| `--keepalive <seconds>` | 心跳间隔，单位秒，默认为 60。 |
| `--tag_len <12\|16>` | 数据帧认证标签长度，默认 16；写 12 时每帧省 4 字节（片长上限与内层 MTU 相应放宽 4 字节）。由客户端在握手时表达，网关据此定夺，会话内不变。 |
| `--pushroutes <route>` | server 端推送给 client 的路由，可多次指定。 |
| `--bypassroutes <route>` | client 端绕过 VPN 走物理线路的路由（ip/cidr 或主机名），可多次指定。 |
| `--pushdns <ip>` | server 端推送给 client 的 DNS，写 `10.9.0.53` 或整数都认。client 侧：systemd-resolved 托管时用 `resolvectl` 配链路 DNS，否则把地址插到 `/etc/resolv.conf` 最前面（原有 nameserver 留作后备，会话结束还原）；Android 侧交给 VpnService 配置。 |
| `--passbyvpn` | 使用 gateway 作为默认路由，client 所有流量经 server 转发（gateway 需做 NAT）。 |
| `--ignore_push` | 忽略 server 推送的路由和 DNS。 |
| `--c2c` | 是否允许 client 之间通过虚拟子网通信，默认关闭。 |
| `--subnet <网段>` | 指定虚拟子网网段，格式如 10.8.0.0/16。 |
| `--v6_subnet <网段>` | 指定 IPv6 虚拟子网网段，默认为 fd00:8888::/64。 |
| `--data_shards <n>` | 纠错数据片数；与 `--parity_shards` 之和必须为 2、4、8、16，且不小于 2，才开启纠错，否则退化为整帧模式。 |
| `--parity_shards <n>` | 纠错冗余片数，即一组里最多能补回的丢包片数，至少为 1 才开启纠错。 |
| `--compress <algo>` | 启用数据压缩，支持 deflate、lz4（deflate 压得狠、lz4 快得多）；两端都配置成同一个算法才生效，只压压得动的 IP 包。 |
| `--obfuscate_key <key>` | 数据特征混淆密钥串，非空时给数据帧套一层随机垃圾（每包多 22~70 字节）；两端必须配同一个密钥串，配错时握手会失败；开启后内层 MTU 会相应减小（默认 1450 → 1382）。 |
| `--pre_up <cmd>` | 钩子：在 tun 接口启用前通过 shell 执行，支持 `%i` 替换为接口名。 |
| `--post_up <cmd>` | 钩子：在 tun 接口配置完成后通过 shell 执行，支持 `%i` 替换为接口名。 |
| `--pre_down <cmd>` | 钩子：在 tun 接口拆除前通过 shell 执行，支持 `%i` 替换为接口名。 |
| `--post_down <cmd>` | 钩子：在 tun 接口拆除后通过 shell 执行，支持 `%i` 替换为接口名。 |
| `--pid_file <path>` | 将进程 PID 写入指定文件（内部使用，由 launcher 设置）。 |

## 性能测试

仓库自带一个基于 Linux 网络命名空间的端到端隧道吞吐测试脚本，可对比不同
FEC / MTU / 压缩配置，并可通过 netem 注入延迟与丢包：

```
sudo ./tools/bench_tunnel.sh
sudo DS=12 PS=4 DUR=10 ./tools/bench_tunnel.sh
sudo DS=12 PS=4 LOSS=0.5% DELAY=20ms ./tools/bench_tunnel.sh
```

需要 root 权限，依赖 `ip` / `tc` / `iperf3`。脚本会在两个 netns 之间建立
veth，分别启动 gateway 与 endpoint，跑 iperf3 上下行后自动清理；可用环境
变量 `AVPN` 指定 avpn 可执行文件路径（默认 `build/bin/avpn`）。纠错总片数
`T = DS + PS` 只能取 2、4、8、16，且 `DS ≥ 2`、`PS ≥ 1` 才会生效，其余取值
下 avpn 会自动退化为整帧模式。

本机 x86_64 参考数据（单流 iperf3，MTU 1400，上行 / 下行 Mbit/s）：

| 场景 | 整帧模式 | 纠错 12/4 |
| --- | --- | --- |
| 无延迟/无丢包 | 952 / 968 | 839 / 809 |
| 2% 丢包 | 265 / 308 | 727 / 742 |

> 高丢包链路下 FEC 对吞吐的提升是数量级的（TCP 会把丢包当作拥塞），
> 因此移动网络建议保持 FEC 开启；干净链路可以关掉纠错省下冗余名额。

### 长 RTT 与高速链路调优

长 RTT、高丢包与高速链路下的瓶颈大多在内核侧而非 avpn 自身，实现细节
与实测数据见[设计文档](doc/design.md) 的「FEC 纠删码」与「传输机制」章节。
使用要点：

- 收发 socket 缓冲会按带宽时延积显式放大，长 RTT 链路上无需再手工调整。
- 纠错收包即发：一个 IP 包占一个数据片，从虚拟网卡读到就立刻加密发出，
  同时留一份；凑够 `ds` 片后立刻算出冗余片发出，不额外攒包等待。
- 外层 UDP 支持 GSO 批量与 `sendmmsg` 合并，TCP 传输合并读写以减少每帧
  开销；瓶颈链路上建议配合 `--udp_pacing_mbps` 限速。
- 高速率下建议加长 tun 队列并把 qdisc 设为 `fq` 且放宽 per-flow 上限
  （或改用 `fq_codel`/`mq`），否则内核会整批丢包导致下行受限。

## 文档

- [协议文档](doc/protocol_v2.md)
- [设计文档](doc/design.md)
- [wintun 实现原理](doc/avpn_wintun.md)
