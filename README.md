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
	--private_key <key> --pkl <peer-pubkey> --data_shards 5 --parity_shards 2
```

客户端 (Windows):

```sh
avpn.exe --ifdev wintun --nexthop <server-ip>:19090 \
	--private_key <key> --pkl <peer-pubkey> --data_shards 5 --parity_shards 2
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
| `--pushroutes <route>` | server 端推送给 client 的路由，可多次指定。 |
| `--bypassroutes <route>` | client 端绕过 VPN 走物理线路的路由（ip/cidr 或主机名），可多次指定。 |
| `--pushdns <ip>` | server 端推送给 client 的 DNS。 |
| `--passbyvpn` | 使用 gateway 作为默认路由，client 所有流量经 server 转发（gateway 需做 NAT）。 |
| `--ignore_push` | 忽略 server 推送的路由和 DNS。 |
| `--c2c` | 是否允许 client 之间通过虚拟子网通信，默认关闭。 |
| `--subnet <网段>` | 指定虚拟子网网段，格式如 10.8.0.0/16。 |
| `--v6_subnet <网段>` | 指定 IPv6 虚拟子网网段，默认为 fd00:8888::/64。 |
| `--data_shards <n>` | FEC 数据分片数，默认 0 不启用 FEC；为 1 时退化为按倍数冗余发包。 |
| `--parity_shards <n>` | FEC 冗余分片数，即最多可丢失的数据包数量；data_shards 为 1 时表示发包倍数（最大 5 倍）。 |
| `--compress <algo>` | 启用数据压缩，可选算法：deflate、lz4、zstd。 |
| `--obfuscate_key <key>` | 数据特征混淆密钥串，非空时启用混淆（两端需配置相同密钥）；开启后加密帧外层填充随机垃圾数据打乱包长。 |
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
sudo DS=8 PS=2 DUR=10 ./tools/bench_tunnel.sh
sudo DS=8 PS=4 LOSS=0.5% DELAY=20ms ./tools/bench_tunnel.sh
```

需要 root 权限，依赖 `ip` / `tc` / `iperf3`。脚本会在两个 netns 之间建立
veth，分别启动 gateway 与 endpoint，跑 iperf3 上下行后自动清理；可用环境
变量 `AVPN` 指定 avpn 可执行文件路径（默认 `build/bin/avpn`）。

本机 x86_64 参考数据（单流 iperf3，MTU 1400）：

| 场景 | FEC 关闭 | FEC 8/2 | FEC 8/4 |
| --- | --- | --- | --- |
| 无延迟/无丢包 | ~700 Mbit/s | ~500 Mbit/s | ~420 Mbit/s |
| 20ms 延迟 + 0.5% 丢包 | ~4 Mbit/s | ~75 Mbit/s | ~115/~155 Mbit/s |

> 高丢包链路下 FEC 对吞吐的提升是数量级的（TCP 会把丢包当作拥塞），
> 因此移动网络建议保持 FEC 开启；干净链路可适当降低 `parity_shards`。

### 长 RTT 链路注意事项

长 RTT 链路上还有两个容易被忽略的瓶颈，代码中已做处理：

- 内核默认 UDP 收发缓冲通常只有 212KB，远小于长 RTT 的带宽时延积，
  接收队列溢出造成的丢包会直接打断内层 TCP 的拥塞窗口。avpn 会显式
  放大 socket 缓冲，并在具备 `CAP_NET_ADMIN` 时使用 `SO_*BUFFFORCE`
  突破 `net.core.{r,w}mem_max` 上限。
- FEC 以 `data_shards` 为一个分组，分组未填满时会被补齐成
  `data_shards + parity_shards` 个分片。分组越小，包数放大越严重，
  低速链路上会把物理链路占满并形成“越慢越放大”的恶性循环。因此能装
  进单个数据包的批量直接以 `data_raw` 发送，不再拆分。
- 但包数放大是 FEC 的固有代价，不能靠“未满分组也直发”来消除。实测
  （netns，20ms RTT + 0.5% 丢包，FEC 8/4）把未满分组改为按包边界直发
  后，吞吐从 ~130/110 Mbit/s 掉到 ~9 Mbit/s：丢包链路上内层 TCP 对
  丢包极其敏感，FEC 的容错收益远大于包数开销。因此只有能装进单个数
  据报的分组才走 `data_raw`，其余一律编码发送。
- 固定分组还会放大“批未填满”时的数据报数量：载荷不足 `data_shards` 片
  时未用的数据分片只是补零，却仍各占一个数据报。例如 FEC 8/4 下两个满
  MTU 报文（约 2.8KB）会被编码成 12 个约 280 字节的小分片，数据报数量
  放大约 6 倍。自适应分组按载荷大小 `k = ceil(payload / 分片目标)` 选
  取数据分片数，冗余同比缩小为 `ceil(k * parity / data_shards)`，在保留
  FEC 保护的前提下把数据报数量降到 `k + 冗余`。实测（netns，MTU 1400，
  FEC 8/4，UDP 注入）中低速率下外层数据报数量减少约一半（放大倍数
  8.0/8.0/5.3 → 3.3/3.3/2.7），满分组时与原先一致；2% 丢包下 UDP
  接收 goodput 未见变化。该能力通过能力协商启用，对端为旧版本时自动
  回退到固定分组格式。
- 干净链路上的 FEC 冗余是纯开销：FEC 8/4 会把外层数据报数量放大约
  1.5 倍。能力协商通过后 avpn 会启用轻量链路探测（每 100ms 一个探测
  包，且仅在链路有数据收发时才发送）：接收端按窗口统计探测丢包并把
  “链路是否持续干净”回带，发送端据此在干净链路上只发数据分片、出现
  丢包立即恢复冗余。为避免单个干净窗口误判，需要连续 8 个窗口（约
  13s）无丢包才关闭冗余，空闲链路则停止探测以免持续唤醒射频。netns
  实测（MTU 1400，FEC 8/4，5 Mbit/s UDP 注入）：干净链路上外层数据报
  放大倍数由 1.51 降到 1.01，注入 5% 丢包后约 2s 回到 1.45，移除丢包
  后约 13s 再次关闭；上行/下行两个方向行为一致。判据偏保守：真机满载
  下行时探测丢包率约 5%（30 个统计窗口中仅 12 个无丢包），冗余会保持
  开启，此时 FEC 确实在修复丢包；只有链路持续干净才会关闭冗余。对端
  为旧版本时不会协商该能力，自动回退到固定冗余。
- 发送端出口 qdisc 的 per-flow 上限会整批丢掉 GSO 尾包。同一批
  `UDP_SEGMENT` 帧是一次 `sendmsg` 交给内核的，而 `fq` 默认
  `flow_limit 100p` 只允许单条流排队 100 个报文，一旦隧道在瓶颈链路
  上突发，超出部分（通常是本批尾部）会被整体丢弃，FEC 分组因此长期
  凑不齐分片。千兆内网实测（MTU 1450，FEC 16/0，4 流下行）：`fq`
  默认配置下 6 秒内 `flows_plimit` 丢包约 3.5 万个，隧道下行只有
  ~726 Mbit/s 且发送端 TCP 重传约 12 万段；把上限放大后丢包归零，
  下行提升到 ~853 Mbit/s（物理链路 iperf3 约 936 Mbit/s）。因此隧道
  发送端建议 `tc qdisc replace dev <iface> root fq flow_limit 10000`
  （或改用无 per-flow 上限的 `fq_codel`/`mq`），并在瓶颈链路上配合
  `--udp_pacing_mbps` 把外层速率压在链路能力以内。
- 网关下行是单核 CPU 瓶颈。低配 VPS（2 vCPU）实测裸 `sendto` 1422
  字节就要 ~27 µs，隧道上下行合计只能跑到 ~60–70 Mbit/s 且网关单核
  跑满，而同一进程内 AEAD 每包仅几微秒。这类主机上瓶颈在内核网络栈
  而不是 avpn 自身，减少隧道数据报数量（而不是加密开销）才是有效方向。
- TCP 传输原本每帧一次 `async_write`、每帧两次 `async_read`：内核会
  按帧生成 TCP 段并逐段通知网卡，虚拟化主机上每包开销很高（实测同一
  链路 TCP 传输只有 ~31 Mbit/s，网关单核已用 60%）。现在写方向合并
  队列中的多帧（最多 128KB 或等待 2ms）后一次写入，内核可以按 TSO/GSO
  分段，网卡通知次数下降一个数量级；读方向一次读入大块（128KB）再逐帧
  解析，异步操作次数与每帧堆分配随帧数一起减少。真机实测（Pixel 6 ↔
  2 vCPU VPS，RTT ≈ 140ms，8 条并发下行流）同一时间窗交替对比，TCP
  传输 8 流吞吐由 30.2 Mbit/s 提升到 34.3 Mbit/s（最好一次 43.7），
  网关单核占用由 53–61% 降到 44–50%。

### 高速链路调优要点

- tun 队列加长并把 qdisc 设为 `fq`（放宽 per-flow 上限）：高速率下 tun 队列
  与内核 `flow_limit` 会整批丢包，导致外层 FEC 分组长期凑不齐、下行受限。
- 不等长的外层 UDP 帧合并到一次 `sendmmsg`：不能走 `UDP_SEGMENT` 的帧不再
  逐帧一次系统调用。
- tun 收包内联处理，不再二次投递到事件循环：省掉每包一次队列调度。
- 链路空闲时立即冲刷 FEC 批次：批次不再为凑分片额外等待。

## 文档

- [设计文档](doc/design.md)
- [wintun 实现原理](doc/avpn_wintun.md)
