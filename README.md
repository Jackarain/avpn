﻿# avpn

一个使用 C++20 的 VPN 的高性能实现, 基于 Boost.Asio 协程.

## 支持平台

- Linux: /dev/net/tun.
- macOS: utun 内核控制.
- Windows: wintun 驱动 (tun 通过 wintun 实现).

## Windows 构建 (MinGW-w64)

```sh
cmake -G Ninja -DCMAKE_TOOLCHAIN_FILE=cmake/mingw.cmake \
	-DENABLE_USE_WINTUN=ON -DENABLE_USE_OPENSSL=ON ..
ninja
```

- `avpn.exe` 内嵌 wintun 驱动 (wintun.sys/inf/cat), 首次运行自动通过 pnputil 安装.
- `wintun.dll` 由构建脚本拷贝到输出目录, 运行时动态加载.
- FEC 在 Windows x64 上使用 SSSE3/AVX2 运行时分派加速 (MinGW 与 MSVC 均支持).

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


## Launcher（WebUI 实例管理器）

`launcher` 用于创建并管理多个 `avpn` 实例：通过内置 WebUI 完成实例的
创建/启停/删除、配置修改、状态监控与日志查看，实例配置持久化在
`data_dir/instances.json`。

### 构建

WebUI 使用 React/Vite 构建，产物在编译期内嵌进 `launcher` 可执行文件，
因此需先构建 WebUI 再编译 launcher：

```sh
cd webui
npm install
npm run build        # 产物输出到 ../launcher/webui
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
launcher 会自动为每个实例生成控制通道 URL（`--controller ws://.../rpc`），
通过 WebSocket + JSON-RPC 采集实例运行状态与日志，无需手工配置。


## 文档

- [设计文档](doc/design.md)
- [wintun 实现原理](doc/avpn_wintun.md)
