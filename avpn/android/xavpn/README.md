# xavpn — aVPN Android 客户端 (Flutter)

基于 `libavpn` 编译出的 `libxavpn.so`, 通过 Android `VpnService` 建立 TUN,
在同一个进程内直接调用 `xavpn.start(json)` 运行 aVPN.

## 架构

```
Flutter (Dart)                          Android 原生 (Kotlin)                 libxavpn.so (C++)
┌────────────────────────┐  MethodChannel ┌─────────────────────────┐  JNI   ┌──────────────────────┐
│ 配置管理/存储/UI        │ ──────────────▶ │ MainActivity            │ ─────▶ │ xavpn.start(json)     │
│ 本地 WS 控制端 (Dart)   │                │ VpnService (TUN+protect)│        │ libavpn 服务          │
│ ControllerServer       │ ◀── ws jsonrpc ─┤                         │ ◀───── │ controller 客户端     │
└────────────────────────┘                └─────────────────────────┘        └──────────────────────┘
```

- **配置**: 多条配置以 JSON 存于 SharedPreferences; 启动时经 json 传入 `libxavpn.so`.
- **TUN**: `VpnService.establish()` 返回的 fd 经 `ptun_fd` 字段注入 json, 同进程直接使用.
- **protect**: `libavpn` 创建 nexthop 对外 socket 时回调 `setProtectCallback`,
  Kotlin 侧调用 `VpnService.protect(fd)` 放行, 避免流量回环进入 TUN.
- **控制通道**: Flutter 内置本地 WS 服务 (`127.0.0.1:<port>`), 经 `controller`
  字段交给 avpn, avpn 主动连接并上报 `register/status/log`;
  应用可下发 `get_status` / `update_config` / `shutdown` RPC.
  `update_config` 支持 keepalive 热更新, 其余字段由原生自动重启生效 (TUN 保留).
- **线程模型**: VpnService 的建立/启停/teardown 全部在专用工作线程串行执行,
  不阻塞主线程, 也天然避免了 START/STOP 竞态; JNI 日志/protect 回调均为线程安全.

## 构建

```sh
# 1. 编译 libxavpn.so (仓库根目录, 参见 build.android.sh)
./build.android.sh /root/avpn /opt/android-sdk/ndk/26.3.11579264 linux-x86_64

# 2. 将产物同步到本工程 (或直接手工拷贝)
cp /root/avpn/release/*/libxavpn.so android/app/src/main/jniLibs/<abi>/
cp /root/avpn/outputs/*.java android/app/src/main/java/com/jackarain/

# 3. 构建 APK
flutter pub get
flutter build apk --debug
```

## 配置字段

- avpn 参数: `nexthop` (支持 `udp://`/`tcp://` 前缀), `private_key`, `public_key`
  (客户端填对端/服务器公钥), `pkl` (网关侧客户端公钥白名单), `mtu_size`, `keepalive`,
  `data_shards`, `parity_shards`, `compress`,
  `obfuscate_key`, `udp_listen`, `tcp_listen`, `subnet`, `passbyvpn`,
  `pushroutes`, `pushdns`, `ignore_push`, `c2c`, `bypassroutes`.
- Android VpnService 专用: `tunAddress`, `tunPrefix`, `routes` (CIDR, 默认全隧道),
  `dns`, `name`, `mode` (client/gateway, 决定默认路由: 网关模式只放虚拟子网).
- 运行时注入 (无需手填): `ptun_fd`, `controller`.
- 保存前做基础校验 (客户端需 nexthop、网关需 subnet、MTU/keepalive 范围等).

## 测试

```sh
flutter analyze
flutter test   # 配置序列化/校验/存储、WS JSON-RPC 协议、列表页交互
```

## 注意事项

- 网关模式在 Android 上无法做系统路由/NAT (需要 root), 仅作为软件网关转发流量.
- 本机 NDK 26.3 可正常构建; 若提示 shared_preferences 需要更高 NDK 版本,
  仅影响其自带原生库, 属无害警告.
