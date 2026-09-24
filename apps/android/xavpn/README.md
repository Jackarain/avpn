# xavpn — aVPN Android 客户端 (Flutter)

基于 `libavpn` 编译出的 `libxavpn.so`, 通过 Android `VpnService` 建立 TUN,
在同一个进程内直接调用 `xavpn.start(json)` 运行 aVPN.

## 架构

```
Flutter (Dart)                          Android 原生 (Kotlin)                 libxavpn.so (C++)
┌────────────────────────┐  MethodChannel ┌─────────────────────────┐  JNI   ┌──────────────────────┐
│ 配置管理/存储/UI        │ ──────────────▶ │ MainActivity            │ ─────▶ │ xavpn.start(json)     │
│ 本地 WS 控制端 (Dart)   │                │ VpnService (TUN+protect)│        │ libavpn 服务          │
│ LauncherServer       │ ◀── ws jsonrpc ─┤                         │ ◀───── │ launcher 客户端     │
└────────────────────────┘                └─────────────────────────┘        └──────────────────────┘
```

- **配置**: 多条配置以 JSON 存于 SharedPreferences; 启动时经 json 传入 `libxavpn.so`.
- **TUN**: `VpnService.establish()` 返回的 fd 经 `ptun_fd` 字段注入 json, 同进程直接使用.
- **protect**: `libavpn` 创建 nexthop 对外 socket 时回调 `setProtectCallback`,
  Kotlin 侧调用 `VpnService.protect(fd)` 放行, 避免流量回环进入 TUN.
- **控制通道**: Flutter 内置本地 WS 服务 (`127.0.0.1:<port>`), 经 `launcher`
  字段交给 avpn, avpn 主动连接并上报 `register/status/log`;
  应用可下发 `get_status` / `update_config` / `shutdown` RPC.
  `update_config` 支持 keepalive 热更新, 其余字段由原生自动重启生效 (TUN 保留).
- **线程模型**: VpnService 的建立/启停/teardown 全部在专用工作线程串行执行,
  不阻塞主线程, 也天然避免了 START/STOP 竞态; JNI 日志/protect 回调均为线程安全.

## 构建

```sh
# 1. 编译 libxavpn.so (仓库根目录, 参见 build.android.sh); 脚本会把
#    libxavpn.so 同步到 jniLibs, 并把 SWIG 生成的 Java 包装类同步到
#    android/app/src/main/java/com/jackarain/, 无需手工拷贝.
#    追加第 4 个参数可只编译指定 ABI (如 arm64-v8a).
./build.android.sh /root/avpn /opt/android-sdk/ndk/26.3.11579264 linux-x86_64

# 2. 构建 APK (构建时自动将 release/<abi>/libxavpn.so 同步到 jniLibs)
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
- 运行时注入 (无需手填): `ptun_fd`, `launcher`.
- 保存前做基础校验 (客户端需 nexthop、网关需 subnet、MTU/keepalive 范围等).

## 测试

```sh
flutter analyze
flutter test   # 配置序列化/校验/存储、WS JSON-RPC 协议、列表页交互、自更新协议
```

## 自动更新

应用启动后(延迟 3s)在后台检查更新, 顶部工具栏的 `检查更新` 按钮可手动触发.
更新源是站点发布目录里的安装包, 以及同一目录的 JSON 列表(每项带整文件 SHA-1):

```
https://www.jackarain.org/download/avpn-release.apk
https://www.jackarain.org/download/?q=json&hash=1
```

发布方式: 构建 `app-release.apk` 后重命名为 `avpn-release.apk` 上传到该地址; 客户端按发布
目录里 `avpn-release.apk` 的整文件 SHA-1 判断有无更新, 因此重新构建或重新上传就会提示,
不强制递增版本号.

版本号: 只写在 `pubspec.yaml` 的 `version: 1.0.0+N`(N 即 `versionCode`), 本地与 CI 都按它
构建, 不要另外传 `--build-number`(否则两种构建来源产出的 versionCode 不一致, 用户装过高
号的那份就再也装不上低号的包). 客户端不靠版本号判断有无更新, 但 `versionCode` 决定能否
覆盖安装: 新包必须 >= 已安装版本, 低于时系统会拒绝降级安装.

流程:

1. **查询**: 取发布目录列表(`?q=json&hash=1`), 找到 `filename` 为 `avpn-release.apk` 的那项,
   用它的 `hash`(整文件 SHA-1)、`filesize` 与 `last_write_time`. 列表本身只有数百字节,
   检查几乎不耗流量.
2. **比对**: 列表里的 hash 与本机记录(已安装或「跳过此版本」)不同即视为有更新; 另外会
   计算已安装 APK 的整包 SHA-1, 与列表值一致时(刚装完或首次检查)不下载也能确认是最新.
3. **下载**: 落地到应用私有外部目录 `update/avpn-release.apk`, 弹进度条显示百分比与速度, 可取消.
4. **校验**: 计算下载包的整包 SHA-1, 必须与列表里的 `hash` 一致(传输截断或被换成别的包
   都会挡在这里); 再读包内 `versionCode` 与签名证书 SHA-256: `versionCode` 小于当前版本
   时系统会拒绝降级安装, 签名不一致则需要卸载重装, 两种情况都提前说明而不是让系统安装器
   报出难以理解的失败.
5. **安装**: 经 `FileProvider` 交给系统安装器(`REQUEST_INSTALL_PACKAGES`), Android 8.0+
   未授权时会跳到「安装未知应用」页, 授权后返回即可继续. 安装会终止应用进程, 因此发起
   安装时先记录「待核对」的 hash, 下次启动发现已安装包的 SHA-1 与记录一致才记为已处理;
   用户若在系统安装器里取消, 记录会被丢弃, 之后仍会再次提示该版本.

已知限制:

- 只要发布目录上的包内容变了(哪怕只是重新构建)就会提示更新; 想低频发版就只在需要时上传新包.
- 只支持自签名分发: 换签名密钥后旧包必须先卸载(签名不同系统会拒绝覆盖安装);
  上架 Google Play 的版本不能自带更新(政策限制).
- 检查只拉数百字节的列表 JSON, 不下载安装包; 自动检查 24h 内只做一次, VPN 运行中不做自动检查.

## 注意事项

- 网关模式在 Android 上无法做系统路由/NAT (需要 root), 仅作为软件网关转发流量.
- 本机 NDK 26.3 可正常构建; 若提示 shared_preferences 需要更高 NDK 版本,
  仅影响其自带原生库, 属无害警告.
