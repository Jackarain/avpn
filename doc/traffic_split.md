# aVPN Android 客户端分流方案

> 本文档总结 Android 客户端（xavpn）的流量与 DNS 分流方案：
> 路由层决定哪些流量进入 VPN 隧道，解析层决定 DNS 查询走 DoH 还是直连，
> 两者配合实现"国内直连保速度、国外走隧道防污染/可访问"的目标。

---

## 1. 概述

客户端采用**两层分流**：

- **路由层（流量分流）**：通过 `VpnService.addRoute` 控制哪些目标地址进入
  tun（VPN 隧道），未覆盖的地址由系统按物理网络直连。
- **解析层（DNS 分流）**：在 tun 上拦截 53 端口 DNS 请求，命中 gfwlist 的
  域名改用 DoH 加密解析，其余域名经直连 DNS（默认 `114.114.114.114`）解析。

两层独立可配：路由分流由 `bypassCn`/`routes` 控制，DNS 分流由 `dnsIntercept`
开关控制。

---

## 2. 路由层分流

### 2.1 VpnService 路由语义

Android `VpnService.Builder.addRoute(cidr)` 将指定网段接入 VPN（流量进入
tun 由隧道转发）；**未** `addRoute` 的地址走系统物理网络直连。因此"直连
某段 IP"的实现方式是**不把该段加入 VPN 路由表**。

### 2.2 三种路由模式

| 模式 | 配置 | VPN 路由 | 效果 |
|---|---|---|---|
| 全隧道 | `bypassCn=false` 且 `routes` 为空 | `0.0.0.0/0` | 所有 IPv4 流量进隧道 |
| 绕过中国大陆 | `bypassCn=true` | 非中国且非保留段（`0.0.0.0/0` 的补集） | 中国/私有段直连，其余走隧道 |
| 自定义路由 | `bypassCn=false` 且 `routes` 非空 | 用户填写的 CIDR 列表 | 仅列出的网段走隧道 |

实现见 `avpn/android/xavpn/lib/services/launcher_server.dart` 的
`_handleVaddr()`（收到服务端下发的 `vaddr` 后按 `bypassCn` 计算路由并建立
tun）。

### 2.3 绕过中国大陆（bypassCn）

- 数据源默认 `https://ispip.clang.cn/all_cn.txt`，拉取中国大陆 IP 段。
- 缓存到本地，启动时自动更新，每日最多拉取一次；更新时与缓存合并（新增
  项保留），下次建立 VPN 时应用完整列表。
- `CnIpList.vpnRoutes()` 计算"非中国且非保留段"作为 VPN 路由：将中国段与
  保留/私有段合并取 `0.0.0.0/0` 的补集，再合并重叠区间为 CIDR 列表。
- 保留/私有段固定直连：`10.0.0.0/8`、`192.168.0.0/16`、`127.0.0.0/8`、
  `169.254.0.0/16`、`100.64.0.0/10` 等。

实现见 `avpn/android/xavpn/lib/services/cn_ip_list.dart`。

### 2.4 系统 DNS 默认走隧道

`VpnService` 建立 tun 时若未配置 DNS 服务器（`dns` 为空），默认使用
`8.8.8.8`。这样系统解析请求进入 tun，由解析层拦截或隧道转发，避免底层
物理网络（运营商 DNS）对国外域名的污染解析。

---

## 3. 解析层（DNS）分流

### 3.1 拦截入口

`dns_proxy::on_tun_packet()`（`libavpn/src/dns_proxy.cpp`）对每个进入 tun
的 IP 包先做 `UDP/53` 定位，仅拦截标准查询（QR=0、opcode=0、至少一个
问题），其余包正常走隧道转发。

### 3.2 分流决策

```
DNS 请求进入 tun
    │
    ├─ 目标是 DoH 服务自身域名？ ──是──► 不拦截，交回隧道转发（防自递归）
    │
    ├─ 域名命中 gfwlist？ ──是──► DoH 加密解析（异步协程，带并发上限）
    │
    └─ 未命中 gfwlist ────────► 直连 DNS 转发（protect 直通 socket）
```

- **DoH 路径**：`doh_query()` 将原始 DNS 报文以
  `application/dns-message` POST 到 DoH 服务，响应重组为 DNS 包写回 tun。
- **直连路径**：`forward_direct()` 将原始 DNS 报文经 protect 放行的 UDP
  socket 发给直连 DNS（默认 `114.114.114.114`），按"事务 ID + 客户端
  端点"匹配回复后重组写回 tun。

### 3.3 gfwlist

- **两种内容格式**：
  - 官方格式（如 `https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt`）：
    base64 编码文本。下载后先 base64 解码，解码内容符合规则特征
    （含 `||`/`@@`/`\n!` 等）时采用解码内容。
  - 纯文本自建列表（如 `http://192.168.1.1:8080/gfwlist`）：直接是规则
    文本，按原样解析。
- 支持规则类型：`||domain^`、`@@||exception`（例外）、`|http(s)://`、
  `*domain`、`.domain`、`/正则/`、裸域名；自动去除协议前缀、路径、
  尾部 `^`/`*`/`.`。
- 例外规则（`@@`）优先：命中例外不按被墙处理。
- 缓存到本地文件，每日自动更新；解析失败/超时回退缓存。
- 解析实现：`dns_proxy::parse_gfwlist()`（私有成员），解析后重建匹配集。

### 3.4 DoH 服务

- URL 支持 `http://` 与 `https://`，也支持 URL userinfo 携带 Basic 认证
  （如 `https://user:password@doh.example.com`）。
- URL 无路径时自动补全 `/dns-query`。
- 常见 DoH 域名（如 `cloudflare-dns.com`、`dns.google`）映射为 IP 直连，
  避免经系统 DNS 解析时被污染或回环。
- 默认地址：`https://1.1.1.1/dns-query`（可配置 `dohUrl`）。

### 3.5 直连 DNS

- 默认 `114.114.114.114`（可配置 `directDns`，支持 `ip:port`）。
- 直连 socket 通过 `protect` 回调放行（Android `VpnService.protect`），
  避免 DNS 包回环进入 tun。
- 国内网站解析走此路径，速度快且不受隧道影响。

---

## 4. 配置项汇总

| 配置字段 | 默认值 | 说明 |
|---|---|---|
| `bypassCn` | `false` | 绕过中国大陆：非中国段接入 VPN，中国/私有段直连 |
| `routes` | `[]` | 自定义 VPN 路由 CIDR（为空时全隧道） |
| `dns` | `[]`（空时用 `8.8.8.8`） | VpnService DNS 服务器 |
| `dnsIntercept` | `false` | 启用 tun 53 端口 DNS 拦截分流 |
| `dohUrl` | `https://1.1.1.1/dns-query` | DoH 服务地址 |
| `directDns` | `114.114.114.114` | 直连 DNS 服务器 |
| `gfwlistUrl` | `https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt` | gfwlist 下载地址 |

---

## 5. 数据流示例

| 场景 | 路由层 | 解析层 | 结果 |
|---|---|---|---|
| 访问 `www.google.com` | 非中国段 → tun | 命中 gfwlist → DoH | 真实 IP，隧道访问 |
| 访问 `www.youtube.com` | 非中国段 → tun | 命中 gfwlist → DoH | 真实 IP，隧道访问 |
| 访问 `www.baidu.com` | 中国段 → 物理网络 | 未命中 gfwlist → 直连 `114.114.114.114` | 直连解析，物理网络访问 |
| 局域网 `192.168.1.1` | 私有段 → 物理网络 | — | 直连 |

---

## 6. 关键实现位置

| 模块 | 文件 |
|---|---|
| 路由计算（bypassCn / 中国段补集） | `avpn/android/xavpn/lib/services/cn_ip_list.dart` |
| 建立 tun 时按配置选择路由/DNS | `avpn/android/xavpn/lib/services/launcher_server.dart` |
| 配置字段定义与校验 | `avpn/android/xavpn/lib/models/vpn_config.dart` |
| tun 53 拦截与分流决策 | `libavpn/src/dns_proxy.cpp` |
| gfwlist 解析 | `libavpn/include/libavpn/dns_proxy.hpp`、`libavpn/src/dns_proxy.cpp` |
| DoH 查询与 Basic 认证 | `libavpn/src/dns_proxy.cpp`（`doh_query`） |
