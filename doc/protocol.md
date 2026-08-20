# aVPN 通信协议文档

> 本文档完整描述 aVPN 的通信协议，包括字节级线格式（wire format）、密钥派生、
> 握手流程、数据通道、保活/断开、传输封装以及相关安全机制。
> 协议实现参考 `libavpn/include/libavpn/avpn_protocol.hpp`、
> `libavpn/src/avpn_protocol.cpp` 与 `libavpn/src/avpn_session.cpp`。

---

## 1. 协议概述

aVPN 采用 **1-RTT 完全加密握手** + **AEAD 对称加密数据通道** 的点对点 VPN 协议：

- 通信双方（客户端/网关）预先持有对方的 X25519 静态公钥，通过配置交换。
- 握手阶段：客户端发送完全加密的 Message 1，网关认证后回复完全加密的
  Message 2，并在此过程中协商出双向会话密钥。
- 数据阶段：所有 IP 包先压缩（可选）、FEC 编码（可选），再以
  ChaCha20-Poly1305 加密传输。
- 网络传输中**不存在任何明文协议标识**，握手包与数据包均为
  `nonce || ciphertext`，无法从流量形态区分握手与数据。

### 1.1 角色定义

| 角色 | 说明 |
|---|---|
| initiator（客户端） | 发起握手的一方，配置对端（网关）静态公钥 |
| responder（网关） | 接受握手的一方，配置客户端静态公钥白名单 |

### 1.2 协议版本

当前协议版本号 `avpn_protocol_version = 1`。版本号目前不参与线格式传输，
仅作为代码常量预留，后续演进可据此做兼容判定。

---

## 2. 协议常量

| 常量 | 值 | 说明 |
|---|---|---|
| `avpn_key_size` | 32 | X25519 密钥 / 派生密钥长度（字节） |
| `avpn_client_id_size` | 32 | 客户端随机身份 ID 长度 |
| `avpn_ephemeral_key_size` | 32 | 临时公钥长度 |
| `avpn_max_mtu` | 1500 | tun 最大 MTU |
| `avpn_max_packet_size` | 2048 | 单帧最大长度（含加密与协议开销） |
| `aead_nonce_size` | 12 | ChaCha20-Poly1305 nonce 长度 |
| `aead_tag_size` | 16 | ChaCha20-Poly1305 认证标签长度 |
| `avpn_handshake_packet_size` | 100 | Message 1 的线上总长度（见 §6.2） |

---

## 3. 密码学原语

| 用途 | 算法 | 说明 |
|---|---|---|
| 密钥交换 | X25519 | 曲线 Curve25519 ECDH |
| 对称加密 | ChaCha20-Poly1305 | AEAD，12 字节 nonce + 16 字节 tag |
| 密钥派生 | HKDF-SHA256 | 所有派生密钥均 32 字节 |
| 随机数 | CSPRNG | nonce、临时密钥、client_id 均来自安全随机源 |

所有密钥派生调用形式统一为：

```
HKDF-SHA256(ikm, salt, info, L=32)
```

---

## 4. 密钥体系与派生

### 4.1 密钥材料

| 密钥 | 生成时机 | 说明 |
|---|---|---|
| `(SPrivC, SPubC)` | 配置/首次运行 | 客户端静态长期密钥对 |
| `(SPrivS, SPubS)` | 配置/首次运行 | 网关静态长期密钥对 |
| `(TPrivC, TPubC)` | 每次握手 | 客户端临时密钥对 |
| `(TPrivS, TPubS)` | 每次握手 | 网关临时密钥对 |
| `K_temp` | 握手时派生 | 加密 Message 1 |
| `K_resp` | 握手时派生 | 加密 Message 2 |
| `K_master` | 握手时派生 | 会话主密钥，再派生方向密钥 |
| `key_c2s` / `key_s2c` | 握手时派生 | 数据通道双向密钥 |

静态公钥通过 base64 编码在配置中交换：
客户端配置 `public_key=<网关公钥>`，网关配置 `pkl=<客户端公钥>`。

### 4.2 临时握手密钥 K_temp（加密 Message 1）

```
K_temp = HKDF(ikm = ECDH(自己的静态私钥, 对端静态公钥),
              salt = "",
              info = "avpn-handshake-temp-v1",
              L = 32)
```

- 客户端：`ECDH(SPrivC, SPubS)`。
- 网关：由于不知道消息来自哪个客户端，遍历白名单中每个 `SPubC` 计算
  `ECDH(SPrivS, SPubC)` 逐一尝试解密，AEAD 认证成功即确定对端身份。

### 4.3 响应密钥 K_resp（加密 Message 2）

客户端收到 Message 2 之前无法独立计算完整的四向 DH 会话密钥，
因此 Message 2 使用独立的 K_resp：

```
客户端视角:
  K_resp = HKDF(ikm = ECDH(TPrivC, SPubS),
                salt = ECDH(SPrivC, SPubS),
                info = "avpn-handshake-resp-v1", L = 32)

网关视角:
  K_resp = HKDF(ikm = ECDH(SPrivS, TPubC),
                salt = ECDH(SPrivS, SPubC),
                info = "avpn-handshake-resp-v1", L = 32)
```

### 4.4 会话主密钥 K_master（四次 DH）

双方在拥有全部临时/静态公钥后计算四个 DH 值：

```
dh_ss = ECDH(本端静态私钥, 对端静态公钥)
dh_se = ECDH(本端静态私钥, 对端临时公钥)
dh_es = ECDH(本端临时私钥, 对端静态公钥)
dh_ee = ECDH(本端临时私钥, 对端临时公钥)

ikm = sort(dh_se, dh_es, dh_ee) 按字典序排序后拼接 (3 x 32 = 96 字节)
K_master = HKDF(ikm = ikm, salt = dh_ss,
                info = "avpn-session-master-v1", L = 32)
```

> `dh_se/dh_es/dh_ee` 排序后拼接，保证两端本地视角不同（“我的静态/临时”
> 与“对端静态/临时”互换）时仍能计算出一致的 `ikm`。

### 4.5 方向密钥

```
key_c2s = HKDF(ikm = K_master, salt = "", info = "avpn-session-c2s-v1", L = 32)
key_s2c = HKDF(ikm = K_master, salt = "", info = "avpn-session-s2c-v1", L = 32)
```

| 角色 | 发送密钥 | 接收密钥 |
|---|---|---|
| initiator（客户端） | `key_c2s` | `key_s2c` |
| responder（网关） | `key_s2c` | `key_c2s` |

---

## 5. 传输层封装

会话数据（握手消息与数据帧）在线上的统一格式：

```
[ nonce(12) | ciphertext ]
```

- `nonce`：12 字节随机数，每帧独立生成。
- `ciphertext`：ChaCha20-Poly1305 密文，末尾含 16 字节认证标签。

### 5.1 UDP 传输

每个帧即一个 UDP 数据报的正文（payload）。握手阶段与数据阶段均如此，
网关通过尝试解密来区分两者。

### 5.2 TCP 传输

TCP 是字节流，帧外加 2 字节**大端**长度前缀：

```
[ len(2, 大端) | wire ]
```

- `len`：`wire` 的长度（nonce + ciphertext），`0 < len <= avpn_max_packet_size`。
- 握手与数据共用同一条 TCP 连接。
- 连接建立后设置 `TCP_NODELAY`，避免小帧（VPN 包普遍很小）受
  Nagle/延迟 ACK 影响而放大延迟。
- TCP 传输本身可靠，因此协商结果中 FEC 会被强制置为 `data_shards=1,
  parity_shards=0`（见 §6.3），避免冗余分片放大传输开销。

### 5.3 传输选择

- `nexthop=udp://host:port`：UDP 传输，配合 FEC 抗丢包。
- `nexthop=tcp://host:port`：TCP 传输，穿透对 UDP 封锁的网络。

### 5.4 数据特征混淆（可选）

两端配置相同混淆密钥串（`obfuscate_key`，WebUI/命令行均可设置）后，
握手时协商 `session_config.obfuscate=1`（见 §6.3），数据通道每个加密帧
外层追加随机垃圾数据以打乱包长分布，隐藏真实载荷长度特征。

混淆后的数据帧线格式：

```
[ salt(4) | len_enc(2) | garbage(16~64) | counter(4) | ciphertext ]
```

| 字段 | 长度 | 说明 |
|---|---|---|
| `salt` | 4 | 每包 CSPRNG 随机，用于派生本包掩码 |
| `len_enc` | 2 | 垃圾长度加密字段，`len_enc = garbage_len XOR mask` |
| `garbage` | 16~64 | 随机垃圾数据，长度每包随机 |
| `counter`/`ciphertext` | 4 / 密文 | 原始加密帧（见 §7.1） |

掩码派生：

```
mask = XXH64(混淆密钥串 + salt) 的低 16 位
```

- `salt` 每包随机，因此掩码逐包变化；`len_enc` 同时作为 AEAD 的 AAD
  输入参与认证，篡改长度字段会导致解密失败被丢弃。
- XXH64 为高速非加密哈希，此处仅用于隐藏垃圾长度（不含机密信息），
  真实载荷仍由 ChaCha20-Poly1305 加密保护。
- 混淆开销每包 22~68 字节，开启时建议相应调小 tun MTU（如 1300），
  避免加密后数据报超过物理链路 MTU。
- 兼容性：混淆须两端同时配置（握手协商），旧版本对端未协商开启时
  数据通道维持原有格式。

---

## 6. 握手协议（1-RTT）

### 6.1 总体时序

```
C (initiator)                          S (responder)
     │ 生成 TPrivC/TPubC                      │
     │ 计算 K_temp                            │
     │                                       │
     │──── Message 1 (K_temp 加密) ──────────▶│ 遍历白名单 SPubC
     │                                       │ 计算 K_temp 尝试解密
     │                                       │ 防重放检查
     │                                       │ 生成 TPrivS/TPubS
     │                                       │ 计算 K_master/key_*
     │                                       │ 分配 vaddr
     │                                       │
     │◀──── Message 2 (K_resp 加密) ─────────│
     │ 用 K_resp 解密                         │
     │ 提取 TPubS, 计算 K_master/key_*        │
     │ 会话建立                               │
     │                                       │
     │══════ 数据通道 (key_c2s/key_s2c) ══════│
```

### 6.2 Message 1（C → S）

线上格式：

```
[ nonce(12) | AEAD(K_temp, nonce, plaintext) ]
```

明文布局（72 字节）：

```
[ TPubC(32) | timestamp(8, 小端, 毫秒) | client_id(32) ]
```

| 字段 | 长度 | 说明 |
|---|---|---|
| `TPubC` | 32 | 客户端临时公钥 |
| `timestamp` | 8 | 系统毫秒时间戳，用于防重放 |
| `client_id` | 32 | 客户端随机身份 ID（仅标识，不参与密钥） |

线上总长度固定：`12 + (72 + 16) = 100` 字节。

### 6.3 Message 2（S → C）

线上格式：

```
[ nonce(12) | AEAD(K_resp, nonce, plaintext) ]
```

明文布局：

```
[ TPubS(32) | session_config ... ]
```

`session_config` 为网关协商并下发的会话配置，二进制布局（小端）：

```
[ compress(1) | data_shards(1) | parity_shards(1) | keepalive(2)
| mtu(2) | vaddr(4) | prefix_length(1)
| v6_prefix(1) | v6_net(16)
| passbyvpn(1) | pushdns(4)
| routes_count(1) | { [len(1) | route] × routes_count } ]
```

| 字段 | 长度 | 说明 |
|---|---|---|
| `compress` | 1 | 压缩算法：0=none, 1=deflate, 2=lz4, 3=zstd |
| `data_shards` | 1 | FEC 数据分片数（TCP 传输下强制为 1） |
| `parity_shards` | 1 | FEC 冗余分片数（TCP 传输下强制为 0） |
| `keepalive` | 2 | 保活间隔（秒） |
| `mtu` | 2 | tun MTU（576 ~ 1500） |
| `vaddr` | 4 | 网关分配给客户端的虚拟地址 |
| `prefix_length` | 1 | 虚拟子网前缀长度 |
| `v6_prefix` | 1 | IPv6 内网前缀长度（默认 64，必须 ≤ 96） |
| `v6_net` | 16 | IPv6 内网网络地址（默认 `fd00:8888::`，按大端字节序） |
| `passbyvpn` | 1 | 是否以网关为全局默认出口（客户端据此配置默认路由） |
| `pushdns` | 4 | 网关推送的 DNS（0 表示不推送） |
| `routes_count` | 1 | 推送路由条数 |
| `route` | ≤255 | 每条路由字符串，前 1 字节为长度 |

### 6.4 防重放

Message 1 的防重放有两层：

1. **时钟窗口**：`timestamp` 必须在网关当前时间 ±30 秒内，否则丢弃。
2. **单调性**：按对端静态公钥记录最近接受的时间戳，拒绝时间戳
   不递增的重复握手（`m_msg1_ts`，per-session 记录）。

### 6.5 重试与超时

- 客户端发送 Message 1 后启动 5 秒定时器；未收到 Message 2 则重发，
  初始发送 + 最多 5 次重发，共 6 次；仍无响应则判定握手超时并关闭会话
  （日志 `Handshake timeout`）。
- TCP 传输下重发在同一 TCP 连接上进行。
- 网关对认证失败的数据报**静默丢弃**，不产生任何可探测的响应。

### 6.6 网络指纹最小化

- 握手包无任何明文标识，网关需用白名单密钥逐一尝试解密来识别。
- 数据通道的 `msg_type` 位于密文内部，不暴露在网络中。
- 对未知来源、认证失败、防重放失败的数据报均无响应。

---

## 7. 数据通道协议

### 7.1 加密帧

会话建立后，每个数据帧均为：

```
[ nonce(12) | AEAD(方向密钥, nonce, plaintext) ]
```

解密后的 `plaintext`：

```
[ msg_type(1) | body ... ]
```

### 7.2 消息类型

| 值 | 类型 | 方向 | 说明 |
|---|---|---|---|
| `0x01` | `data` | 双向 | 数据消息，body 可为 FEC 分片帧 |
| `0x02` | `keepalive` | 双向 | 保活请求，body = 8 字节时间戳（小端，毫秒） |
| `0x03` | `keepalive_reply` | 双向 | 保活回复，body = 对端时间戳原样返回 |
| `0x04` | `disconnect` | 双向 | 主动断开，body = 1 字节原因码 |
| `0x05` | `ack` | 预留 | 数据确认（未启用） |

### 7.3 数据消息与 FEC 分片帧

当协商的 `data_shards > 1`（仅 UDP 传输）时，每个 IP 包被编码为
`data_shards + parity_shards` 个分片，每个分片作为一条 `data` 消息发送。

FEC 分片帧（data 消息的 body，8 字节头）：

```
[ fec_id(4, 小端) | total(1) | index(1) | len(2, 小端) | shard_data ... ]
```

| 字段 | 长度 | 说明 |
|---|---|---|
| `fec_id` | 4 | 发送方递增的组 ID，每 IP 包一个分组 |
| `total` | 1 | 总分片数（data_shards + parity_shards） |
| `index` | 1 | 分片索引（0 ~ total-1） |
| `len` | 2 | 原始 IP 包长度，用于去除分片填充 |

接收方按 `fec_id` 收集分片，收到 `data_shards` 片即可用
Reed-Solomon（GF(2⁸)）恢复出完整 IP 包；超过 3 秒未凑齐的分组被清理。

**冗余拷贝模式**：当 `data_shards <= 1` 且 `parity_shards > 0` 时，
不再使用 RS 编码，改为把整个 IP 包发送 `parity_shards + 1` 份（冗余拷贝）。

### 7.4 发送流水线（tun → 网络）

```
tun 读到的 IP 包
  → 压缩（协商为 none 时跳过）
  → FEC 编码（data_shards>1 时拆分为多片）
  → 组装 data 消息：msg_type(0x01) + [fec_header + shard]
  → AEAD 加密（方向密钥 + 随机 nonce，混淆时以 len_enc 为 AAD）
  → 混淆封装（协商开启时追加 [salt][len_enc][garbage]，见 §5.4）
  → UDP 数据报 或 TCP 长度前缀帧
```

### 7.5 接收流水线（网络 → tun）

```
UDP 数据报 / TCP 帧
  → 剥离混淆封装（协商开启时，先解出垃圾长度并校验，见 §5.4）
  → AEAD 解密（接收密钥，混淆时以 len_enc 为 AAD），失败静默丢弃
  → 解析 msg_type
  → data：FEC 解码（按 fec_id 分组、凑够分片重建）或直接取整包
  → 解压（协商为 none 时跳过）
  → 写入 tun
```

### 7.6 压缩

压缩在握手时协商（`session_config.compress`），发送方先压缩后加密，
接收方先解密后解压。目前实现支持 deflate（zlib），lz4/zstd 为预留。

---

## 8. 保活与会话超时

- 会话建立后启动每秒 tick 协程：
  - **保活**：距离上次发送 keepalive 超过 `keepalive` 秒时发送
    `keepalive`（携带毫秒时间戳），对端回复 `keepalive_reply` 原样带回，
    可用于 RTT 观测。
  - **超时**：`keepalive * 3` 秒内未收到任何有效数据帧（`m_last_seen`
    未更新），判定对端失联，关闭会话并释放资源。
- 默认 `keepalive` 由网关配置决定并通过 Message 2 下发（默认 60 秒，
  本部署配置为 30 秒）。

---

## 9. 断开流程

- 主动断开：发送 `disconnect`（1 字节原因码）后关闭传输。
- 被动断开：收到 `disconnect` 或传输层错误/超时后关闭。
- 会话关闭回调会通知服务层清理会话表、释放 vaddr，并在客户端侧恢复
  被修改的系统路由（见 §13）。

---

## 10. 虚拟地址与内网编址

### 10.1 IPv4

- 网关 tun 地址为子网网络地址（如 `subnet=10.10.0.0/16` 时为 `10.10.0.0`）。
- 客户端虚拟地址由网关在 `(网络地址, 广播地址)` 范围内递增分配
  （`alloc_vaddr`），首个客户端为 `10.10.0.1`。
- 网关侧按目标 IP 查找会话（`find_session`），将 tun 包转发给对应客户端；
  客户端侧把所有 tun 包交给唯一会话。

### 10.2 IPv6

- IPv6 内网子网由网关配置 `v6_subnet` 指定（默认 `fd00:8888::/64`），
  并通过 Message 2 的 `v6_net`/`v6_prefix` 协商下发，客户端无需配置。
- 客户端地址 = 子网网络地址 + vaddr（低 32 位映射到地址低 32 位），
  网关自身 = 子网网络地址 + `ffff:ffff`。
- 前缀长度必须 ≤ 96，保证低 32 位作为 vaddr 主机位。
- 网关按目标 IPv6 地址低 32 位（即 vaddr）查找会话。

---

## 11. 网络切换无感知（UDP）

客户端物理网络变化（如 Wi-Fi → 移动网络）导致本地出口 IP 变化时：

1. 客户端 `client_network_monitor` 每 2 秒检测本地到网关的出口源地址，
   变化时重建 UDP socket（尽量复用原端口）并立即发送 keepalive。
2. 网关收到来自未知 endpoint 的数据报时，用各已建立会话的接收密钥
   尝试解密（`try_decrypt_udp`），命中即视为该会话的网络迁移：
   - 将会话的远端 endpoint 更新为新地址；
   - 会话表按新 endpoint 重建索引；
   - 继续处理该数据报。

TCP 传输无需此机制（TCP 连接不感知对端 IP 变化），依赖自动重连恢复。

---

## 12. 网关侧会话识别与 DDoS 缓解

### 12.1 会话识别

- 新来源的 UDP 数据报先做 DDoS 检查，再创建临时 responder 会话尝试握手。
- 握手成功后登记会话表（按远端 endpoint 与对端公钥双索引）。
- UDP 路径下，同公钥的新握手会先关闭该公钥的旧会话，避免重复会话；
  TCP 路径按新连接的 endpoint 登记，旧会话在超时后由网关清理。

### 12.2 DDoS 缓解（无 Cookie 设计）

| 规则 | 参数 |
|---|---|
| 握手频率限制 | 同一源 IP 每 5 秒最多 1 次握手尝试 |
| 失败封禁 | 非握手/认证失败累计 ≥ 5 次 → 封禁 60 秒 |
| 成功解除 | 握手成功后清零失败计数 |

---

## 13. 客户端路由应用

握手成功后客户端根据协商的 `session_config` 应用系统路由：

| 配置 | 行为 |
|---|---|
| `passbyvpn=true` | 默认路由改走隧道（`default via <子网网络地址> dev <tun>`） |
| `pushroutes` | 逐条 `ip route replace <route> dev <tun>` 加入隧道路由 |
| `bypassroutes`（客户端本地配置） | 绕过隧道走物理线路；支持域名，自动解析全部地址并每 60 秒刷新，避免 CDN 动态 IP 被误送进隧道 |

路由应用顺序与保护措施：

1. 保存当前默认路由（退出/断线时恢复）。
2. 钉住 VPN 服务器地址 `/32` 走物理默认网关，避免隧道连接自身陷入隧道。
3. 删除旧默认路由，再设置隧道默认路由。
4. 在隧道出口添加 MASQUERADE，修正绑定本地源地址的流量。
5. 会话断开或进程停止时恢复原默认路由并删除 MASQUERADE。

---

## 14. 可靠性机制（TCP）

- 客户端 TCP 连接断开或失败后延迟 3 秒自动重连，重建会话并重新握手。
- 断线期间恢复物理默认路由，重连握手成功后重新接管默认路由。
- 网关对 TCP 连接同样采用白名单握手，连接关闭即清理会话。

---

## 15. 协议版本与扩展性

- `msg_type` 中预留 `ack(0x05)` 供可靠 UDP/丢包重传演进。
- `compress` 字段预留 lz4/zstd，扩展压缩算法无需改动线格式。
- 会话配置为自描述的长度/计数编码，新增配置项时向前兼容（接收端
  校验 `pos == data.size()`，未知尾部字节会导致解析失败，扩展需同步
  版本号或按长度容忍处理）。
