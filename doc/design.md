# aVPN 设计文档

> aVPN 是一个基于 C++20 协程（boost::asio awaitable）的端到端加密 VPN 实现。
> 本文档描述系统的整体设计、协议细节与模块实现。

---

## 1. 概述

aVPN 设计基于点对点通信，本身不区分 server/client，而是通过配置将一端作为 **gateway**（网关，即传统意义上的 server），另一端作为 **endpoint / client**（端点）。通信双方预先配置对方的静态公钥，通过 **1-RTT 完全加密握手** 协商出对称会话密钥，之后所有流量均通过该密钥加密传输。

**核心设计目标：**

- 握手报文在网络传输时**完全加密**，不包含任何明文的可识别指纹。
- 数据帧只有 4 字节明文帧头加认证标签，其余载荷全部经 AEAD 加密（ChaCha20-Poly1305）。
- 支持 UDP + 纠错冗余与 TCP 两种传输，适配不同网络环境。
- 客户端换网（源 IP / 端口变化）无感知：不重新握手、不中断会话、虚拟地址不变。

### 配置示例

| 角色 | 示例地址 | 说明 |
|---|---|---|
| gateway | `10.0.0.1` | 拥有静态密钥对 `(SPrivS, SPubS)`，配置客户端静态公钥白名单 `pkl_` |
| endpoint | `10.0.0.2` | 拥有静态密钥对 `(SPrivC, SPubC)`，配置网关静态公钥 `SPubS` |

---

## 2. 架构与模块划分

```
┌─────────────────────────── avpn_service ───────────────────────────┐
│  gateway/client 模式调度 · 监听 · 会话管理 · DDoS 防护 · vaddr 分配 │
└───────┬──────────────────────────────────────────────┬─────────────┘
        │ create/session 回调                           │
┌───────▼──────────────────────────────────────────────▼─────────────┐
│                         avpn_session                                │
│  握手 · 密钥派生 · 数据通路 · keepalive/断开 · UDP/TCP 传输          │
└───┬──────────┬───────────┬───────────┬───────────┬─────────┬────────┘
    │          │           │           │           │         │
┌───▼───┐ ┌────▼────┐ ┌────▼────┐ ┌────▼────┐ ┌────▼────┐ ┌──▼─────┐
│crypto │ │ frame   │ │compress │ │ fec_v2  │ │  tun    │ │ 日志   │
│OpenSSL│ │ header  │ │zlib     │ │RS GF(2⁸)│ │Linux/mac│ │xlogger │
│X25519 │ │ hs/param│ │deflate  │ │ group   │ │OS utun  │ │        │
│AEAD   │ │ key/rep │ │         │ │         │ │         │ │        │
│HKDF   │ │         │ │         │ │         │ │         │ │        │
└───────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘
```

| 模块 | 文件 | 职责 |
|---|---|---|
| `avpn_service` | `avpn.cpp` / `avpn.hpp` | 服务调度、监听、会话管理、DDoS 防护、虚拟地址分配 |
| `avpn_session` | `avpn_session.cpp/.hpp` | 单会话：握手、密钥派生、数据通路、漫游、保活/断开、UDP/TCP 传输 |
| `avpn_crypto` | `avpn_crypto.cpp/.hpp` | OpenSSL/BoringSSL 封装：X25519、ChaCha20-Poly1305、HKDF-SHA256、base64 |
| `avpn_frame` | `avpn_frame.cpp/.hpp` | 帧头/次代/组号算术、明文分类、容器、控制消息、会话参数 TLV、握手报文 |
| `avpn_keys` | `avpn_keys.cpp/.hpp` | 握手密钥与会话主密钥派生、按次代派生数据面密钥、nonce 构造 |
| `avpn_replay` | `avpn_replay.hpp` | 64 位全局序号重放窗口 |
| `avpn_rs` | `avpn_rs.cpp/.hpp` | Reed-Solomon 纠删码（GF(2⁸)）与 SIMD 批量查表 |
| `avpn_fec_v2` | `avpn_fec_v2.cpp/.hpp` | 纠错分组：一包一片、凑够数据片出冗余片、按需还原 |
| `avpn_datapath` | `avpn_datapath.cpp/.hpp` | 数据面：封包/收包、次代推断、重放过滤、漫游帧 |
| `avpn_protocol` | `avpn_protocol.cpp/.hpp` | 常量（mtu、包大小、压缩类型）与 endpoint 解析 |
| `avpn_compress` | `avpn_compress.cpp/.hpp` | 压缩抽象（zlib deflate） |
| `avpn_obfuscate` | `avpn_obfuscate.cpp/.hpp` | 混淆层：在数据帧外面套一层随机垃圾（可选） |
| `avpn_tun` | `avpn_tun.cpp/.hpp` | tun 设备抽象（Linux `/dev/net/tun`、macOS utun、Windows wintun、fd 透传） |
| 基础设施 | `io_context_pool.hpp` / `logging.hpp` | 线程池与日志（xlogger） |

---

## 3. 密钥体系

密钥与密钥派生的字节级定义见 `doc/protocol_v2.md` 第 3 章；本节只列实现要点。

### 3.1 密钥材料

| 密钥 | 说明 |
|---|---|
| `(SPriv, SPub)` | 静态长期密钥对（X25519），双方预先交换公钥 |
| `(EPriv, EPub)` | 握手时生成的临时密钥对，每次握手随机 |
| `K_temp` / `K_resp` | 两把握手密钥，由双方**静态密钥**派生，分别加密握手请求与回复 |
| `K_master` | 会话主密钥，由四次 X25519 派生 |
| `K_e` | 数据面密钥，由 `K_master` 按次代派生；同一次代内不变 |

### 3.2 密钥派生（HKDF-SHA256）

全部派生都用 HKDF-SHA256：

```cpp
// 握手密钥: 共享秘密来自双方静态密钥
shared    = X25519(my_static_priv, peer_static_pub)
K_temp    = HKDF-SHA256(ikm = shared, info = "avpn-hs-temp-v2", L = 32)
K_resp    = HKDF-SHA256(ikm = shared, info = "avpn-hs-resp-v2", L = 32)

// 会话主密钥: 四次 X25519, 静态×静态做盐
ikm       = sort(dh_se, dh_es, dh_ee) 拼接
K_master  = HKDF-SHA256(ikm = ikm, salt = dh_ss, info = "avpn-master-v2", L = 32)

// 数据面密钥: 按次代派生, 方向用用途标签区分
K_e       = HKDF-SHA256(ikm = K_master, salt = 次代(8 字节小端),
                        info = "avpn-datakey-v2" + "c2s"/"s2c", L = 32)
```

- `dh_ss` 是静态×静态，`dh_se` 是静态×临时，`dh_es` 是临时×静态，`dh_ee` 是临时×临时；
  后三个按字典序排序后拼接，保证两端在本地视角不同时算出相同的 `ikm`。
- 客户端用 `c2s` 加密、`s2c` 解密，网关相反；AEAD 认证失败直接丢弃，无任何明文反馈。
- 次代回绕换钥时只重算 `K_e`，主密钥与握手密钥不变。

---

## 4. 握手协议（1-RTT）

握手报文的完整字节布局、字段与参数表见 `doc/protocol_v2.md` §2.2。实现要点：

- 请求最前面是 8 字节 `hint`（客户端静态公钥的哈希前缀，可选）：网关据此一步查到白名单
  项；不带（填 0）时网关逐个白名单项试解密。
- 请求明文含版本、临时公钥、时间戳、客户端标识、期望虚拟地址与参数；回复明文含网关临时
  公钥与参数。两个方向共用同一条 `session_params` 参数表，网关在回复里定下本会话最终值。
- initiator 发送请求后启动重发定时器，最多重发 5 次（间隔 5 秒），超时关闭；responder 只有
  认证成功才回复，解密失败的数据报直接丢弃，不产生任何响应。
- 防重放：请求带毫秒时间戳，网关按对端静态公钥记录最近接受值，拒绝不回退的重复请求。

---

## 5. 数据通道协议

数据帧的完整定义见 `doc/protocol_v2.md` §2.3~§2.5 与第 3 章。实现要点：

- 每帧最前面是 4 字节固定帧头（32 位小端计数器），明文传输；`nonce = 帧头 || 0×8`，
  帧头不再进密文。
- 计数器从 0 数到 2^32 算一个次代，一旦回绕就进入下一个次代并换钥；次代不写进报文，
  接收端用最近两个次代推断（最多试 2 个）。全局序号 `g = 次代 × 2^32 + 计数器` 进 64 位
  重放窗口，既挡重放也定出纠错分组身份（`g ÷ T`）。
- 帧内明文靠首字节分类：`0x4x` / `0x6x` = IP 包（IPv4 / IPv6），`0x00` = 容器（一帧装多个
  条目），`0x01` = 压缩载荷，其它 = 控制消息 `[消息码(1), 长度(2), 内容]`；类型不额外占字节。
- 漫游帧在帧头前多带 8 字节 `roam_cookie`（握手时下发，同时作为 AEAD 的 AAD）；网关在
  解密之前就能按 cookie O(1) 认出会话，用于换网重绑与保活。

发送 / 接收流水线：

```
发送 (tun → 对端):
  ip_packet ──► 机会性聚合(手里已有的包能塞进一帧就按容器装上)
             ──► 纠错分组(一片一个包或容器, 满了补冗余片)
             ──► 帧头 + AEAD 加密 ──► UDP/TCP 发送

接收 (对端 → tun):
  UDP/TCP ──► 按帧头解密(判次代/挡重放) ──► 纠错还原(收齐 ds 片)
           ──► 拆容器/解压 ──► 交付 tun
```

---

## 6. FEC 纠删码

### 6.1 Reed-Solomon 编码

- 基于 **GF(2⁸)**，本原多项式 `0x11d`。
- `reedsolomon(data_shards, parity_shards)`：`data` 分片经 Vandermonde 生成矩阵编码为
  `parity` 分片。
- **系统形式（systematic form）**：编码矩阵经行变换化为 `[I | P]`，编码时数据分片原样
  保留，仅附加校验分片。
- **重建**：任意选取 `data_shards` 个未丢失的分片，构建子矩阵并求逆，恢复全部数据分片。
  最多可容忍 `parity_shards` 个分片丢失。

### 6.2 GF(2⁸) 查表与 SIMD 优化

域运算全部基于**编译期生成**的静态表（`constexpr`，无运行时初始化开销）：

| 表 | 说明 |
|---|---|
| `log_table` / `exp_table` | 对数/指数表；指数表长度为 512（双周期），加法免取模 |
| `mul_table` | 256×256 乘法表，单次查表完成 GF 乘法 |
| `low_tables` / `high_tables` | 低/高半字节紧凑表（256×16），供 SIMD 批量查表 |

批量乘法 `out = c × in` / `out ^= c × in` 按平台分派：

- **x86-64**：SSSE3 / AVX2，`pshufb` 并行查表（16/32 字节每次）。
- **aarch64**：NEON，`vqtbl1q` 并行查表。
- **分派策略**：GCC/Clang 使用 per-function `target` attribute + `__builtin_cpu_supports`
  运行时检测；MSVC 无 per-function attribute，整个 TU 以 `/arch:AVX2` 编译，用 `__cpuid`
  运行时分派，不支持 AVX2/SSSE3 时回退标量查表。

### 6.3 矩阵缓存

- **编码矩阵缓存**：按 `(data_shards, parity_shards)` 全局缓存系统形式编码矩阵，避免每个
  会话重复生成 Vandermonde 矩阵。
- **逆矩阵 LRU 缓存**：按 `(data_shards, parity_shards, 选中分片位图)` 缓存解码子矩阵的逆
  （容量 64），避免每次恢复重复高斯-约当消元。

### 6.4 纠错分组

一个 IP 包就是一个数据片，收到即发（不等凑齐）：

- 每攒够 `ds` 个数据片，立即算出 `ps = T − ds` 个冗余片并一起发出；`T = 1` 表示不开纠错，
  退化为整帧模式。
- 参与运算时短的片用 0 补齐到组内最长数据片的长度；补出来的 0 不进报文，只有冗余片按该
  长度发送。
- 接收端数据片立即投递并留一份缓存，收齐任意 `ds` 片即可还原缺失片；超时仍未凑齐就整组
  丢弃。

---

## 7. 压缩与混淆

### 7.1 压缩

- 两端握手时用参数 `0x0C` 谈定算法，实现了 `deflate` 与 `lz4`，`zstd` 预留；
  两端配成同一个算法才生效，默认不压缩。
- 压缩放在 `avpn_datapath` 里做，只压 IP 包：压后数据加 3 字节条目头仍比原包小，才发压缩
  载荷 `[标记(1) = 0x01, 压后长度(2), 压后数据]`；否则原样发 IP 包，一个字节都不多花。
- 压之前先花一点点时间判断值不值得压（`looks_compressible`）：沿载荷均匀取 256 个字节，
  数出现过的字节种类，种类占样本数一半以上就当作随机数据直接跳过。这样已经加密的载荷、
  压过的媒体流不会被白白塞给 deflate（deflate 在随机数据上要几十微秒，一条 Gbit 隧道
  的每包预算才十几微秒）。判错的代价只是错过一次压缩机会。
- 收包方向先看明文首字节，是 `0x01` 就按长度字段取出压后数据（顺带剥掉纠错补零）再解压；
  长度越界、数据解不开、解压结果超过一个满长包（防解压炸弹）都整片丢弃。
- `compressor` 抽象封装 `set_type / compress / decompress`，解压的最大输出由调用方按
  `mtu` 给（防解压炸弹），两种算法各走各的路：
  - `deflate`：压用原始 deflate（`Z_BEST_SPEED`，不带 zlib 头，报文已由 AEAD 认证，
    省下的 10 个字节在小包上很值）；每包是一个独立的流，压 / 解两条 `z_stream` 常驻，
    每包只 `deflateReset` / `inflateReset` 一次，每包重建 zlib 流要几十微秒，会直接
    吃光包速率的预算。
  - `lz4`：用 `third_party/lz4` 里的库本体，压 / 解都走块接口
    （`LZ4_compress_default` / `LZ4_decompress_safe`），一次调用进出，没有常驻状态；
    输出上限直接交给解压接口，越界解不开就丢。
- 两种算法的实测差距（跨机，纠错 12/16、MTU 1450、可压的重复载荷，同一链路，各跑一次
  6 秒 iperf3，多次运行有百分之几的波动）：lz4 上行 826 / 下行 928 Mbit/s，deflate
  上行 541 / 下行 672 Mbit/s，不压缩 669 / 680 Mbit/s。lz4 把省下来的线上字节换成了
  吞吐，deflate 则先撞上 CPU 上限；压不动的流量两种算法都跳过，吞吐和不压缩一样。

### 7.2 混淆层（可选）

线格式与协商见 `doc/protocol_v2.md` §2.6；实现要点：

- `avpn_obfuscate` 只有两个动作：`obfuscate_frame` 在加密帧外面套
  `[salt(4), len_enc(2), 垃圾(16~64)]`，`deobfuscate_frame` 把它剥掉。垃圾长度按
  `XXH64(密钥串, salt)` 的低 16 位掩码异或后写在线上，没有密钥串就算不出真实长度。
- 垃圾的长短**只跟帧长挂钩**，不随机：等长帧套出来还是等长，内核收方向的合并
  （GRO）与发方向的 GSO 才认得出来。长度一随机，实测吞吐掉三成，而帧长本来就在
  报文长度里（§6 的开销表），换不来什么。
- 会话在 `queue_frame` 里套层、在 `handle_wire` 里剥层，条件是握手谈成了混淆、且本端
  配了密钥串；**带漫游凭证的帧不套**，网关靠最前面 8 字节凭证做 O(1) 会话分流。
- 只在会话建立之后的数据帧上套，握手报文不套——“开不开混淆”本身就是握手谈出来的。
- 混淆层的开销（最坏 70 字节）从片长上限里扣：`wire_payload_limit()` 按 `tag_len`
  和混淆开关算出一片能装多长，握手时下发的内层 MTU 也跟着收（默认 1450 → 1382），
  保证套上垃圾后外层报文仍不超过线缆 MTU，不会被 IP 分片。
- 两端密钥串不一致时握手直接失败（客户端在参数 `0x13` 里带上密钥指纹，网关比对），
  免得数据面把帧算错位，变成“能握手但一个包也过不去”。

---

## 8. 传输机制

### 8.1 UDP 传输

- 每帧一个 UDP 数据报，正文为 `[帧头(4) | AEAD]`（见 §5）。
- 支持纠错冗余（§6），适用于丢包率高的网络环境。
- 网关侧共享一个 UDP socket（`udp_send_handler` 由 service 注入），多会话复用。
- **并发接收**：每个 UDP socket 启动 `udp_receive_concurrency` 个并发接收协程
  （`clamp(hardware_concurrency, 2, 16)`，参考 avpn 的 `global_op_concurrency`）。
  单 io_context 单线程调度下，多协程并发异步接收，在数据包处理（解密/FEC）期间
  接收不中断，提升高 PPS 场景下的吞吐。

### 8.2 TCP 传输

- 每帧为 `[len(2, BE) | 帧头(4) | AEAD]` 的 TCP 流式帧，线格式与长度上限见
  `doc/protocol_v2.md` §2.8。
- 使用 `m_tcp_oqe` 写队列 + `start_tcp_write` 协程泵串行写出（合并最多 128KB 或
  等待 2ms），保证帧边界完整。
- 接收端 `tcp_read_loop` 读取长度前缀后按帧分发（握手/数据）。
- 一个 TCP 连接对应一条隧道：网关接受连接后建会话，会话身份即连接本身，因此 TCP
  下没有漫游帧，换网只能重连重握手。
- 跨机实测（192.168.1.130 网关 ↔ 192.168.1.143 客户端，千兆局域网）：ping 0% 丢包，
  iperf3 双向约 890 Mbit/s，两端无错误日志。
- 数据面优化（设计目标，当前为后续增强，见 §15）：
  - IP 包为 TCP 且为 SYN 时，为该 TCP 流创建**专用 TCP socket** 传输，避免 TCP-in-TCP。
  - IP 包为 UDP 时，按目标 Address 建立**独立 TCP socket** 传输。
  - 当前所有数据都走这一条加密控制流（相当于 TCP-in-TCP），上述拆分尚未接线。

### 8.3 内核协同与批量优化

- **UDP 收发缓冲**：内核默认 UDP 收发缓冲通常只有 212KB，远小于长 RTT 的
  带宽时延积，接收队列溢出造成的丢包会直接打断内层 TCP 拥塞窗口。avpn 显式
  放大 socket 缓冲，并在具备 `CAP_NET_ADMIN` 时使用 `SO_*BUFFFORCE` 突破
  `net.core.{r,w}mem_max` 上限。
- **UDP 批量发送**：等长帧走 `UDP_SEGMENT`（GSO），由内核按段生成报文；
  不等长帧合并到一次 `sendmmsg`，避免逐帧一次系统调用。
- **TCP 读写合并**：写方向合并队列中的多帧（最多 128KB 或等待 2ms）后一次
  写入，内核可按 TSO/GSO 分段，网卡通知次数下降一个数量级；读方向一次读入
  大块（128KB）再逐帧解析，异步操作次数与每帧堆分配随帧数减少。真机实测
  （Pixel 6 ↔ 2 vCPU VPS，RTT ≈ 140ms，8 条并发下行流）TCP 传输 8 流吞吐由
  30.2 Mbit/s 提升到 34.3 Mbit/s（最好一次 43.7），网关单核占用由 53–61%
  降到 44–50%。
- **tun 收包内联处理**：tun 收包不再二次投递到事件循环，省掉每包一次队列
  调度；纠错模式下数据片收到即发，不攒批等待。
- **出口 qdisc 与限速**：发送端出口 qdisc 的 per-flow 上限会整批丢掉 GSO
  尾包。同一批 `UDP_SEGMENT` 帧是一次 `sendmsg` 交给内核的，而 `fq` 默认
  `flow_limit 100p` 只允许单条流排队 100 个报文，隧道在瓶颈链路上突发时
  超出部分（通常是本批尾部）会被整体丢弃，接收端因此长期凑不齐 `ds` 片。
  千兆内网实测（MTU 1450，4 流下行）：`fq` 默认配置下 6 秒内
  `flows_plimit` 丢包约 3.5 万个，隧道下行只有 ~726 Mbit/s 且发送端 TCP
  重传约 12 万段；把上限放大后丢包归零，下行提升到 ~853 Mbit/s（物理链路
  iperf3 约 936 Mbit/s）。因此发送端建议
  `tc qdisc replace dev <iface> root fq flow_limit 10000`（或改用无 per-flow
  上限的 `fq_codel`/`mq`），并在瓶颈链路上配合 `--udp_pacing_mbps` 把外层
  速率压在链路能力以内。
- **tun 批量发送与 `fq` 的排队深度**：tun 读取循环把一次收下的一批包连成
  一串发出去，交给内核的外层报文比逐个发送时深得多；`fq` 的 `flow_limit`
  按“单条流排队多深”算，灌得太快就会压过上限、把超出的丢掉。千兆内网实测
  （FEC 12/16，MTU 1450，单流上行，发送端出口 `fq` 用默认 `flow_limit 100p`）：
  一次收包上限取 32 时，10 秒内 `flows_plimit` 丢掉 97,617 个外层报文，
  内层 TCP 重传 46,306 段，上行只有约 599 Mbit/s；同一条链路把 `flow_limit`
  放大到 10000 后重传降到 26 段、上行约 655 Mbit/s，换成 `pfifo` 只有 5 段
  重传。丢的包先由纠错补，一组超过 `ps` 片补不回来才落到内层 TCP 头上，
  所以既丢吞吐、又放大重传。结论和上一条一致：发送端要么放大 `flow_limit`、
  要么换掉带 per-flow 上限的 qdisc；要么让发送端自己盯着外层排队深度、排太深
  就先停一停（见下一条）。
- **外层发送背压**：tun 读取循环每轮先看外层 socket 里还有多少字节没发出去
  （Linux 用 `SIOCOUTQ`），排队超过 64 KB 就先不读 tun，等内核把队列排空再读。
  这样出口 qdisc 的 per-flow 队列始终很浅，撞不上 `fq` 默认的 100 个报文上限。
  同一条链路实测（FEC 12/16，上行 10 秒）：不加背压时 `flows_plimit` 丢 66,141
  个报文、内层 TCP 重传 36,194 段、上行 584 Mbit/s；加了之后丢包为 0、重传 9 段、
  上行 644 Mbit/s，下行不掉（683 → 682 Mbit/s），ping 往返 0.56~0.84 ms 也没有
  变化。停等间隔取 100 µs：取 200 µs 太粗，下行会掉到约 658 Mbit/s。
- **CPU 瓶颈判断**：网关下行可能受限于单核 CPU。低配 VPS（2 vCPU）实测裸
  `sendto` 1422 字节就要 ~27 µs，隧道上下行合计只能跑到 ~60–70 Mbit/s 且
  网关单核跑满，而同一进程内 AEAD 每包仅几微秒。这类主机瓶颈在内核网络栈
  而不是 avpn 自身，减少隧道数据报数量（而不是加密开销）才是有效方向。

---

## 9. 会话生命周期

### 9.1 状态

| 状态 | 说明 |
|---|---|
| `established` | 握手完成，可收发数据 |
| `abort` | 会话已终止（超时/断开/关闭） |

### 9.2 Keepalive 与超时

- 每 `keepalive` 秒发送加密 `keepalive` 消息（携带发送时间戳），对端回复 `keepalive_reply`（回显时间戳）。
- 收到任何有效数据（含 keepalive/reply）均刷新 `m_last_seen`。
- 超时判定：`now - m_last_seen > 120` 秒（`peer_idle_timeout`）→ 判定对端失联，
  关闭会话并释放资源。

### 9.3 主动断开

- 一端调用 `disconnect()` 时发送加密 `disconnect` 消息，对端收到后进入 `abort` 状态并释放资源。
- 意外断开由 9.2 的超时机制兜底。

### 9.4 tick 协程

`tick()` 为 1 秒循环协程（`m_tick_timer`），驱动保活发送与超时检测；会话关闭时取消定时器。

### 9.5 网络切换无感知

客户端物理网络变化（如 Wi-Fi → 移动网络）会让出口地址/端口变，avpn 靠“漫游帧 + 漫游凭证”
做到无感切换：

- 握手时网关给每个会话下发一个 8 字节 `roam_cookie`；客户端换网后发的报文最前面带上它
  （漫游帧），并把它作为 AEAD 的 AAD 一起校验。
- 网关除 `m_sessions`（endpoint → session）外，另维护 `m_sessions_by_cookie`（cookie →
  session）。来自陌生 endpoint 的报文先按最前面的 8 字节查表，命中且 cookie 校验通过就把
  该会话的远端 endpoint 改到新地址（`update_remote_udp`）并迁移 `m_sessions` 索引，数据流
  不中断、无需重新握手。
- 客户端由 `client_network_monitor` 定期探测出口地址变化，变化后 `renew_client_udp` 重建
  UDP socket 并调用 `notify_network_changed` 立即补发一个漫游保活；此外每 `cookie_beacon_K`
  帧数据帧顺带一次 cookie，一直收不到下行时也会自动补发。
- 每次重新绑定（迁移成功）后网关都轮换一次漫游凭证（`rotate_roam_cookie`）：新凭证用
  控制消息 `0x05` 通知客户端，旧凭证在 10 秒重叠期内仍然有效（`roam_cookie_window`），
  免得轮换前发出的在途帧被丢掉；被顶出窗口的那把从 `m_sessions_by_cookie` 索引里删除，
  索引里因此最多同时挂两把。
- 会话密钥与 vaddr 都不依赖 IP，迁移后虚拟地址不变、tun 配置无需变更。
- 客户端重启（同公钥重新握手）时，网关关闭同公钥旧会话并替换（`Replacing old session`）。

### 9.6 带宽统计

- 会话在 `send_plaintext` / `process_plaintext` 中累计明文上下行字节
  （`m_upload_bytes` / `m_download_bytes`，含 FEC 帧开销）。
- `tick()` 每秒对累计值做 3 采样槽滑窗采样（`update_speed`），以窗口首尾差值计算
  瞬时速率（`upload_rate` / `download_rate`）。
- 服务端与客户端均启动 `bandwidth_report_loop`，每 10 秒输出各会话/隧道的
  `up=` / `down=` 速率与 `total_up=` / `total_down=` 累计值。

---

## 10. DDoS 缓解

为避免引入 2-RTT Cookie，网关侧通过 `avpn_service::ddos_guard` 实现：

| 机制 | 参数（默认） | 说明 |
|---|---|---|
| 每 IP 握手限速 | 5 秒 | 单个源 IP 每 5 秒最多接受一次握手尝试 |
| 失败次数限制 | 5 次 | 连续 5 次握手失败进入封锁 |
| 封锁时长 | 60 秒 | 封锁期内直接丢弃该 IP 的握手包 |

流程：`on_gateway_udp_packet` → `ddos_guard->allow_handshake(ip)` 校验 → 尝试握手 → `report_success` / `report_failure` 更新状态。被封锁或超限的 IP 在封锁期/限速窗口内不做任何响应。

---

## 11. tun 设备

`tun_device` 提供三种打开方式：

1. `ptun_fd_ >= 0`：直接使用外部传入的 tun fd（如通过 SCM_RIGHTS 传递）。
2. `utun_fd_ >= 0`：通过 Unix Domain Datagram Socket 以 IPC 方式读写 IP 数据包。
3. 平台默认打开：
   - **Linux**：`/dev/net/tun` + `TUNSETIFF`，通过 `SIOCSIFADDR`/`SIOCSIFNETMASK`/`SIOCSIFMTU`/`SIOCSIFFLAGS` 配置地址、掩码、MTU 与 UP。
   - **macOS**：`utun` 接口（`<net/if_utun.h>` + `SYSPROTO_CONTROL`），配置使用 `ifconfig`。
   - **Windows**：wintun 驱动（见 `avpn_wintun` 模块）。

异步读写封装在 `net::posix::stream_descriptor`（`async_read_some` / `async_write_some`），与 asio 协程无缝集成。

### 11.1 Windows wintun

Windows 平台由 `avpn_wintun`（`avpn_wintun.cpp/.hpp`）实现 tun 后端，`tun_device`
在 `_WIN32` 下将成员替换为 `wintun_tun_device` 并转发全部操作：

- **驱动集成**：wintun 驱动（`wintun.sys/inf/cat`）以资源方式内嵌 exe，首次运行
  自动解压并经 `pnputil` 安装；适配器管理动态加载 `wintun.dll`。
- **环形缓冲**：应用自建 send/receive 两个 ring（`CreateFileMapping` +
  `MapViewOfFile`）与两个 auto-reset 事件，通过 `TUN_IOCTL_REGISTER_RINGS`
  注册给驱动。ring 为无锁 SPSC 队列，`head`（消费者）/`tail`（生产者）按
  8 MiB 容量取模，带 64 KiB 尾部冗余避免跨环拆分；驱动侧
  `WriteULongRelease`/`ReadULongAcquire`，用户态 volatile 读写保证顺序。
  注意 `TUN_REGISTER_RINGS` 的 `send`/`receive` 字段是**驱动视角**命名。
- **异步读写**：读采用"同步首读 → 约 100us spin → `object_handle.async_wait`
  等待事件"三级策略，突发多包时连续调用天然排空 ring；写遇 ring 满则以
  `steady_timer` 定时重试。
- **网络配置**：`CreateUnicastIpAddressEntry` 设置 IPv4/IPv6 地址，
  `SetIpInterfaceEntry` 设置 MTU。

详细原理与实现见 `doc/avpn_wintun.md`。

### 11.2 客户端系统路由与 DNS

客户端握手成功后，网关推送的路由与 DNS 由 `wait_handshake_and_setup_tun()` 落地
（`setup_system_routes()` / `apply_system_dns()`），会话结束或进程退出时再还原
（`restore_system_routes()` / `restore_system_dns()`）。配了 `ignore_push_` 时两样
都不落地。

- **路由**（Linux，走 netlink，`netlink_route.cpp`）：`pushroutes_` 逐条写入路由表，
  `passbyvpn` 时把默认路由拆成 `0.0.0.0/1` + `128.0.0.0/1` 两条更具体的路由指向
  tun（不删原默认路由，`bypassroutes_` 与服务器地址仍走物理网卡）；`bypassroutes_`
  用物理默认网关钉住，域名目标定期重新解析（`bypass_route_refresh_loop()`）。
- **DNS**（Linux，`resolv_conf.cpp`）：按系统解析器由谁管分两条路走。
  - **systemd-resolved**（`/etc/resolv.conf` 是指向 `/run/systemd/resolve/` 的符号
    链接）：改文件会被守护进程立刻盖掉，所以走
    `resolvectl dns <tun> <地址>` + `resolvectl domain <tun> '~.'` 配链路级 DNS
    （不设 `~.` 这个路由域的话，物理链路的 DNS 仍然优先）；会话结束
    `resolvectl revert <tun>` 撤销，tun 消失时设置本来也会跟着没。
  - **其它情况**（`/etc/resolv.conf` 是普通文件）：把推送的地址插到 `nameserver`
    列表最前面，原来的 nameserver 与 `search` / `options` 等行原样留在后面当后备，
    会话中解析照旧可用；文件就地截断写，保留原 inode 与权限。只记第一次改动前的
    内容，重连时推送地址变了也能还原，叠加应用不会重复插入（同样的地址只留一条）。
  - 走哪条路都记在日志里（`System resolver uses pushed dns: <地址> (resolvectl avpn0)`
    或 `(/etc/resolv.conf)`），出问题时一眼能看出改的是哪儿。
  - `resolv_conf_merge()` 是纯函数，单独用 `tests/resolv_conf_tests.cpp` 覆盖。
- **外部 tun fd 模式**（Android `VpnService` 等）：系统路由与 DNS 都由宿主应用随
  tun 一起配，核心只把推送的 DNS 放进 `vaddr` 通知（`notify_vaddr()`）交给应用。

---

## 12. 服务架构

### 12.1 运行模式

`avpn_service::start()` 根据配置自动选择模式：

- **客户端模式**：配置了 `nexthop_`（支持 `udp://` 或 `tcp://` 前缀）。
  - 打开 tun，创建 initiator 会话（配置对端 `public_key_`）。
  - UDP：创建 socket + `run_initiator_udp(server_ep)` + `client_udp_receive_loop`。
  - TCP：`client_tcp_connect` 连接对端 + `run_initiator_tcp`。
  - `route_tun_packet`：从 tun 读到的 IP 包一律交给 `m_tunnel` 加密发送。
  - 握手完成后 `wait_handshake_and_setup_tun` 按协商的 vaddr/prefix/mtu 配置 tun。

- **网关模式**：配置了 `tcp_listens_` / `udp_listens_`。
  - 打开 tun（配置为子网地址）。
  - UDP/TCP 监听 + `udp_receive_loop` / `tcp_accept_loop`。
  - 每个新对端创建 responder 会话，握手成功后注册进 `m_sessions`（按对端 endpoint 字符串索引），
    同时按对端静态公钥注册进 `m_sessions_by_pubkey`（网络切换识别用）。
  - `route_tun_packet`：解析目标 IP（v4 第 16-19 字节），按目标地址查找会话转发（支持客户端互通）。
  - 会话关闭回调：从 `m_sessions` 移除并释放 vaddr。

### 12.2 虚拟地址分配

- 网关从 `subnet_` 解析子网（如 `10.8.0.0/16`），维护 `m_allocated_addrs` / `m_next_vaddr`。
- `alloc_vaddr()` 分配下一个可用地址，握手成功后通过 `session_config.vaddr` 下发给客户端。

---

## 13. 配置项（service_config）

| 字段 | 说明 |
|---|---|
| `ifdev_` | tun 设备名称（Linux/macOS 接口名；Windows 为 `wintun`） |
| `ptun_fd_` / `utun_fd_` | 外部 tun fd / IPC fd（-1 表示不使用） |
| `launcher_` | 控制服务地址（如 `ws://ip:port`），用于动态下发配置 |
| `nexthop_` | 目标 VPN 服务器（客户端模式），支持 `udp://` / `tcp://` |
| `tcp_listens_` / `udp_listens_` | 监听地址（网关模式） |
| `private_key_` / `public_key_` | 本端静态密钥对（base64） |
| `pkl_` | 远端公钥白名单（base64 列表） |
| `mtu_size_` | tun MTU |
| `keepalive_` | 保活间隔（秒） |
| `tag_len_` | 数据帧认证标签长度（16 或 12，默认 16）；客户端在握手请求里表达，网关按 §5 的规则定夺 |
| `pushroutes_` / `pushdns_` | 网关推送的路由 / DNS；`pushdns_` 是 IPv4 地址的数值（命令行与配置文件里写 `10.9.0.53` 或整数都认） |
| `passbyvpn_` | 是否默认全局出口（网关需配置 NAT） |
| `ignore_push_` | 是否忽略推送的 route/dns |
| `c2c_` | 是否允许客户端间通信 |
| `subnet_` | VPN 子网（如 `10.0.0.0/16`） |
| `data_shards_` / `parity_shards_` | 纠错参数：`T = data_shards_ + parity_shards_` 须为 2 的幂，`ds = data_shards_`；`ds < 2` 时不开纠错 |
| `compress_` | 压缩算法（`deflate` 或 `lz4`，空为不压缩；客户端在握手请求里带上，网关据此确认） |
| `hint_` | 握手是否附带静态公钥哈希前缀（O(1) 查白名单，代价是公钥可被关联） |

---

## 14. 安全与健壮性

- 握手包无任何明文指纹，网关仅通过 AEAD 认证 + 白名单遍历识别对端，无法从线路上区分握手与数据包。
- 所有控制消息（keepalive/disconnect）均使用会话密钥加密。
- AEAD 认证失败一律静默丢弃，不产生可观测差异。
- 握手请求防重放（按对端记录最近接受的时间戳，拒绝回退或重复），DDoS 防护（限速 +
  失败封锁）无需 2-RTT。
- 解压设置最大输出限制，防止解压炸弹。

---

## 15. 已知限制与后续工作

1. **TCP 按流拆分**：TCP 传输下内层 TCP 目前仍走 TCP-in-TCP（单一加密控制流）。
   按 SYN 为每条内层 TCP 流建专用外层连接、按目标地址为内层 UDP 建独立连接的优化
   （见 §8.2）还没接线，配套的 IP 头解析函数也还没写。
2. **压缩算法**：`deflate` 与 `lz4` 已实现，`zstd` 为预留接口。
3. **多线程**：`io_context_pool` 已提供，当前服务逻辑运行在主 context，可扩展至多 context 提升吞吐。
4. **wintun 单读者**：ring 的 `head` 推进无锁，需保证单个 io_context 上串行调用
   `async_read_some`（当前 `tun_read_loop` 单协程满足）；多协程并发读取会对
   `head` 竞争。
5. **容器聚合**：机会性聚合已接线——从 tun 一次收下的一批包按会话合并提交，能塞进
   一帧的按容器装上，不为攒包等待（一次最多 `tun_batch_max` = 32 个，见
   `doc/protocol_v2.md` §2.4）。开纠错时，聚合会把同组里较短的片补到最长片的长度，
   聚合度越大，这部分放大越多。
6. **外层发送背压的平台差异**：Linux 上已按外层未发送字节数（`SIOCOUTQ`）做背压
   （见 §8.3）；wintun/其它平台拿不到这个计数，等同于没有背压，出口 qdisc 带
   per-flow 上限时仍要靠系统侧配置（见 §8.3）。
