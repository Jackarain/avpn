# avpn_wintun 实现文档

> 本文档描述 `avpn_wintun` 模块的实现原理，重点是 wintun 环形缓冲区
> （ring buffer）的读写规则，以及驱动安装、设备打开、ring 注册等与驱动
> 交互的实现细节。实现参考 avpn 的 `wintun_windows_service`。

---

## 1. 概述

`avpn_wintun` 是 avpn 在 Windows 平台上的 tun 后端。Windows 没有类似
Linux `/dev/net/tun` 的统一 tun 接口，avpn 选择 wintun 驱动实现：

- wintun 是 WireGuard 官方发布的 tun 驱动（`wintun.sys`），提供
  NDIS 虚拟网卡。
- wintun 的用户态 API 有两种使用方式：
  - **session API**（`wintun.dll` 的 `WintunStartSession` 等）：由
    wintun.dll 封装 ring 的创建与注册。
  - **raw ring 接口**（`TUN_IOCTL_REGISTER_RINGS`）：应用自行创建
    环形缓冲与事件，通过 IOCTL 注册给驱动。avpn 与 avpn 均采用该方式，
    不依赖 wintun.dll 的数据通路，仅用 wintun.dll 做适配器管理。
- avpn 只在 Windows 编译 `avpn_wintun.cpp`，通过 `tun_device` 抽象对外
  提供与 Linux/macOS 一致的异步读写接口（`async_read_some` /
  `async_write_some`），上层（`avpn.cpp`）无需感知平台差异。

整体数据流：

```
                    用户态 (avpn)                        内核态 (wintun.sys)
    ┌──────────────────────────────────┐        ┌──────────────────────┐
    │  avpn_session ←→ avpn_tun        │        │                      │
    │            │                     │        │  NDIS 虚拟网卡        │
    │  async_read_some / write_some    │        │                      │
    │            │                     │        │                      │
    │  ┌──────────────────────────┐    │        │   ┌──────────────┐   │
    │  │  receive ring (驱动→应用) │◄───┼────────┼───│   驱动写入    │   │
    │  │  send ring    (应用→驱动) │───►┼────────┼──►│   驱动读取    │   │
    │  └──────────────────────────┘    │        │   └──────────────┘   │
    │      ▲ event            ▲ event │        │      ▲          ▲     │
    └──────┼───────────────────┼───────┘        └──────┼──────────┼────┘
           │  receive_tail_moved (驱动置位)             │          │
           └── 应用等待 ────────────────────── 驱动等待 ◄── send_tail_moved (应用置位)
```

---

## 2. wintun 环形缓冲原理

### 2.1 ring 结构

ring 由 wintun 的 `ring_buffer.h`（第三方目录
`third_party/wintun/include/ring_buffer.h`）定义：

```c
#define WINTUN_RING_CAPACITY       0x800000  /* 8 MiB, 必须是 2 的幂 */
#define WINTUN_RING_TRAILING_BYTES 0x10000   /* 64 KiB 尾部冗余 */
#define WINTUN_MAX_PACKET_SIZE     0xffff    /* 最大包长 65535 */
#define WINTUN_PACKET_ALIGN        4         /* 包对齐 4 字节 */

struct tun_ring
{
    volatile ULONG head;      /* 消费者读取位置 */
    volatile ULONG tail;      /* 生产者写入位置 */
    volatile LONG  alertable; /* 驱动就绪标志 */
    UCHAR data[WINTUN_RING_CAPACITY + WINTUN_RING_TRAILING_BYTES];
};

struct TUN_PACKET_HEADER { uint32_t size; };

struct TUN_PACKET
{
    uint32_t size;
    UCHAR data[WINTUN_MAX_PACKET_SIZE];
};
```

每个数据包在 ring 中的布局为 `TUN_PACKET_HEADER + payload`，并按
`WINTUN_PACKET_ALIGN`（4 字节）对齐：

```c
aligned_size = align4(sizeof(TUN_PACKET_HEADER) + packet->size)
```

### 2.2 head / tail 语义

ring 是一个无锁单生产者单消费者环形队列，容量 `WINTUN_RING_CAPACITY`
为 2 的幂，因此取模可以用位与实现：

```c
wrap(v) = v & (WINTUN_RING_CAPACITY - 1)
```

规则：

| 方向 | 生产者 | 消费者 |
|---|---|---|
| send ring（应用→驱动） | 应用写 `tail` | 驱动读 `head` 并推进 |
| receive ring（驱动→应用） | 驱动写 `tail` | 应用读 `head` 并推进 |

- `head == tail`：ring 为空。
- 有效数据区间为 `[head, tail)`（按容量取模）。
- 消费者可读内容长度：`content_len = wrap(tail - head)`。
- 生产者可用空间：`space = wrap(head - tail - WINTUN_PACKET_ALIGN)`，
  预留 4 字节，保证 `tail` 追上 `head` 时仍能区分空/满。
- 指针越界保护：`head` / `tail` 任意大于等于容量视为协议错误。

### 2.3 尾部冗余（trailing bytes）

`data[]` 实际大小为容量 + 64 KiB。生产者写入数据包时**不跨环边界拆分**
（写入位置 `tail` 已取模，但写入地址使用 `&data[tail]` 的线性地址），
即使数据包跨越容量边界，也会落在尾部冗余区，物理上仍是连续内存。
消费者在推进 `head` 时才做取模。这保证了一次 `memcpy` 即可完成读写，
避免跨边界分包。

### 2.4 内存序

ring 是无锁共享内存，跨内核/用户态边界，需要显式内存序：

- 生产者：先写数据包内容，再发布（release）`tail`。
- 消费者：先读取（acquire）`tail`，再读数据包内容。

驱动侧使用 `WriteULongRelease` / `ReadULongAcquire`（对应 MSVC 的
`InterlockedExchange` 类原语或 GCC 的 `__atomic`）。用户态侧
`head`/`tail` 声明为 `volatile ULONG`，在 x86/amd64 上 32 位对齐读写的
顺序性由 volatile + 硬件保证，这是 wintun 官方用户态示例的通行做法。

avpn 的 `read_wintun` / `write_wintun` 遵守上述顺序：一次调用内只读取
一次 `head`/`tail` 快照，基于快照计算并操作，最后才推进本端指针。

### 2.5 注册结构体的命名约定

`TUN_IOCTL_REGISTER_RINGS` 的输入结构 `tun_register_rings` 中
`send` / `receive` 字段是**驱动视角**命名，容易与直觉相反：

```c
struct tun_register_rings
{
    struct { ULONG ring_size; struct tun_ring *ring; HANDLE tail_moved; } send, receive;
};
```

- `send`：驱动**发送给应用**的 ring，即应用的 **receive ring**；
  其 `tail_moved` 事件由驱动置位、应用等待。
- `receive`：驱动**从应用接收**的 ring，即应用的 **send ring**；
  其 `tail_moved` 事件由应用置位、驱动等待。

因此 avpn 注册时做了对应映射：

```cpp
rr.send.ring = m_receive_ring;               // 应用接收环
rr.send.tail_moved = m_receive_event_moved;  // 应用等待的事件
rr.receive.ring = m_send_ring;               // 应用发送环
rr.receive.tail_moved = m_send_event_moved;  // 驱动等待的事件
```

### 2.6 事件通知

两个事件均为 auto-reset 事件（`CreateEventW(NULL, FALSE, FALSE, NULL)`）：

- 驱动把数据包写入 receive ring 并发布 `tail` 后，置位
  `receive_tail_moved`，唤醒等待中的应用。
- 应用把数据包写入 send ring 并发布 `tail` 后，置位
  `send_tail_moved`，唤醒等待中的驱动。
- `ring->alertable` 是驱动维护的就绪标志；应用写包后仅在该标志非零时
  置位事件，避免驱动尚未就绪时事件丢失。

---

## 3. 驱动集成

### 3.1 驱动文件嵌入

wintun 驱动三件套（`wintun.sys` / `wintun.inf` / `wintun.cat`）放在
`avpn/src/resource/driver/`，通过 `avpn/src/resource/avpn.rc.in` 以
`RCDATA` 资源嵌入 `avpn.exe`：

```rc
wintun.cat RCDATA "@AVPN_RESOURCE_DIR@/driver/wintun.cat"
wintun.inf RCDATA "@AVPN_RESOURCE_DIR@/driver/wintun.inf"
wintun.sys RCDATA "@AVPN_RESOURCE_DIR@/driver/wintun.sys"
```

`avpn.rc.in` 由 CMake 的 `configure_file` 生成 `avpn.rc`（已加入
`.gitignore`），仅在 Windows 构建时参与编译。

### 3.2 驱动安装（install_wintun）

首次运行流程：

1. 通过注册表枚举已安装网卡（`enum_windows_devices`），若存在
   `ComponentId` 含 `wintun` 的驱动则直接返回，跳过安装。
2. 否则用 `FindResource` / `LoadResource` 从 exe 资源中解压
   `wintun.sys` / `wintun.inf` / `wintun.cat` 到临时目录
   `%TEMP%/<pid>/`。
3. 调用 `pnputil /add-driver <wintun.inf>` 安装驱动（
   `run_command` 通过 `CreateProcessW` 执行并等待退出码）。
4. 清理临时目录。

### 3.3 wintun.dll 动态加载

适配器管理（创建/打开/关闭适配器、获取 LUID）需要 wintun.dll，avpn
通过 `wintun_detail::wintun_api::load()` 动态加载：

- `LoadLibraryW(L"wintun.dll")` + `GetProcAddress` 获取
  `WintunCreateAdapter` / `WintunOpenAdapter` / `WintunCloseAdapter` /
  `WintunGetAdapterLUID` 四个函数指针。
- 任一函数缺失即视为加载失败；模块句柄由 `wintun_api` 析构时
  `FreeLibrary` 释放。
- `wintun.dll` 由 CMake 在构建后拷贝到输出目录，运行时从 exe 同目录
  加载。

### 3.4 适配器创建 / 打开

```cpp
m_wintun_handle = m_api->create_adapter(L"AVPN", L"AVPN", &adapter_guid);
if (!m_wintun_handle)
    m_wintun_handle = m_api->open_adapter(L"AVPN");
```

优先 `WintunCreateAdapter` 创建（固定 GUID，保证 NLA 确定性），失败则
`WintunOpenAdapter` 打开已存在的同名适配器，最多重试 5 次。

### 3.5 设备路径枚举与打开

wintun 的数据通路不是通过 wintun.dll，而是直接打开驱动设备对象文件：

1. `enum_windows_devices()`：从注册表
   `HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-...}` 枚举
   网卡，读取 `ComponentId`（驱动名）与 `NetCfgInstanceId`（网卡 GUID）；
   再从 `Control\Network\{4D36E972-...}` 读取适配器显示名（如 `AVPN`）。
2. `enum_device_interfaces()`：用 SetupDi API 枚举
   `GUID_DEVCLASS_NET` 设备，读取 `NetCfgInstanceId` 与设备接口路径
   （`CM_Get_Device_Interface_ListA`）。
3. `open_wintun()`：按名称匹配（`ComponentId` 含 `wintun` 且显示名为
   `AVPN`），得到 `NetCfgInstanceId`，再在接口列表中定位设备路径，
   最终 `CreateFileA(..., GENERIC_READ | GENERIC_WRITE, ..., FILE_FLAG_OVERLAPPED)`
   打开设备文件。

### 3.6 ring 注册

`open()` 中创建两个 ring 与两个事件并注册：

```cpp
m_send_ring_handle = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr,
    PAGE_READWRITE, 0, sizeof(struct tun_ring), nullptr);
m_send_ring = (struct tun_ring*)MapViewOfFile(m_send_ring_handle, ...);
// receive ring 同理; 事件用 CreateEventW 创建

struct tun_register_rings rr;
rr.send.ring = m_receive_ring;
rr.send.tail_moved = m_receive_event_moved;
rr.receive.ring = m_send_ring;
rr.receive.tail_moved = m_send_event_moved;
DeviceIoControl(m_wintun_file, TUN_IOCTL_REGISTER_RINGS, &rr, sizeof(rr), ...);
```

`m_receive_event_moved` 随后通过
`m_receive_object_moved.assign(m_receive_event_moved)` 交给
`boost::asio::windows::object_handle` 管理，用于异步等待。

---

## 4. avpn_wintun 实现

### 4.1 生命周期与资源管理

类成员（`avpn_wintun.hpp`）：

| 成员 | 用途 |
|---|---|
| `m_api` | wintun.dll 函数指针封装 |
| `m_wintun_handle` | 适配器句柄 |
| `m_wintun_file` | 设备文件句柄 |
| `m_send_ring` / `m_receive_ring` | 两个 ring 映射 |
| `m_send_ring_handle` / `m_receive_ring_handle` | ring 文件映射句柄 |
| `m_send_event_moved` / `m_receive_event_moved` | 两个事件句柄 |
| `m_receive_object_moved` | asio object_handle，包装接收事件 |
| `m_address_row` | 已配置的 IPv4 地址行，close 时删除 |
| `m_abort` | 运行/关闭标志，初始为 `true` |

资源清理的关键点：`open()` 开头先调用 `close()` 释放上次可能残留的
资源（句柄、映射、事件），并**提前**将 `m_abort` 置为 `false`。这样
`open()` 中途任何一步失败时，失败路径上的 `close()`（或调用方的
`close()` / 析构函数）都能正确清理已创建的部分资源，避免句柄泄漏。

`close()` 依次：删除 IPv4 地址 → 关闭发送事件 → 关闭
`m_receive_object_moved`（asio 会以 `operation_aborted` 完成挂起的
`async_wait`）→ 解除两个 ring 映射 → 关闭两个文件映射句柄 → 关闭设备
文件 → 关闭适配器。

### 4.2 网络配置

- `configure(vaddr, prefix, mtu)`：`WintunGetAdapterLUID` 获取网卡
  LUID，`CreateUnicastIpAddressEntry` 设置 IPv4 地址；再
  `ConvertInterfaceLuidToIndex` + `GetIpInterfaceEntry` /
  `SetIpInterfaceEntry` 设置 MTU（IPv4 用 `mtu`，IPv6 用
  `max(mtu, 1280)`）。
- `configure_v6(vaddr, prefix)`：生成 `fd00::<x>:<x>` 内网地址，
  `CreateUnicastIpAddressEntry` 设置 IPv6。

### 4.3 异步读取

`async_read_some` 采用"同步首读 → 短 spin → 事件等待"三级策略：

```
async_read_some
  ├─ read_wintun() 同步读 ring
  │    ├─ >0 : 直接完成（post handler）
  │    ├─ <0 : 报 operation_aborted
  │    └─ =0 : ↓
  ├─ spin 约 100us（QueryPerformanceCounter + Sleep(0)），期间反复读
  │    ├─ 读到数据 : 完成
  │    └─ m_abort : 报 operation_aborted
  └─ 仍为空 : co_spawn 协程
       └─ co_await m_receive_object_moved.async_wait()
            ├─ 事件到达 → read_wintun() → 有数据则完成，空则继续等待
            ├─ 句柄关闭 → operation_aborted
            └─ read_wintun() 错误 → operation_aborted
```

设计要点：

- spin 阶段减少高频小包场景下的协程切换开销；事件等待阶段避免忙等。
- 每次 `async_read_some` 都先同步读 ring，因此突发多包时，上层
  `tun_read_loop` 连续调用会在不等待事件的情况下排空 ring，不存在
  事件丢失导致的数据滞留。
- 事件为 auto-reset，若数据在 spin 结束与 `async_wait` 注册之间到达，
  事件保持 signaled，`async_wait` 立即返回并重新读 ring，无 lost wakeup。
- `complete()` 闭包带 `done` 守卫，保证 handler 只回调一次。

`read_wintun` 读包流程（`avpn_wintun.cpp`）：

1. 快照 `head`/`tail`；越界（`>= WINTUN_RING_CAPACITY`）或
   `m_abort` 返回 -1。
2. `head == tail` 返回 0（空）。
3. `content_len = wrap(tail - head)`，不足包头大小返回 -1。
4. 解析 `TUN_PACKET`，校验 `size <= WINTUN_MAX_PACKET_SIZE`、对齐后
   不超过 `content_len`、不超过用户缓冲区大小，任一失败返回 -1
   （**不推进 head**）。
5. `memcpy` 数据到用户缓冲，`head = wrap(head + aligned)` 并回写。

### 4.4 异步写入

`async_write_some`：

```
async_write_some
  ├─ write_wintun() 同步写
  │    ├─ 成功 : 完成
  │    ├─ 错误 : operation_aborted
  │    └─ 0 (ring 满) : ↓
  └─ co_spawn 定时重试（steady_timer 1ms）
       └─ 反复 write_wintun() 直到成功 / 错误 / m_abort
```

`write_wintun` 写包流程：

1. 快照 `head`/`tail` 并做越界检查。
2. `aligned = align4(4 + size)`，`space = wrap(head - tail - 4)`；
   `aligned > space` 返回 0（ring 满）。
3. 在 `tail` 处写包头与数据，`tail = wrap(tail + aligned)` 回写。
4. 若 `ring->alertable` 非零，`SetEvent(m_send_event_moved)` 唤醒驱动。

### 4.5 tun_device 集成

`avpn_tun.hpp` / `avpn_tun.cpp` 在 `_WIN32` 下将成员替换为
`wintun_tun_device m_wintun`，`open` / `close` / `configure` /
`configure_v6` / `async_read_some` / `async_write_some` 全部转发到
wintun 实现，上层 `avpn.cpp` 与平台无关。

---

## 5. 与 avpn 的对比与改进

avpn 的 wintun 实现整体参考 avpn
（`avpn/include/avpn/wintun_windows_service.hpp`），差异与改进：

| 项目 | avpn | avpn |
|---|---|---|
| 事件等待 | 原生事件 + 协程 | `boost::asio::windows::object_handle`，与 asio 生态一致 |
| 资源清理 | `m_abort` 在 open 末尾才置 false，失败路径不清理 | open 开头先 `close()`，提前置 `m_abort = false`，失败路径显式 `close()` |
| 句柄检查 | `!= INVALID_HANDLE_VALUE` | 一致 |
| 多缓冲区 | 直接取首个 buffer | 明确仅使用第一个缓冲区，避免 `buffer_size()` 总大小导致越界 |
| 错误字节数 | -1 直接转 `size_t`（`SIZE_MAX`） | 错误时字节数归零 |

---

## 6. 已知限制

1. **单读者**：ring 的 `head` 推进无锁，若多个协程并发调用
   `async_read_some` 会对 `head` 竞争。当前 `tun_read_loop` 单协程
   串行读取，满足约束。
2. **超大数据包**：用户缓冲区固定为 `avpn_max_mtu`（1500 字节），
   若驱动送达更大的包，`read_wintun` 返回 -1 且不推进 `head`，上层
   读取循环遇错退出。wintun MTU 默认 1450，正常不会触发。
3. **生命周期**：异步协程持有裸 `self` 指针，设备销毁前必须 `close()`
   且 io_context 已排空，当前关机流程满足该顺序。
4. **线程模型**：`async_read_some` 的同步首读发生在调用线程，需与
   io_context 线程串行化，避免并发访问 ring。
