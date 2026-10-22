# third_party 补丁说明

`scripts/vendor.sh` 重新拉取 `third_party/` 下的三方库后，会自动套用本目录中与各库
同名的子目录下的所有补丁（补丁路径以仓库根为基准，使用 `git apply` 应用）。这些补丁
用于让上游源码适配本项目的构建方式与需求，更新三方库版本后需要相应维护。

## 目录结构

```
scripts/patch/
├── boost/
│   ├── 0001-Add-option-BOOST_ASIO_BUILD_CONTEXT.patch
│   ├── 0001-Enable-UTF-8-paths-with-BOOST_FILESYSTEM_USE_UTF8_CO.patch
│   └── 0001-Resolve-mismatched-tags-compiler-warning.patch
└── README.md
```

## boost/

### 0001-Add-option-BOOST_ASIO_BUILD_CONTEXT.patch

- 作用对象：`third_party/boost/libs/asio/CMakeLists.txt`
- 修改内容：新增 CMake 选项 `BOOST_ASIO_BUILD_CONTEXT`，默认 `ON`；关闭时不再构建、
  链接与导出 `boost_asio_spawn`。

本工程使用 C++20 协程，不使用 Asio 的栈式协程 spawn。根 `CMakeLists.txt` 通过
`set(BOOST_ASIO_BUILD_CONTEXT OFF)` 和 `BOOST_EXCLUDE_LIBRARIES` 排除
`Boost.Context`，因此 Asio 不能继续无条件链接 `Boost::context`。

### 0001-Enable-UTF-8-paths-with-BOOST_FILESYSTEM_USE_UTF8_CO.patch

- 作用对象：`third_party/boost/libs/filesystem/src/path.cpp`
- 修改内容：在启用 UTF-8 codecvt facet 的预处理器条件中追加
  `defined(BOOST_FILESYSTEM_USE_UTF8_CODECVT_FACET)`。

本工程定义 `BOOST_FILESYSTEM_USE_UTF8_CODECVT_FACET`，要求所有平台统一使用 UTF-8
路径编码。Boost.Filesystem 原版只在部分系统上启用该 facet，其它平台会退化为
locale 相关编码，导致中文路径乱码。

### 0001-Resolve-mismatched-tags-compiler-warning.patch

- 作用对象：`third_party/boost/libs/asio/include/boost/asio/detail/io_uring_service.hpp`
- 修改内容：把前置声明 `class io_object;` 改为 `struct io_object;`。

`io_object` 实际定义为 `struct`，前置声明写成 `class` 会触发 Clang 的
`-Wmismatched-tags` 告警。

## 使用方式

`scripts/vendor.sh` 在拉取对应库后自动套用补丁。脚本必须显式指定要更新的库；不带参数
或传 `-h` / `--help` 时仅打印帮助：

```bash
scripts/vendor.sh            # 不带参数只打印帮助
scripts/vendor.sh all        # 更新全部三方库
scripts/vendor.sh boost      # 仅更新 boost，并自动套用 boost 补丁
scripts/vendor.sh boost zlib # 更新指定的多个库
```

如需手工应用（在仓库根目录执行）：

```bash
# 先校验是否可干净应用
git apply --check scripts/patch/boost/0001-Add-option-BOOST_ASIO_BUILD_CONTEXT.patch
# 再应用
git apply scripts/patch/boost/0001-Add-option-BOOST_ASIO_BUILD_CONTEXT.patch
```

## 维护说明

- 补丁路径均以仓库根为基准（`-p1`），因此可在仓库根统一用 `git apply` 应用。
- 更新三方库版本后，若补丁无法干净应用，需按上述补丁的意图手工同步修改，并更新补丁文件。
- 新增针对某个库的补丁：放到 `scripts/patch/<库名>/` 下即可，`vendor.sh` 会自动套用。
- `vendor.sh` 拉取 Boost 后按 `BOOST_KEEP_LIBS`（在 `scripts/vendor.sh` 中）裁剪目录树，
  只保留用到的库及传递依赖。工程新用到某个 Boost 库时，需要把库名补进
  `BOOST_KEEP_LIBS`。
- `fmt`、`httpc`、`lz4` 使用仓库内定制 CMakeLists.txt，更新脚本只刷新上游源码，不能删除
  这些文件。
