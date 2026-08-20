# avpn Launcher WebUI（React + Vite + Tailwind + shadcn/ui）

基于 React 19 + Vite + TypeScript + Tailwind CSS v4 + shadcn/ui + zustand 实现的
launcher WebUI：实例管理、状态监控、配置管理与日志查看。

## 环境要求

- **Node.js 18+**（推荐 20 LTS 或更高）
- **npm**（依赖由 `package-lock.json` 锁定）
- 安装依赖与构建需**联网**访问 npm registry

## 目录结构

```
webui/
├── index.html            # Vite 入口
├── vite.config.ts        # 构建输出到 avpn/launcher/webui（launcher 编译期内嵌）
├── src/
│   ├── main.tsx          # 入口
│   ├── App.tsx           # 布局 + 2 秒轮询调度
│   ├── index.css         # Tailwind v4 + 深色主题 CSS 变量
│   ├── lib/              # api 客户端、格式化工具、日志增量、复制地址等
│   ├── store/            # zustand：app（实例/每实例状态/轮询）+ dialogs（弹窗）
│   └── components/
│       ├── ui/           # shadcn/ui 组件（button/input/dialog/checkbox/switch/badge）
│       ├── layout/       # Header / InstanceList / DetailView / DetailHeader
│       ├── status/       # 状态页（摘要条/会话表）
│       ├── config/       # 配置页（flags 风格）
│       ├── logs/         # 日志页（增量渲染）
│       └── dialogs/      # prompt / select / 新建实例弹窗
```

## 开发

```bash
cd webui
npm install

# 1) 先启动后端 launcher（默认 WebUI 端口 18080）：
#    build/launcher/bin/launcher --avpn ../build/bin/avpn --data_dir /tmp/launcher_data

# 2) 启动 Vite dev server（/api 代理到 127.0.0.1:18080）：
npm run dev
```

## 构建

```bash
cd webui
npm install
npm run build        # 产物输出到 ../avpn/launcher/webui，launcher 编译期内嵌
```

构建完成后重新构建 launcher 即得到内嵌 WebUI 的单文件可执行程序。
