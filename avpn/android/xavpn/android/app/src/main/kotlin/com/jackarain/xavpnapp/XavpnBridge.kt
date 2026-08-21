package com.jackarain.xavpnapp

import com.jackarain.xavpn

/**
 * libxavpn.so 的 JNI 桥.
 *
 * 注意: System.loadLibrary 必须先于任何 com.jackarain.xavpn* 类的使用,
 * 因为 xavpnJNI 的静态初始化会调用 native swig_module_init.
 */
object XavpnBridge {
    init {
        System.loadLibrary("xavpn")
    }

    /** 注册 socket 保护回调 (VpnService.protect), 传 null 取消. */
    fun setProtectHandler(handler: ((Int) -> Boolean)?) {
        if (handler == null) {
            xavpn.setProtectCallback(null as xavpn.ProtectHandler?)
        } else {
            xavpn.setProtectCallback(xavpn.ProtectHandler { fd -> handler(fd) })
        }
    }

    /** 注册日志回调, 传 null 取消. */
    fun setLogHandler(handler: ((Long, Int, String) -> Unit)?) {
        if (handler == null) {
            xavpn.setLogCallback(null as xavpn.LogCallbackHandler?)
        } else {
            xavpn.setLogCallback(xavpn.LogCallbackHandler { time, level, message ->
                handler(time, level.swigValue(), message)
            })
        }
    }

    /**
     * 启动 avpn: 注入 Android tun fd 与本地 controller 地址后调用 xavpn.start.
     *
     * @param config 用户配置 json (由 Flutter 下发, 含 avpn 参数字段).
     * @param tunFd  VpnService.establish() 返回的 tun 文件描述符.
     * @param controllerPort 本地 JSON-RPC over WS 控制端端口.
     */
    fun start(config: String, tunFd: Int, controllerPort: Int): Int {
        val cfg = org.json.JSONObject(config)
        cfg.put("ifdev", "")
        cfg.put("ptun_fd", tunFd)
        cfg.put("controller", "ws://127.0.0.1:$controllerPort")
        return xavpn.start(cfg.toString())
    }

    fun stop() = xavpn.stop()

    fun status(): String = xavpn.status()
}
