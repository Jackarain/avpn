package com.jackarain.xavpnapp

import com.jackarain.xavpn
import com.jackarain.LogLevel
import com.jackarain.LogCallback
import com.jackarain.ProtectCallback
import org.json.JSONObject

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

    // SWIG director 包装对象必须被强引用持有, 否则 Java GC 回收后
    // C++ 侧回调会因 upcall object 为 null 而抛 NullPointerException
    // (如 xavpn::log_callback::on_log / protect_callback::on_protect).
    // 注意不能使用 xavpn.setLogCallback(LogCallbackHandler) 这类函数式
    // 接口重载: 它在内部 new 的 LogCallbackAdapter 无强引用, 同样会被 GC.
    private var protectCallback: ProtectCallback? = null
    private var logCallback: LogCallback? = null

    /** 注册 socket 保护回调 (VpnService.protect), 传 null 取消. */
    fun setProtectHandler(handler: ((Int) -> Boolean)?) {
        protectCallback = handler?.let {
            object : ProtectCallback() {
                override fun onProtect(fd: Int): Boolean = it(fd)
            }
        }
        xavpn.setProtectCallback(protectCallback)
    }

    /** 注册日志回调, 传 null 取消. */
    fun setLogHandler(handler: ((Long, Int, String) -> Unit)?) {
        logCallback = handler?.let {
            object : LogCallback() {
                override fun onLog(time: Long, level: LogLevel, message: String) {
                    it(time, level.swigValue(), message)
                }
            }
        }
        xavpn.setLogCallback(logCallback)
    }

    /**
     * 启动 avpn: 将 Flutter 下发的 UI 配置 (camelCase) 翻译为 libavpn 配置
     * (snake_case), 注入 Android tun fd 与本地 controller 地址后调用 xavpn.start.
     *
     * @param config 用户配置 json (VpnConfig.toJson, 含 VpnService 专用字段).
     * @param tunFd  VpnService.establish() 返回的 tun 文件描述符.
     * @param controllerPort 本地 JSON-RPC over WS 控制端端口.
     */
    fun start(config: String, tunFd: Int, controllerPort: Int): Int {
        val cfg = JSONObject(config)
        // camelCase (Flutter) -> snake_case (libavpn).
        rename(cfg, "privateKey", "private_key")
        rename(cfg, "publicKey", "public_key")
        rename(cfg, "mtuSize", "mtu_size")
        rename(cfg, "dataShards", "data_shards")
        rename(cfg, "parityShards", "parity_shards")
        rename(cfg, "obfuscateKey", "obfuscate_key")
        rename(cfg, "udpListen", "udp_listen")
        rename(cfg, "tcpListen", "tcp_listen")
        rename(cfg, "ignorePush", "ignore_push")
        // tunAddress (VpnService 分配的地址) -> vaddr: 请求网关分配同一地址,
        // 避免网关分配的 vaddr 与本端 tun 地址不一致导致数据包无法投递.
        val tunAddress = cfg.optString("tunAddress", "")
        if (tunAddress.isNotEmpty()) {
            val parts = tunAddress.trim().split('.')
            if (parts.size == 4) {
                val octets = parts.map { it.toIntOrNull() }
                if (octets.all { it != null && it in 0..255 }) {
                    cfg.put(
                        "vaddr",
                        (octets[0]!! shl 24) or (octets[1]!! shl 16) or
                            (octets[2]!! shl 8) or octets[3]!!,
                    )
                }
            }
        }
        cfg.put("ifdev", "")
        cfg.put("ptun_fd", tunFd)
        cfg.put("controller", "ws://127.0.0.1:$controllerPort")
        return xavpn.start(cfg.toString())
    }

    fun stop() = xavpn.stop()

    fun status(): String = xavpn.status()

    private fun rename(cfg: JSONObject, old: String, new: String) {
        if (cfg.has(old)) {
            cfg.put(new, cfg.remove(old))
        }
    }
}
