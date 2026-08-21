package com.jackarain.xavpnapp

import com.jackarain.xavpn
import org.json.JSONObject

/**
 * libxavpn.so 的 JNI 桥.
 *
 * 注意: System.loadLibrary 必须先于任何 com.jackarain.xavpn* 类的使用,
 * 因为 xavpnJNI 的静态初始化会调用 native swig_module_init.
 *
 * 与 libxavpn 的交互以控制通道 WebSocket 为主 (日志/protect/vaddr 下发),
 * 本桥仅保留进程内必须直调的启动/停止/状态查询.
 */
object XavpnBridge {
    init {
        System.loadLibrary("xavpn")
    }

    /**
     * 启动 avpn: 将 Flutter 下发的 UI 配置 (camelCase) 翻译为 libavpn 配置
     * (snake_case) 后调用 xavpn.start. tun fd 不在启动时传入, 由握手后
     * 服务端下发的 vaddr 建立 VpnService tun 再经控制通道 set_tun_fd 注入.
     *
     * @param config 用户配置 json (VpnConfig.toJson, 含 VpnService 专用字段).
     * @param controllerPort 本地 JSON-RPC over WS 控制端端口.
     */
    fun start(config: String, controllerPort: Int): Int {
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
        rename(cfg, "dnsIntercept", "dns_intercept")
        rename(cfg, "dohUrl", "dns_doh_url")
        rename(cfg, "directDns", "dns_direct")
        rename(cfg, "gfwlistUrl", "gfwlist_url")
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
        cfg.put("ptun_fd", -1)
        cfg.put("controller", "ws://127.0.0.1:$controllerPort")
        // gfwlist 缓存落盘应用私有目录 (与 lib/services 的默认路径一致),
        // 保证下次启动直接复用, 无需重新下载.
        if (!cfg.has("gfwlist_cache")) {
            cfg.put(
                "gfwlist_cache",
                "/data/data/com.jackarain.xavpn/files/gfwlist.txt",
            )
        }
        return xavpn.start(cfg.toString())
    }

    fun stop() = xavpn.stop()

    private fun rename(cfg: JSONObject, old: String, new: String) {
        if (cfg.has(old)) {
            cfg.put(new, cfg.remove(old))
        }
    }
}
