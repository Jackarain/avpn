package com.jackarain.xavpnapp

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Handler
import android.os.HandlerThread
import android.os.ParcelFileDescriptor
import com.jackarain.xavpn.R
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import org.json.JSONArray
import org.json.JSONObject

/**
 * VpnService: 创建 TUN 设备、放行 nexthop socket, 并通过 XavpnBridge
 * 在同一个进程内直接调用 libxavpn.so (tun fd 经 ptun_fd 传入).
 *
 * 启停均在专用工作线程执行: 避免阻塞主线程 (avpn 启动/停止涉及线程池
 * 创建与回收), 同时保证 START/STOP 串行处理, 不会并发操作同一实例.
 */
class XavpnVpnService : VpnService() {

    companion object {
        const val ACTION_START = "com.jackarain.xavpnapp.START"
        const val ACTION_RESTART = "com.jackarain.xavpnapp.RESTART"
        const val ACTION_STOP = "com.jackarain.xavpnapp.STOP"
        const val EXTRA_CONFIG = "config"
        const val EXTRA_CONTROLLER_PORT = "controller_port"

        private const val CHANNEL_ID = "xavpn_vpn"
        private const val NOTIFY_ID = 1001

        fun startForegroundServiceCompat(context: Context, intent: Intent) {
            ContextCompat.startForegroundService(context, intent)
        }

        fun requestStop(context: Context) {
            context.startService(
                Intent(context, XavpnVpnService::class.java).setAction(ACTION_STOP)
            )
        }
    }

    private val workerThread = HandlerThread("xavpn-worker").apply { start() }
    private val worker = Handler(workerThread.looper)

    @Volatile
    private var tunFd: ParcelFileDescriptor? = null

    @Volatile
    private var started = false

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> worker.post { teardownAndStop() }
            ACTION_RESTART -> {
                val config = intent.getStringExtra(EXTRA_CONFIG) ?: ""
                val port = intent.getIntExtra(EXTRA_CONTROLLER_PORT, 0)
                // 前台通知必须在 startForegroundService 后尽快发出 (主线程同步).
                startForegroundCompat()
                // 在单个工作线程任务内完成 停旧->启新, 避免 stopSelf 与 START
                // 交错导致服务被系统销毁 (进而误停新实例).
                worker.post { restartVpn(config, port) }
            }
            ACTION_START -> {
                val config = intent.getStringExtra(EXTRA_CONFIG) ?: ""
                val port = intent.getIntExtra(EXTRA_CONTROLLER_PORT, 0)
                // 前台通知必须在 startForegroundService 后尽快发出 (主线程同步).
                startForegroundCompat()
                worker.post { startVpn(config, port) }
            }
        }
        return START_NOT_STICKY
    }

    private fun startForegroundCompat() {
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val channel = NotificationChannel(
            CHANNEL_ID, "aVPN", NotificationManager.IMPORTANCE_LOW
        )
        manager.createNotificationChannel(channel)

        val contentIntent = packageManager.getLaunchIntentForPackage(packageName)
        val pending = PendingIntent.getActivity(
            this, 0, contentIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val notification: Notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("aVPN")
            .setContentText("VPN 运行中")
            .setSmallIcon(R.drawable.ic_vpn)
            .setContentIntent(pending)
            .setOngoing(true)
            .build()
        startForeground(NOTIFY_ID, notification)
    }

    private fun restartVpn(configJson: String, controllerPort: Int) {
        teardown()
        startVpn(configJson, controllerPort)
    }

    private fun startVpn(configJson: String, controllerPort: Int) {
        // 防御: 重复的 START 先停旧实例, 保证同一时刻只有一个.
        if (started) teardown()
        try {
            val cfg = JSONObject(configJson)

            // 1. 建立 TUN 设备 (地址/路由/MTU 由 VpnService 配置).
            val fd = buildTun(cfg) ?: throw IllegalStateException("VpnService establish 失败")
            tunFd = fd

            // 2. 注册 protect 回调: nexthop 等对外 socket 经 VpnService.protect 放行,
            //    避免流量回环进入 tun; 日志回调转发给 Flutter.
            XavpnBridge.setProtectHandler { fdInt -> protect(fdInt) }
            XavpnBridge.setLogHandler { time, level, message ->
                XavpnEvents.emitLog(time, level, message)
            }

            // 3. 启动 avpn: tun fd 与本地 controller 地址由 XavpnBridge 注入 json.
            val rc = XavpnBridge.start(configJson, fd.fd, controllerPort)
            if (rc != 0) {
                XavpnEvents.emitVpnState("error", "xavpn.start 失败: rc=$rc")
                teardownAndStop()
                return
            }
            started = true
            XavpnEvents.emitVpnState("running")
        } catch (e: Exception) {
            XavpnEvents.emitVpnState("error", e.message ?: e.toString())
            teardownAndStop()
        }
    }

    /** 依据配置创建 TUN, 失败返回 null (地址/路由非法时 VpnService 抛异常). */
    private fun buildTun(cfg: JSONObject): ParcelFileDescriptor? {
        val builder = Builder()
        builder.setSession(cfg.optString("name", "aVPN"))
        builder.addAddress(
            cfg.optString("tunAddress", "10.8.0.2"),
            cfg.optInt("tunPrefix", 24),
        )
        val routes = optStringList(cfg, "routes")
        if (routes.isNotEmpty()) {
            for (route in routes) {
                addRoute(builder, route)
            }
        } else {
            // 默认路由: 客户端全隧道; 网关只放虚拟子网, 避免自身流量回环.
            val mode = cfg.optString("mode", "client")
            if (mode == "gateway") {
                val subnet = cfg.optString("subnet", "10.9.0.0/16")
                val parsed = parseCidr(subnet)
                if (parsed != null) {
                    builder.addRoute(parsed.first, parsed.second)
                } else {
                    builder.addRoute("10.9.0.0", 16)
                }
            } else {
                builder.addRoute("0.0.0.0", 0)
            }
        }
        for (dns in optStringList(cfg, "dns")) {
            builder.addDnsServer(dns)
        }
        val mtu = cfg.optInt("mtu_size", 1450)
        if (mtu > 0) builder.setMtu(mtu)
        builder.setBlocking(true)
        return builder.establish()
    }

    private fun addRoute(builder: Builder, cidr: String) {
        val parsed = parseCidr(cidr)
        if (parsed != null) {
            builder.addRoute(parsed.first, parsed.second)
        } else {
            builder.addRoute(cidr, 32)
        }
    }

    private fun parseCidr(cidr: String): Pair<String, Int>? {
        val slash = cidr.indexOf('/')
        if (slash < 0) return null
        val host = cidr.substring(0, slash).trim()
        val prefix = cidr.substring(slash + 1).trim().toIntOrNull() ?: return null
        if (host.isEmpty() || prefix < 0 || prefix > 128) return null
        return host to prefix
    }

    private fun optStringList(obj: JSONObject, key: String): List<String> {
        val v = obj.opt(key) ?: return emptyList()
        return when (v) {
            is JSONArray -> {
                val out = mutableListOf<String>()
                for (i in 0 until v.length()) {
                    v.optString(i).takeIf { it.isNotBlank() }?.let { out.add(it) }
                }
                out
            }
            is String -> {
                if (v.isBlank()) emptyList()
                else v.trim().split(Regex("[\\s,;]+")).filter { it.isNotEmpty() }
            }
            else -> emptyList()
        }
    }

    /** 停止 avpn 并释放资源; 幂等, 可重复调用. */
    private fun teardown() {
        XavpnBridge.setProtectHandler(null)
        XavpnBridge.setLogHandler(null)
        if (started) {
            try {
                XavpnBridge.stop()
            } catch (_: Throwable) {
                // 忽略停止时的异常.
            }
            started = false
        }
        try {
            tunFd?.close()
        } catch (_: Throwable) {
        }
        tunFd = null
    }

    private fun teardownAndStop() {
        teardown()
        stopForeground(true)
        stopSelf()
    }

    override fun onDestroy() {
        // 工作线程可能正持有资源, 排队清理后退出.
        worker.post {
            teardown()
            workerThread.quitSafely()
        }
        super.onDestroy()
    }
}
