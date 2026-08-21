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
import com.jackarain.xavpn.R
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat

/**
 * VpnService: 以服务端下发的 vaddr 创建 TUN 设备、放行 nexthop socket,
 * 并持有 libxavpn.so 生命周期.
 *
 * 启动时先经 XavpnBridge 启动 libavpn (无 tun), 握手后 libavpn 通过
 * 控制通道 WebSocket 下发 vaddr, Flutter 收到后调用 establishTun 在此
 * 建立 VpnService tun 并 detach fd, 再经控制通道 set_tun_fd 注入 libavpn.
 * protect 同样经控制通道请求到达 (onProtectSocket), 由本服务放行,
 * 避免对外 socket 流量回环进 tun.
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

        /** 当前服务实例 (MainActivity 经 MethodChannel 调用 establishTun/protect). */
        @Volatile
        var instance: XavpnVpnService? = null
            private set

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
    private var started = false

    override fun onCreate() {
        super.onCreate()
        instance = this
    }

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
            // 启动 avpn (无 tun): 握手后经控制通道下发 vaddr,
            // Flutter 据此调用 establishTun 建立 tun 再 set_tun_fd 注入.
            val rc = XavpnBridge.start(configJson, controllerPort)
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

    /**
     * 以服务端下发的 vaddr 建立 VpnService tun, detach 返回 fd (由 libavpn
     * 持有并负责关闭). 地址/路由/MTU 在此一次性配置, 后续不可更改.
     *
     * @param address 服务端握手下发的 tun 地址.
     * @param prefix  地址前缀 (由服务端下发).
     * @param mtu     tun MTU.
     * @param routes  需要接入 VPN 的路由 (为空时默认全隧道).
     * @param dns     DNS 服务器列表 (可为空).
     * @param session VPN 会话名称.
     * @return tun fd; 失败抛出异常.
     */
    fun establishTun(
        address: String,
        prefix: Int,
        mtu: Int,
        routes: List<String>,
        dns: List<String>,
        session: String,
    ): Int {
        val builder = Builder()
        builder.setSession(session.ifEmpty { "aVPN" })
        builder.addAddress(address, prefix)
        if (routes.isNotEmpty()) {
            for (route in routes) {
                addRoute(builder, route)
            }
        } else {
            // 默认全隧道.
            builder.addRoute("0.0.0.0", 0)
        }
        for (server in dns) {
            if (server.isNotBlank()) builder.addDnsServer(server.trim())
        }
        if (mtu > 0) builder.setMtu(mtu)
        builder.setBlocking(true)
        val fd = builder.establish()
            ?: throw IllegalStateException("VpnService establish 失败")
        return fd.detachFd()
    }

    /** 放行对外 socket (经控制通道 protect 请求到达), 避免回环进 tun. */
    fun protectSocket(fd: Int): Boolean = try {
        protect(fd)
    } catch (_: Throwable) {
        false
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

    /** 停止 avpn 并释放资源; 幂等, 可重复调用. tun fd 由 libavpn 持有并关闭. */
    private fun teardown() {
        if (started) {
            try {
                XavpnBridge.stop()
            } catch (_: Throwable) {
                // 忽略停止时的异常.
            }
            started = false
        }
    }

    private fun teardownAndStop() {
        teardown()
        stopForeground(true)
        stopSelf()
    }

    override fun onDestroy() {
        if (instance === this) instance = null
        // 工作线程可能正持有资源, 排队清理后退出.
        worker.post {
            teardown()
            workerThread.quitSafely()
        }
        super.onDestroy()
    }
}
