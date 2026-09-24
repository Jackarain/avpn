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
 * 需要直通物理网络的 socket 一律经控制通道 protect: 隧道 nexthop 连接
 * 与 DNS 拦截的直连 DNS socket. 其余流量 (DoH/gfwlist 下载等) 不 protect,
 * 按路由进入 tun 走 VPN 隧道.
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
        const val EXTRA_LAUNCHER_PORT = "launcher_port"

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

        /** 服务实例代次: 每次新实例 onCreate 递增, 旧实例 onDestroy 据此判断是否让位. */
        @Volatile
        private var generation = 0L

        /** 停止完成回调: MainActivity 的 stop MethodChannel 据此在实例销毁
         *  (onDestroy) 后再返回, 使 Flutter 停止流程与 native teardown 同步. */
        @Volatile
        private var onStopComplete: (() -> Unit)? = null

        /** 注册停止完成回调; 已有未决回调时返回 false(并发 stop 兜底). */
        fun registerStopCallback(cb: () -> Unit): Boolean {
            if (onStopComplete != null) return false
            onStopComplete = cb
            return true
        }

        /** 丢弃未决回调: 停止请求提交失败时避免其后续被误触发. */
        fun clearStopCallback() {
            onStopComplete = null
        }
    }

    private val workerThread = HandlerThread("xavpn-worker").apply { start() }
    private val worker = Handler(workerThread.looper)

    @Volatile
    private var started = false

    /** 本实例的代次: onCreate 时领取, teardown 据此判断是否已被新实例接管. */
    private var myGeneration = 0L

    override fun onCreate() {
        super.onCreate()
        myGeneration = ++generation
        instance = this
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> worker.post { teardownAndStop() }
            ACTION_RESTART -> {
                val config = intent.getStringExtra(EXTRA_CONFIG) ?: ""
                val port = intent.getIntExtra(EXTRA_LAUNCHER_PORT, 0)
                // 前台通知必须在 startForegroundService 后尽快发出 (主线程同步).
                startForegroundCompat()
                // 在单个工作线程任务内完成 停旧->启新, 避免 stopSelf 与 START
                // 交错导致服务被系统销毁 (进而误停新实例).
                worker.post { restartVpn(config, port) }
            }
            ACTION_START -> {
                val config = intent.getStringExtra(EXTRA_CONFIG) ?: ""
                val port = intent.getIntExtra(EXTRA_LAUNCHER_PORT, 0)
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

    private fun restartVpn(configJson: String, launcherPort: Int) {
        teardown()
        startVpn(configJson, launcherPort)
    }

    private fun startVpn(configJson: String, launcherPort: Int) {
        // 防御: 重复的 START 先停旧实例, 保证同一时刻只有一个.
        if (started) teardown()
        try {
            // 启动 avpn (无 tun): 握手后经控制通道下发 vaddr,
            // Flutter 据此调用 establishTun 建立 tun 再 set_tun_fd 注入.
            val rc = XavpnBridge.start(configJson, launcherPort)
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
            // 代次检查: 快速 停止->再运行 时若已有新实例接管 (其 start 流程会
            // 停旧启新), 本实例不得再停 avpn, 否则会误停新实例刚启动的服务,
            // 表现为重新启动后 VPN 无法正常工作.
            if (myGeneration == generation) {
                try {
                    XavpnBridge.stop()
                } catch (_: Throwable) {
                    // 忽略停止时的异常.
                }
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
        // 通知 Flutter 停止已完成(实例已销毁): 取走回调并清空, 使下一次
        // 连接由新实例执行, 避免 establish_tun 时实例已销毁导致 TUN 失败.
        val cb = onStopComplete
        onStopComplete = null
        try {
            cb?.invoke()
        } catch (_: Throwable) {
        }
        // 注意: 这里不再 teardown() 停止 avpn. 复用同一服务实例快速启停时,
        // 旧实例的 onDestroy 若 teardown 会误停队列中刚启动的新服务(started
        // 指向新服务, 同实例代次未变), 表现为快速启停后 avpn 刚启动就被停,
        // 控制通道永远连不上. avpn 的停止统一由显式 ACTION_STOP
        // (teardownAndStop) 与下一次启动的防御性 teardown 负责, onDestroy
        // 只回收工作线程.
        worker.post { workerThread.quitSafely() }
        super.onDestroy()
    }
}
