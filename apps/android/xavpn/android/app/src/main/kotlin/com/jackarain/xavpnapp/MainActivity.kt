package com.jackarain.xavpnapp

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodChannel

class MainActivity : FlutterActivity() {
    companion object {
        private const val CHANNEL = "com.jackarain.xavpn/vpn"
        private const val EVENTS = "com.jackarain.xavpn/events"
        private const val REQ_VPN = 1001
        private const val REQ_NOTIFICATION = 1002
    }

    private var pendingPrepare: MethodChannel.Result? = null

    /** 自更新通道 (持工作线程), 引擎销毁时回收. */
    private var updateChannel: UpdateChannel? = null

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)

        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL)
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    "prepare" -> handlePrepare(result)
                    "start" -> {
                        val config = call.argument<String>("config") ?: ""
                        val port = call.argument<Int>("launcherPort") ?: 0
                        handleStart(config, port, result)
                    }
                    "restart" -> {
                        val config = call.argument<String>("config") ?: ""
                        val port = call.argument<Int>("launcherPort") ?: 0
                        handleRestart(config, port, result)
                    }
                    "stop" -> {
                        // 等待 VpnService 实例销毁(onDestroy)后再返回:
                        // 使 Flutter 侧停止流程与 native teardown 的真实
                        // 生命周期同步, 避免下一次 START 提交到正在销毁的
                        // 旧实例(VpnService 未运行, establish_tun 失败).
                        // 正常情况下 onDestroy 在停止请求后立即触发, 回调
                        // 在数百毫秒内完成, 不会明显卡顿.
                        val registered = XavpnVpnService.registerStopCallback {
                            runOnUiThread {
                                try {
                                    result.success(true)
                                } catch (_: Throwable) {
                                    // result 已失效(如 Flutter 侧超时), 忽略.
                                }
                            }
                        }
                        if (!registered) {
                            // 已有未决的 stop 回调(并发 stop 的兜底):
                            // 立即返回, 避免本 result 永久挂起.
                            result.success(true)
                        }
                        try {
                            XavpnVpnService.requestStop(this)
                        } catch (e: Exception) {
                            // 请求提交失败: 仅当本次注册了回调时才丢弃并回错,
                            // 否则会误清他人的未决回调或重复应答(result 已发).
                            if (registered) {
                                XavpnVpnService.clearStopCallback()
                                result.error("STOP_FAILED", e.message, null)
                            }
                        }
                    }
                    // libxavpn 编译时记录的 git commit hash 前 6 位.
                    "build_version" -> {
                        result.success(XavpnBridge.buildVersion())
                    }
                    // 控制通道 protect 请求: 放行 libavpn 的对外 socket.
                    "protect" -> {
                        val fd = call.argument<Int>("fd") ?: -1
                        result.success(XavpnVpnService.instance?.protectSocket(fd) ?: false)
                    }
                    // 控制通道 vaddr 下发后: 以服务端下发的地址建立 tun.
                    "establish_tun" -> {
                        val address = call.argument<String>("address") ?: ""
                        val prefix = call.argument<Int>("prefix") ?: 24
                        val mtu = call.argument<Int>("mtu") ?: 1400
                        val routes = call.argument<List<String>>("routes") ?: emptyList()
                        val dns = call.argument<List<String>>("dns") ?: emptyList()
                        val session = call.argument<String>("session") ?: "aVPN"
                        val instance = XavpnVpnService.instance
                        if (instance == null) {
                            result.error("NO_SERVICE", "VpnService 未运行", null)
                        } else {
                            try {
                                result.success(
                                    instance.establishTun(
                                        address, prefix, mtu, routes, dns, session
                                    )
                                )
                            } catch (e: Exception) {
                                result.error("ESTABLISH_FAILED", e.message, null)
                            }
                        }
                    }
                    else -> result.notImplemented()
                }
            }

        EventChannel(flutterEngine.dartExecutor.binaryMessenger, EVENTS)
            .setStreamHandler(object : EventChannel.StreamHandler {
                override fun onListen(arguments: Any?, events: EventChannel.EventSink?) {
                    XavpnEvents.setSink(events)
                }

                override fun onCancel(arguments: Any?) {
                    XavpnEvents.setSink(null)
                }
            })

        // 更新包的版本/签名读取与安装.
        updateChannel = UpdateChannel(this).also { it.attach(flutterEngine) }
    }

    /** 界面/引擎销毁: 回收自更新通道的工作线程 (已提交的任务继续跑完). */
    override fun onDestroy() {
        updateChannel?.close()
        updateChannel = null
        super.onDestroy()
    }

    private fun handlePrepare(result: MethodChannel.Result) {
        requestNotificationPermissionIfNeeded()
        val intent = VpnService.prepare(this)
        if (intent == null) {
            // 已授权.
            result.success(true)
        } else {
            // 阻塞等待用户在系统授权弹窗中的选择.
            pendingPrepare = result
            startActivityForResult(intent, REQ_VPN)
        }
    }

    /** Android 13+ 请求通知权限, 保证前台 VPN 通知可见 (未授权不影响 VPN 本身). */
    private fun requestNotificationPermissionIfNeeded() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return
        val granted = ContextCompat.checkSelfPermission(
            this, Manifest.permission.POST_NOTIFICATIONS
        ) == PackageManager.PERMISSION_GRANTED
        if (!granted) {
            ActivityCompat.requestPermissions(
                this, arrayOf(Manifest.permission.POST_NOTIFICATIONS), REQ_NOTIFICATION
            )
        }
    }

    @Suppress("DEPRECATION")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQ_VPN) {
            val ok = resultCode == Activity.RESULT_OK
            pendingPrepare?.success(ok)
            pendingPrepare = null
            XavpnEvents.emitVpnState(if (ok) "prepared" else "permission_denied")
        }
    }

    private fun sendServiceCommand(
        action: String, config: String, launcherPort: Int, result: MethodChannel.Result
    ) {
        if (config.isEmpty() || launcherPort <= 0) {
            result.error("BAD_ARGS", "config/launcherPort 缺失", null)
            return
        }
        try {
            val intent = Intent(this, XavpnVpnService::class.java).apply {
                this.action = action
                putExtra(XavpnVpnService.EXTRA_CONFIG, config)
                putExtra(XavpnVpnService.EXTRA_LAUNCHER_PORT, launcherPort)
            }
            XavpnVpnService.startForegroundServiceCompat(this, intent)
            result.success(true)
        } catch (e: Exception) {
            result.error("START_FAILED", e.message, null)
        }
    }

    private fun handleStart(config: String, launcherPort: Int, result: MethodChannel.Result) {
        sendServiceCommand(XavpnVpnService.ACTION_START, config, launcherPort, result)
    }

    private fun handleRestart(config: String, launcherPort: Int, result: MethodChannel.Result) {
        sendServiceCommand(XavpnVpnService.ACTION_RESTART, config, launcherPort, result)
    }
}
