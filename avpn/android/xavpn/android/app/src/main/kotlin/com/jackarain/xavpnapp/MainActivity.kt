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

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)

        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL)
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    "prepare" -> handlePrepare(result)
                    "start" -> {
                        val config = call.argument<String>("config") ?: ""
                        val port = call.argument<Int>("controllerPort") ?: 0
                        handleStart(config, port, result)
                    }
                    "restart" -> {
                        val config = call.argument<String>("config") ?: ""
                        val port = call.argument<Int>("controllerPort") ?: 0
                        handleRestart(config, port, result)
                    }
                    "stop" -> {
                        XavpnVpnService.requestStop(this)
                        result.success(true)
                    }
                    "status" -> result.success(XavpnBridge.status())
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
        action: String, config: String, controllerPort: Int, result: MethodChannel.Result
    ) {
        if (config.isEmpty() || controllerPort <= 0) {
            result.error("BAD_ARGS", "config/controllerPort 缺失", null)
            return
        }
        try {
            val intent = Intent(this, XavpnVpnService::class.java).apply {
                this.action = action
                putExtra(XavpnVpnService.EXTRA_CONFIG, config)
                putExtra(XavpnVpnService.EXTRA_CONTROLLER_PORT, controllerPort)
            }
            XavpnVpnService.startForegroundServiceCompat(this, intent)
            result.success(true)
        } catch (e: Exception) {
            result.error("START_FAILED", e.message, null)
        }
    }

    private fun handleStart(config: String, controllerPort: Int, result: MethodChannel.Result) {
        sendServiceCommand(XavpnVpnService.ACTION_START, config, controllerPort, result)
    }

    private fun handleRestart(config: String, controllerPort: Int, result: MethodChannel.Result) {
        sendServiceCommand(XavpnVpnService.ACTION_RESTART, config, controllerPort, result)
    }
}
