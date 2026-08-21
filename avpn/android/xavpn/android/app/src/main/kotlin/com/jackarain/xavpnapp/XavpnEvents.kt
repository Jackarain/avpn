package com.jackarain.xavpnapp

import android.os.Handler
import android.os.Looper
import io.flutter.plugin.common.EventChannel

/** 将原生事件 (日志 / VPN 状态) 转发给 Flutter EventChannel. */
object XavpnEvents {
    @Volatile
    private var sink: EventChannel.EventSink? = null

    private val mainHandler = Handler(Looper.getMainLooper())

    fun setSink(s: EventChannel.EventSink?) {
        sink = s
    }

    fun emitLog(time: Long, level: Int, message: String) {
        post(mapOf(
            "type" to "log",
            "time" to time,
            "level" to level,
            "message" to message,
        ))
    }

    fun emitVpnState(state: String, message: String? = null) {
        post(mapOf(
            "type" to "vpn_state",
            "state" to state,
            "message" to (message ?: ""),
        ))
    }

    private fun post(data: Map<String, Any?>) {
        mainHandler.post { sink?.success(data) }
    }
}
