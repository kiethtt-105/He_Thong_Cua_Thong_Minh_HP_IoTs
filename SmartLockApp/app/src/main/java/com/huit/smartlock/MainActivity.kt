package com.huit.smartlock

import android.annotation.SuppressLint
import android.os.Bundle
import android.webkit.CookieManager
import android.webkit.WebResourceError
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.activity.ComponentActivity
import androidx.activity.OnBackPressedCallback
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import java.net.HttpURLConnection
import java.net.URL
import kotlin.concurrent.thread

class MainActivity : ComponentActivity() {

    private lateinit var web: WebView
    private var current: String? = null
    private val failed = mutableSetOf<String>()

    // Thứ tự ưu tiên: máy local -> devtunnel (VS Code) -> Vercel (cuối cùng)
    private val servers = listOf(
        "http://127.0.0.1:8000/",   // máy thật: chạy `adb reverse tcp:8000 tcp:8000`
        "http://10.0.2.2:8000/",    // emulator -> localhost của máy dev
        "https://d81h6zk7-8000.asse.devtunnels.ms/",
        "https://he-thong-cua-thong-minh-hp-iots.vercel.app/"
    )

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        WebView.setWebContentsDebuggingEnabled(true) // debug bằng chrome://inspect

        web = WebView(this)
        setContentView(web)

        // tránh web bị đè dưới thanh trạng thái / thanh điều hướng
        ViewCompat.setOnApplyWindowInsetsListener(web) { v, insets ->
            val bars = insets.getInsets(
                WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.ime()
            )
            v.setPadding(bars.left, bars.top, bars.right, bars.bottom)
            insets
        }

        web.settings.apply {
            javaScriptEnabled = true
            domStorageEnabled = true
            loadWithOverviewMode = true
            useWideViewPort = true
        }
        CookieManager.getInstance().setAcceptCookie(true)
        CookieManager.getInstance().setAcceptThirdPartyCookies(web, true)

        web.webViewClient = object : WebViewClient() {
            override fun onReceivedError(
                view: WebView, request: WebResourceRequest, error: WebResourceError
            ) {
                if (request.isForMainFrame) {
                    val cur = current ?: return
                    if (cur != servers.last()) {
                        failed.add(cur)
                        load()
                    }
                }
            }
        }

        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                if (web.canGoBack()) web.goBack() else finish()
            }
        })

        if (savedInstanceState == null) load() else web.restoreState(savedInstanceState)
    }

    private fun load() {
        thread {
            val url = servers.firstOrNull { it !in failed && isUp(it) } ?: servers.last()
            runOnUiThread {
                current = url
                web.loadUrl(url, mapOf("X-Tunnel-Skip-AntiPhishing-Page" to "true"))
            }
        }
    }

    private fun isUp(base: String): Boolean = try {
        val c = URL(base).openConnection() as HttpURLConnection
        c.connectTimeout = 1200
        c.readTimeout = 1500
        c.instanceFollowRedirects = false
        c.requestMethod = "GET"
        val code = c.responseCode
        val loc = c.getHeaderField("Location")
        c.disconnect()
        code in 200..399 && (loc == null || loc.startsWith("/") ||
                URL(base).host == runCatching { URL(loc).host }.getOrNull())
    } catch (e: Exception) {
        false
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        web.saveState(outState)
    }
}