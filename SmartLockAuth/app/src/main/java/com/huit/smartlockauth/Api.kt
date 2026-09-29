package com.huit.smartlockauth

import okhttp3.Cookie
import okhttp3.CookieJar
import okhttp3.HttpUrl
import okhttp3.OkHttpClient
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import retrofit2.http.*

private const val TUNNEL = "https://d81h6zk7-8000.asse.devtunnels.ms/api/v1/"
private const val VERCEL = "https://he-thong-cua-thong-minh-hp-iots.vercel.app/api/v1/"
const val BASE_URL = TUNNEL   // đổi thành VERCEL khi cần

// Giữ cookie sessionid + csrftoken trong bộ nhớ
class MemoryCookieJar : CookieJar {
    private val store = mutableListOf<Cookie>()
    @Synchronized override fun saveFromResponse(url: HttpUrl, cookies: List<Cookie>) {
        cookies.forEach { c -> store.removeAll { it.name == c.name && it.domain == c.domain } ; store.add(c) }
    }
    @Synchronized override fun loadForRequest(url: HttpUrl) = store.filter { it.matches(url) }
    @Synchronized fun value(name: String) = store.firstOrNull { it.name == name }?.value
    @Synchronized fun clear() = store.clear()
}

// --- Model (ĐOÁN tên trường, cần đối chiếu serializers.py) ---
data class LoginBody(val username: String, val password: String)
data class UserDto(val id: String?, val username: String?, val email: String?)
data class DeviceDto(
    val id: String, val name: String?, val device_code: String?,
    val status: String?, val battery_level: Int?, val lock_state: String?, val location: String?
)
data class Page<T>(val count: Int, val results: List<T>)
data class CommandBody(val command: String)

interface SmartLockApi {
    @GET("csrf/") suspend fun csrf(): retrofit2.Response<Unit>
    @POST("login/") suspend fun login(@Body body: LoginBody): UserDto
    @GET("devices/") suspend fun devices(): Page<DeviceDto>
    @GET("devices/{id}/") suspend fun device(@Path("id") id: String): DeviceDto
    @POST("devices/{id}/command/") suspend fun command(@Path("id") id: String, @Body body: CommandBody): retrofit2.Response<Unit>
}

object Net {
    val jar = MemoryCookieJar()

    private val client = OkHttpClient.Builder()
        .cookieJar(jar)
        .addInterceptor { chain ->
            val req = chain.request()
            val b = req.newBuilder()
            if (req.method != "GET") {
                jar.value("csrftoken")?.let { b.header("X-CSRFToken", it) }
                b.header("Referer", BASE_URL)
            }
            chain.proceed(b.build())
        }
        .build()

    val api: SmartLockApi = Retrofit.Builder()
        .baseUrl(BASE_URL)
        .client(client)
        .addConverterFactory(GsonConverterFactory.create())
        .build()
        .create(SmartLockApi::class.java)
}