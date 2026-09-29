package com.huit.smartlockauth

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { MaterialTheme { Surface { App() } } }
    }
}

@Composable
fun App() {
    var loggedIn by remember { mutableStateOf(false) }
    var selected by remember { mutableStateOf<DeviceDto?>(null) }
    when {
        !loggedIn -> LoginScreen { loggedIn = true }
        selected == null -> DeviceListScreen(onOpen = { selected = it })
        else -> DeviceDetailScreen(selected!!, onBack = { selected = null })
    }
}

@Composable
fun LoginScreen(onSuccess: () -> Unit) {
    val scope = rememberCoroutineScope()
    var user by remember { mutableStateOf("") }
    var pass by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    var loading by remember { mutableStateOf(false) }

    Column(Modifier.fillMaxSize().padding(24.dp), verticalArrangement = Arrangement.Center) {
        Text("Smart Lock", style = MaterialTheme.typography.headlineMedium)
        Spacer(Modifier.height(24.dp))
        OutlinedTextField(user, { user = it }, label = { Text("Tên đăng nhập / email") },
            singleLine = true, modifier = Modifier.fillMaxWidth())
        Spacer(Modifier.height(12.dp))
        OutlinedTextField(pass, { pass = it }, label = { Text("Mật khẩu" ) },
            visualTransformation = PasswordVisualTransformation(),
            singleLine = true, modifier = Modifier.fillMaxWidth())
        error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
        Spacer(Modifier.height(16.dp))
        Button(
            enabled = !loading,
            onClick = {
                scope.launch {
                    loading = true; error = null
                    try {
                        Net.api.csrf()                       // lấy csrftoken cookie
                        Net.api.login(LoginBody(user, pass))
                        onSuccess()
                    } catch (e: Exception) {
                        error = "Đăng nhập thất bại: ${e.message}"
                    }
                    loading = false
                }
            },
            modifier = Modifier.fillMaxWidth()
        ) { Text(if (loading) "Đang đăng nhập..." else "Đăng nhập") }
    }
}

@Composable
fun DeviceListScreen(onOpen: (DeviceDto) -> Unit) {
    var devices by remember { mutableStateOf<List<DeviceDto>>(emptyList()) }
    var error by remember { mutableStateOf<String?>(null) }
    LaunchedEffect(Unit) {
        try { devices = Net.api.devices().results } catch (e: Exception) { error = e.message }
    }
    Column(Modifier.fillMaxSize().padding(16.dp)) {
        Text("Thiết bị của tôi", style = MaterialTheme.typography.headlineSmall)
        error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
        LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            items(devices) { d ->
                Card(Modifier.fillMaxWidth().clickable { onOpen(d) }) {
                    Column(Modifier.padding(16.dp)) {
                        Text(d.name ?: d.device_code ?: "Thiết bị", style = MaterialTheme.typography.titleMedium)
                        Text("Trạng thái: ${d.status}  |  Khoá: ${d.lock_state}  |  Pin: ${d.battery_level}%")
                    }
                }
            }
        }
    }
}

@Composable
fun DeviceDetailScreen(device: DeviceDto, onBack: () -> Unit) {
    val scope = rememberCoroutineScope()
    var msg by remember { mutableStateOf("") }

    fun send(cmd: String) = scope.launch {
        msg = try {
            val r = Net.api.command(device.id, CommandBody(cmd))
            if (r.isSuccessful) "Đã gửi lệnh $cmd" else "Lỗi ${r.code()}"
        } catch (e: Exception) { "Lỗi: ${e.message}" }
    }

    Column(Modifier.fillMaxSize().padding(16.dp)) {
        TextButton(onClick = onBack) { Text("← Quay lại") }
        Text(device.name ?: "Thiết bị", style = MaterialTheme.typography.headlineSmall)
        Text("Vị trí: ${device.location ?: "-"}")
        Text("Pin: ${device.battery_level}%")
        Spacer(Modifier.height(24.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Button(onClick = { send("UNLOCK") }) { Text("Mở khoá") }
            OutlinedButton(onClick = { send("LOCK") }) { Text("Khoá") }
        }
        Spacer(Modifier.height(16.dp))
        Text(msg)
    }
}