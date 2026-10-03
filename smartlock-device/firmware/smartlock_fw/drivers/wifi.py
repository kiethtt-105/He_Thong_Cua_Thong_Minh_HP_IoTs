"""Wi-Fi: sim (giả lập RSSI) | system (đọc Wi-Fi THẬT của máy: Windows/Linux/macOS).
Bật/tắt radio trong firmware chỉ là tắt kết nối của khoá (không tắt Wi-Fi của hệ điều hành)."""
import random
import re
import subprocess
import sys


def _run(cmd, timeout=6):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                              creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)).stdout or ""
    except Exception:
        return ""


def pct_to_dbm(pct):  # Windows/nmcli trả % chất lượng -> dBm xấp xỉ
    return int(pct / 2 - 100)


class SimWifi:
    kind = "sim"
    def __init__(self, cfg): self.ssid = cfg.s("wifi", "ssid") or "SimWiFi"; self.base = cfg.i("wifi", "sim_rssi")
    def probe(self): return {"connected": True, "ssid": self.ssid, "rssi": self.base + random.randint(-3, 3)}
    def connect(self): return True


class SystemWifi:
    kind = "system"
    def __init__(self, cfg):
        self.cfg, self.ethernet = cfg, cfg.b("wifi", "allow_ethernet")

    def probe(self):
        if sys.platform.startswith("win"):
            out = _run(["netsh", "wlan", "show", "interfaces"])
            ssid = re.search(r"^\s*SSID\s*:\s*(.+)$", out, re.M)
            sig = re.search(r"^\s*Signal\s*:\s*(\d+)%", out, re.M)
            if ssid and sig: return {"connected": True, "ssid": ssid.group(1).strip(), "rssi": pct_to_dbm(int(sig.group(1)))}
        elif sys.platform == "darwin":
            out = _run(["/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-I"])
            ssid = re.search(r"^\s*SSID: (.+)$", out, re.M); rssi = re.search(r"agrCtlRSSI: (-?\d+)", out)
            if ssid: return {"connected": True, "ssid": ssid.group(1).strip(), "rssi": int(rssi.group(1)) if rssi else None}
        else:
            out = _run(["nmcli", "-t", "-f", "ACTIVE,SSID,SIGNAL", "dev", "wifi"])
            for line in out.splitlines():
                p = line.split(":")
                if p[0] == "yes" and len(p) >= 3 and p[-1].isdigit():
                    return {"connected": True, "ssid": ":".join(p[1:-1]), "rssi": pct_to_dbm(int(p[-1]))}
        if self.ethernet and self._has_default_route():
            return {"connected": True, "ssid": "(mạng có dây)", "rssi": None}
        return {"connected": False, "ssid": "", "rssi": None}

    @staticmethod
    def _has_default_route():
        import socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("8.8.8.8", 80)); s.close(); return True
        except OSError:
            return False

    def connect(self):
        ssid, pw = self.cfg.s("wifi", "ssid"), self.cfg.s("wifi", "password")
        if not ssid: return False
        if sys.platform.startswith("linux"):
            cmd = ["nmcli", "dev", "wifi", "connect", ssid] + (["password", pw] if pw else [])
        elif sys.platform.startswith("win"):
            cmd = ["netsh", "wlan", "connect", f"name={ssid}"]     # cần profile Wi-Fi đã lưu sẵn
        else:
            cmd = ["networksetup", "-setairportnetwork", "en0", ssid] + ([pw] if pw else [])
        return bool(_run(cmd, 25) is not None)


def make_wifi(cfg):
    return SystemWifi(cfg) if cfg.s("wifi", "driver").lower() == "system" else SimWifi(cfg)
