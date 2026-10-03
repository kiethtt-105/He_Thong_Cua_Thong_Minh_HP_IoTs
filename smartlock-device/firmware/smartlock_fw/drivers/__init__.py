"""Mỗi phần cứng có driver `sim` (chạy trên PC) và driver thật (Raspberry Pi / đầu đọc USB / BLE của máy)."""
import logging
log = logging.getLogger("smartlock.drivers")


def optional_import(name, hint):
    try:
        return __import__(name, fromlist=["_"])
    except Exception as e:  # ImportError hoặc lỗi nạp thư viện native
        raise RuntimeError(f"Thiếu thư viện '{name}' ({e}). Cài: {hint}") from e
