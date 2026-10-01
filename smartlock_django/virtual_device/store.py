# virtual_device/store.py
"""Lưu "bộ nhớ flash" của khoá ảo: identity.json (mã + secret) và state.json (trạng thái + hàng đợi offline)."""
import json
import os
import threading

from . import config


class Store:
    def __init__(self, profile: str = 'default'):
        self.profile = profile
        self.dir = config.DATA_DIR / profile
        self.identity_path = self.dir / 'identity.json'
        self.state_path = self.dir / 'state.json'
        self._mu = threading.Lock()

    @staticmethod
    def _read(path):
        try:
            return json.loads(path.read_text(encoding='utf-8'))
        except (FileNotFoundError, ValueError):
            return {}

    def _write(self, path, data):
        self.dir.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix('.tmp')
        with self._mu:
            tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')
            os.replace(tmp, path)          # ghi nguyên tử: mất điện giữa chừng không hỏng file

    def has_identity(self) -> bool:
        return self.identity_path.exists()

    def load_identity(self) -> dict:
        return self._read(self.identity_path)

    def save_identity(self, data: dict):
        self._write(self.identity_path, data)
        try:
            os.chmod(self.identity_path, 0o600)
        except OSError:
            pass

    def load_state(self) -> dict:
        return self._read(self.state_path)

    def save_state(self, data: dict):
        self._write(self.state_path, data)
