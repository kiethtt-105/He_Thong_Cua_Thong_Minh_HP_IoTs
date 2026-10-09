"""HTTP client gọi /api/device/* (chỉ dùng thư viện chuẩn -> dễ port sang MicroPython urequests)."""
import json
import urllib.error
import urllib.request


class NetError(Exception):
    """Không tới được server (mất mạng, DNS, timeout, TLS...)."""


class ApiError(Exception):
    def __init__(self, status, code, message, retry_after=None, body=None):
        super().__init__(f'{status} {code}: {message}')
        self.status, self.code, self.message, self.retry_after, self.body = status, code, message, retry_after, body


class DeviceApi:
    def __init__(self, creds):
        self._creds = creds          # callable -> (base_url, device_code, secret)
        self.timeout = 10

    def _req(self, method, path, body=None, timeout=None):
        base, code, secret = self._creds()
        if not base or not code or not secret:
            raise NetError('Chưa cấu hình server / mã thiết bị / secret')
        url = base.rstrip('/') + '/api/device' + path
        data = json.dumps(body, ensure_ascii=False).encode('utf-8') if body is not None else None
        req = urllib.request.Request(url, data=data, method=method, headers={
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'X-Device-Code': code,
            'X-Device-Secret': secret,
            'User-Agent': 'SmartLock-ESP32-Sim/1.0',
            'X-Tunnel-Skip-AntiPhishing-Page': 'true',     # dev tunnel của VS Code bỏ trang cảnh báo
        })
        try:
            with urllib.request.urlopen(req, timeout=timeout or self.timeout) as resp:
                raw = resp.read().decode('utf-8', 'replace')
        except urllib.error.HTTPError as e:
            raw = e.read().decode('utf-8', 'replace')
            try:
                j = json.loads(raw)
            except ValueError:
                raise ApiError(e.code, 'HTTP_%s' % e.code, raw[:120].replace('\n', ' '))
            err = (j.get('error') or {}) if isinstance(j, dict) else {}
            raise ApiError(e.code, err.get('code', 'HTTP_%s' % e.code), err.get('message', ''),
                           retry_after=err.get('retry_after_seconds'), body=j)
        except (urllib.error.URLError, OSError, TimeoutError) as e:
            raise NetError(str(getattr(e, 'reason', e)))
        try:
            return json.loads(raw)
        except ValueError:
            raise NetError('Server trả về không phải JSON (sai URL / bị chặn?): ' + raw[:80].replace('\n', ' '))

    # ---- endpoint ----
    def config(self):            return self._req('GET', '/config/')
    def heartbeat(self, d):      return self._req('POST', '/heartbeat/', d)
    def commands(self):          return self._req('GET', '/commands/')
    def ack(self, d):            return self._req('POST', '/ack/', d)
    def events(self, d):         return self._req('POST', '/events/', d)
    def access_rfid(self, uid):  return self._req('POST', '/access/rfid/', {'uid': uid})
    def access_pin(self, pin):   return self._req('POST', '/access/pin/', {'pin': pin})
    def access_face(self, emb):  return self._req('POST', '/access/face/', {'embedding': emb})
    def access_phone(self, evs): return self._req('POST', '/access/phone/', {'events': evs})
    def ota(self, d):            return self._req('POST', '/ota/', d)
