"""Camera + trích embedding khuôn mặt 128 chiều (cùng kích thước FACE_DIM của server).
  sim    : lấy vector từ faces/*.json (+ nhiễu nhỏ như thật) hoặc "người lạ" ngẫu nhiên
  opencv : webcam thật + thư viện `face_recognition` (dlib ResNet 128-d)  -> pip install opencv-python face_recognition
LƯU Ý: server đăng ký khuôn mặt bằng face-api.js trên trình duyệt. Hai mô hình cùng 128-d nhưng KHÔNG đồng nhất
tuyệt đối; để so khớp chính xác hãy đăng ký và nhận diện bằng CÙNG một mô hình."""
import json
import random
from pathlib import Path
from . import optional_import

DIM = 128


def load_profiles(folder):
    out = {}
    for f in sorted(Path(folder).glob("*.json")):
        try:
            d = json.loads(f.read_text(encoding="utf-8"))
            if len(d.get("embedding", [])) == DIM: out[d.get("name") or f.stem] = d["embedding"]
        except Exception: pass
    return out


class SimCamera:
    kind = "sim"
    def __init__(self, cfg): self.dir = cfg.p("camera", "faces_dir")
    def profiles(self): return load_profiles(self.dir)
    def scan(self, who=None):
        """who=None/'stranger' -> người lạ; còn lại là tên profile."""
        prof = self.profiles()
        if who and who in prof:
            return [x + random.gauss(0, 0.01) for x in prof[who]]
        return [random.gauss(0, 0.2) for _ in range(DIM)]


class OpenCvCamera:
    kind = "opencv"
    def __init__(self, cfg):
        self.cv2 = optional_import("cv2", "pip install opencv-python")
        self.fr = optional_import("face_recognition", "pip install face_recognition")
        self.idx, self.frames, self.dir = cfg.i("camera", "index"), cfg.i("camera", "frames"), cfg.p("camera", "faces_dir")
    def profiles(self): return load_profiles(self.dir)
    def scan(self, who=None):
        cap = self.cv2.VideoCapture(self.idx)
        if not cap.isOpened(): raise RuntimeError("Không mở được camera")
        vecs = []
        try:
            for _ in range(self.frames * 3):
                ok, frame = cap.read()
                if not ok: continue
                enc = self.fr.face_encodings(self.cv2.cvtColor(frame, self.cv2.COLOR_BGR2RGB))
                if len(enc) == 1: vecs.append([float(x) for x in enc[0]])
                if len(vecs) >= self.frames: break
        finally: cap.release()
        if not vecs: return None
        return [sum(c) / len(vecs) for c in zip(*vecs)]


def make_camera(cfg):
    if not cfg.b("camera", "enabled"): return None
    return OpenCvCamera(cfg) if cfg.s("camera", "driver").lower() == "opencv" else SimCamera(cfg)
