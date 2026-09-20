#!/usr/bin/env python
"""
Kiểm tra template email Smart Lock. 

  python test_email.py                          # render  email 
  python test_email.py --list                   # liệt kê template
  python test_email.py --only password_reset    # chỉ 1 (|| nhiều) template
  python test_email.py --send you@gmail.com     # GỬI THẬT tất cả email đến địa chỉ này
  python test_email.py --send you@gmail.com --only password_reset share_code_notification
  python test_email.py --smtp-check             # chỉ kiểm tra đăng nhập SMTP
  python test_email.py --base-url https://he-thong-cua-thong-minh-hp-iots.vercel.app

LẤY DƯ LIEU MAIL CONF TỪ .ENV
  """
import argparse
import html as html_lib
import os
import re
import string
import sys
import webbrowser
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "smartlock_django.settings")

OK, BAD, WARN = "[OK] ", "[LỖI]", "[!]  "



def build_samples(base_url, reset_minutes):
    base = base_url.rstrip("/")
    verify_link = f"{base}/verify-email/3f2c9d1e-8a4b-4c1f-9e2a-7d5b6c0a1f34/"
    reset_link = f"{base}/reset-password/ZWYyNTgwMGQtOWFmNC00NDlm/df7bca-a4048054bf2b7caa6f54f89e9b60aa51/"
    dashboard = f"{base}/dashboard/"
    return {
        "user_verification.html": dict(
            context=dict(full_name="Trần Tuấn Kiệt", username="kiethtt", verification_link=verify_link, expiry_minutes=30),
            expect=[verify_link, "Trần Tuấn Kiệt", "30"],
        ),
        "password_reset.html": dict(
            context=dict(full_name="Trần Tuấn Kiệt", reset_link=reset_link, expiry_minutes=reset_minutes),
            expect=[reset_link, "Trần Tuấn Kiệt", str(reset_minutes)],
        ),
        "device_added.html": dict(
            context=dict(full_name="Nguyễn Văn A", device_name="Cửa chính - Tầng 1", device_code="SL-ESP32-0A41", action_url=dashboard),
            expect=["Cửa chính - Tầng 1", "SL-ESP32-0A41", dashboard],
        ),
        "share_code_notification.html": dict(
            context=dict(full_name="Nguyễn Văn A", device_name="Cửa chính - Tầng 1", share_code="482951", expiry_minutes=10, action_url=dashboard),
            expect=["482951", "Cửa chính - Tầng 1", "10"],
        ),
        "admin_nfc_approval.html": dict(
            context=dict(user_email="user@example.com", card_name="Thẻ nhân viên", card_uid="04:A2:3B:19:7C:80", action_url=f"{base}/admin-sys/"),
            expect=["user@example.com", "Thẻ nhân viên", "04:A2:3B:19:7C:80"],
        ),
        "admin_device_approval.html": dict(
            context=dict(user_email="user@example.com", device_code="SL-ESP32-0A41", action_url=f"{base}/admin-sys/"),
            expect=["user@example.com", "SL-ESP32-0A41"],
        ),
        "recovery_notification.html": dict(
            context=dict(full_name="Nguyễn Văn A", device_name="Cửa chính - Tầng 1"),
            expect=["Nguyễn Văn A", "Cửa chính - Tầng 1"],
        ),
        "system_announcement.html": dict(
            context=dict(title="Bảo trì hệ thống",
                         body="Hệ thống sẽ bảo trì từ 23:00 đến 23:30 ngày 25/09.\n\nTrong thời gian này bạn không thể điều khiển khóa từ xa.",
                         action_url=base, action_label="Xem chi tiết"),
            expect=["Bảo trì hệ thống", "23:00"],
        ),
    }


# --------------------------------------------------------------------------
def lint(name, ctx, expect, subject, html, plain):
    issues = []
    if not subject.strip():
        issues.append("Subject rỗng")
    if not html.strip():
        issues.append("HTML rỗng")
    if not plain.strip():
        issues.append("Bản text thuần rỗng")

    leftover = re.findall(r"\{\{.*?\}\}|\{%.*?%\}", html)
    if leftover:
        issues.append(f"HTML còn cú pháp template chưa render: {leftover[:2]}")
    if re.search(r'href=""|href="None"', html):
        issues.append("Có nút/link bị trống (href rỗng hoặc None)")
    if "None" in plain.split():
        issues.append("Bản text có chữ 'None' (biến bị None)")

    for value in expect:
        esc = html_lib.escape(value)
        if value not in html and esc not in html:
            issues.append(f"HTML thiếu giá trị: {value[:60]}")
        if value not in plain:
            issues.append(f"Bản text thiếu giá trị: {value[:60]}")

    from smartlock.email_templates import EMAIL_TEMPLATES
    body = EMAIL_TEMPLATES.get(name, {}).get("body", "")
    fields = {f for _, f, _, _ in string.Formatter().parse(body) if f}
    skip = {"brand_name", "year", "support_email", "password_reset_link", "action_line"}
    missing = sorted(f for f in fields if f not in skip and not ctx.get(f))
    if missing:
        issues.append(f"Body text dùng biến không có trong context: {missing}")
    return issues


INDEX_TMPL = """<!DOCTYPE html><html lang="vi"><head><meta charset="utf-8"><title>Xem trước email</title>
<style>
*{box-sizing:border-box}body{margin:0;font-family:Segoe UI,Arial,sans-serif;background:#0f172a;color:#e2e8f0;display:flex;height:100vh}
aside{width:340px;overflow:auto;padding:18px;border-right:1px solid #1e293b}
h2{margin:0 0 14px;font-size:18px}
.item{display:block;width:100%;text-align:left;background:#111c33;border:1px solid #1e293b;color:inherit;border-radius:10px;padding:12px;margin-bottom:10px;cursor:pointer}
.item.active{border-color:#2563eb;background:#14264f}
.item b{display:block;font-size:14px}.item small{color:#94a3b8;display:block;margin-top:2px}
.ok{color:#4ade80}.bad{color:#f87171}
main{flex:1;display:flex;flex-direction:column;min-width:0}
.bar{padding:10px 16px;border-bottom:1px solid #1e293b;display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.bar button{background:#1e293b;border:0;color:#e2e8f0;padding:7px 12px;border-radius:8px;cursor:pointer}
.bar button.on{background:#2563eb}
.stage{flex:1;overflow:auto;padding:20px;display:flex;justify-content:center;background:#0b1120}
iframe{border:0;background:#fff;border-radius:10px;height:100%;width:680px;max-width:100%}
pre{display:none;white-space:pre-wrap;margin:0;padding:24px;background:#0b1120;color:#cbd5e1;flex:1;overflow:auto;font-size:14px;line-height:1.6}
.issues{color:#f87171;font-size:12px;margin-top:6px}
</style></head><body>
<aside><h2>Email templates</h2>__ITEMS__</aside>
<main>
  <div class="bar"><span id="subj" style="margin-right:auto;font-weight:600"></span>
    <button id="bDesk" class="on">Máy tính</button><button id="bMob">Điện thoại</button><button id="bTxt">Text thuần</button></div>
  <div class="stage" id="stage"><iframe id="frm"></iframe></div>
  <pre id="txt"></pre>
</main>
<script>
const DATA=__DATA__;let cur=0;
const frm=document.getElementById('frm'),txt=document.getElementById('txt'),stage=document.getElementById('stage');
function show(i){cur=i;document.querySelectorAll('.item').forEach((e,k)=>e.classList.toggle('active',k===i));
 frm.src=DATA[i].file;txt.textContent=DATA[i].plain;document.getElementById('subj').textContent='Subject: '+DATA[i].subject;}
document.querySelectorAll('.item').forEach((e,k)=>e.onclick=()=>show(k));
function mode(m){stage.style.display=m==='txt'?'none':'flex';txt.style.display=m==='txt'?'block':'none';
 frm.style.width=m==='mob'?'390px':'680px';
 ['bDesk','bMob','bTxt'].forEach(id=>document.getElementById(id).classList.remove('on'));
 document.getElementById(m==='mob'?'bMob':m==='txt'?'bTxt':'bDesk').classList.add('on');}
bDesk.onclick=()=>mode('desk');bMob.onclick=()=>mode('mob');bTxt.onclick=()=>mode('txt');
show(0);
</script></body></html>"""


def write_previews(results, out_dir):
    import json
    out_dir.mkdir(parents=True, exist_ok=True)
    items, data = [], []
    for r in results:
        stem = r["name"].replace(".html", "")
        (out_dir / f"{stem}.html").write_text(r["html"], encoding="utf-8")
        (out_dir / f"{stem}.txt").write_text(r["plain"], encoding="utf-8")
        status = '<span class="ok">Đạt</span>' if not r["issues"] else f'<span class="bad">{len(r["issues"])} vấn đề</span>'
        issues = "".join(f"<div class='issues'>• {html_lib.escape(i)}</div>" for i in r["issues"])
        items.append(f'<button class="item"><b>{html_lib.escape(r["subject"])}</b><small>{r["name"]} · {status}</small>{issues}</button>')
        data.append({"file": f"{stem}.html", "plain": r["plain"], "subject": r["subject"]})
    page = INDEX_TMPL.replace("__ITEMS__", "".join(items)).replace("__DATA__", json.dumps(data, ensure_ascii=False))
    index = out_dir / "index.html"
    index.write_text(page, encoding="utf-8")
    return index


def send_all(results, to_addr):
    from django.conf import settings
    from django.core.mail import EmailMultiAlternatives

    sent = failed = 0
    for r in results:
        try:
            msg = EmailMultiAlternatives(f"[TEST] {r['subject']}", r["plain"], settings.DEFAULT_FROM_EMAIL, [to_addr])
            msg.attach_alternative(r["html"], "text/html")
            msg.send(fail_silently=False)
            print(f"  {OK} đã gửi: {r['name']}")
            sent += 1
        except Exception as exc:  # noqa: BLE001
            print(f"  {BAD} {r['name']}: {type(exc).__name__}: {exc}")
            failed += 1
    print(f"\nKết quả gửi: {sent} thành công, {failed} thất bại  ->  {to_addr}")
    return failed == 0


def smtp_check():
    from django.conf import settings
    from django.core.mail import get_connection

    print("Cấu hình SMTP đang dùng:")
    print(f"  backend  : {settings.EMAIL_BACKEND}")
    print(f"  host:port: {settings.EMAIL_HOST}:{settings.EMAIL_PORT}  (SSL={settings.EMAIL_USE_SSL}, TLS={settings.EMAIL_USE_TLS})")
    print(f"  user     : {settings.EMAIL_HOST_USER}")
    print(f"  password : {'(đã đặt, %d ký tự)' % len(settings.EMAIL_HOST_PASSWORD) if settings.EMAIL_HOST_PASSWORD else '(TRỐNG!)'}")
    print(f"  from     : {settings.DEFAULT_FROM_EMAIL}")
    try:
        conn = get_connection(fail_silently=False)
        conn.open()
        conn.close()
        print(f"\n{OK} Đăng nhập SMTP thành công.")
        return True
    except Exception as exc:  # noqa: BLE001
        print(f"\n{BAD} Không kết nối/đăng nhập được SMTP: {type(exc).__name__}: {exc}")
        print("     Gmail cần 'App password' (16 ký tự), không dùng mật khẩu đăng nhập thường.")
        return False


def main():
    ap = argparse.ArgumentParser(description="Kiểm tra template email Smart Lock")
    ap.add_argument("--list", action="store_true", help="liệt kê template")
    ap.add_argument("--only", nargs="+", metavar="TEN", help="chỉ chạy các template này (vd: password_reset)")
    ap.add_argument("--send", metavar="EMAIL", help="gửi thật đến địa chỉ này")
    ap.add_argument("--smtp-check", action="store_true", help="chỉ kiểm tra kết nối SMTP")
    ap.add_argument("--base-url", default="http://localhost:8000", help="domain dùng cho link mẫu")
    ap.add_argument("--out", default="email_previews", help="thư mục xuất bản xem trước")
    ap.add_argument("--no-open", action="store_true", help="không tự mở trình duyệt")
    args = ap.parse_args()

    try:
        import django
        django.setup()
        from django.conf import settings
        from smartlock.email_templates import EMAIL_TEMPLATES, render_email
    except Exception as exc:  # noqa: BLE001
        print(f"{BAD} Không khởi tạo được Django: {type(exc).__name__}: {exc}")
        print("     Kiểm tra: đã activate .venv chưa? file .env có DJANGO_SECRET_KEY chưa?")
        return 2

    if args.smtp_check:
        return 0 if smtp_check() else 1

    reset_minutes = getattr(settings, "PASSWORD_RESET_TIMEOUT", 259200) // 60
    samples = build_samples(args.base_url, reset_minutes)

    if args.list:
        for name in samples:
            print(f"  {name.replace('.html', ''):32s} {EMAIL_TEMPLATES.get(name, {}).get('subject', '')}")
        return 0

    names = list(samples)
    if args.only:
        wanted = {n if n.endswith(".html") else f"{n}.html" for n in args.only}
        unknown = wanted - set(samples)
        if unknown:
            print(f"{BAD} Không có template: {', '.join(sorted(unknown))}. Dùng --list để xem danh sách.")
            return 2
        names = [n for n in samples if n in wanted]

    print(f"PASSWORD_RESET_TIMEOUT hiện tại = {reset_minutes} phút\n")
    print("Đang render và kiểm tra...\n")
    results, has_error = [], False
    for name in names:
        s = samples[name]
        subject, html, plain = render_email(name, s["context"])
        try:
            from django.template.loader import get_template
            get_template(f"emails/{name}")
            used_file = True
        except Exception:  # noqa: BLE001
            used_file = False
        issues = lint(name, s["context"], s["expect"], subject, html, plain)
        if not used_file:
            issues.append("Chưa thấy file templates/emails/" + name + " -> đang dùng bản text dự phòng (xấu)")
        results.append(dict(name=name, subject=subject, html=html, plain=plain, issues=issues))
        print(f"  {OK if not issues else BAD} {name:32s} {subject}")
        for i in issues:
            print(f"        - {i}")
        has_error |= bool(issues)

    out_dir = (BASE_DIR / args.out)
    index = write_previews(results, out_dir)
    print(f"\nĐã xuất bản xem trước: {index}")

    if args.send:
        print(f"\nĐang gửi thật đến {args.send} ...")
        if not send_all(results, args.send):
            has_error = True
    elif not args.no_open:
        webbrowser.open(index.as_uri())

    print("\n" + ("Có vấn đề cần xem lại ở trên." if has_error else "Tất cả template đều đạt."))
    return 1 if has_error else 0


if __name__ == "__main__":
    sys.exit(main())
