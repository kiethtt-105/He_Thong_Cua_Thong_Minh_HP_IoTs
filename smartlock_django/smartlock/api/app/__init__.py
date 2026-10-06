"""API dùng chung cho APP di động (Bearer) và WEB (session cookie + CSRF) - gắn dưới /api/app/.

    auth.py        đăng ký · đăng nhập · 2FA khi login · refresh · quên mật khẩu
    account.py     hồ sơ · đổi mật khẩu · phiên đăng nhập · push token · bootstrap · snapshot
    two_factor.py  cài đặt 2FA: TOTP · email · passkey
    devices.py     khoá của tôi · claim · live · gửi lệnh · vé BLE/NFC
    access.py      PIN khách · thẻ NFC · đầu đọc · khuôn mặt · chia sẻ quyền
    activity.py    lịch sử ra vào · audit · thông báo · polling sự kiện · thông báo hệ thống
    serializers.py serializer + helper dùng chung
"""
