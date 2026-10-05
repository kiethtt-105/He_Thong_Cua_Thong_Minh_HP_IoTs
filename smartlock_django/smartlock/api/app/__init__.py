"""API dùng chung cho APP di động (Bearer) và WEB (session cookie + CSRF) - gắn dưới /api/app/.

Chia theo miền nghiệp vụ, mỗi nhóm có urls.py riêng:
    auth/      đăng ký · đăng nhập · 2FA khi login · refresh · quên mật khẩu
    account/   hồ sơ · đổi mật khẩu · phiên đăng nhập · push token · bootstrap
    devices/   khoá của tôi · claim · live · gửi lệnh · vé BLE/NFC
    access/    PIN khách · thẻ NFC · đầu đọc · khuôn mặt · chia sẻ quyền
    activity/  lịch sử ra vào · audit · thông báo · polling sự kiện · thông báo hệ thống
"""
