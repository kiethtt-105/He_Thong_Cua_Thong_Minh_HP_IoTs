# Chạy TRƯỚC khi migrate (chỉ đọc, không sửa dữ liệu):
#     python manage.py shell < tools/precheck_constraints.py
# In ra số dòng sẽ vi phạm từng ràng buộc mới. Tất cả phải = 0 thì migrate mới chạy được.
from django.db.models import Q, F, Count
from django.db.models.functions import Lower
from smartlock.models import (User, OneTimeCode, SystemSettings, Device, DeviceStatusLog, DeviceAccess,
                              NfcReader, Notification, DoorPinCode, FaceProfile, MobileSession)

bad = 0
def check(label, qs, hint):
    global bad
    n = qs.count()
    if n:
        bad += n
    print(f"[{'FAIL' if n else ' ok '}] {label}: {n}" + (f"   -> {hint}" if n else ''))
    for pk in list(qs.values_list('pk', flat=True)[:5]) if n else []:
        print('         ví dụ id:', pk)

def dup(model, field, label, hint):
    qs = (model.objects.annotate(k=Lower(field)).values('k').annotate(c=Count('pk')).filter(c__gt=1))
    n = qs.count()
    global bad
    bad += n
    print(f"[{'FAIL' if n else ' ok '}] {label}: {n} nhóm trùng" + (f"   -> {hint}" if n else ''))
    for r in list(qs[:5]):
        print('         ví dụ:', r['k'], 'x', r['c'])

dup(User, 'email', 'User.email trùng không phân biệt hoa-thường', 'gộp/đổi email')
dup(User, 'username', 'User.username trùng không phân biệt hoa-thường', 'đổi username')
check('User đếm khoá đăng nhập âm', User.objects.filter(Q(login_failed_attempts__lt=0) | Q(login_lock_stage__lt=0)), 'set về 0')
check('OneTimeCode attempts âm', OneTimeCode.objects.filter(attempts__lt=0), 'set về 0')
check('OneTimeCode có used_at nhưng is_used=False', OneTimeCode.objects.filter(used_at__isnull=False, is_used=False), 'set is_used=True')
check('SystemSettings id != 1', SystemSettings.objects.exclude(id=1), 'xoá dòng thừa')
check('SystemSettings ngoài biên', SystemSettings.objects.exclude(
    verification_token_expiry_minutes__range=(1, 10080), share_code_expiry_minutes__range=(1, 1440),
    session_timeout_hours__range=(1, 720)), 'đưa về giá trị hợp lệ')
check('Device pin ngoài 0..100', Device.objects.exclude(battery_level__range=(0, 100)), 'kẹp về 0..100')
check('Device is_purchased nhưng thiếu purchased_at', Device.objects.filter(is_purchased=True, purchased_at__isnull=True), 'set purchased_at=created_at')
check('DeviceStatusLog pin ngoài 0..100', DeviceStatusLog.objects.exclude(battery_level__range=(0, 100)), 'kẹp về 0..100')
dups = (DeviceAccess.objects.filter(is_active=True).values('device', 'user').annotate(c=Count('pk')).filter(c__gt=1))
n = dups.count(); bad += n
print(f"[{'FAIL' if n else ' ok '}] DeviceAccess đang hoạt động bị trùng (device,user): {n}" + ("   -> giữ bản mới nhất, is_active=False cho bản cũ" if n else ''))
check('NfcReader expires_at <= valid_from', NfcReader.objects.filter(expires_at__isnull=False, expires_at__lte=F('valid_from')), 'set expires_at=NULL hoặc lùi valid_from')
check('Notification có read_at nhưng is_read=False', Notification.objects.filter(read_at__isnull=False, is_read=False), 'set is_read=True')
check('DoorPinCode max_uses/use_count âm', DoorPinCode.objects.filter(Q(max_uses__lt=0) | Q(use_count__lt=0)), 'set về 0')
check('DoorPinCode expires_at <= valid_from', DoorPinCode.objects.filter(expires_at__lte=F('valid_from')), 'sửa hạn hoặc thu hồi')
check('DoorPinCode is_revoked nhưng thiếu revoked_at', DoorPinCode.objects.filter(is_revoked=True, revoked_at__isnull=True), 'set revoked_at=created_at')
check('FaceProfile threshold ngoài (0,2]', FaceProfile.objects.exclude(threshold__gt=0, threshold__lte=2), 'set 0.6')
check('FaceProfile đang bật nhưng chưa consent', FaceProfile.objects.filter(is_active=True, consent_confirmed=False), 'TẮT is_active (không tự đặt consent=True)')
check('MobileSession expires_at <= created_at', MobileSession.objects.filter(expires_at__lte=F('created_at')), 'thu hồi phiên')

print('\n==> TỔNG VI PHẠM:', bad, '| An toàn để migrate' if not bad else '| Xử lý các dòng FAIL rồi chạy lại')
