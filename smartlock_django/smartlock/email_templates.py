# smartlock/email_templates.py
import logging

from django.template import TemplateDoesNotExist
from django.template.loader import render_to_string
from django.utils.html import linebreaks, strip_tags, urlize


logger = logging.getLogger('smartlock.email')


class _SafeDict(dict):
    def __missing__(self, key):
        return ''


def render_email(template_name: str, context: dict) -> tuple[str, str, str]:
    """Trả về (subject, html_content, plain_text).

    Ưu tiên file templates/emails/<template_name>; nếu chưa có thì dùng body
    trong EMAIL_TEMPLATES bên dưới.
    """
    conf = EMAIL_TEMPLATES.get(template_name, {})
    subject = conf.get('subject') or template_name.replace('.html', '').replace('_', ' ').title()

    logger.info("render_email: template=%s context_keys=%s", template_name, sorted(context.keys()))
    try:
        html_content = render_to_string(f'emails/{template_name}', context)
        plain_text = strip_tags(html_content)
        logger.info("render_email: dùng file templates/emails/%s", template_name)
    except TemplateDoesNotExist as e:
        logger.warning("render_email: không thấy file emails/%s (%s) -> dùng EMAIL_TEMPLATES", template_name, e)
        plain_text = conf.get('body', '').format_map(_SafeDict(context))
        html_content = linebreaks(urlize(plain_text, autoescape=True))
    except Exception:
        logger.exception("render_email: lỗi khi render emails/%s -> dùng EMAIL_TEMPLATES", template_name)
        plain_text = conf.get('body', '').format_map(_SafeDict(context))
        html_content = linebreaks(urlize(plain_text, autoescape=True))

    if not plain_text.strip():
        logger.error("render_email: nội dung rỗng cho %s (template không có trong EMAIL_TEMPLATES?)", template_name)

    return subject, html_content, plain_text


# ==================== CÁC TEMPLATE EMAIL ====================
EMAIL_TEMPLATES = {
    "user_verification.html": {
        "purpose": "EMAIL_VERIFY",
        "subject": "Xác thực tài khoản Smart Lock",
        "body": """Chào {full_name} hoặc {username},

Cảm ơn bạn đã đăng ký tài khoản tại Smart Lock!

Để kích hoạt tài khoản, vui lòng click vào link dưới đây:

{verification_link}

Nếu bạn không đăng ký, vui lòng bỏ qua email này.

Trân trọng,
Đội ngũ Smart Lock"""
    },

    "password_reset.html": {
        "purpose": "PASSWORD_RESET",
        "subject": "Đặt lại mật khẩu Smart Lock",
        "body": """Chào {full_name},

Bạn đã yêu cầu đặt lại mật khẩu.

Link đặt lại: {password_reset_link}

Link sẽ hết hạn sau {expiry_minutes} phút.

Nếu không phải bạn, vui lòng bỏ qua.

Trân trọng,
Đội ngũ Smart Lock"""
    },

    "device_added.html": {
        "purpose": "DEVICE_ADDED",
        "subject": "Thiết bị mới đã được thêm vào tài khoản của bạn",
        "body": """Chào {full_name},

Thiết bị {device_name} ({device_code}) đã được thêm vào tài khoản của bạn bởi admin.

Bạn có thể truy cập ngay để điều khiển.

Trân trọng,
Đội ngũ Smart Lock"""
    },

    "share_code_notification.html": {
        "purpose": "SHARE_CODE",
        "subject": "Bạn đã nhận được mã chia sẻ khóa",
        "body": """Chào {full_name},

Chủ khóa {device_name} đã chia sẻ khóa với bạn.

**Mã chia sẻ**: {share_code} (nhập đúng 6 số)

Mã này chỉ có hiệu lực trong {expiry_minutes} phút.

Trân trọng,
Đội ngũ Smart Lock"""
    },

    "admin_nfc_approval.html": {
        "purpose": "NFC_APPROVAL",
        "subject": "Yêu cầu kích hoạt thẻ NFC mới",
        "body": """Chào Admin,

Tài khoản {user_email} đã thêm thẻ NFC mới:
- Tên thẻ: {card_name}
- UID: {card_uid}

Bạn cần xác nhận để thẻ này hoạt động trên hệ thống.

Trân trọng,
Đội ngũ Smart Lock"""
    },

    "admin_device_approval.html": {
        "purpose": "DEVICE_APPROVAL",
        "subject": "Thiết bị mới cần kích hoạt",
        "body": """Chào Admin,

Thiết bị {device_code} của {user_email} cần kích hoạt.

Vui lòng kiểm tra và kích hoạt (hoặc thông báo cho chủ thiết bị).

Trân trọng,
Đội ngũ Smart Lock"""
    },

    "recovery_notification.html": {
        "purpose": "RECOVERY",
        "subject": "Thông báo khôi phục thiết bị",
        "body": """Chào {full_name},

Chủ thiết bị {device_name} đã yêu cầu khôi phục thiết bị.

Vui lòng liên hệ admin để hỗ trợ.

Trân trọng,
Đội ngũ Smart Lock"""
    },

    "system_announcement.html": {
        "purpose": "SYSTEM_ANNOUNCEMENT",
        "subject": "Thông báo hệ thống",
        "body": """{body}"""
    },
}