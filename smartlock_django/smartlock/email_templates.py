# smartlock/email_templates.py
import logging
import re
from email.utils import parseaddr

from django.conf import settings
from django.template import TemplateDoesNotExist
from django.template.loader import render_to_string
from django.utils import timezone
from django.utils.html import linebreaks, strip_tags, urlize


logger = logging.getLogger('smartlock.email')

BRAND_NAME = 'Smart Lock'


class _SafeDict(dict):
    def __missing__(self, key):
        return ''


def _build_context(context: dict, template_name: str = '') -> dict:
    """Bổ sung biến dùng chung cho mọi email và chuẩn hóa tên key."""
    ctx = dict(context)

    # Dòng link hành động cho bản text thuần (chỉ hiện khi có action_url)
    ctx['action_line'] = f"\nTruy cập: {ctx['action_url']}\n" if ctx.get('action_url') else ''
    if template_name == 'system_announcement.html' and not ctx.get('title'):
        ctx['title'] = 'Thông báo hệ thống'

    # views.py đang truyền 'reset_link'; template dùng 'password_reset_link'
    if not ctx.get('password_reset_link') and ctx.get('reset_link'):
        ctx['password_reset_link'] = ctx['reset_link']

    ctx.setdefault('brand_name', BRAND_NAME)
    ctx.setdefault('year', timezone.now().year)
    if 'support_email' not in ctx:
        ctx['support_email'] = parseaddr(getattr(settings, 'DEFAULT_FROM_EMAIL', '') or '')[1]
    return ctx


def _html_to_text(html: str) -> str:
    """Chuyển HTML sang text thuần (bỏ <style>, <head>) khi không có body dự phòng."""
    html = re.sub(r'(?is)<(head|style|script).*?</\1>', '', html)
    html = re.sub(r'(?i)<br\s*/?>|</p>|</tr>|</h1>|</div>', '\n', html)
    text = strip_tags(html)
    text = re.sub(r'[ \t\xa0]+', ' ', text)
    text = re.sub(r'\n\s*\n+', '\n\n', text)
    return text.strip()


def render_email(template_name: str, context: dict) -> tuple[str, str, str]:
    """Trả về (subject, html_content, plain_text).

    - HTML: ưu tiên file templates/emails/<template_name> (giao diện đẹp).
    - Plain text: lấy từ 'body' trong EMAIL_TEMPLATES bên dưới.
    - Nếu chưa có file HTML thì dùng body làm cả HTML lẫn text.
    """
    conf = EMAIL_TEMPLATES.get(template_name, {})
    subject = conf.get('subject') or template_name.replace('.html', '').replace('_', ' ').title()
    ctx = _build_context(context, template_name)

    logger.info("render_email: template=%s context_keys=%s", template_name, sorted(ctx.keys()))

    plain_text = conf.get('body', '').format_map(_SafeDict(ctx))

    try:
        html_content = render_to_string(f'emails/{template_name}', ctx)
        if not plain_text.strip():
            plain_text = _html_to_text(html_content)
        logger.info("render_email: dùng file templates/emails/%s", template_name)
    except TemplateDoesNotExist as e:
        logger.warning("render_email: không thấy file emails/%s (%s) -> dùng EMAIL_TEMPLATES", template_name, e)
        html_content = linebreaks(urlize(plain_text, autoescape=True))
    except Exception:
        logger.exception("render_email: lỗi khi render emails/%s -> dùng EMAIL_TEMPLATES", template_name)
        html_content = linebreaks(urlize(plain_text, autoescape=True))

    if not plain_text.strip():
        logger.error("render_email: nội dung rỗng cho %s (template không có trong EMAIL_TEMPLATES?)", template_name)

    return subject, html_content, plain_text


# ==================== BẢN TEXT THUẦN (dự phòng / phiên bản plain-text của email) ====================
EMAIL_TEMPLATES = {
    "user_verification.html": {
        "purpose": "EMAIL_VERIFY",
        "subject": "Xác thực tài khoản Smart Lock",
        "body": """Xin chào {full_name},

Cảm ơn bạn đã đăng ký tài khoản Smart Lock.
Để kích hoạt tài khoản, vui lòng mở liên kết sau:

{verification_link}

Liên kết có hiệu lực trong {expiry_minutes} phút.
Nếu bạn không thực hiện đăng ký, hãy bỏ qua email này.

Trân trọng,
Đội ngũ Smart Lock"""
    },

    "password_reset.html": {
        "purpose": "PASSWORD_RESET",
        "subject": "Đặt lại mật khẩu Smart Lock",
        "body": """Xin chào {full_name},

Chúng tôi nhận được yêu cầu đặt lại mật khẩu cho tài khoản của bạn.

Liên kết đặt lại mật khẩu:
{password_reset_link}

Liên kết có hiệu lực trong {expiry_minutes} phút và chỉ dùng được một lần.
Nếu không phải bạn, hãy bỏ qua email này - mật khẩu vẫn được giữ nguyên.

Trân trọng,
Đội ngũ Smart Lock"""
    },

    "device_added.html": {
        "purpose": "DEVICE_ADDED",
        "subject": "Thiết bị mới đã được thêm vào tài khoản của bạn",
        "body": """Xin chào {full_name},

Quản trị viên vừa thêm thiết bị {device_name} ({device_code}) vào tài khoản của bạn.
Bạn có thể truy cập ngay để điều khiển.
{action_line}
Trân trọng,
Đội ngũ Smart Lock"""
    },

    "share_code_notification.html": {
        "purpose": "SHARE_CODE",
        "subject": "Bạn đã nhận được mã chia sẻ khóa",
        "body": """Xin chào {full_name},

Chủ khóa {device_name} đã chia sẻ khóa với bạn.

Mã chia sẻ (6 chữ số): {share_code}

Mã chỉ có hiệu lực trong {expiry_minutes} phút. Không chia sẻ mã này với người khác.
{action_line}
Trân trọng,
Đội ngũ Smart Lock"""
    },

    "admin_nfc_approval.html": {
        "purpose": "NFC_APPROVAL",
        "subject": "Yêu cầu kích hoạt thẻ NFC mới",
        "body": """Xin chào Quản trị viên,

Tài khoản {user_email} đã thêm thẻ NFC mới:
- Tên thẻ: {card_name}
- UID: {card_uid}

Thẻ chỉ hoạt động sau khi bạn xác nhận.
{action_line}
Trân trọng,
Đội ngũ Smart Lock"""
    },

    "admin_device_approval.html": {
        "purpose": "DEVICE_APPROVAL",
        "subject": "Thiết bị mới cần kích hoạt",
        "body": """Xin chào Quản trị viên,

Thiết bị {device_code} của {user_email} đang chờ kích hoạt.
Vui lòng kiểm tra và kích hoạt (hoặc thông báo cho chủ thiết bị).
{action_line}
Trân trọng,
Đội ngũ Smart Lock"""
    },

    "recovery_notification.html": {
        "purpose": "RECOVERY",
        "subject": "Thông báo khôi phục thiết bị",
        "body": """Xin chào {full_name},

Chủ thiết bị {device_name} vừa gửi yêu cầu khôi phục thiết bị.
Vui lòng liên hệ quản trị viên để được hỗ trợ.
{action_line}
Trân trọng,
Đội ngũ Smart Lock"""
    },

    "two_factor_code.html": {
        "purpose": "TWO_FACTOR_CODE",
        "subject": "Mã xác thực 2 lớp Smart Lock",
        "body": """Xin chào {full_name},

Mã xác thực (OTP) của bạn là: {otp_code}

Mã có hiệu lực trong {expiry_minutes} phút và chỉ dùng được một lần.
Tuyệt đối không chia sẻ mã này với bất kỳ ai.
Nếu không phải bạn yêu cầu, hãy đổi mật khẩu ngay.

Trân trọng,
Đội ngũ Smart Lock"""
    },

    "system_announcement.html": {
        "purpose": "SYSTEM_ANNOUNCEMENT",
        "subject": "Thông báo hệ thống",
        "body": """{title}

{body}
{action_line}"""
    },
}