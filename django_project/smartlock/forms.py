from django import forms
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError

from .models import User

INPUT_CLASS = "form-control"


class RegisterForm(forms.Form):
    email = forms.EmailField(
        label="Email",
        max_length=254,
        widget=forms.EmailInput(attrs={"class": INPUT_CLASS, "placeholder": "ban@vidu.com"}),
    )
    full_name = forms.CharField(
        label="Họ và tên",
        max_length=100,
        required=False,
        widget=forms.TextInput(attrs={"class": INPUT_CLASS, "placeholder": "Nguyễn Văn A"}),
    )
    phone = forms.CharField(
        label="Số điện thoại",
        max_length=20,
        required=False,
        widget=forms.TextInput(attrs={"class": INPUT_CLASS, "placeholder": "09xxxxxxxx"}),
    )
    password1 = forms.CharField(
        label="Mật khẩu",
        widget=forms.PasswordInput(attrs={"class": INPUT_CLASS}),
    )
    password2 = forms.CharField(
        label="Xác nhận mật khẩu",
        widget=forms.PasswordInput(attrs={"class": INPUT_CLASS}),
    )

    def clean_email(self):
        email = self.cleaned_data['email'].strip().lower()
        if User.objects.filter(email=email, email_verified=True).exists():
            raise ValidationError("Email này đã được đăng ký và xác thực. Vui lòng đăng nhập.")
        return email

    def clean_password1(self):
        password1 = self.cleaned_data.get('password1', '')
        try:
            validate_password(password1)
        except ValidationError as exc:
            raise ValidationError(exc.messages)
        return password1

    def clean(self):
        cleaned_data = super().clean()
        p1 = cleaned_data.get('password1')
        p2 = cleaned_data.get('password2')
        if p1 and p2 and p1 != p2:
            self.add_error('password2', "Mật khẩu xác nhận không khớp.")
        return cleaned_data


class OtpForm(forms.Form):
    otp = forms.CharField(
        label="Mã OTP (6 chữ số)",
        max_length=6,
        min_length=6,
        widget=forms.TextInput(attrs={
            "class": INPUT_CLASS,
            "placeholder": "------",
            "inputmode": "numeric",
            "autocomplete": "one-time-code",
        }),
    )

    def clean_otp(self):
        otp = self.cleaned_data['otp'].strip()
        if not otp.isdigit():
            raise ValidationError("Mã OTP chỉ được gồm chữ số.")
        return otp


class LoginForm(forms.Form):
    email = forms.EmailField(
        label="Email",
        widget=forms.EmailInput(attrs={"class": INPUT_CLASS, "placeholder": "ban@vidu.com"}),
    )
    password = forms.CharField(
        label="Mật khẩu",
        widget=forms.PasswordInput(attrs={"class": INPUT_CLASS}),
    )
