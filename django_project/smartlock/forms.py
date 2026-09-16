from django import forms
from django.core.exceptions import ValidationError

from .models import User


class RegisterForm(forms.Form):
    full_name = forms.CharField(
        label='Họ và tên', max_length=100,
        widget=forms.TextInput(attrs={'placeholder': 'Nguyễn Văn A', 'autofocus': True})
    )
    email = forms.EmailField(
        label='Email',
        widget=forms.EmailInput(attrs={'placeholder': 'ban@example.com'})
    )
    password = forms.CharField(
        label='Mật khẩu', min_length=8,
        widget=forms.PasswordInput(attrs={'placeholder': 'Tối thiểu 8 ký tự'})
    )
    password_confirm = forms.CharField(
        label='Nhập lại mật khẩu',
        widget=forms.PasswordInput(attrs={'placeholder': 'Nhập lại mật khẩu'})
    )

    def clean_email(self):
        email = self.cleaned_data['email'].strip().lower()
        if User.objects.filter(email=email).exists():
            raise ValidationError('Email này đã được đăng ký. Vui lòng đăng nhập.')
        return email

    def clean(self):
        cleaned = super().clean()
        pw = cleaned.get('password')
        pw2 = cleaned.get('password_confirm')
        if pw and pw2 and pw != pw2:
            self.add_error('password_confirm', 'Mật khẩu nhập lại không khớp.')
        return cleaned


class VerifyOtpForm(forms.Form):
    otp_code = forms.CharField(
        label='Mã OTP', min_length=6, max_length=6,
        widget=forms.TextInput(attrs={
            'placeholder': '------', 'autofocus': True,
            'inputmode': 'numeric', 'autocomplete': 'one-time-code',
        })
    )

    def clean_otp_code(self):
        code = self.cleaned_data['otp_code'].strip()
        if not code.isdigit():
            raise ValidationError('Mã OTP chỉ gồm 6 chữ số.')
        return code


class LoginForm(forms.Form):
    email = forms.EmailField(
        label='Email',
        widget=forms.EmailInput(attrs={'placeholder': 'ban@example.com', 'autofocus': True})
    )
    password = forms.CharField(
        label='Mật khẩu',
        widget=forms.PasswordInput(attrs={'placeholder': 'Mật khẩu'})
    )
