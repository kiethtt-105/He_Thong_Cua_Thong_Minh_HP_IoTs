from django import forms


class RegisterForm(forms.Form):
    email = forms.EmailField(label='Email')
    full_name = forms.CharField(label='Họ và tên', max_length=100)
    phone = forms.CharField(label='Số điện thoại', max_length=20, required=False)
    password = forms.CharField(label='Mật khẩu', widget=forms.PasswordInput, min_length=8)
    password2 = forms.CharField(label='Nhập lại mật khẩu', widget=forms.PasswordInput)

    def clean(self):
        cleaned = super().clean()
        pw1 = cleaned.get('password')
        pw2 = cleaned.get('password2')
        if pw1 and pw2 and pw1 != pw2:
            raise forms.ValidationError('Mật khẩu nhập lại không khớp.')
        return cleaned


class OTPForm(forms.Form):
    otp = forms.CharField(
        label='Mã OTP',
        max_length=6,
        min_length=6,
        widget=forms.TextInput(attrs={'inputmode': 'numeric', 'autocomplete': 'one-time-code'}),
    )


class LoginForm(forms.Form):
    email = forms.EmailField(label='Email')
    password = forms.CharField(label='Mật khẩu', widget=forms.PasswordInput)
