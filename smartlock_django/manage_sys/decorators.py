# manage_sys/decorators.py
from functools import wraps

from django.contrib import messages
from django.contrib.auth import logout
from django.contrib.auth.views import redirect_to_login
from django.urls import reverse
from django.views.decorators.cache import never_cache

from .helpers import is_manager


def manage_required(view_func):
    """Chỉ cho tài khoản quản trị đã đăng nhập ở cổng quản trị riêng."""
    @wraps(view_func)
    @never_cache
    def wrapper(request, *args, **kwargs):
        user = request.user
        if not user.is_authenticated:
            return redirect_to_login(request.get_full_path(), reverse('manage_sys:login'))
        if not is_manager(user):
            logout(request)  # chỉ hủy phiên admin, không đụng phiên user
            messages.error(request, 'Tài khoản không còn quyền quản trị.')
            return redirect_to_login(request.get_full_path(), reverse('manage_sys:login'))
        return view_func(request, *args, **kwargs)
    return wrapper
