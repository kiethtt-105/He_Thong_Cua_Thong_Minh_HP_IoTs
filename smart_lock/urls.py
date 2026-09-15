from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    # Trang chính của ứng dụng accounts (login, register, dashboard...)
    path('', include('accounts.urls')),
    # Admin site
    path('admin/', admin.site.urls),
]