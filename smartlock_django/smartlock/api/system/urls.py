"""Route hệ thống công khai - gắn dưới /api/system/ (xem api/urls.py)."""
from django.urls import path

from . import views

urlpatterns = [
    path('health/', views.health, name='system-health'),
    path('config/', views.config, name='system-config'),
]
