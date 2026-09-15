from django.urls import path

from . import views

app_name = 'accounts'

urlpatterns = [
    path('register/', views.register_view, name='register'),
    path('verify-otp/', views.verify_otp_view, name='verify_otp'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    
    # Trang dashboard mặc định
    path('', views.dashboard_view, name='dashboard'),
    
    # Các trang khác (BE tự làm sau)
    path('settings/', views.settings_view, name='settings'),
    path('devices/', views.devices_view, name='devices'),
    path('notifications/', views.notifications_view, name='notifications'),
]