from django.urls import path
from django.views.generic import RedirectView

from . import views

app_name = 'smartlock'

urlpatterns = [
    path('', RedirectView.as_view(url='/smartlock/login/', permanent=False), name='home'),
    path('register/', views.register_view, name='register'),
    path('verify-email/', views.verify_email_view, name='verify_email'),
    path('verify-email/resend/', views.resend_otp_view, name='resend_otp'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('dashboard/', views.dashboard_view, name='dashboard'),
]