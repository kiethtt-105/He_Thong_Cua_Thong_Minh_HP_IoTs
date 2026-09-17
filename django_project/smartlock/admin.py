from django.contrib import admin
from .models import User, PendingRegistration


@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ('email', 'full_name', 'is_active', 'email_verified', 'is_staff', 'is_superuser', 'created_at')
    list_filter = ('is_active', 'email_verified', 'is_staff')
    search_fields = ('email', 'full_name', 'phone')
    ordering = ('-created_at',)


@admin.register(PendingRegistration)
class PendingRegistrationAdmin(admin.ModelAdmin):
    list_display = ('email', 'is_used', 'expires_at', 'created_at')
    search_fields = ('email',)
