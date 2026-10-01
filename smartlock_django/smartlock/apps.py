# smartlock/apps.py
from django.apps import AppConfig


class SmartlockConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'smartlock'

    def ready(self):
        from . import services
        services.register_signals()   # push FCM mỗi khi có Notification mới