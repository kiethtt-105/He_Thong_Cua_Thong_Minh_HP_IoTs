#!/usr/bin/env python
import os
import sys


def main():
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'smart_lock.settings')
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Không import được Django. Đã cài đặt requirements.txt chưa? "
            "Nhớ activate virtualenv trước khi chạy."
        ) from exc
    execute_from_command_line(sys.argv)


if __name__ == '__main__':
    main()
