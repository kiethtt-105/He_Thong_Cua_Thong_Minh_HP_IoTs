@echo off
title Django SmartLock Server Launcher

echo [1/3] Chuyen den thu muc goc du an...
cd /d D:\.GitHub\He_Thong_Cua_Thong_Minh_HP_IoTs

echo [2/3] Kich hoat moi truong ao (.venv)...
call .venv\Scripts\activate.bat

echo [3/3] Chuyen den thu muc smartlock_django va khoi chay Server...
cd smartlock_django
python manage.py runserver

pause