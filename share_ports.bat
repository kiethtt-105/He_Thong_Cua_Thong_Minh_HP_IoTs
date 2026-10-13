@echo off
title VS Code DevTunnel Public Forwarder

echo [1/2] Kiem tra va dang nhap DevTunnel...
echo (Neu chua dang nhap, cua so trinh duyet se mo ra de xac thuc Bang tai khoản GitHub/Microsoft)
devtunnel user login

echo.
echo [2/2] Dang cong khai dong thoi Cong 8000 va Cong 8080...
echo.
devtunnel host -p 8000 -p 8080 --allow-anonymous

pause