cd /d "D:\.GitHub\Khoa_Cua_Thong_Minh\backend\templates"

echo @echo off > account.bat
echo. >> account.bat
echo :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::: >> account.bat
echo :         TẠO THƯ MỤC account + 20 FILE HTML TỰ ĐỘNG         >> account.bat
echo :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::: >> account.bat
echo. >> account.bat
echo echo Đang tạo thư mục account... >> account.bat
echo mkdir -p account\base account\devices account\nfc account\permissions account\share account\support account\audit account\settings >> account.bat
echo echo. >> account.bat
echo echo Tạo các file HTML... >> account.bat
echo for %%f in ( >> account.bat
echo     base\dashboard.html >> account.bat
echo     base\login.html >> account.bat
echo     base\register.html >> account.bat
echo     base\verify_email.html >> account.bat
echo     base\reset_password.html >> account.bat
echo     base\profile.html >> account.bat
echo     base\notifications.html >> account.bat
echo     devices\list.html >> account.bat
echo     devices\detail.html >> account.bat
echo     nfc\tags.html >> account.bat
echo     nfc\reader.html >> account.bat
echo     permissions\manage.html >> account.bat
echo     share\codes.html >> account.bat
echo     share\request.html >> account.bat
echo     support\requests.html >> account.bat
echo     support\request_detail.html >> account.bat
echo     audit\logs.html >> account.bat
echo     settings\system.html >> account.bat
echo ) do ( >> account.bat
echo     echo > "templates\account\%%f" >> account.bat
echo     echo ^<!DOCTYPE html^> >> "templates\account\%%f" >> account.bat
echo     echo ^<html lang="vi"^> >> "templates\account\%%f" >> account.bat
echo     echo ^<head^> >> "templates\account\%%f" >> account.bat
echo     echo ^<meta charset="UTF-8"^> >> "templates\account\%%f" >> account.bat
echo     echo ^<title^>%%~nf - Smart Lock^</title^> >> "templates\account\%%f" >> account.bat
echo     echo ^</head^> >> "templates\account\%%f" >> account.bat
echo     echo ^<body^> >> "templates\account\%%f" >> account.bat
echo     echo ^<h1^>%%~nf^</h1^> >> "templates\account\%%f" >> account.bat
echo     echo ^</body^> >> "templates\account\%%f" >> account.bat
echo     echo ^</html^> >> "templates\account\%%f" >> account.bat
echo ) >> account.bat
echo echo. >> account.bat
echo echo ✅ ĐÃ TẠO XONG 20 FILE HTML TRONG account\ >> account.bat
echo echo Đường dẫn: templates\account\ >> account.bat
echo echo =============================================== >> account.bat
echo echo Để tạo lại, chỉ cần mở CMD tại thư mục templates và chạy: >> account.bat
echo echo   account.bat >> account.bat
echo pause >> account.bat
echo. >> account.bat

echo Đã tạo xong file account.bat!
echo Bây giờ chỉ cần double-click vào account.bat là tự động tạo hết.