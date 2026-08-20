@echo off
setlocal
cd /d "%~dp0"
title ServerStatus
where py >nul 2>nul
if %errorlevel%==0 (
    py -3 server.py
    goto :done
)
where python >nul 2>nul
if %errorlevel%==0 (
    python server.py
    goto :done
)
echo.
echo ServerStatus needs Python 3.
echo Install Python 3, make sure it is added to PATH, then run start.bat again.
echo.
pause
:done
endlocal
