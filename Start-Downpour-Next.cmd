@echo off
setlocal
cd /d "%~dp0"
if not exist "%~dp0service\Downpour.Service.exe" (
    echo Downpour Next service is missing. Check that the full portable ZIP was extracted.
    pause
    exit /b 1
)
if not exist "%~dp0Downpour.Desktop.exe" (
    echo Downpour Next desktop app is missing. Check that the full portable ZIP was extracted.
    pause
    exit /b 1
)
start "Downpour Next read-only service" /D "%~dp0service" "%~dp0service\Downpour.Service.exe"
timeout /t 2 /nobreak >nul
start "" "%~dp0Downpour.Desktop.exe"
