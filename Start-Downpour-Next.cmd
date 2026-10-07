@echo off
setlocal
cd /d "%~dp0"
if not exist "%~dp0Downpour.Desktop.exe" (
    echo Downpour Next has not been built or the portable archive was not fully extracted.
    echo Expected executable: "%~dp0Downpour.Desktop.exe"
    echo Download and extract the complete Windows x64 package, then run this file again.
    pause
    exit /b 1
)

if exist "%~dp0service\Downpour.Service.exe" (
    start "Downpour Service (CLI Monitor)" "%~dp0service\Downpour.Service.exe"
)

start "" "%~dp0Downpour.Desktop.exe"
