@echo off
setlocal
cd /d "%~dp0"

set "EXE_PATH="
if exist "%~dp0Downpour.Desktop.exe" set "EXE_PATH=%~dp0Downpour.Desktop.exe"
if not defined EXE_PATH if exist "%~dp0DownpourNext-Portable\Downpour.Desktop.exe" set "EXE_PATH=%~dp0DownpourNext-Portable\Downpour.Desktop.exe"
if not defined EXE_PATH if exist "%~dp0src\Downpour.Desktop\bin\Debug\net10.0-windows10.0.19041.0\win-x64\Downpour.Desktop.exe" set "EXE_PATH=%~dp0src\Downpour.Desktop\bin\Debug\net10.0-windows10.0.19041.0\win-x64\Downpour.Desktop.exe"

if not defined EXE_PATH (
    echo Downpour Next has not been built or the portable archive was not fully extracted.
    echo Expected executable: "%~dp0Downpour.Desktop.exe"
    echo Download and extract the complete Windows x64 package, or run dotnet build, then run this file again.
    pause
    exit /b 1
)

set "SVC_PATH="
if exist "%~dp0service\Downpour.Service.exe" set "SVC_PATH=%~dp0service\Downpour.Service.exe"
if not defined SVC_PATH if exist "%~dp0src\Downpour.Service\bin\Debug\net10.0-windows10.0.19041.0\Downpour.Service.exe" set "SVC_PATH=%~dp0src\Downpour.Service\bin\Debug\net10.0-windows10.0.19041.0\Downpour.Service.exe"

if defined SVC_PATH (
    start "Downpour Service (CLI Monitor)" "%SVC_PATH%"
)

start "" "%EXE_PATH%"
