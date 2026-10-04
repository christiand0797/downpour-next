@echo off
setlocal

set "APP=%~dp0Downpour.Desktop.exe"
if not exist "%APP%" (
    echo Downpour Next has not been built or the portable archive was not fully extracted.
    echo Expected executable: "%APP%"
    echo Download and extract the complete Windows x64 package, then run this file again.
    pause
    exit /b 1
)

start "" "%APP%"
exit /b 0
