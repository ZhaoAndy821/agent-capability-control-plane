@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\doctor.ps1" %*
exit /b %ERRORLEVEL%
