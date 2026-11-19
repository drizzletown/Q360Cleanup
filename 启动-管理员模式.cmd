@echo off
chcp 65001>nul
cd /d "%~dp0"
set "PWSH=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if not exist "%PWSH%" (
  echo The system PowerShell executable cannot be found.
  echo Right-click Q360Cleanup_Windows_x64.exe and choose Run as administrator.
  pause
  exit /b 1
)
"%PWSH%" -NoProfile -NonInteractive -Command "Start-Process -FilePath '.\Q360Cleanup_Windows_x64.exe' -Verb RunAs"
if errorlevel 1 (
  echo Launch failed. Please right-click Q360Cleanup_Windows_x64.exe and choose Run as administrator.
  pause
)
