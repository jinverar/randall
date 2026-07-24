@echo off
setlocal
REM Launcher for Windows: runs the UTF-8 BOM script via -File (safe on PS 5.1).
set "SCRIPT=%~dp0install-lab-tools.ps1"
if not exist "%SCRIPT%" (
  echo [!] Missing %SCRIPT%
  exit /b 1
)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%" %*
exit /b %ERRORLEVEL%
