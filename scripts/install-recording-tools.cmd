@echo off
setlocal
REM Launcher for Windows: runs the UTF-8 script via -File (preserves encoding).
REM Prefer this over copying script text into a new file (that often breaks PS 5.1 parse).
set "SCRIPT=%~dp0install-recording-tools.ps1"
if not exist "%SCRIPT%" (
  echo [!] Missing %SCRIPT%
  exit /b 1
)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%" %*
exit /b %ERRORLEVEL%
