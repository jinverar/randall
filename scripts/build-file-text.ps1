# Build in-repo file-text lab target for Windows (MinGW gcc).
param()
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Out = Join-Path $Root "targets\file-text"
$Src = Join-Path $Out "file_text.c"
if (-not (Get-Command gcc -ErrorAction SilentlyContinue)) {
    Write-Host "[!] gcc not on PATH - run scripts\install-gcc.ps1" -ForegroundColor Yellow
    exit 1
}
New-Item -ItemType Directory -Force -Path $Out | Out-Null
& gcc -O1 -g -fno-omit-frame-pointer -Wall -Wextra -U_FORTIFY_SOURCE -o (Join-Path $Out "file-text.exe") $Src
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Copy-Item -Force (Join-Path $Out "file-text.exe") (Join-Path $Out "app.exe")
Write-Host "Built $Out\file-text.exe (+ app.exe)"
exit 0
