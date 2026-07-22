# Build in-repo file-framed lab target for Windows (MinGW gcc).
param()
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Out = Join-Path $Root "targets\file-framed"
$Src = Join-Path $Out "file_framed.c"
if (-not (Get-Command gcc -ErrorAction SilentlyContinue)) {
    Write-Host "[!] gcc not on PATH — run scripts\install-gcc.ps1" -ForegroundColor Yellow
    exit 1
}
New-Item -ItemType Directory -Force -Path $Out | Out-Null
& gcc -O1 -g -fno-omit-frame-pointer -Wall -Wextra -U_FORTIFY_SOURCE -o (Join-Path $Out "file-framed.exe") $Src
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Copy-Item -Force (Join-Path $Out "file-framed.exe") (Join-Path $Out "app.exe")
Write-Host "Built $Out\file-framed.exe (+ app.exe)"
exit 0
