# Build png-demo lab target for Windows (MinGW gcc): cold EXE + native harness DLL.
param()
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Out = Join-Path $Root "targets\png-demo"
$Parse = Join-Path $Out "png_parse.c"
$Demo = Join-Path $Out "png_demo.c"
$Fuzz = Join-Path $Out "png_fuzz.c"
if (-not (Get-Command gcc -ErrorAction SilentlyContinue)) {
    Write-Host "[!] gcc not on PATH - run scripts\install-gcc.ps1" -ForegroundColor Yellow
    exit 1
}
New-Item -ItemType Directory -Force -Path $Out | Out-Null
$cflags = @("-O1", "-g", "-fno-omit-frame-pointer", "-Wall", "-Wextra", "-U_FORTIFY_SOURCE")
& gcc @cflags -o (Join-Path $Out "png-demo.exe") $Parse $Demo
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Copy-Item -Force (Join-Path $Out "png-demo.exe") (Join-Path $Out "app.exe")
& gcc @cflags -shared -o (Join-Path $Out "png-demo.dll") $Parse $Fuzz
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host "Built $Out\png-demo.exe (+ app.exe) and png-demo.dll"
exit 0
