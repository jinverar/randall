# Build ReelDeck lab media target on Windows (MinGW gcc).
# Counterpart to scripts/build-reeldeck.sh - same C source, .exe for Windows fuzz profiles.
#
# Examples:
#   powershell -ExecutionPolicy Bypass -File .\scripts\build-reeldeck.ps1
#   $env:ASAN=1; powershell -ExecutionPolicy Bypass -File .\scripts\build-reeldeck.ps1
param(
    [switch]$Asan
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Out = Join-Path $Root "targets\reeldeck"
$Src = Join-Path $Out "reeldeck.c"
$Exe = Join-Path $Out "reeldeck.exe"
$Bare = Join-Path $Out "reeldeck"

if (-not (Test-Path $Src)) {
    Write-Error "Missing $Src"
    exit 1
}

$gcc = Get-Command gcc -ErrorAction SilentlyContinue
if (-not $gcc) {
    Write-Host "[!] gcc not on PATH - run scripts\install-gcc.ps1 (or build-all-lab-targets.ps1)." -ForegroundColor Yellow
    exit 1
}

New-Item -ItemType Directory -Force -Path $Out | Out-Null
$cflags = @("-O1", "-g", "-fno-omit-frame-pointer", "-Wall", "-Wextra", "-U_FORTIFY_SOURCE")
if ($Asan -or $env:ASAN -eq "1") {
    $cflags += "-fsanitize=address"
    Write-Host "Building ReelDeck with AddressSanitizer"
} else {
    Write-Host "Building plain ReelDeck (pass -Asan or ASAN=1 for AddressSanitizer)"
}

& gcc @cflags -o $Exe $Src
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# ExecutableResolver also accepts a bare name on Windows via .exe sibling.
Copy-Item -Force $Exe $Bare -ErrorAction SilentlyContinue
Write-Host "Built $Exe"
exit 0
