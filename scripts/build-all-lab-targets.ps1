# Build all Randall lab target binaries.
# ScreamCrash needs gcc. By default, if gcc is missing, this script runs install-gcc.ps1
# (WinLibs zip primary; optional winget / Chocolatey). Use -SkipGcc to skip install + Scream.
#
# Examples:
#   powershell -ExecutionPolicy Bypass -File .\scripts\build-all-lab-targets.ps1
#   powershell -ExecutionPolicy Bypass -File .\scripts\build-all-lab-targets.ps1 -SkipGcc
#   powershell -ExecutionPolicy Bypass -File .\scripts\build-all-lab-targets.ps1 -InstallGcc
param(
    [switch]$InstallGcc,
    [switch]$SkipGcc
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)

function Refresh-SessionPath {
    $machine = [Environment]::GetEnvironmentVariable("Path", "Machine")
    $user = [Environment]::GetEnvironmentVariable("Path", "User")
    $env:Path = (@($machine, $user) | Where-Object { $_ }) -join ";"
}

function Test-GccOnPath {
    Refresh-SessionPath
    return [bool](Get-Command gcc -ErrorAction SilentlyContinue)
}

# Required labs - failure stops the build.
$Required = @(
    "build-vulnserver.ps1",
    "build-vulnhttp.ps1",
    "build-vulnftp.ps1",
    "build-vulnssh.ps1",
    "build-vulntftp.ps1",
    "build-vulnrpc.ps1",
    "build-vulnsmb.ps1"
)

# Optional labs - warn and continue on skip/failure.
$Optional = @(
    "build-screamcrash.ps1",
    "build-reeldeck.ps1"
)

$skippedOptional = @()

# Ensure gcc before optional Scream build (unless -SkipGcc).
if (-not $SkipGcc) {
    if (-not (Test-GccOnPath) -or $InstallGcc) {
        Write-Host "`n=== install-gcc.ps1 ===" -ForegroundColor Cyan
        $installScript = Join-Path $Root "scripts\install-gcc.ps1"
        if (-not (Test-Path $installScript)) {
            Write-Host "[!] install-gcc.ps1 missing - Scream may be skipped." -ForegroundColor Yellow
        } else {
            try {
                & $installScript
                if ($LASTEXITCODE -ne 0) {
                    Write-Host "[!] gcc install failed/skipped - Scream may be skipped. Use -SkipGcc to silence this." -ForegroundColor Yellow
                }
            } catch {
                Write-Host ("[!] gcc install error: {0} - continuing; Scream may be skipped." -f $_.Exception.Message) -ForegroundColor Yellow
            }
            Refresh-SessionPath
        }
    } else {
        Write-Host "gcc found on PATH - Scream native helpers can build." -ForegroundColor Green
    }
} else {
    Write-Host "Skipping gcc install (-SkipGcc). Scream will warn/skip if gcc is missing." -ForegroundColor Yellow
}

foreach ($s in $Required) {
    Write-Host "`n=== $s ===" -ForegroundColor Cyan
    & (Join-Path $Root "scripts\$s")
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[x] $s failed (exit $LASTEXITCODE)" -ForegroundColor Red
        exit $LASTEXITCODE
    }
}

foreach ($s in $Optional) {
    Write-Host "`n=== $s (optional) ===" -ForegroundColor Cyan
    try {
        & (Join-Path $Root "scripts\$s")
        if ($LASTEXITCODE -ne 0) {
            Write-Host "[!] $s failed (exit $LASTEXITCODE) - continuing without it." -ForegroundColor Yellow
            $skippedOptional += $s
        }
    } catch {
        Write-Host ("[!] {0} error: {1} - continuing without it." -f $s, $_.Exception.Message) -ForegroundColor Yellow
        $skippedOptional += $s
    }
}

Write-Host ""
if ($skippedOptional.Count -gt 0) {
    Write-Host ("Lab targets built (optional skipped/failed: {0})." -f ($skippedOptional -join ', ')) -ForegroundColor Yellow
} else {
    Write-Host "All lab targets built." -ForegroundColor Green
}
