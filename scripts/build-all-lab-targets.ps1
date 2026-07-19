# Build all Randall lab target binaries.
# ScreamCrash needs gcc; if missing, that script warns and skips (exit 0).
# Other labs (vulnserver, etc.) always build; optional failures are summarized.
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)

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
    "build-screamcrash.ps1"
)

$skippedOptional = @()

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
