# Build all Randall lab target binaries
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Scripts = @(
    "build-vulnserver.ps1",
    "build-vulnhttp.ps1",
    "build-vulnftp.ps1",
    "build-vulnssh.ps1",
    "build-vulntftp.ps1",
    "build-vulnrpc.ps1",
    "build-vulnsmb.ps1",
    "build-screamcrash.ps1"
)
foreach ($s in $Scripts) {
    Write-Host "`n=== $s ===" -ForegroundColor Cyan
    & (Join-Path $Root "scripts\$s")
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
Write-Host "`nAll lab targets built." -ForegroundColor Green
