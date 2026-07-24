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

function Add-MingwBinsToSessionPath {
    param([string]$RepoRoot)
    $bins = @(
        (Join-Path $RepoRoot "tools\mingw64\bin"),
        (Join-Path $env:LOCALAPPDATA "Randfuzz\mingw64\bin")
    )
    foreach ($bin in $bins) {
        if (-not (Test-Path (Join-Path $bin "gcc.exe"))) { continue }
        $norm = $bin.TrimEnd('\')
        $present = $false
        foreach ($part in ($env:Path -split ";")) {
            if ($part -and ($part.TrimEnd('\') -ieq $norm)) { $present = $true; break }
        }
        if (-not $present) { $env:Path = "$norm;$env:Path" }
    }
}

function Test-GccOnPath {
    Refresh-SessionPath
    Add-MingwBinsToSessionPath $Root
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
    "build-vulnsmb.ps1",
    "build-vulndrone.ps1",
    "build-vulnuas.ps1",
    "build-vulnturret.ps1",
    "build-vulnmqtt.ps1",
    "build-vulnrobot.ps1",
    "build-vulnrosbus.ps1",
    "build-vulnrobotio.ps1",
    "build-vulnai.ps1"
)

# Optional labs - warn and continue on skip/failure.
$Optional = @(
    "build-screamcrash.ps1",
    "build-reeldeck.ps1",
    "build-file-text.ps1",
    "build-file-framed.ps1"
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
            Write-Host "  Running install-gcc.ps1 via -File..."
            try {
                $psExe = Get-Command powershell.exe -ErrorAction SilentlyContinue
                if ($psExe -and $psExe.Source) {
                    & $psExe.Source -NoProfile -ExecutionPolicy Bypass -File $installScript
                } else {
                    & $installScript
                }
                if ($LASTEXITCODE -ne 0) {
                    Write-Host "[!] gcc install failed/skipped - Scream may be skipped. Use -SkipGcc to silence this." -ForegroundColor Yellow
                }
            } catch {
                Write-Host ("[!] gcc install error: {0} - continuing; Scream may be skipped." -f $_.Exception.Message) -ForegroundColor Yellow
            }
            Refresh-SessionPath
            Add-MingwBinsToSessionPath $Root
        }
    } else {
        Write-Host "gcc found on PATH - Scream native helpers can build." -ForegroundColor Green
    }
} else {
    Write-Host "Skipping gcc install (-SkipGcc). Scream will warn/skip if gcc is missing." -ForegroundColor Yellow
}

function Invoke-LabBuildScript {
    param([string]$ScriptName)
    $scriptPath = Join-Path $Root "scripts\$ScriptName"
    if (-not (Test-Path -LiteralPath $scriptPath)) {
        throw "Missing script: $scriptPath"
    }
    # Use -File so Windows PowerShell 5.1 honors UTF-8 BOM (avoids missing ] / quote parse errors).
    $psExe = Get-Command powershell.exe -ErrorAction SilentlyContinue
    if ($psExe -and $psExe.Source) {
        & $psExe.Source -NoProfile -ExecutionPolicy Bypass -File $scriptPath
        return $LASTEXITCODE
    }
    & $scriptPath
    return $LASTEXITCODE
}

foreach ($s in $Required) {
    Write-Host "`n=== $s ===" -ForegroundColor Cyan
    $code = Invoke-LabBuildScript -ScriptName $s
    if ($null -eq $code) { $code = 0 }
    if ($code -ne 0) {
        Write-Host "[x] $s failed (exit $code)" -ForegroundColor Red
        exit $code
    }
}

foreach ($s in $Optional) {
    Write-Host "`n=== $s (optional) ===" -ForegroundColor Cyan
    try {
        $code = Invoke-LabBuildScript -ScriptName $s
        if ($null -eq $code) { $code = 0 }
        if ($code -ne 0) {
            Write-Host "[!] $s failed (exit $code) - continuing without it." -ForegroundColor Yellow
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
