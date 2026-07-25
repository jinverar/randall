# WinAFL companion installer — external coverage-guided Windows fuzzer (NOT the Randfuzz engine).
# Clones googleprojectzero/winafl into tools/winafl and prints build steps.
#
# Examples:
#   powershell -ExecutionPolicy Bypass -File .\scripts\install-winafl.ps1
#   powershell -ExecutionPolicy Bypass -File .\scripts\install-winafl.ps1 -SkipClone
#   powershell -ExecutionPolicy Bypass -File .\scripts\install-winafl.ps1 -WhatIf
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$Force,
    [switch]$Skip,
    [switch]$SkipClone,
    [string]$RepoUrl = "https://github.com/googleprojectzero/winafl.git",
    [string]$Branch = "master"
)

$ErrorActionPreference = "Stop"

function Write-WaLog {
    param([string]$Message, [string]$Level = "Info")
    switch ($Level) {
        "Warn"  { Write-Host $Message -ForegroundColor Yellow }
        "Error" { Write-Host $Message -ForegroundColor Red }
        "Ok"    { Write-Host $Message -ForegroundColor Green }
        "Cyan"  { Write-Host $Message -ForegroundColor Cyan }
        default { Write-Host $Message }
    }
}

if ($Skip) {
    Write-WaLog "Skipped (-Skip)." "Warn"
    exit 0
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$dest = Join-Path $repoRoot "tools\winafl"
$dynamo = Join-Path $repoRoot "tools\dynamorio\bin64\drrun.exe"

Write-WaLog "WinAFL companion (external engine — Randfuzz does not embed WinAFL)" "Cyan"
Write-WaLog "Target: $dest"

if (-not $SkipClone) {
    if (Test-Path -LiteralPath (Join-Path $dest ".git")) {
        Write-WaLog "Existing clone — git pull" "Ok"
        if ($PSCmdlet.ShouldProcess($dest, "git pull")) {
            Push-Location $dest
            try { git pull --ff-only 2>&1 | ForEach-Object { Write-WaLog "  $_" } }
            finally { Pop-Location }
        }
    }
    elseif (Test-Path -LiteralPath $dest) {
        if ($Force -and $PSCmdlet.ShouldProcess($dest, "Remove and re-clone")) {
            Remove-Item -LiteralPath $dest -Recurse -Force
        }
        else {
            Write-WaLog "Folder exists without .git — use -Force to replace or -SkipClone" "Warn"
        }
    }

    if (-not (Test-Path -LiteralPath (Join-Path $dest ".git"))) {
        if ($PSCmdlet.ShouldProcess($dest, "git clone $RepoUrl")) {
            New-Item -ItemType Directory -Force -Path (Split-Path $dest) | Out-Null
            git clone --depth 1 --branch $Branch $RepoUrl $dest 2>&1 | ForEach-Object { Write-WaLog "  $_" }
        }
    }
}

if (Test-Path -LiteralPath $dynamo) {
    Write-WaLog "DynamoRIO ready: $dynamo" "Ok"
}
else {
    Write-WaLog "DynamoRIO not found — WinAFL needs drrun.exe:" "Warn"
    Write-WaLog "  powershell -ExecutionPolicy Bypass -File .\scripts\install-dynamorio.ps1" "Warn"
}

$afl = Join-Path $dest "afl-fuzz.exe"
$built = Join-Path $dest "build\Release\afl-fuzz.exe"
if ((Test-Path -LiteralPath $afl) -or (Test-Path -LiteralPath $built)) {
    Write-WaLog "WinAFL binary found — companion ready for external campaigns." "Ok"
    exit 0
}

Write-WaLog "" 
Write-WaLog "Build WinAFL (Visual Studio 2019+ required — not automated here):" "Cyan"
Write-WaLog "  1. Open tools\winafl\winafl.sln in Visual Studio"
Write-WaLog "  2. Build Release | x64"
Write-WaLog "  3. Confirm tools\winafl\afl-fuzz.exe (or build\Release\afl-fuzz.exe)"
Write-WaLog ""
Write-WaLog "Use WinAFL beside Randfuzz — see docs/RECORDING.md and docs/PERSISTENT.md" "Ok"
Write-WaLog "Doctor check: winafl (after build completes)" "Ok"
