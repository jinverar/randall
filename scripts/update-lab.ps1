# Pull latest Randall source and rebuild CLI, Server, and lab targets.
# Does NOT re-download DynamoRIO, Sysinternals, gcc, etc. unless -InstallTools.
#
# Examples:
#   powershell -ExecutionPolicy Bypass -File .\scripts\update-lab.ps1
#   powershell -ExecutionPolicy Bypass -File .\scripts\update-lab.ps1 -InstallTools
#   powershell -ExecutionPolicy Bypass -File .\scripts\update-lab.ps1 -SkipPull
#   powershell -ExecutionPolicy Bypass -File .\scripts\update-lab.ps1 -SkipLabTargets
[CmdletBinding()]
param(
    [switch]$InstallTools,
    [switch]$SkipPull,
    [switch]$SkipLabTargets,
    [switch]$SkipGcc
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Scripts = $PSScriptRoot

function Write-UpdateLog {
    param([string]$Message, [string]$Level = "Info")
    switch ($Level) {
        "Warn"  { Write-Host $Message -ForegroundColor Yellow }
        "Error" { Write-Host $Message -ForegroundColor Red }
        "Ok"    { Write-Host $Message -ForegroundColor Green }
        "Cyan"  { Write-Host $Message -ForegroundColor Cyan }
        default { Write-Host $Message }
    }
}

function Assert-GitRepo {
    $gitDir = Join-Path $Root ".git"
    if (-not (Test-Path $gitDir)) {
        Write-UpdateLog "[x] Not a git repository: $Root" "Error"
        Write-UpdateLog '    One-time setup - clone instead of a GitHub ZIP:' "Warn"
        Write-UpdateLog "      cd `$env:USERPROFILE\Projects" "Cyan"
        Write-UpdateLog "      git clone https://github.com/jinverar/randall.git" "Cyan"
        Write-UpdateLog "      cd randall" "Cyan"
        Write-UpdateLog "      powershell -ExecutionPolicy Bypass -File .\scripts\install-lab-tools.ps1" "Cyan"
        Write-UpdateLog "    If you already installed tools under Downloads\randall-main, copy tools\ into the clone once." "Warn"
        exit 1
    }
}

function Test-ServerMayBeRunning {
    $names = @("Randall.Server", "dotnet")
    foreach ($name in $names) {
        Get-Process -Name $name -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                $cmd = (Get-CimInstance Win32_Process -Filter "ProcessId = $($_.Id)" -ErrorAction SilentlyContinue).CommandLine
                if ($cmd -match "Randall\.Server") {
                    return $true
                }
            } catch { }
        }
    }
    return $false
}

Set-Location $Root
Write-UpdateLog "Randfuzz lab update (repo: $Root)" "Cyan"

Assert-GitRepo

if (Test-ServerMayBeRunning) {
    Write-UpdateLog ""
    Write-UpdateLog "[!] Randall.Server may be running. Stop it before rebuild if DLLs are locked." "Warn"
    Write-UpdateLog "    Ctrl+C in the server terminal, or close the window, then re-run this script." "Warn"
}

if (-not $SkipPull) {
    Write-UpdateLog ""
    Write-UpdateLog "======== git pull ========" "Cyan"
    & git -C $Root pull --ff-only
    if ($LASTEXITCODE -ne 0) {
        Write-UpdateLog "[x] git pull failed (exit $LASTEXITCODE). Resolve conflicts or fetch manually." "Error"
        exit $LASTEXITCODE
    }
} else {
    Write-UpdateLog ""
    Write-UpdateLog "======== git pull ======== (skipped)" "Warn"
}

Write-UpdateLog ""
Write-UpdateLog '======== dotnet build ========' "Cyan"
& dotnet build $Root\Randall.sln
if ($LASTEXITCODE -ne 0) {
    Write-UpdateLog "[x] dotnet build failed (exit $LASTEXITCODE)" "Error"
    exit $LASTEXITCODE
}

if (-not $SkipLabTargets) {
    Write-UpdateLog ""
    Write-UpdateLog "======== lab targets ========" "Cyan"
    $buildArgs = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", (Join-Path $Scripts "build-all-lab-targets.ps1"))
    if ($SkipGcc) { $buildArgs += "-SkipGcc" }
    & powershell.exe @buildArgs
    if ($LASTEXITCODE -ne 0) {
        Write-UpdateLog "[x] build-all-lab-targets failed (exit $LASTEXITCODE)" "Error"
        exit $LASTEXITCODE
    }
} else {
    Write-UpdateLog ""
    Write-UpdateLog "======== lab targets ======== (skipped)" "Warn"
}

if ($InstallTools) {
    Write-UpdateLog ""
    Write-UpdateLog "======== install-lab-tools (-InstallTools) ========" "Cyan"
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Scripts "install-lab-tools.ps1")
    if ($LASTEXITCODE -ne 0) {
        Write-UpdateLog "[!] install-lab-tools reported errors (exit $LASTEXITCODE) - see summary above." "Warn"
    }
} else {
    Write-UpdateLog ""
    Write-UpdateLog "Tool installs skipped (tools\ is preserved across pulls). Re-run with -InstallTools if needed." "Ok"
}

Write-UpdateLog ""
Write-UpdateLog "Update complete." "Ok"
Write-UpdateLog "Restart the web UI if it was running:" "Cyan"
Write-UpdateLog "  dotnet run --project src\Randall.Server --urls http://127.0.0.1:5000" "Cyan"
Write-UpdateLog "Optional preflight: dotnet run --project src\Randall.Cli -- doctor -c projects\vulnserver.yaml" "Cyan"
exit 0
