# Umbrella lab installer: gcc + DynamoRIO + recording tools + debuggers (WinDbg / cdb).
# Each step is optional via -Skip* switches. Uses ExecutionPolicy Bypass-friendly -File invocation.
#
# Examples:
#   powershell -ExecutionPolicy Bypass -File .\scripts\install-lab-tools.ps1
#   powershell -ExecutionPolicy Bypass -File .\scripts\install-lab-tools.ps1 -SkipDynamoRio
#   powershell -ExecutionPolicy Bypass -File .\scripts\install-lab-tools.ps1 -SkipDebuggers
#   powershell -ExecutionPolicy Bypass -File .\scripts\install-lab-tools.ps1 -SysinternalsOnly
#   powershell -ExecutionPolicy Bypass -File .\scripts\install-lab-tools.ps1 -SkipGcc -SkipDynamoRio -SkipFrida
[CmdletBinding()]
param(
    [switch]$Force,
    [switch]$SkipGcc,
    [switch]$SkipDynamoRio,
    [switch]$SkipRecordingTools,
    [switch]$SkipDebuggers,
    [switch]$SysinternalsOnly,
    [switch]$IncludeFrida,
    [switch]$SkipFrida,
    [switch]$SkipApiMonitor,
    [switch]$SkipPython
)

$ErrorActionPreference = "Stop"
$Scripts = $PSScriptRoot
$failed = [System.Collections.Generic.List[string]]::new()

function Get-WindowsPowerShellExe {
    # Prefer Windows PowerShell 5.1 for -File + UTF-8 BOM scripts on Windows.
    # Fall back to current host (pwsh) on non-Windows / when powershell.exe is absent.
    $cmd = Get-Command powershell.exe -ErrorAction SilentlyContinue
    if ($cmd -and $cmd.Source) { return $cmd.Source }
    if ($PSHOME) {
        $candidate = Join-Path $PSHOME "powershell.exe"
        if (Test-Path -LiteralPath $candidate) { return $candidate }
        $pwsh = Join-Path $PSHOME "pwsh"
        if (Test-Path -LiteralPath $pwsh) { return $pwsh }
        $pwshExe = Join-Path $PSHOME "pwsh.exe"
        if (Test-Path -LiteralPath $pwshExe) { return $pwshExe }
    }
    return $null
}

function Invoke-Step {
    param(
        [string]$Name,
        [string]$ScriptPath,
        [string[]]$ScriptArgs = @()
    )
    Write-Host ""
    Write-Host "======== $Name ========" -ForegroundColor Cyan
    if (-not (Test-Path $ScriptPath)) {
        Write-Host "[!] Missing script: $ScriptPath" -ForegroundColor Red
        $failed.Add($Name) | Out-Null
        return
    }
    $psExe = Get-WindowsPowerShellExe
    $prev = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    if ($psExe) {
        # -File + UTF-8 BOM is required so WinPS 5.1 does not misread ASCII punctuation.
        & $psExe -NoProfile -ExecutionPolicy Bypass -File $ScriptPath @ScriptArgs
        $code = $LASTEXITCODE
    } else {
        & $ScriptPath @ScriptArgs
        $code = $LASTEXITCODE
    }
    $ErrorActionPreference = $prev
    if ($null -eq $code) { $code = 0 }
    if ($code -ne 0) {
        Write-Host "[!] $Name exited $code (continuing)" -ForegroundColor Yellow
        $failed.Add("$Name (exit $code)") | Out-Null
    }
    return $code
}

function Add-MingwBinsToSessionPath {
    $repoRoot = Split-Path $Scripts -Parent
    $bins = @(
        (Join-Path $repoRoot "tools\mingw64\bin"),
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

Write-Host "Randfuzz lab tools umbrella installer"
Write-Host "  Scripts: $Scripts"

if (-not $SkipGcc -and -not $SysinternalsOnly) {
    $gccArgs = @()
    if ($Force) { $gccArgs += "-Force" }
    Invoke-Step -Name "gcc / MinGW" -ScriptPath (Join-Path $Scripts "install-gcc.ps1") -ScriptArgs $gccArgs
    Add-MingwBinsToSessionPath
} else {
    Write-Host ""
    Write-Host "======== gcc / MinGW ======== (skipped)" -ForegroundColor DarkGray
}

if (-not $SkipDynamoRio -and -not $SysinternalsOnly) {
    $drArgs = @()
    if ($Force) { $drArgs += "-Force" }
    Invoke-Step -Name "DynamoRIO" -ScriptPath (Join-Path $Scripts "install-dynamorio.ps1") -ScriptArgs $drArgs
} else {
    Write-Host ""
    Write-Host "======== DynamoRIO ======== (skipped)" -ForegroundColor DarkGray
}

if (-not $SkipRecordingTools) {
    $recArgs = @()
    if ($Force) { $recArgs += "-Force" }
    if ($SysinternalsOnly) { $recArgs += "-SysinternalsOnly" }
    if ($IncludeFrida) { $recArgs += "-IncludeFrida" }
    if ($SkipFrida) { $recArgs += "-SkipFrida" }
    if ($SkipApiMonitor) { $recArgs += "-SkipApiMonitor" }
    if ($SkipPython) { $recArgs += "-SkipPython" }
    Invoke-Step -Name "Recording tools" -ScriptPath (Join-Path $Scripts "install-recording-tools.ps1") -ScriptArgs $recArgs
} else {
    Write-Host ""
    Write-Host "======== Recording tools ======== (skipped)" -ForegroundColor DarkGray
}

if (-not $SkipDebuggers -and -not $SysinternalsOnly) {
    $dbgArgs = @()
    if ($Force) { $dbgArgs += "-Force" }
    Invoke-Step -Name "Debuggers (WinDbg / cdb)" -ScriptPath (Join-Path $Scripts "install-debuggers.ps1") -ScriptArgs $dbgArgs
} else {
    Write-Host ""
    Write-Host "======== Debuggers ======== (skipped)" -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "========== Lab tools summary =========="
if ($failed.Count -eq 0) {
    Write-Host "All requested steps finished (check per-step summaries above)." -ForegroundColor Green
} else {
    Write-Host "Some steps reported errors:" -ForegroundColor Yellow
    foreach ($f in $failed) { Write-Host "  ! $f" -ForegroundColor Yellow }
}
Write-Host "Doctor: dotnet run --project src\Randall.Cli -- doctor -c projects\vulnserver.yaml"
if ($failed.Count -gt 0) { exit 1 }
exit 0
