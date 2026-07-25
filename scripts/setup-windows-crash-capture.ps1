# Opt-in Windows crash capture: AeDebug post-mortem, WER DontShowUI, optional LocalDumps.
# Randfuzz Scream remains the preferred in-fuzz path — use this for system-wide fallback.
#
# Examples:
#   powershell -ExecutionPolicy Bypass -File .\scripts\setup-windows-crash-capture.ps1 -WhatIf
#   powershell -ExecutionPolicy Bypass -File .\scripts\setup-windows-crash-capture.ps1
#   powershell -ExecutionPolicy Bypass -File .\scripts\setup-windows-crash-capture.ps1 -LocalDumps -Force
#   powershell -ExecutionPolicy Bypass -File .\scripts\setup-windows-crash-capture.ps1 -Revert
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$Force,
    [switch]$SkipAeDebug,
    [switch]$SkipDontShowUi,
    [switch]$LocalDumps,
    [string]$LocalDumpFolder = "",
    [switch]$Revert,
    [switch]$WhatIf
)

$ErrorActionPreference = "Stop"

function Test-IsElevated {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = [Security.Principal.WindowsPrincipal]::new($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Write-SetupLog {
    param([string]$Message, [string]$Level = "Info")
    switch ($Level) {
        "Warn"  { Write-Host $Message -ForegroundColor Yellow }
        "Error" { Write-Host $Message -ForegroundColor Red }
        "Ok"    { Write-Host $Message -ForegroundColor Green }
        "Cyan"  { Write-Host $Message -ForegroundColor Cyan }
        default { Write-Host $Message }
    }
}

function Find-ClassicWinDbg {
    $candidates = @(
        $env:WINDBG_PATH,
        "${env:ProgramFiles(x86)}\Windows Kits\10\Debuggers\x64\windbg.exe",
        "$env:ProgramFiles\Windows Kits\10\Debuggers\x64\windbg.exe",
        "C:\Debuggers\windbg.exe"
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }
    return $candidates | Select-Object -First 1
}

function Get-RepoRoot {
    $dir = Split-Path -Parent $PSScriptRoot
    if (Test-Path -LiteralPath (Join-Path $dir "Randall.sln")) { return $dir }
    return $dir
}

function Invoke-RegistryAction {
    param(
        [string]$Path,
        [string]$Name,
        [object]$Value,
        [Microsoft.Win32.RegistryValueKind]$Kind = [Microsoft.Win32.RegistryValueKind]::String,
        [string]$Description
    )
    if ($WhatIf) {
        Write-SetupLog "[WhatIf] Would set HKLM:\$Path\$Name = $Value ($Description)" "Cyan"
        return
    }
    if ($PSCmdlet.ShouldProcess("HKLM:\$Path", "Set $Name = $Value ($Description)")) {
        if (-not (Test-Path -LiteralPath "HKLM:\$Path")) {
            New-Item -Path "HKLM:\$Path" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\$Path" -Name $Name -Value $Value -Type $Kind -Force
        Write-SetupLog "  Set HKLM:\$Path\$Name" "Ok"
    }
}

function Remove-RegistryValueSafe {
    param([string]$Path, [string]$Name)
    if (-not (Test-Path -LiteralPath "HKLM:\$Path")) { return }
    if ($WhatIf) {
        Write-SetupLog "[WhatIf] Would remove HKLM:\$Path\$Name" "Cyan"
        return
    }
    if ($PSCmdlet.ShouldProcess("HKLM:\$Path\$Name", "Remove")) {
        Remove-ItemProperty -Path "HKLM:\$Path" -Name $Name -ErrorAction SilentlyContinue
        Write-SetupLog "  Removed HKLM:\$Path\$Name" "Ok"
    }
}

if (-not (Test-IsElevated)) {
    Write-SetupLog "Administrator privileges required for AeDebug / WER registry changes." "Error"
    Write-SetupLog "Re-run from an elevated PowerShell, or use -WhatIf to preview." "Warn"
    exit 1
}

$repo = Get-RepoRoot
if ([string]::IsNullOrWhiteSpace($LocalDumpFolder)) {
    $LocalDumpFolder = Join-Path $repo "data\wer-dumps"
}

Write-SetupLog "Randfuzz Windows crash capture setup" "Cyan"
Write-SetupLog "Repo: $repo"
Write-SetupLog "Note: Randfuzz Scream (debuggerMode wait) is preferred during fuzz campaigns."
Write-SetupLog "      AeDebug is a system-wide fallback for crashes outside Randfuzz."

if ($Revert) {
    Write-SetupLog "Reverting AeDebug / DontShowUI / LocalDumps…" "Warn"
    Remove-RegistryValueSafe "SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug" "Debugger"
    Remove-RegistryValueSafe "SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug" "Auto"
    Remove-RegistryValueSafe "SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug" "Debugger"
    Remove-RegistryValueSafe "SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug" "Auto"
    Remove-RegistryValueSafe "SOFTWARE\Microsoft\Windows\Windows Error Reporting" "DontShowUI"
    Remove-RegistryValueSafe "SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps" "DumpFolder"
    Remove-RegistryValueSafe "SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps" "DumpType"
    Remove-RegistryValueSafe "SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps" "DumpCount"
    Write-SetupLog "Revert complete (defaults restored on next crash)." "Ok"
    exit 0
}

if (-not $SkipDontShowUi) {
    Write-SetupLog "WER: suppress crash UI (DontShowUI=1)…"
    Invoke-RegistryAction `
        -Path "SOFTWARE\Microsoft\Windows\Windows Error Reporting" `
        -Name "DontShowUI" `
        -Value 1 `
        -Kind DWord `
        -Description "hide WER dialogs during fuzz"
}

if ($LocalDumps) {
    Write-SetupLog "WER LocalDumps → $LocalDumpFolder (full dumps, max 10)…"
    if (-not $WhatIf) {
        New-Item -ItemType Directory -Force -Path $LocalDumpFolder | Out-Null
    }
    Invoke-RegistryAction `
        -Path "SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps" `
        -Name "DumpFolder" `
        -Value $LocalDumpFolder `
        -Description "WER dump folder"
    Invoke-RegistryAction `
        -Path "SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps" `
        -Name "DumpType" `
        -Value 2 `
        -Kind DWord `
        -Description "2 = full dump"
    Invoke-RegistryAction `
        -Path "SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps" `
        -Name "DumpCount" `
        -Value 10 `
        -Kind DWord `
        -Description "rotate up to 10 dumps"
}

if (-not $SkipAeDebug) {
    $windbg = Find-ClassicWinDbg
    if (-not $windbg) {
        Write-SetupLog "Classic windbg.exe not found — run scripts/install-debuggers.ps1 first." "Warn"
        Write-SetupLog "Manual: https://aka.ms/windbg/download (SDK Debugging Tools for Windows)" "Warn"
    }
    else {
        Write-SetupLog "AeDebug: registering post-mortem debugger via windbg -I…"
        if ($WhatIf) {
            Write-SetupLog "[WhatIf] Would run: `"$windbg`" -I" "Cyan"
        }
        elseif ($PSCmdlet.ShouldProcess("AeDebug", "windbg -I using $windbg")) {
            & $windbg -I 2>&1 | ForEach-Object { Write-SetupLog "  $_" }
            Write-SetupLog "Registered AeDebug (64-bit). WinDbg Preview does not support -I — classic windbg/cdb only." "Ok"
            Write-SetupLog "32-bit WOW64 AeDebug (Wow6432Node) may need separate registration on mixed targets." "Warn"
        }
    }
}

Write-SetupLog "" 
Write-SetupLog "Done. Verify with: randall doctor -c projects\vulnserver.yaml" "Ok"
Write-SetupLog "During fuzz: prefer fuzz.debuggerMode: wait (Scream) — see docs/CRASH_ANALYSIS.md" "Ok"
