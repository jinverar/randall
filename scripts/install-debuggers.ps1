# Install WinDbg Preview + Debugging Tools for Windows (classic windbg / cdb).
# Idempotent. Soft-fails with manual links. Matches Randall.Infrastructure.DebuggerTools discovery.
#
# Examples:
#   powershell -ExecutionPolicy Bypass -File .\scripts\install-debuggers.ps1
#   powershell -ExecutionPolicy Bypass -File .\scripts\install-debuggers.ps1 -SkipWinDbgPreview
#   powershell -ExecutionPolicy Bypass -File .\scripts\install-debuggers.ps1 -SkipClassicDebuggers
#   powershell -ExecutionPolicy Bypass -File .\scripts\install-debuggers.ps1 -Force
#
# Packages / sources:
#   WinDbg Preview:  winget Microsoft.WinDbg  (MSIX; may need Store / interactive on some VMs)
#   Classic + cdb:   Windows SDK winsdksetup.exe /features OptionId.WindowsDesktopDebuggers
#                    (winget Microsoft.WindowsSDK.* is full SDK - we prefer feature-only install)
#
# Manual:
#   https://aka.ms/windbg/download
#   Store: ms-windows-store://pdp/?ProductId=9PGJGD53TN86
#   SDK (pick "Debugging Tools for Windows"):
#     https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/
[CmdletBinding()]
param(
    [switch]$Force,
    [switch]$Skip,
    [switch]$SkipWinDbgPreview,
    [switch]$SkipClassicDebuggers,
    # Override SDK bootstrapper URL (default: winget Microsoft.WindowsSDK.10.0.26100 installer).
    [string]$SdkSetupUrl = "https://download.microsoft.com/download/f4b30f2a-4fc3-430e-9b03-c842b5f5f9f1/KIT_BUNDLE_WINDOWSSDK_MEDIACREATION/winsdksetup.exe"
)

$ErrorActionPreference = "Stop"
$script:Results = [System.Collections.Generic.List[object]]::new()

function Write-DbgLog {
    param([string]$Message, [string]$Level = "Info")
    switch ($Level) {
        "Warn"  { Write-Host $Message -ForegroundColor Yellow }
        "Error" { Write-Host $Message -ForegroundColor Red }
        "Ok"    { Write-Host $Message -ForegroundColor Green }
        "Cyan"  { Write-Host $Message -ForegroundColor Cyan }
        default { Write-Host $Message }
    }
}

function Add-Result {
    param(
        [string]$Name,
        [ValidateSet("installed", "skipped", "failed", "ok", "note")]
        [string]$Status,
        [string]$Detail = ""
    )
    $script:Results.Add([pscustomobject]@{ Name = $Name; Status = $Status; Detail = $Detail }) | Out-Null
}

function Refresh-SessionPath {
    $machine = [Environment]::GetEnvironmentVariable("Path", "Machine")
    $user = [Environment]::GetEnvironmentVariable("Path", "User")
    $env:Path = (@($machine, $user) | Where-Object { $_ }) -join ";"
}

function Test-IsElevated {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = [Security.Principal.WindowsPrincipal]::new($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Ensure-UserPathEntry {
    param([string]$Dir)
    if (-not $Dir -or -not (Test-Path -LiteralPath $Dir)) { return }
    $user = [Environment]::GetEnvironmentVariable("Path", "User")
    if ([string]::IsNullOrWhiteSpace($user)) { $user = "" }
    $parts = $user.Split(';', [System.StringSplitOptions]::RemoveEmptyEntries) |
        ForEach-Object { $_.TrimEnd('\') }
    $norm = $Dir.TrimEnd('\')
    foreach ($p in $parts) {
        if ($p.Equals($norm, [StringComparison]::OrdinalIgnoreCase)) { return }
    }
    $new = if ([string]::IsNullOrWhiteSpace($user)) { $norm } else { "$user;$norm" }
    [Environment]::SetEnvironmentVariable("Path", $new, "User")
    Write-DbgLog "  Added to user PATH: $norm" "Ok"
}

function Find-WinDbgPreview {
    $cmdX = Get-Command WinDbgX.exe -ErrorAction SilentlyContinue
    $cmdShell = Get-Command DbgX.Shell.exe -ErrorAction SilentlyContinue
    $candidates = @(
        $(if ($cmdX) { $cmdX.Source }),
        $(if ($cmdShell) { $cmdShell.Source }),
        $env:WINDBGX_PATH,
        (Join-Path $env:LOCALAPPDATA "Microsoft\WindowsApps\WinDbgX.exe"),
        (Join-Path $env:LOCALAPPDATA "Microsoft\WinDbg\DbgX.Shell.exe")
    )
    foreach ($c in $candidates) {
        if ($c -and (Test-Path -LiteralPath $c)) { return $c }
    }
    $apps = "C:\Program Files\WindowsApps"
    if (Test-Path $apps) {
        try {
            foreach ($dir in Get-ChildItem -Path $apps -Directory -Filter "Microsoft.WinDbg_*" -ErrorAction SilentlyContinue) {
                $shell = Join-Path $dir.FullName "DbgX.Shell.exe"
                if (Test-Path -LiteralPath $shell) { return $shell }
            }
        } catch { }
    }
    return $null
}

function Find-KitDebugger {
    param([string]$Exe)
    $roots = @(
        "C:\Program Files\Windows Kits\10\Debuggers\x64",
        "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64",
        "C:\Program Files\Windows Kits\10\Debuggers\x86",
        "C:\Program Files (x86)\Windows Kits\10\Debuggers\x86",
        "C:\Debuggers",
        "C:\tools\debugging"
    )
    foreach ($r in $roots) {
        $p = Join-Path $r $Exe
        if (Test-Path -LiteralPath $p) { return $p }
    }
    foreach ($kits in @(
        "C:\Program Files\Windows Kits\10\Debuggers",
        "C:\Program Files (x86)\Windows Kits\10\Debuggers"
    )) {
        if (-not (Test-Path $kits)) { continue }
        foreach ($dir in Get-ChildItem -Path $kits -Directory -ErrorAction SilentlyContinue) {
            $p = Join-Path $dir.FullName $Exe
            if (Test-Path -LiteralPath $p) { return $p }
        }
    }
    $cmd = Get-Command $Exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    if ($Exe -eq "windbg.exe" -and $env:WINDBG_PATH -and (Test-Path -LiteralPath $env:WINDBG_PATH)) {
        return $env:WINDBG_PATH
    }
    if ($Exe -eq "cdb.exe" -and $env:CDB_PATH -and (Test-Path -LiteralPath $env:CDB_PATH)) {
        return $env:CDB_PATH
    }
    return $null
}

function Find-ClassicWinDbg { Find-KitDebugger "windbg.exe" }
function Find-Cdb { Find-KitDebugger "cdb.exe" }

function Test-WingetAvailable {
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if (-not $winget) { return $null }
    try {
        $prev = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        $verOut = & winget --version 2>&1
        $ErrorActionPreference = $prev
        if ($LASTEXITCODE -ne 0 -and -not ($verOut -match '\d+\.\d+')) { return $null }
        return $winget
    } catch {
        return $null
    }
}

function Invoke-WingetInstall {
    param([string]$PackageId, [string]$Name)
    $winget = Test-WingetAvailable
    if (-not $winget) {
        Write-DbgLog "  winget not available." "Warn"
        return $false
    }

    Write-DbgLog ("  winget install {0} ({1})..." -f $Name, $PackageId) "Cyan"
    $log = Join-Path $env:TEMP ("randall-winget-{0}.log" -f ($PackageId -replace '[^\w\.-]', '_'))
    $argSets = @(
        @("install", "--id", $PackageId, "-e", "--accept-package-agreements", "--accept-source-agreements", "--disable-interactivity"),
        @("install", "--id", $PackageId, "-e", "--accept-package-agreements", "--accept-source-agreements")
    )
    foreach ($wingetArgs in $argSets) {
        $prev = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        try {
            & winget @wingetArgs 2>&1 | Tee-Object -FilePath $log | ForEach-Object { Write-Host $_ }
            $code = $LASTEXITCODE
        } catch {
            $code = -1
        } finally {
            $ErrorActionPreference = $prev
        }
        # 0 = success, -1978335189 (0x8A15002B) = already installed
        if ($code -eq 0 -or $code -eq -1978335189) {
            Refresh-SessionPath
            return $true
        }
        Write-Verbose ("winget exit {0}; trying next arg set..." -f $code)
    }
    Write-DbgLog ("  winget failed for {0}. Log: {1}" -f $PackageId, $log) "Warn"
    return $false
}

function Download-File {
    param([string]$Uri, [string]$OutFile)
    $dir = Split-Path $OutFile -Parent
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
    }
    $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
    if ($curl) {
        Write-Host "  Downloading with curl.exe..."
        $prev = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        & curl.exe -L --fail --retry 5 --retry-delay 2 --retry-all-errors -C - --progress-bar -o $OutFile $Uri
        $code = $LASTEXITCODE
        $ErrorActionPreference = $prev
        if ($code -ne 0) { throw "curl.exe exit $code" }
        return
    }
    Write-Host "  Downloading with Invoke-WebRequest..."
    Invoke-WebRequest -Uri $Uri -OutFile $OutFile -UseBasicParsing
}

function Install-ClassicDebuggersViaSdkSetup {
    Write-DbgLog "Installing Debugging Tools for Windows (SDK feature OptionId.WindowsDesktopDebuggers)..." "Cyan"
    if (-not (Test-IsElevated)) {
        Write-DbgLog "  Classic debuggers need an elevated (Admin) PowerShell." "Warn"
        Write-DbgLog "  Re-run elevated, or install manually (see summary links)." "Warn"
        return $false
    }

    $setup = Join-Path $env:TEMP "randall-winsdksetup.exe"
    try {
        if ($Force -or -not (Test-Path -LiteralPath $setup)) {
            Download-File -Uri $SdkSetupUrl -OutFile $setup
        } else {
            Write-Host "  Reusing cached: $setup"
        }
    } catch {
        Write-DbgLog ("  Download failed: {0}" -f $_.Exception.Message) "Warn"
        return $false
    }

    Write-Host "  Running winsdksetup (Debugging Tools only; may take several minutes)..."
    $prev = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $p = Start-Process -FilePath $setup -ArgumentList @(
        "/features", "OptionId.WindowsDesktopDebuggers",
        "/quiet", "/norestart"
    ) -Wait -PassThru
    $ErrorActionPreference = $prev
    if ($p.ExitCode -ne 0 -and $p.ExitCode -ne 3010) {
        # 3010 = success, reboot required
        Write-DbgLog ("  winsdksetup exit {0}" -f $p.ExitCode) "Warn"
        return $false
    }
    Refresh-SessionPath
    return $true
}

function Install-ClassicDebuggersViaChocolatey {
    $choco = Get-Command choco -ErrorAction SilentlyContinue
    if (-not $choco) { return $false }
    Write-DbgLog "Trying Chocolatey fallback for Windows SDK / debuggers..." "Cyan"
    $prev = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    # Package names vary by chocolatey.org catalog; try common ones then soft-fail.
    foreach ($pkg in @("windows-sdk-10.1", "windows-sdk-10.0", "windbg")) {
        Write-Host "  choco install $pkg -y ..."
        & choco install $pkg -y
        if ($LASTEXITCODE -eq 0) {
            Refresh-SessionPath
            if ((Find-ClassicWinDbg) -or (Find-Cdb)) {
                $ErrorActionPreference = $prev
                return $true
            }
        }
    }
    $ErrorActionPreference = $prev
    return $false
}

function Write-ManualHints {
    Write-Host ""
    Write-DbgLog "Manual install links:" "Cyan"
    Write-Host "  WinDbg Preview (Store / winget):"
    Write-Host "    winget install -e --id Microsoft.WinDbg --accept-package-agreements --accept-source-agreements"
    Write-Host "    https://aka.ms/windbg/download"
    Write-Host "    ms-windows-store://pdp/?ProductId=9PGJGD53TN86"
    Write-Host "  Classic WinDbg + cdb (Debugging Tools for Windows):"
    Write-Host "    https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/"
    Write-Host "    In the installer, select only 'Debugging Tools for Windows' (deselect other features)."
    Write-Host "    Quiet: winsdksetup.exe /features OptionId.WindowsDesktopDebuggers /quiet /norestart"
    Write-Host "  After install, expected paths (doctor probes these):"
    Write-Host "    WinDbgX / DbgX.Shell  (Preview)"
    Write-Host "    C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\windbg.exe"
    Write-Host "    C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe"
}

# --- main ---

if ($Skip) {
    Write-DbgLog "Skipping debugger install (-Skip)." "Warn"
    Add-Result "debuggers" "skipped" "-Skip"
    Write-Host "Doctor:  dotnet run --project src\Randall.Cli -- doctor -c projects\vulnserver.yaml"
    exit 0
}

Write-Host "Randfuzz debugger installer"
Write-Host "  WinDbg Preview (Microsoft.WinDbg) + Debugging Tools (cdb / classic windbg)"
Write-Host ""

Refresh-SessionPath

# --- WinDbg Preview ---
if ($SkipWinDbgPreview) {
    Write-DbgLog "======== WinDbg Preview ======== (skipped)" "Cyan"
    Add-Result "WinDbg Preview" "skipped" "-SkipWinDbgPreview"
} else {
    Write-DbgLog "======== WinDbg Preview ========" "Cyan"
    $preview = Find-WinDbgPreview
    if ($preview -and -not $Force) {
        Write-DbgLog "  Already present: $preview" "Ok"
        Add-Result "WinDbg Preview" "ok" $preview
    } else {
        $ok = Invoke-WingetInstall -PackageId "Microsoft.WinDbg" -Name "WinDbg"
        Refresh-SessionPath
        Start-Sleep -Seconds 1
        $preview = Find-WinDbgPreview
        if ($preview) {
            Write-DbgLog "  Found: $preview" "Ok"
            Add-Result "WinDbg Preview" "installed" $preview
        } else {
            Write-DbgLog "  WinDbg Preview not detected after winget (Store/interactive may be required)." "Warn"
            Add-Result "WinDbg Preview" "failed" "winget Microsoft.WinDbg - try Store / aka.ms/windbg/download"
        }
    }
}

# --- Classic + cdb ---
if ($SkipClassicDebuggers) {
    Write-DbgLog "======== Classic WinDbg / cdb ======== (skipped)" "Cyan"
    Add-Result "WinDbg (classic)" "skipped" "-SkipClassicDebuggers"
    Add-Result "cdb" "skipped" "-SkipClassicDebuggers"
} else {
    Write-DbgLog "======== Classic WinDbg / cdb ========" "Cyan"
    $windbg = Find-ClassicWinDbg
    $cdb = Find-Cdb
    if ($windbg -and $cdb -and -not $Force) {
        Write-DbgLog "  Already present:" "Ok"
        Write-Host "    windbg: $windbg"
        Write-Host "    cdb:    $cdb"
        Add-Result "WinDbg (classic)" "ok" $windbg
        Add-Result "cdb" "ok" $cdb
        Ensure-UserPathEntry (Split-Path $cdb -Parent)
    } else {
        $ok = Install-ClassicDebuggersViaSdkSetup
        if (-not $ok) {
            $ok = Install-ClassicDebuggersViaChocolatey
        }
        # Last resort: full SDK via winget (large; only if still missing).
        if (-not $ok -and -not (Find-Cdb)) {
            Write-DbgLog "  Trying winget full Windows SDK (large) as last resort..." "Warn"
            $ok = Invoke-WingetInstall -PackageId "Microsoft.WindowsSDK.10.0.26100" -Name "Windows SDK 10.0.26100"
        }

        Refresh-SessionPath
        Start-Sleep -Seconds 1
        $windbg = Find-ClassicWinDbg
        $cdb = Find-Cdb
        if ($windbg) {
            Add-Result "WinDbg (classic)" $(if ($ok) { "installed" } else { "ok" }) $windbg
            Write-DbgLog "  windbg: $windbg" "Ok"
            Ensure-UserPathEntry (Split-Path $windbg -Parent)
        } else {
            Add-Result "WinDbg (classic)" "failed" "install Debugging Tools for Windows (SDK)"
            Write-DbgLog "  windbg.exe not found" "Warn"
        }
        if ($cdb) {
            Add-Result "cdb" $(if ($ok) { "installed" } else { "ok" }) $cdb
            Write-DbgLog "  cdb: $cdb" "Ok"
            Ensure-UserPathEntry (Split-Path $cdb -Parent)
        } else {
            Add-Result "cdb" "failed" "install Debugging Tools for Windows (SDK)"
            Write-DbgLog "  cdb.exe not found" "Warn"
        }
    }
}

Refresh-SessionPath

Write-Host ""
Write-Host "========== Debuggers summary =========="
$failed = @($script:Results | Where-Object { $_.Status -eq "failed" })
foreach ($r in $script:Results) {
    $color = switch ($r.Status) {
        "ok" { "Green" }
        "installed" { "Green" }
        "skipped" { "DarkGray" }
        "note" { "Cyan" }
        default { "Yellow" }
    }
    Write-Host ("  [{0,-9}] {1,-18} {2}" -f $r.Status, $r.Name, $r.Detail) -ForegroundColor $color
}

if ($failed.Count -gt 0) {
    Write-ManualHints
}

Write-Host ""
Write-Host "Verify (doctor probes debugger:windbg-preview / windbg / cdb):"
Write-Host "  dotnet run --project src\Randall.Cli -- doctor -c projects\vulnserver.yaml"
Write-Host "Open a NEW shell if PATH was updated."

if ($failed.Count -gt 0) { exit 1 }
exit 0
