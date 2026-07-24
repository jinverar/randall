# Download Sysinternals (+ optional Frida / API Monitor) into tools/ for Randfuzz recording bookends.
# Idempotent. Soft-fails per tool; prints a summary at the end.
#
# Examples:
#   powershell -ExecutionPolicy Bypass -File .\scripts\install-recording-tools.ps1
#   powershell -ExecutionPolicy Bypass -File .\scripts\install-recording-tools.ps1 -SysinternalsOnly
#   powershell -ExecutionPolicy Bypass -File .\scripts\install-recording-tools.ps1 -SkipFrida
#   powershell -ExecutionPolicy Bypass -File .\scripts\install-recording-tools.ps1 -IncludeFrida -Force
#   powershell -ExecutionPolicy Bypass -File .\scripts\install-recording-tools.ps1 -SkipApiMonitor
#   powershell -ExecutionPolicy Bypass -File .\scripts\install-recording-tools.ps1 -IncludeWireshark
#   powershell -ExecutionPolicy Bypass -File .\scripts\install-recording-tools.ps1 -SkipPython
#
# Official Suite: https://download.sysinternals.com/files/SysinternalsSuite.zip
# Docs: https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite
# Built-in (no download): wpr.exe (ETW), pktmon.exe - already on Windows.
# Optional (large): Wireshark/tshark - only with -IncludeWireshark (not default).
# Frida needs Python: installer downloads Python 3 when missing (unless -SkipFrida / -SkipPython).
[CmdletBinding()]
param(
    [switch]$Force,
    [switch]$SysinternalsOnly,
    [switch]$IncludeFrida,
    [switch]$SkipFrida,
    [switch]$SkipApiMonitor,
    [switch]$IncludeWireshark,
    [switch]$SkipPython,
    [string]$SuiteZipUrl = "https://download.sysinternals.com/files/SysinternalsSuite.zip",
    [string]$SuiteZipPath = "",
    [string]$ApiMonitorZipUrl = "http://www.rohitab.com/download/api-monitor-v2r13-x86-x64.zip",
    [string]$PythonInstallerUrl = "https://www.python.org/ftp/python/3.12.10/python-3.12.10-amd64.exe",
    [string]$PythonWingetId = "Python.Python.3.12"
)

$ErrorActionPreference = "Stop"
$Root = Split-Path $PSScriptRoot -Parent
$ToolsDir = Join-Path $Root "tools"
$script:Results = [System.Collections.Generic.List[object]]::new()

function Get-RecTempDir {
    foreach ($cand in @($env:TEMP, $env:TMP, $env:TMPDIR)) {
        if (-not [string]::IsNullOrWhiteSpace($cand)) {
            return $cand.TrimEnd('\', '/')
        }
    }
    return ([System.IO.Path]::GetTempPath()).TrimEnd('\', '/')
}

$script:RecTempDir = Get-RecTempDir

function Write-RecLog {
    param([string]$Message, [string]$Level = "Info")
    switch ($Level) {
        "Warn"   { Write-Host $Message -ForegroundColor Yellow }
        "Yellow" { Write-Host $Message -ForegroundColor Yellow }
        "Error"  { Write-Host $Message -ForegroundColor Red }
        "Ok"     { Write-Host $Message -ForegroundColor Green }
        "Cyan"   { Write-Host $Message -ForegroundColor Cyan }
        default  { Write-Host $Message }
    }
}

function Add-Result {
    param(
        [string]$Name,
        [ValidateSet("installed", "skipped", "failed", "note")]
        [string]$Status,
        [string]$Detail = ""
    )
    $script:Results.Add([pscustomobject]@{ Name = $Name; Status = $Status; Detail = $Detail }) | Out-Null
}

function Format-Bytes {
    param([long]$Bytes)
    if ($Bytes -ge 1GB) { return "{0:N2} GB" -f ($Bytes / 1GB) }
    if ($Bytes -ge 1MB) { return "{0:N1} MB" -f ($Bytes / 1MB) }
    if ($Bytes -ge 1KB) { return "{0:N0} KB" -f ($Bytes / 1KB) }
    return "$Bytes B"
}

function Download-WithProgress {
    param(
        [string]$Uri,
        [string]$OutFile
    )

    $dir = Split-Path $OutFile -Parent
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
    }

    $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
    if ($curl) {
        Write-Host "Downloading with curl.exe (progress + resume)..."
        Write-Verbose "URL: $Uri"
        $curlArgs = @(
            "-L", "--fail", "--retry", "5", "--retry-delay", "2",
            "--retry-all-errors", "-C", "-",
            "--progress-bar",
            "-o", $OutFile,
            $Uri
        )
        $prev = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        & curl.exe @curlArgs
        $code = $LASTEXITCODE
        $ErrorActionPreference = $prev
        if ($code -ne 0) {
            throw "curl.exe download failed (exit $code). Re-run to resume."
        }
        return
    }

    try {
        Import-Module BitsTransfer -ErrorAction Stop
        Write-Host "Downloading with BITS..."
        Start-BitsTransfer -Source $Uri -Destination $OutFile -DisplayName "Randfuzz recording tools" -Description $Uri
        return
    } catch {
        Write-RecLog ("BITS unavailable ({0}); falling back to Invoke-WebRequest..." -f $_.Exception.Message) "Warn"
    }

    Write-Host "Downloading with Invoke-WebRequest (no resume)..."
    $tmpPartial = "$OutFile.partial"
    try {
        Invoke-WebRequest -Uri $Uri -OutFile $tmpPartial -UseBasicParsing
        Move-Item -Force $tmpPartial $OutFile
    } catch {
        Remove-Item $tmpPartial -Force -ErrorAction SilentlyContinue
        throw
    }
}

# Preferred tools/ names -> candidates inside the Suite extract (case-insensitive match).
$SysinternalsTools = @(
    @{ Dest = "Procmon64.exe";   Sources = @("Procmon64.exe", "Procmon.exe") },
    @{ Dest = "procdump.exe";    Sources = @("procdump.exe", "Procdump.exe") },
    @{ Dest = "procdump64.exe";  Sources = @("procdump64.exe", "Procdump64.exe") },
    @{ Dest = "tcpvcon64.exe";   Sources = @("tcpvcon64.exe", "Tcpvcon64.exe", "tcpvcon.exe", "Tcpvcon.exe") },
    @{ Dest = "Dbgview.exe";     Sources = @("Dbgview.exe", "dbgview.exe", "Dbgview64.exe") },
    @{ Dest = "handle64.exe";    Sources = @("handle64.exe", "Handle64.exe", "handle.exe") },
    @{ Dest = "listdlls64.exe";  Sources = @("listdlls64.exe", "ListDLLs64.exe", "Listdlls64.exe", "listdlls.exe", "ListDLLs.exe") },
    @{ Dest = "pslist64.exe";    Sources = @("pslist64.exe", "PsList64.exe", "pslist.exe", "PsList.exe") },
    @{ Dest = "pslist.exe";      Sources = @("pslist.exe", "PsList.exe") },
    @{ Dest = "strings64.exe";   Sources = @("strings64.exe", "Strings64.exe", "strings.exe", "Strings.exe") },
    @{ Dest = "sigcheck64.exe";  Sources = @("sigcheck64.exe", "Sigcheck64.exe", "sigcheck.exe", "Sigcheck.exe") },
    @{ Dest = "accesschk64.exe"; Sources = @("accesschk64.exe", "Accesschk64.exe", "accesschk.exe", "Accesschk.exe") },
    @{ Dest = "vmmap64.exe";     Sources = @("vmmap64.exe", "Vmmap64.exe", "vmmap.exe", "Vmmap.exe") },
    @{ Dest = "PsInfo64.exe";    Sources = @("PsInfo64.exe", "psinfo64.exe", "PsInfo.exe", "psinfo.exe") },
    @{ Dest = "procexp64.exe";   Sources = @("procexp64.exe", "Procexp64.exe", "procexp.exe") }
)

function Find-SourceFile {
    param(
        [string]$ExtractDir,
        [string[]]$Candidates
    )
    foreach ($name in $Candidates) {
        $hit = Get-ChildItem -Path $ExtractDir -Filter $name -Recurse -File -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($hit) { return $hit }
    }
    return $null
}

function Install-FromLiveSysinternals {
    param(
        [string]$DestName,
        [string[]]$LiveNames
    )
    $dest = Join-Path $ToolsDir $DestName
    foreach ($live in $LiveNames) {
        $uri = "https://live.sysinternals.com/$live"
        $tmp = Join-Path $script:RecTempDir ("randall-live-" + $live)
        try {
            Write-Verbose "Live.sysinternals fallback: $uri"
            Download-WithProgress -Uri $uri -OutFile $tmp
            if ((Test-Path -LiteralPath $tmp) -and (Get-Item -LiteralPath $tmp).Length -gt 1024) {
                Copy-Item -Force $tmp $dest
                Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
                return $true
            }
        } catch {
            Write-Verbose ("Live download failed for {0}: {1}" -f $live, $_.Exception.Message)
            Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
        }
    }
    return $false
}

function Install-SysinternalsSuite {
    New-Item -ItemType Directory -Force -Path $ToolsDir | Out-Null

    $needed = @()
    foreach ($tool in $SysinternalsTools) {
        $dest = Join-Path $ToolsDir $tool.Dest
        if ((Test-Path $dest) -and -not $Force) {
            Add-Result $tool.Dest "skipped" "already present"
        } else {
            $needed += $tool
        }
    }

    if ($needed.Count -eq 0) {
        Write-RecLog "All Sysinternals targets already present under tools\ (use -Force to refresh)." "Ok"
        return
    }

    Write-RecLog ("Need {0} Sysinternals binary(ies); downloading Suite..." -f $needed.Count) "Cyan"

    $zip = $SuiteZipPath
    if (-not $zip) {
        $zip = Join-Path $script:RecTempDir "SysinternalsSuite.zip"
    }

    $extract = Join-Path $script:RecTempDir "randall-sysinternals-extract"
    $haveZip = $false

    if ($SuiteZipPath -and (Test-Path $SuiteZipPath)) {
        Write-Host "Using local Suite zip: $SuiteZipPath"
        $haveZip = $true
        $zip = $SuiteZipPath
    } elseif ((Test-Path $zip) -and -not $Force -and (Get-Item $zip).Length -gt 1MB) {
        Write-Host ("Reusing cached Suite zip: {0} ({1})" -f $zip, (Format-Bytes (Get-Item $zip).Length))
        $haveZip = $true
    } else {
        try {
            Write-Host "URL: $SuiteZipUrl"
            Write-Host "Cache: $zip"
            Write-Host "(~180+ MB; may take a few minutes on a VM)"
            if ($Force -and (Test-Path $zip)) {
                Remove-Item $zip -Force -ErrorAction SilentlyContinue
            }
            Download-WithProgress -Uri $SuiteZipUrl -OutFile $zip
            $haveZip = $true
        } catch {
            Write-RecLog ("[!] Suite download failed: {0}" -f $_.Exception.Message) "Warn"
            Write-RecLog "    Falling back to live.sysinternals.com per binary..." "Warn"
        }
    }

    $extracted = $false
    if ($haveZip) {
        try {
            if (Test-Path $extract) { Remove-Item $extract -Recurse -Force }
            New-Item -ItemType Directory -Force -Path $extract | Out-Null
            Write-Host "Extracting Suite zip..."
            Expand-Archive -Path $zip -DestinationPath $extract -Force
            $extracted = $true
        } catch {
            Write-RecLog ("[!] Suite extract failed: {0}" -f $_.Exception.Message) "Warn"
            Write-RecLog "    Falling back to live.sysinternals.com per binary..." "Warn"
        }
    }

    foreach ($tool in $needed) {
        $dest = Join-Path $ToolsDir $tool.Dest
        $ok = $false
        $detail = ""

        if ($extracted) {
            $src = Find-SourceFile -ExtractDir $extract -Candidates $tool.Sources
            if ($src) {
                try {
                    Copy-Item -Force $src.FullName $dest
                    $ok = $true
                    $detail = "from Suite ($($src.Name))"
                } catch {
                    $detail = "copy failed: $($_.Exception.Message)"
                }
            } else {
                $detail = "not in Suite extract"
            }
        }

        if (-not $ok) {
            Write-Host ("  Trying live.sysinternals.com for {0}..." -f $tool.Dest)
            if (Install-FromLiveSysinternals -DestName $tool.Dest -LiveNames $tool.Sources) {
                $ok = $true
                $detail = "from live.sysinternals.com"
            } elseif (-not $detail) {
                $detail = "Suite + live download failed"
            }
        }

        if ($ok -and (Test-Path $dest)) {
            Write-RecLog ("  [+] {0}" -f $tool.Dest) "Ok"
            Add-Result $tool.Dest "installed" $detail
        } else {
            Write-RecLog ("  [!] {0} - {1}" -f $tool.Dest, $detail) "Warn"
            Add-Result $tool.Dest "failed" $detail
        }
    }

    Remove-Item $extract -Recurse -Force -ErrorAction SilentlyContinue
    if ($haveZip -and -not $SuiteZipPath) {
        Write-Host "Suite zip kept at $zip (safe to delete)."
    }
}

function Test-RecIsWindows {
    if ($env:OS -eq "Windows_NT") { return $true }
    try {
        if ($IsWindows -eq $true) { return $true }
    } catch { }
    return $false
}

function Update-RecSessionPath {
    try {
        $machine = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
        $user = [System.Environment]::GetEnvironmentVariable("Path", "User")
        $parts = @()
        if ($machine) { $parts += $machine }
        if ($user) { $parts += $user }
        if ($parts.Count -gt 0) {
            $env:Path = ($parts -join ";")
        }
    } catch {
        Write-Verbose ("PATH refresh skipped: {0}" -f $_.Exception.Message)
    }
}

function Find-PythonExe {
    # Returns a python executable path usable as: & $py -m pip ...
    Update-RecSessionPath

    foreach ($cand in @("python", "python3")) {
        $cmd = Get-Command $cand -ErrorAction SilentlyContinue
        if ($cmd -and $cmd.Source) {
            # Avoid the Windows Store alias stub that opens ms-windows-store
            $src = $cmd.Source
            if ($src -match 'WindowsApps\\python') { continue }
            return $src
        }
    }

    $pyLauncher = Get-Command py -ErrorAction SilentlyContinue
    if ($pyLauncher) {
        $prev = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        $probe = & py -3 -c "import sys; print(sys.executable)" 2>$null
        $ErrorActionPreference = $prev
        if ($LASTEXITCODE -eq 0 -and $probe) {
            $exe = ($probe | Select-Object -Last 1).ToString().Trim()
            if ($exe -and (Test-Path -LiteralPath $exe)) { return $exe }
        }
    }

    $localApp = $env:LocalAppData
    $roots = @(
        (Join-Path $ToolsDir "python")
    )
    if ($localApp) {
        $roots += (Join-Path $localApp "Programs\Python")
    }
    foreach ($root in $roots) {
        if (-not $root -or -not (Test-Path -LiteralPath $root)) { continue }
        $hit = Get-ChildItem -Path $root -Filter "python.exe" -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -notmatch '\\WindowsApps\\' } |
            Select-Object -First 1
        if ($hit) { return $hit.FullName }
    }

    return $null
}

function Install-PythonRuntime {
    if ($SkipPython) {
        Add-Result "Python" "skipped" "-SkipPython"
        return $false
    }

    if (-not (Test-RecIsWindows)) {
        Write-RecLog "[!] Auto Python install is Windows-only. Install python3 via your package manager for Frida." "Warn"
        Add-Result "Python" "failed" "non-Windows host"
        return $false
    }

    New-Item -ItemType Directory -Force -Path $ToolsDir | Out-Null

    # 1) winget (when available)
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if ($winget) {
        Write-RecLog ("Trying winget install {0}..." -f $PythonWingetId) "Cyan"
        try {
            $prev = $ErrorActionPreference
            $ErrorActionPreference = "Continue"
            & winget install --id $PythonWingetId -e --accept-package-agreements --accept-source-agreements
            $code = $LASTEXITCODE
            $ErrorActionPreference = $prev
            Update-RecSessionPath
            if (Find-PythonExe) {
                Write-RecLog "Python available via winget." "Ok"
                Add-Result "Python" "installed" ("winget {0}" -f $PythonWingetId)
                return $true
            }
            Write-RecLog ("winget exit {0}; falling back to python.org installer..." -f $code) "Warn"
        } catch {
            Write-RecLog ("winget Python failed ({0}); falling back to python.org installer..." -f $_.Exception.Message) "Warn"
        }
    } else {
        Write-Host "  winget not found; using python.org installer."
    }

    # 2) Official python.org installer (per-user, pip, add to PATH)
    $setup = Join-Path $script:RecTempDir "python-randall-amd64.exe"
    try {
        Write-RecLog "Downloading Python installer from python.org..." "Cyan"
        Write-Host "  URL: $PythonInstallerUrl"
        Write-Host "  Cache: $setup"
        if ($Force -and (Test-Path -LiteralPath $setup)) {
            Remove-Item -LiteralPath $setup -Force -ErrorAction SilentlyContinue
        }
        if (-not (Test-Path -LiteralPath $setup) -or (Get-Item -LiteralPath $setup).Length -lt 1MB) {
            Download-WithProgress -Uri $PythonInstallerUrl -OutFile $setup
        }

        Write-Host "  Running silent per-user install (Include_pip=1, PrependPath=1)..."
        $prev = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        $p = Start-Process -FilePath $setup -ArgumentList @(
            "/quiet",
            "InstallAllUsers=0",
            "PrependPath=1",
            "Include_pip=1",
            "Include_test=0",
            "Include_launcher=1",
            "SimpleInstall=1"
        ) -Wait -PassThru
        $ErrorActionPreference = $prev
        Update-RecSessionPath

        Start-Sleep -Seconds 2
        $py = Find-PythonExe
        if ($py) {
            Write-RecLog ("Python installed: {0}" -f $py) "Ok"
            Add-Result "Python" "installed" "python.org silent installer"
            return $true
        }

        throw ("installer exit {0}; python.exe still not found (open a new shell or check LocalAppData\Programs\Python)" -f $p.ExitCode)
    } catch {
        Write-RecLog ("[!] Python auto-install failed: {0}" -f $_.Exception.Message) "Warn"
        Write-Host "  Manual: https://www.python.org/downloads/windows/ (enable Add python.exe to PATH)"
        Write-Host "  Or: winget install -e --id $PythonWingetId --accept-package-agreements --accept-source-agreements"
        Add-Result "Python" "failed" $_.Exception.Message
        return $false
    }
}

function Install-FridaTools {
    if ($SysinternalsOnly -or $SkipFrida) {
        Add-Result "frida-tools" "skipped" $(if ($SysinternalsOnly) { "-SysinternalsOnly" } else { "-SkipFrida" })
        return
    }

    # Default: attempt Frida (companion). -IncludeFrida is explicit but same path.
    if ($IncludeFrida) {
        Write-RecLog "Installing Frida (-IncludeFrida)..." "Cyan"
    } else {
        Write-RecLog "Installing Frida (default; use -SkipFrida to skip)..." "Cyan"
        Write-Host "  Note: Frida is a GUI/external companion - Randfuzz does not inject it."
    }

    $py = Find-PythonExe
    if (-not $py) {
        if ($SkipPython) {
            Write-RecLog "[!] Python not found and -SkipPython set - cannot install frida-tools." "Warn"
            Add-Result "frida-tools" "failed" "python missing (-SkipPython)"
            Add-Result "Python" "skipped" "-SkipPython"
            return
        }
        Write-RecLog "Python not found - installing Python 3 for Frida..." "Cyan"
        if (Install-PythonRuntime) {
            $py = Find-PythonExe
        }
    }

    if (-not $py) {
        Write-RecLog "[!] Python/pip still not available - skip Frida." "Warn"
        Write-RecLog "    Manual: install Python 3 from https://www.python.org/downloads/windows/ (check Add python.exe to PATH)," "Warn"
        Write-RecLog "    then: python -m pip install frida-tools" "Warn"
        Add-Result "frida-tools" "failed" "python/pip missing after install attempt"
        return
    }

    Write-Host ("  Using Python: {0}" -f $py)

    try {
        $prev = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        & $py -m pip --version 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Host "  Bootstrapping pip (ensurepip)..."
            & $py -m ensurepip --upgrade 2>&1 | Out-Null
        }
        & $py -m pip install --upgrade frida-tools
        $code = $LASTEXITCODE
        $ErrorActionPreference = $prev
        if ($code -ne 0) {
            throw "pip exit $code"
        }
        Write-RecLog "Frida tools installed (frida / frida-ps on PATH if Scripts dir is on PATH)." "Ok"
        Add-Result "frida-tools" "installed" ("pip install frida-tools via {0}" -f $py)
    } catch {
        Write-RecLog ("[!] Frida install failed: {0}" -f $_.Exception.Message) "Warn"
        Write-RecLog ("    Manual: `"{0}`" -m pip install frida-tools" -f $py) "Warn"
        Add-Result "frida-tools" "failed" $_.Exception.Message
    }
}

function Install-ApiMonitor {
    if ($SysinternalsOnly -or $SkipApiMonitor) {
        Add-Result "API Monitor" "skipped" $(if ($SysinternalsOnly) { "-SysinternalsOnly" } else { "-SkipApiMonitor" })
        return
    }

    $apiDir = Join-Path $ToolsDir "API Monitor"
    $marker64 = Join-Path $apiDir "apimonitor-x64.exe"
    $marker86 = Join-Path $apiDir "apimonitor-x86.exe"
    $alt64 = Join-Path $apiDir "API Monitor (rohitab.com)\apimonitor-x64.exe"

    if (((Test-Path $marker64) -or (Test-Path $marker86) -or (Test-Path $alt64)) -and -not $Force) {
        Write-RecLog "API Monitor already present under tools\API Monitor\" "Ok"
        Add-Result "API Monitor" "skipped" "already present"
        return
    }

    Write-RecLog "Trying API Monitor download (best-effort; rohitab URLs can be flaky)..." "Cyan"
    Write-Host "  Expected path: tools\API Monitor\apimonitor-x64.exe"
    Write-Host "  URL: $ApiMonitorZipUrl"

    $zip = Join-Path $script:RecTempDir "api-monitor-v2r13-x86-x64.zip"
    $extract = Join-Path $script:RecTempDir "randall-apimonitor-extract"

    try {
        if ($Force -and (Test-Path $zip)) {
            Remove-Item $zip -Force -ErrorAction SilentlyContinue
        }
        if (-not (Test-Path $zip) -or (Get-Item $zip).Length -lt 1MB) {
            Download-WithProgress -Uri $ApiMonitorZipUrl -OutFile $zip
        }

        if (Test-Path $extract) { Remove-Item $extract -Recurse -Force }
        New-Item -ItemType Directory -Force -Path $extract | Out-Null
        Expand-Archive -Path $zip -DestinationPath $extract -Force

        $exe = Get-ChildItem -Path $extract -Filter "apimonitor-x64.exe" -Recurse -File -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if (-not $exe) {
            $exe = Get-ChildItem -Path $extract -Filter "apimonitor-x86.exe" -Recurse -File -ErrorAction SilentlyContinue |
                Select-Object -First 1
        }
        if (-not $exe) {
            throw "apimonitor-x64.exe / apimonitor-x86.exe not found in zip"
        }

        $innerRoot = $exe.Directory.FullName
        # Prefer the folder that contains the exe (often "API Monitor (rohitab.com)").
        if (Test-Path $apiDir) { Remove-Item $apiDir -Recurse -Force }
        New-Item -ItemType Directory -Force -Path $ToolsDir | Out-Null
        # If extract has a single top-level dir, move that; else copy exe parent.
        $topDirs = Get-ChildItem $extract -Directory
        if ($topDirs.Count -eq 1) {
            Move-Item $topDirs[0].FullName $apiDir
        } else {
            New-Item -ItemType Directory -Force -Path $apiDir | Out-Null
            Copy-Item -Path (Join-Path $innerRoot "*") -Destination $apiDir -Recurse -Force
        }

        if (-not ((Test-Path $marker64) -or (Test-Path (Join-Path $apiDir "apimonitor-x64.exe")) -or
                  (Test-Path $marker86) -or (Get-ChildItem $apiDir -Filter "apimonitor-*.exe" -Recurse -ErrorAction SilentlyContinue))) {
            throw "Extract finished but apimonitor exe missing under $apiDir"
        }

        Write-RecLog "API Monitor installed under tools\API Monitor\" "Ok"
        Add-Result "API Monitor" "installed" $apiDir
    } catch {
        Write-RecLog ("[!] API Monitor auto-download failed: {0}" -f $_.Exception.Message) "Warn"
        Write-Host ""
        Write-Host "Manual API Monitor install (GUI companion - not injected by Randfuzz):" -ForegroundColor Yellow
        Write-Host "  1. Open https://www.rohitab.com/apimonitor"
        Write-Host "  2. Download the Portable or x86/x64 zip (api-monitor-v2r13-x86-x64.zip)"
        Write-Host "  3. Extract so one of these exists:"
        Write-Host "       tools\API Monitor\apimonitor-x64.exe"
        Write-Host "       tools\API Monitor\apimonitor-x86.exe"
        Write-Host "  Optional URL (may redirect / break): $ApiMonitorZipUrl"
        Add-Result "API Monitor" "failed" "manual steps printed"
    } finally {
        Remove-Item $extract -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Show-BuiltinNotes {
    Write-Host ""
    Write-RecLog "Built-in Windows tools (no download):" "Cyan"
    Write-Host "  wpr.exe     - ETW / fuzz.etwCapture  (%SystemRoot%\System32\wpr.exe)"
    Write-Host "  pktmon.exe  - fuzz.pktmonCapture     (%SystemRoot%\System32\pktmon.exe)"
    Write-Host "  Often need an elevated console/agent for capture."
    Add-Result "wpr/pktmon" "note" "built into Windows - no download"

    Write-Host ""
    Write-RecLog "Optional Wireshark / tshark (fuzz.tsharkCapture -> fuzz.pcapng):" "Cyan"
    Write-Host "  Not installed by default (large). Manual:"
    Write-Host "    winget install WiresharkFoundation.Wireshark"
    Write-Host "    choco install wireshark"
    Write-Host "  Or:  .\scripts\install-recording-tools.ps1 -IncludeWireshark"
    Write-Host "  Needs Npcap; live capture often requires elevation. Soft-fails if denied."
    Add-Result "tshark/Wireshark" "note" "optional - use -IncludeWireshark or install manually"
}

function Install-WiresharkOptional {
    if (-not $IncludeWireshark) { return }
    if ($SysinternalsOnly) {
        Write-RecLog "Skipping Wireshark (-SysinternalsOnly)." "Yellow"
        return
    }

    Write-Host ""
    Write-RecLog "Installing Wireshark via winget (-IncludeWireshark)..." "Cyan"
    $tshark = Get-Command tshark.exe -ErrorAction SilentlyContinue
    $pf = Join-Path ${env:ProgramFiles} "Wireshark\tshark.exe"
    if (-not $Force -and (($tshark) -or (Test-Path -LiteralPath $pf))) {
        $where = if ($tshark) { $tshark.Source } else { $pf }
        Write-Host "  Already present: $where"
        Add-Result "Wireshark" "skipped" $where
        return
    }

    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if (-not $winget) {
        Write-Host "  winget not found. Install manually:"
        Write-Host "    https://www.wireshark.org/download.html"
        Write-Host "    or: choco install wireshark"
        Add-Result "Wireshark" "failed" "winget missing - manual install"
        return
    }

    try {
        & winget install --id WiresharkFoundation.Wireshark -e --accept-package-agreements --accept-source-agreements
        if ($LASTEXITCODE -ne 0) {
            throw "winget exit $LASTEXITCODE"
        }
        Add-Result "Wireshark" "installed" "winget WiresharkFoundation.Wireshark (open new shell for PATH)"
    } catch {
        Write-Host "  winget install failed: $_"
        Write-Host "  Manual: winget install WiresharkFoundation.Wireshark  |  choco install wireshark"
        Add-Result "Wireshark" "failed" "$_"
    }
}

# --- main ---
Write-Host "Randfuzz recording tools installer"
Write-Host "  Repo:  $Root"
Write-Host "  Tools: $ToolsDir"
Write-Host ""

Install-SysinternalsSuite
Install-FridaTools
Install-ApiMonitor
Install-WiresharkOptional
Show-BuiltinNotes

Write-Host ""
Write-Host "========== Summary =========="
$installed = @($script:Results | Where-Object { $_.Status -eq "installed" })
$skipped   = @($script:Results | Where-Object { $_.Status -eq "skipped" })
$failed    = @($script:Results | Where-Object { $_.Status -eq "failed" })
$notes     = @($script:Results | Where-Object { $_.Status -eq "note" })

Write-Host ("Installed : {0}" -f $installed.Count) -ForegroundColor Green
foreach ($r in $installed) { Write-Host ("  + {0}  {1}" -f $r.Name, $r.Detail) }
Write-Host ("Skipped   : {0}" -f $skipped.Count)
foreach ($r in $skipped) { Write-Host ("  = {0}  {1}" -f $r.Name, $r.Detail) }
if ($failed.Count -gt 0) {
    Write-Host ("Failed    : {0}" -f $failed.Count) -ForegroundColor Yellow
    foreach ($r in $failed) { Write-Host ("  ! {0}  {1}" -f $r.Name, $r.Detail) -ForegroundColor Yellow }
} else {
    Write-Host "Failed    : 0"
}
foreach ($r in $notes) { Write-Host ("  ~ {0}  {1}" -f $r.Name, $r.Detail) }

Write-Host ""
Write-Host "Verify:  dir tools\*.exe"
Write-Host "Doctor:  dotnet run --project src\Randall.Cli -- doctor -c projects\vulnserver.yaml"
Write-Host "Docs:    docs\RECORDING.md | tools\README.md"

# Soft-fail: exit 0 unless every Sysinternals core binary failed
$coreNames = @("Procmon64.exe", "procdump.exe", "handle64.exe", "listdlls64.exe", "pslist64.exe", "pslist.exe")
$coreFailed = @($failed | Where-Object { $coreNames -contains $_.Name })
$coreOk = @($script:Results | Where-Object {
    ($coreNames -contains $_.Name) -and ($_.Status -in @("installed", "skipped"))
})
if ($coreOk.Count -eq 0 -and $coreFailed.Count -gt 0) {
    Write-RecLog "[!] No core Sysinternals binaries landed - re-run or copy Suite manually into tools\" "Error"
    exit 1
}
exit 0
