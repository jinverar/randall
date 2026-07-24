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
    [string]$PythonEmbedUrl = "https://www.python.org/ftp/python/3.12.10/python-3.12.10-embed-amd64.zip",
    [string]$GetPipUrl = "https://bootstrap.pypa.io/get-pip.py",
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

function Get-ToolsPythonDir {
    return (Join-Path $ToolsDir "python")
}

function Get-ToolsPythonExe {
    $dir = Get-ToolsPythonDir
    if (Test-RecIsWindows) {
        return (Join-Path $dir "python.exe")
    }
    # Linux/macOS CI / non-Windows: venv layout
    foreach ($rel in @("bin/python3", "bin/python", "python3", "python")) {
        $cand = Join-Path $dir $rel
        if (Test-Path -LiteralPath $cand) { return $cand }
    }
    return (Join-Path $dir "bin/python3")
}

function ConvertTo-ProcessArgumentString {
    param([string[]]$ArgumentList)
    # Windows PowerShell 5.1 Start-Process mangles string[] ArgumentList;
    # pass one correctly quoted string instead.
    $parts = foreach ($a in $ArgumentList) {
        if ($null -eq $a) { continue }
        $s = [string]$a
        if ($s -match '[\s"]') {
            '"' + ($s.Replace('"', '\"')) + '"'
        } else {
            $s
        }
    }
    return ($parts -join ' ')
}

function Invoke-NativeCapture {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$ArgumentList = @(),
        [int]$TimeoutSec = 1200
    )
    # Never invoke Windows Store python stubs via bare PATH 'python' - that raises
    # NativeCommandError (exit 9009). Callers must pass an absolute tools\python path.
    if (-not (Test-Path -LiteralPath $FilePath)) {
        return @{ ExitCode = 9009; StdOut = ""; StdErr = "exe missing: $FilePath" }
    }
    if ($FilePath -match '(?i)[\\/]WindowsApps[\\/]') {
        return @{ ExitCode = 9009; StdOut = ""; StdErr = "refusing WindowsApps python stub: $FilePath" }
    }

    $prev = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $lines = & $FilePath @ArgumentList 2>&1
        $code = $LASTEXITCODE
        if ($null -eq $code) { $code = 0 }
        $stdout = New-Object System.Text.StringBuilder
        $stderr = New-Object System.Text.StringBuilder
        foreach ($line in @($lines)) {
            if ($line -is [System.Management.Automation.ErrorRecord]) {
                [void]$stderr.AppendLine($line.ToString())
            } else {
                [void]$stdout.AppendLine([string]$line)
            }
        }
        return @{
            ExitCode = [int]$code
            StdOut   = $stdout.ToString()
            StdErr   = $stderr.ToString()
        }
    } catch {
        return @{ ExitCode = 1; StdOut = ""; StdErr = $_.Exception.Message }
    } finally {
        $ErrorActionPreference = $prev
    }
}

function Test-PythonExeWorks {
    param([string]$Exe)
    if ([string]::IsNullOrWhiteSpace($Exe)) { return $false }
    if (-not (Test-Path -LiteralPath $Exe)) { return $false }
    if ($Exe -match '(?i)[\\/]WindowsApps[\\/]') { return $false }
    try {
        $item = Get-Item -LiteralPath $Exe -Force -ErrorAction Stop
        # Windows Store app aliases are tiny reparse points under WindowsApps.
        # Do NOT reject normal symlinks (Linux venv python -> /usr/bin/python3).
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -and
            ($Exe -match '(?i)[\\/]WindowsApps[\\/]' -or $item.Length -eq 0)) {
            return $false
        }
    } catch { }

    $r = Invoke-NativeCapture -FilePath $Exe -ArgumentList @(
        "-c", "import sys; print(sys.version_info[0]); print(sys.version_info[1])"
    )
    if ($r.ExitCode -ne 0) { return $false }
    $combined = ($r.StdOut + "`n" + $r.StdErr)
    if ($combined -match '(?i)Microsoft Store|ms-windows-store|Python was not found') {
        return $false
    }
    $lines = @($r.StdOut.Trim() -split "\r?\n" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($lines.Count -lt 2) { return $false }
    return ($lines[0] -match '^[23]$' -and $lines[1] -match '^\d+$')
}

function Enable-EmbeddableSite {
    param([string]$PythonDir)
    $pth = Get-ChildItem -Path $PythonDir -Filter "python*._pth" -File -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if (-not $pth) { return }
    $lines = @(Get-Content -LiteralPath $pth.FullName)
    $out = New-Object System.Collections.Generic.List[string]
    $hasSitePackages = $false
    $hasImportSite = $false
    foreach ($line in $lines) {
        $t = $line.Trim()
        if ($t -match '^#\s*import site') {
            [void]$out.Add("import site")
            $hasImportSite = $true
            continue
        }
        if ($t -eq "import site") { $hasImportSite = $true }
        if ($t -eq "Lib\site-packages" -or $t -eq "Lib/site-packages") { $hasSitePackages = $true }
        [void]$out.Add($line)
    }
    if (-not $hasSitePackages) { [void]$out.Add("Lib\site-packages") }
    if (-not $hasImportSite) { [void]$out.Add("import site") }
    Set-Content -LiteralPath $pth.FullName -Value $out -Encoding ASCII
}

function Install-PythonRuntime {
    if ($SkipPython) {
        Add-Result "Python" "skipped" "-SkipPython"
        return $false
    }

    $toolsPyDir = Get-ToolsPythonDir
    $toolsPyExe = Get-ToolsPythonExe
    if ((-not $Force) -and (Test-PythonExeWorks $toolsPyExe)) {
        Write-RecLog ("Python already present: {0}" -f $toolsPyExe) "Ok"
        Add-Result "Python" "skipped" "already present under tools\python"
        return $true
    }

    New-Item -ItemType Directory -Force -Path $ToolsDir | Out-Null

    # Non-Windows (CI/agent): create a venv under tools/python so the same Frida path works.
    if (-not (Test-RecIsWindows)) {
        Write-RecLog "Non-Windows host - creating tools/python venv for Frida..." "Cyan"
        $bootstrap = $null
        foreach ($cand in @("python3", "python")) {
            $cmd = Get-Command $cand -ErrorAction SilentlyContinue
            if ($cmd -and $cmd.Source) { $bootstrap = $cmd.Source; break }
        }
        if (-not $bootstrap) {
            Write-RecLog "[!] python3 not found to create tools/python venv." "Warn"
            Add-Result "Python" "failed" "python3 missing on non-Windows host"
            return $false
        }
        try {
            if (Test-Path -LiteralPath $toolsPyDir) {
                Remove-Item -LiteralPath $toolsPyDir -Recurse -Force -ErrorAction SilentlyContinue
            }
            $prev = $ErrorActionPreference
            $ErrorActionPreference = "Continue"
            # Prefer full venv; if ensurepip missing (Debian), create without pip and use get-pip.py.
            & $bootstrap -m venv $toolsPyDir 2>$null
            $vc = $LASTEXITCODE
            if ($vc -ne 0) {
                & $bootstrap -m venv --without-pip $toolsPyDir
                $vc = $LASTEXITCODE
            }
            $ErrorActionPreference = $prev
            if ($vc -ne 0) { throw "venv exit $vc" }
            $toolsPyExe = Get-ToolsPythonExe
            if (-not (Test-Path -LiteralPath $toolsPyExe)) {
                throw "venv python missing at $toolsPyExe"
            }
            # Ensure pip exists (venv --without-pip or broken ensurepip)
            $pipCheck = Invoke-NativeCapture -FilePath $toolsPyExe -ArgumentList @("-m", "pip", "--version")
            if ($pipCheck.ExitCode -ne 0) {
                Write-Host "  Bootstrapping pip into venv (get-pip.py)..."
                $getPip = Join-Path $script:RecTempDir "randall-get-pip.py"
                if (-not (Test-Path -LiteralPath $getPip) -or (Get-Item -LiteralPath $getPip).Length -lt 10KB) {
                    Download-WithProgress -Uri $GetPipUrl -OutFile $getPip
                }
                $boot = Invoke-NativeCapture -FilePath $toolsPyExe -ArgumentList @($getPip, "--no-warn-script-location")
                if ($boot.StdOut) { Write-Host $boot.StdOut.TrimEnd() }
                if ($boot.StdErr) { Write-Host $boot.StdErr.TrimEnd() }
                if ($boot.ExitCode -ne 0) { throw "get-pip exit $($boot.ExitCode)" }
            }
            if (-not (Test-PythonExeWorks $toolsPyExe)) {
                throw "venv python not usable at $toolsPyExe"
            }
            Write-RecLog ("Python venv ready: {0}" -f $toolsPyExe) "Ok"
            Add-Result "Python" "installed" "venv -> tools/python"
            return $true
        } catch {
            Write-RecLog ("[!] venv install failed: {0}" -f $_.Exception.Message) "Warn"
            Add-Result "Python" "failed" $_.Exception.Message
            return $false
        }
    }

    # Windows primary: embeddable package -> tools\python (never PATH / Store stub)
    $zip = Join-Path $script:RecTempDir "python-randall-embed-amd64.zip"
    $getPip = Join-Path $script:RecTempDir "randall-get-pip.py"
    try {
        Write-RecLog "Downloading embeddable Python -> tools\python (avoids Microsoft Store stub)..." "Cyan"
        Write-Host "  URL: $PythonEmbedUrl"
        Write-Host "  Target: $toolsPyDir"
        if ($Force -and (Test-Path -LiteralPath $zip)) {
            Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue
        }
        if (-not (Test-Path -LiteralPath $zip) -or (Get-Item -LiteralPath $zip).Length -lt 1MB) {
            Download-WithProgress -Uri $PythonEmbedUrl -OutFile $zip
        }

        if (Test-Path -LiteralPath $toolsPyDir) {
            Remove-Item -LiteralPath $toolsPyDir -Recurse -Force -ErrorAction SilentlyContinue
        }
        New-Item -ItemType Directory -Force -Path $toolsPyDir | Out-Null
        Write-Host "  Extracting embeddable package..."
        Expand-Archive -Path $zip -DestinationPath $toolsPyDir -Force
        Enable-EmbeddableSite -PythonDir $toolsPyDir

        $toolsPyExe = Get-ToolsPythonExe
        if (-not (Test-Path -LiteralPath $toolsPyExe)) {
            throw "python.exe missing after extract under $toolsPyDir"
        }
        if (-not (Test-PythonExeWorks $toolsPyExe)) {
            throw "extracted python.exe is not usable"
        }

        Write-Host "  Installing pip (get-pip.py)..."
        if ($Force -and (Test-Path -LiteralPath $getPip)) {
            Remove-Item -LiteralPath $getPip -Force -ErrorAction SilentlyContinue
        }
        if (-not (Test-Path -LiteralPath $getPip) -or (Get-Item -LiteralPath $getPip).Length -lt 10KB) {
            Download-WithProgress -Uri $GetPipUrl -OutFile $getPip
        }
        $pipRc = Invoke-NativeCapture -FilePath $toolsPyExe -ArgumentList @(
            $getPip, "--no-warn-script-location"
        )
        if ($pipRc.StdOut) { Write-Host $pipRc.StdOut.TrimEnd() }
        if ($pipRc.StdErr) { Write-Host $pipRc.StdErr.TrimEnd() }
        if ($pipRc.ExitCode -ne 0) {
            throw "get-pip.py exit $($pipRc.ExitCode)"
        }

        $verRc = Invoke-NativeCapture -FilePath $toolsPyExe -ArgumentList @("-m", "pip", "--version")
        if ($verRc.ExitCode -ne 0) {
            throw "pip not available after get-pip.py"
        }
        Write-Host ("  {0}" -f $verRc.StdOut.Trim())
        Write-RecLog ("Python ready: {0}" -f $toolsPyExe) "Ok"
        Add-Result "Python" "installed" "embeddable -> tools\python + get-pip"
        return $true
    } catch {
        Write-RecLog ("[!] Embeddable Python install failed: {0}" -f $_.Exception.Message) "Warn"
        Write-Host "  Falling back to full python.org installer into tools\python..."
    }

    # Windows fallback: full installer TargetDir=tools\python
    $setup = Join-Path $script:RecTempDir "python-randall-amd64.exe"
    try {
        if ($Force -and (Test-Path -LiteralPath $setup)) {
            Remove-Item -LiteralPath $setup -Force -ErrorAction SilentlyContinue
        }
        if (-not (Test-Path -LiteralPath $setup) -or (Get-Item -LiteralPath $setup).Length -lt 1MB) {
            Download-WithProgress -Uri $PythonInstallerUrl -OutFile $setup
        }
        if (Test-Path -LiteralPath $toolsPyDir) {
            Remove-Item -LiteralPath $toolsPyDir -Recurse -Force -ErrorAction SilentlyContinue
        }
        New-Item -ItemType Directory -Force -Path $toolsPyDir | Out-Null
        Write-Host "  Running silent full installer (TargetDir=tools\python)..."
        $setupArgs = @(
            "/quiet",
            "TargetDir=$toolsPyDir",
            "InstallAllUsers=0",
            "PrependPath=0",
            "Include_pip=1",
            "Include_test=0",
            "Include_launcher=0",
            "Include_doc=0",
            "AssociateFiles=0",
            "Shortcuts=0",
            "SimpleInstall=1"
        )
        $setupParams = @{
            FilePath         = $setup
            ArgumentList     = $setupArgs
            Wait             = $true
            PassThru         = $true
        }
        if (Test-RecIsWindows) { $setupParams["WindowStyle"] = "Hidden" }
        $p = Start-Process @setupParams
        Start-Sleep -Seconds 2
        $toolsPyExe = Get-ToolsPythonExe
        if (Test-PythonExeWorks $toolsPyExe) {
            Write-RecLog ("Python installed: {0}" -f $toolsPyExe) "Ok"
            Add-Result "Python" "installed" "python.org TargetDir=tools\python"
            return $true
        }
        throw ("full installer exit {0}; tools\python\python.exe still unusable" -f $p.ExitCode)
    } catch {
        Write-RecLog ("[!] Python auto-install failed: {0}" -f $_.Exception.Message) "Warn"
        Write-Host "  Important: Settings -> Apps -> Advanced app settings -> App execution aliases"
        Write-Host "            Turn OFF python.exe and python3.exe (Microsoft Store stubs)."
        Write-Host "  Manual: extract python.org embeddable zip to tools\python, then re-run."
        Add-Result "Python" "failed" $_.Exception.Message
        return $false
    }
}

function Install-FridaTools {
    if ($SysinternalsOnly -or $SkipFrida) {
        Add-Result "frida-tools" "skipped" $(if ($SysinternalsOnly) { "-SysinternalsOnly" } else { "-SkipFrida" })
        return
    }

    if ($IncludeFrida) {
        Write-RecLog "Installing Frida (-IncludeFrida)..." "Cyan"
    } else {
        Write-RecLog "Installing Frida (default; use -SkipFrida to skip)..." "Cyan"
        Write-Host "  Note: Frida is a GUI/external companion - Randfuzz does not inject it."
    }

    # Frida uses ONLY tools\python - never PATH / Store alias (exit 9009).
    $py = Get-ToolsPythonExe
    Write-Host "  Frida Python path: $py (PATH python.exe is ignored)"

    if (-not (Test-PythonExeWorks $py)) {
        if ($SkipPython) {
            Write-RecLog "[!] tools\python missing and -SkipPython set." "Warn"
            Add-Result "frida-tools" "failed" "tools\python missing (-SkipPython)"
            Add-Result "Python" "skipped" "-SkipPython"
            return
        }
        Write-RecLog "tools\python not ready - installing Python into tools\python (not the Store stub)..." "Cyan"
        # Capture only the last bool - PowerShell functions can leak pipeline noise.
        $pyInstalled = @(Install-PythonRuntime | Where-Object { $_ -is [bool] } | Select-Object -Last 1)
        if (-not ($pyInstalled -contains $true)) {
            Add-Result "frida-tools" "failed" "python auto-install failed"
            return
        }
        $py = Get-ToolsPythonExe
    }

    if (-not (Test-PythonExeWorks $py)) {
        Write-RecLog "[!] tools\python still not usable - skip Frida." "Warn"
        Add-Result "frida-tools" "failed" "tools\python unusable"
        return
    }

    Write-Host ("  Using Python: {0}" -f $py)
    try {
        $pipVer = Invoke-NativeCapture -FilePath $py -ArgumentList @("-m", "pip", "--version")
        if ($pipVer.ExitCode -ne 0) {
            Write-Host "  Bootstrapping pip..."
            $gp = Join-Path $script:RecTempDir "randall-get-pip.py"
            if (-not (Test-Path -LiteralPath $gp) -or (Get-Item -LiteralPath $gp).Length -lt 10KB) {
                Download-WithProgress -Uri $GetPipUrl -OutFile $gp
            }
            $boot = Invoke-NativeCapture -FilePath $py -ArgumentList @($gp, "--no-warn-script-location")
            if ($boot.StdOut) { Write-Host $boot.StdOut.TrimEnd() }
            if ($boot.StdErr) { Write-Host $boot.StdErr.TrimEnd() }
            if ($boot.ExitCode -ne 0) { throw "get-pip exit $($boot.ExitCode)" }
        } else {
            if ($pipVer.StdOut) { Write-Host ("  {0}" -f $pipVer.StdOut.Trim()) }
        }

        Write-Host "  pip install --upgrade frida-tools ..."
        $code = Invoke-NativeCapture -FilePath $py -ArgumentList @(
            "-m", "pip", "install", "--upgrade", "frida-tools"
        )
        if ($code.StdOut) { Write-Host $code.StdOut.TrimEnd() }
        if ($code.StdErr) { Write-Host $code.StdErr.TrimEnd() }
        if ($code.ExitCode -ne 0) {
            throw "pip exit $($code.ExitCode)"
        }
        Write-RecLog "Frida tools installed via tools\python (Store python.exe was not used)." "Ok"
        Add-Result "frida-tools" "installed" ("pip via {0}" -f $py)
    } catch {
        Write-RecLog ("[!] Frida install failed: {0}" -f $_.Exception.Message) "Warn"
        Write-RecLog ("    Manual: `"{0}`" -m pip install frida-tools" -f $py) "Warn"
        Write-Host "  If Microsoft Store python still appears: turn OFF App execution aliases for python.exe"
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
