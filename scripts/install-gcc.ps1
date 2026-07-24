# Install MinGW gcc on Windows so Scream/native helpers can build.
# Idempotent. Primary path: direct WinLibs zip (no admin, no winget) under
# tools\mingw64 or %LOCALAPPDATA%\Randfuzz\mingw64. Optional: winget / Chocolatey.
#
# Examples:
#   powershell -ExecutionPolicy Bypass -File .\scripts\install-gcc.ps1
#   powershell -ExecutionPolicy Bypass -File .\scripts\install-gcc.ps1 -Verbose
#   powershell -ExecutionPolicy Bypass -File .\scripts\install-gcc.ps1 -Skip
#   powershell -ExecutionPolicy Bypass -File .\scripts\install-gcc.ps1 -Force
[CmdletBinding()]
param(
    [switch]$Skip,
    [switch]$Force,
    [string]$ZipUrl = "",
    [string]$InstallDir = ""
)

$ErrorActionPreference = "Stop"
$Root = Split-Path $PSScriptRoot -Parent

# WinLibs: real MinGW-w64 gcc on PATH via winget (portable zip).
# Strawberry: MSI fallback that also ships gcc (C:\Strawberry\c\bin).
$WingetPackages = @(
    @{ Id = "BrechtSanders.WinLibs.POSIX.UCRT"; Name = "WinLibs MinGW (POSIX/UCRT)" },
    @{ Id = "StrawberryPerl.StrawberryPerl"; Name = "Strawberry Perl (includes gcc)" }
)

# Pinned WinLibs x86_64 POSIX/UCRT zip (Windows can Expand-Archive / tar without 7-Zip).
# Override with -ZipUrl if this release moves.
$DefaultWinLibsZipUrl = "https://github.com/brechtsanders/winlibs_mingw/releases/download/16.1.0posix-14.0.0-ucrt-r3/winlibs-x86_64-posix-seh-gcc-16.1.0-mingw-w64ucrt-14.0.0-r3.zip"
$script:LastInstallError = $null

function Write-GccLog {
    param([string]$Message, [string]$Level = "Info")
    switch ($Level) {
        "Warn"  { Write-Host $Message -ForegroundColor Yellow }
        "Error" { Write-Host $Message -ForegroundColor Red }
        "Ok"    { Write-Host $Message -ForegroundColor Green }
        "Cyan"  { Write-Host $Message -ForegroundColor Cyan }
        default { Write-Host $Message }
    }
    Write-Verbose $Message
}

function Refresh-SessionPath {
    $machine = [Environment]::GetEnvironmentVariable("Path", "Machine")
    $user = [Environment]::GetEnvironmentVariable("Path", "User")
    $env:Path = (@($machine, $user) | Where-Object { $_ }) -join ";"
}

function Get-PreferredMingwRoot {
    if ($InstallDir) { return $InstallDir.TrimEnd('\') }

    $repoTools = Join-Path $Root "tools\mingw64"
    $localApp = Join-Path $env:LOCALAPPDATA "Randfuzz\mingw64"

    # Prefer repo tools\ if we can create/write there; else per-user LocalAppData (no admin).
    try {
        $toolsParent = Join-Path $Root "tools"
        if (-not (Test-Path $toolsParent)) {
            New-Item -ItemType Directory -Force -Path $toolsParent | Out-Null
        }
        $probe = Join-Path $toolsParent ".write-probe"
        [IO.File]::WriteAllText($probe, "ok")
        Remove-Item $probe -Force -ErrorAction SilentlyContinue
        return $repoTools
    } catch {
        Write-Verbose ("Repo tools\ not writable ({0}); using {1}" -f $_.Exception.Message, $localApp)
        return $localApp
    }
}

function Find-GccCandidates {
    $preferred = Get-PreferredMingwRoot
    $dirs = @(
        (Join-Path $preferred "bin"),
        (Join-Path $Root "tools\mingw64\bin"),
        (Join-Path $env:LOCALAPPDATA "Randfuzz\mingw64\bin"),
        "C:\Strawberry\c\bin",
        "C:\mingw64\bin",
        "C:\mingw\bin",
        "C:\msys64\mingw64\bin",
        "C:\ProgramData\mingw64\mingw64\bin",
        "C:\Program Files\mingw-w64\*\mingw64\bin",
        "C:\Program Files\WinLibs\*\bin",
        "C:\Program Files\WinLibs\mingw64\bin",
        "$env:LOCALAPPDATA\Microsoft\WinGet\Packages\BrechtSanders.WinLibs*\*\bin",
        "$env:LOCALAPPDATA\Microsoft\WinGet\Packages\BrechtSanders.WinLibs*\mingw64\bin",
        "$env:LOCALAPPDATA\Microsoft\WinGet\Packages\BrechtSanders.WinLibs*\*\mingw64\bin",
        "$env:LOCALAPPDATA\Microsoft\WinGet\Links",
        "$env:ProgramFiles\WinGet\Links"
    )
    $found = [System.Collections.Generic.List[string]]::new()
    foreach ($pattern in $dirs) {
        Get-Item -Path $pattern -ErrorAction SilentlyContinue |
            ForEach-Object {
                $gccPath = Join-Path $_.FullName "gcc.exe"
                if ((Test-Path $gccPath) -and -not $found.Contains($gccPath)) {
                    $found.Add($gccPath) | Out-Null
                }
            }
    }

    # Deep probe WinGet package trees (layout varies by version).
    $wingetRoots = @(
        (Join-Path $env:LOCALAPPDATA "Microsoft\WinGet\Packages"),
        (Join-Path ${env:ProgramFiles} "WinGet\Packages")
    )
    foreach ($wgRoot in $wingetRoots) {
        if (-not (Test-Path $wgRoot)) { continue }
        Get-ChildItem -Path $wgRoot -Filter "gcc.exe" -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match 'WinLibs|mingw64|Strawberry' } |
            Select-Object -First 8 |
            ForEach-Object {
                if (-not $found.Contains($_.FullName)) { $found.Add($_.FullName) | Out-Null }
            }
    }

    return $found
}

function Test-GccAvailable {
    Refresh-SessionPath
    $cmd = Get-Command gcc -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }

    foreach ($candidate in (Find-GccCandidates)) {
        $bin = Split-Path $candidate -Parent
        if ($env:Path -notlike "*$bin*") {
            $env:Path = "$bin;$env:Path"
            Write-Verbose "Prepended to session PATH: $bin"
        }
        $cmd = Get-Command gcc -ErrorAction SilentlyContinue
        if ($cmd) { return $cmd.Source }
        if (Test-Path $candidate) { return $candidate }
    }
    return $null
}

function Show-GccVersion {
    param([string]$GccPath)
    try {
        $ver = & $GccPath --version 2>&1 | Select-Object -First 1
        Write-Host "gcc: $GccPath"
        Write-Host "     $ver"
        return [string]$ver
    } catch {
        Write-Host "gcc: $GccPath"
        return $null
    }
}

function Ensure-UserPathEntry {
    param([string]$Dir)
    if (-not (Test-Path $Dir)) { return }
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if (-not $userPath) { $userPath = "" }
    $parts = $userPath -split ";" | Where-Object { $_ }
    if ($parts -contains $Dir) {
        Write-Verbose "User PATH already contains: $Dir"
        return
    }
    # Prepend so gcc wins over stale entries.
    $newPath = if ($userPath.TrimEnd(";")) { "$Dir;$userPath" } else { $Dir }
    [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
    Write-GccLog "Added to user PATH: $Dir" "Ok"
    if ($env:Path -notlike "*$Dir*") {
        $env:Path = "$Dir;$env:Path"
    }
    Refresh-SessionPath
}

function Persist-GccBinPaths {
    foreach ($candidate in (Find-GccCandidates)) {
        Ensure-UserPathEntry (Split-Path $candidate -Parent)
    }
}

function Test-WingetAvailable {
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if (-not $winget) {
        Write-Verbose "winget not found on PATH"
        return $null
    }
    try {
        $prev = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        $verOut = & winget --version 2>&1
        $ErrorActionPreference = $prev
        if ($LASTEXITCODE -ne 0 -and -not ($verOut -match '\d+\.\d+')) {
            $script:LastInstallError = "winget --version failed: $verOut"
            Write-GccLog "[!] winget present but not usable: $verOut" "Warn"
            return $null
        }
        Write-Verbose ("winget OK: {0}" -f ($verOut | Select-Object -First 1))
        return $winget
    } catch {
        $script:LastInstallError = "winget --version threw: $($_.Exception.Message)"
        Write-GccLog "[!] winget probe failed: $($_.Exception.Message)" "Warn"
        return $null
    }
}

function Install-ViaWinget {
    $winget = Test-WingetAvailable
    if (-not $winget) {
        Write-Verbose "winget not available (optional); skipping"
        return $false
    }

    foreach ($pkg in $WingetPackages) {
        Write-GccLog ("Trying winget: {0} ({1})..." -f $pkg.Name, $pkg.Id) "Cyan"
        Write-Host "This may take a few minutes; Ctrl+C to cancel, then re-run or use -Skip."

        $log = Join-Path $env:TEMP ("randall-winget-{0}.log" -f ($pkg.Id -replace '[^\w\.-]', '_'))
        $args = @(
            "install", "--id", $pkg.Id,
            "-e", "--accept-package-agreements", "--accept-source-agreements",
            "--disable-interactivity", "--scope", "user"
        )
        Write-Verbose ("winget args: {0}" -f ($args -join ' '))

        $prev = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        try {
            & winget @args 2>&1 | Tee-Object -FilePath $log | ForEach-Object { Write-Host $_ }
            $code = $LASTEXITCODE
        } catch {
            $code = -1
            $_ | Out-File -FilePath $log -Append
            Write-GccLog ("[!] winget threw for {0}: {1}" -f $pkg.Id, $_.Exception.Message) "Warn"
        } finally {
            $ErrorActionPreference = $prev
        }

        # 0 = success, -1978335189 (0x8A15002B) = already installed
        # -1978335212 (0x8A150014) = no applicable upgrade / already present (some builds)
        $okCodes = @(0, -1978335189, -1978335212)
        if ($okCodes -notcontains $code) {
            # Retry without --scope user (some packages reject user scope).
            Write-Verbose ("winget exit {0} with --scope user; retrying without scope..." -f $code)
            $argsNoScope = @(
                "install", "--id", $pkg.Id,
                "-e", "--accept-package-agreements", "--accept-source-agreements",
                "--disable-interactivity"
            )
            $ErrorActionPreference = "Continue"
            try {
                & winget @argsNoScope 2>&1 | Tee-Object -FilePath $log | ForEach-Object { Write-Host $_ }
                $code = $LASTEXITCODE
            } catch {
                $code = -1
                $_ | Out-File -FilePath $log -Append
            } finally {
                $ErrorActionPreference = $prev
            }
        }

        if ($okCodes -notcontains $code) {
            $tail = ""
            if (Test-Path $log) {
                $tail = (Get-Content $log -ErrorAction SilentlyContinue | Select-Object -Last 15) -join "`n"
            }
            $script:LastInstallError = ("winget exit {0} for {1}. Log: {2}`n{3}" -f $code, $pkg.Id, $log, $tail)
            Write-GccLog ("[!] winget exit {0} for {1}" -f $code, $pkg.Id) "Warn"
            if ($tail) { Write-Host $tail }
            continue
        }

        Refresh-SessionPath
        Start-Sleep -Seconds 1
        $gcc = Test-GccAvailable
        if ($gcc) {
            Persist-GccBinPaths
            return $true
        }

        Write-GccLog "[!] Package reported OK but gcc not found yet - probing / next option..." "Warn"
        Write-Verbose ("winget log: {0}" -f $log)
    }
    return $false
}

function Install-ViaChocolatey {
    $choco = Get-Command choco -ErrorAction SilentlyContinue
    if (-not $choco) {
        Write-Verbose "Chocolatey not found"
        return $false
    }

    Write-GccLog "Trying Chocolatey: mingw..." "Cyan"
    $prev = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    & choco install mingw -y
    $code = $LASTEXITCODE
    if ($code -ne 0) {
        Write-GccLog "[!] choco mingw failed (exit $code); trying strawberryperl..." "Warn"
        & choco install strawberryperl -y
        $code = $LASTEXITCODE
        if ($code -ne 0) {
            $script:LastInstallError = "choco strawberryperl exit $code"
            $ErrorActionPreference = $prev
            return $false
        }
    }
    $ErrorActionPreference = $prev

    Refresh-SessionPath
    Start-Sleep -Seconds 1
    $gcc = Test-GccAvailable
    if ($gcc) {
        Persist-GccBinPaths
        return $true
    }
    $script:LastInstallError = "choco install finished but gcc still not found"
    return $false
}

function Format-Bytes {
    param([long]$Bytes)
    if ($Bytes -ge 1GB) { return "{0:N2} GB" -f ($Bytes / 1GB) }
    if ($Bytes -ge 1MB) { return "{0:N1} MB" -f ($Bytes / 1MB) }
    if ($Bytes -ge 1KB) { return "{0:N0} KB" -f ($Bytes / 1KB) }
    return "$Bytes B"
}

function Download-File {
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
        Write-Verbose "URL: $Uri"
        Start-BitsTransfer -Source $Uri -Destination $OutFile -DisplayName "WinLibs MinGW" -Description "Randall gcc zip"
        return
    } catch {
        Write-GccLog ("BITS unavailable ({0}); falling back to Invoke-WebRequest..." -f $_.Exception.Message) "Warn"
    }

    Write-Host "Downloading with Invoke-WebRequest (no resume)..."
    Write-Verbose "URL: $Uri"
    $tmpPartial = "$OutFile.partial"
    try {
        Invoke-WebRequest -Uri $Uri -OutFile $tmpPartial -UseBasicParsing
        Move-Item -Force $tmpPartial $OutFile
    } catch {
        Remove-Item $tmpPartial -Force -ErrorAction SilentlyContinue
        throw
    }
}

function Install-ViaWinLibsZip {
    $destRoot = Get-PreferredMingwRoot
    $destBin = Join-Path $destRoot "bin"
    $marker = Join-Path $destBin "gcc.exe"

    if ((Test-Path $marker) -and -not $Force) {
        Write-GccLog "Found existing WinLibs gcc at $marker - updating PATH..." "Cyan"
        Ensure-UserPathEntry $destBin
        return $true
    }

    $url = if ($ZipUrl) { $ZipUrl } else { $DefaultWinLibsZipUrl }
    Write-GccLog "Trying direct WinLibs zip (no admin required)..." "Cyan"
    Write-Host "  Dest: $destRoot"
    Write-Host "  URL:  $url"
    Write-Host "  (~260+ MB download; may take several minutes on a VM)"

    $zipName = Split-Path $url -Leaf
    if (-not $zipName) { $zipName = "winlibs-mingw64.zip" }
    $zipPath = Join-Path $env:TEMP $zipName
    $extractRoot = Join-Path $env:TEMP "randall-winlibs-extract"

    try {
        if ($Force -and (Test-Path $zipPath)) {
            Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
        }
        if (-not (Test-Path $zipPath) -or (Get-Item $zipPath).Length -lt 1MB) {
            Download-File -Uri $url -OutFile $zipPath
        } else {
            Write-Verbose ("Reusing existing zip: {0} ({1})" -f $zipPath, (Format-Bytes (Get-Item $zipPath).Length))
        }

        if (Test-Path $extractRoot) {
            Remove-Item $extractRoot -Recurse -Force
        }
        New-Item -ItemType Directory -Force -Path $extractRoot | Out-Null

        Write-Host "Extracting (this can take a minute)..."
        $tar = Get-Command tar.exe -ErrorAction SilentlyContinue
        if ($tar) {
            $prev = $ErrorActionPreference
            $ErrorActionPreference = "Continue"
            & tar.exe -xf $zipPath -C $extractRoot
            $tarCode = $LASTEXITCODE
            $ErrorActionPreference = $prev
            if ($tarCode -ne 0) {
                Write-Verbose "tar.exe failed (exit $tarCode); trying Expand-Archive..."
                Expand-Archive -Path $zipPath -DestinationPath $extractRoot -Force
            }
        } else {
            Expand-Archive -Path $zipPath -DestinationPath $extractRoot -Force
        }

        # Zip layout is typically mingw64\bin\gcc.exe at top level.
        $gccFound = Get-ChildItem -Path $extractRoot -Filter "gcc.exe" -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.DirectoryName -match '\\bin$' } |
            Select-Object -First 1
        if (-not $gccFound) {
            throw "Unexpected WinLibs zip layout - gcc.exe not found under $extractRoot"
        }

        $mingwFromZip = Split-Path (Split-Path $gccFound.FullName -Parent) -Parent
        Write-Verbose "Extracted mingw root: $mingwFromZip"

        $destParent = Split-Path $destRoot -Parent
        if (-not (Test-Path $destParent)) {
            New-Item -ItemType Directory -Force -Path $destParent | Out-Null
        }
        if (Test-Path $destRoot) {
            Remove-Item $destRoot -Recurse -Force
        }
        Move-Item -Path $mingwFromZip -Destination $destRoot

        if (-not (Test-Path $marker)) {
            throw "Install moved to $destRoot but $marker is missing"
        }

        Ensure-UserPathEntry $destBin
        Write-GccLog "Installed WinLibs MinGW to $destRoot" "Ok"
        return $true
    } catch {
        $script:LastInstallError = "WinLibs zip install failed: $($_.Exception.Message)"
        Write-GccLog "[!] $($script:LastInstallError)" "Error"
        return $false
    } finally {
        Remove-Item $extractRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# --- main ---
if ($Skip) {
    Write-Host "Skipping gcc install (-Skip). Scream/native helpers will be skipped without gcc."
    exit 0
}

$existing = Test-GccAvailable
if ($existing -and -not $Force) {
    Write-Host "gcc already available."
    Show-GccVersion $existing
    Persist-GccBinPaths
    exit 0
}

if ($Force -and $existing) {
    Write-Host "gcc already present; -Force will still try package install / PATH refresh."
    Show-GccVersion $existing
}

Write-Host "gcc not found (or -Force). Installing MinGW gcc for Scream/native helpers..."
Write-Host "1) Direct WinLibs zip (primary; no admin / winget required)"
Write-Host "   -> tools\mingw64 or %LOCALAPPDATA%\Randfuzz\mingw64"
Write-Host "2) winget (optional, if installed)"
Write-Host "3) Chocolatey (optional, if installed)"
Write-Host ""

# Fresh Win10 VMs often have no winget - zip is the reliable primary path.
$ok = Install-ViaWinLibsZip
if (-not $ok) {
    Write-GccLog "Zip install failed; trying winget if available..." "Warn"
    $ok = Install-ViaWinget
}
if (-not $ok) { $ok = Install-ViaChocolatey }

$gcc = Test-GccAvailable
if ($gcc) {
    Persist-GccBinPaths
    Write-Host ""
    Write-GccLog "gcc ready for this session." "Ok"
    Show-GccVersion $gcc
    Write-Host "Open a new PowerShell window if another shell still lacks gcc (user PATH was updated)."
    exit 0
}

Write-Host ""
Write-GccLog "[!] Could not install gcc automatically." "Error"
if ($script:LastInstallError) {
    Write-Host "Last error:"
    Write-Host $script:LastInstallError
}
Write-Host "Manual options (no winget needed):"
Write-Host "  1) Re-run with logs:"
Write-Host "       powershell -ExecutionPolicy Bypass -File .\scripts\install-gcc.ps1 -Verbose"
Write-Host "  2) Download x86_64 POSIX UCRT .zip from https://winlibs.com/"
Write-Host "       Extract so mingw64\bin\gcc.exe exists, then:"
Write-Host "       [Environment]::SetEnvironmentVariable('Path', `"$env:LOCALAPPDATA\Randfuzz\mingw64\bin;`" + [Environment]::GetEnvironmentVariable('Path','User'), 'User')"
Write-Host "  3) If you have winget: winget install -e --id BrechtSanders.WinLibs.POSIX.UCRT --accept-package-agreements --accept-source-agreements"
Write-Host "Then open a NEW shell and: gcc --version"
Write-Host "Re-run: powershell -ExecutionPolicy Bypass -File .\scripts\build-screamcrash.ps1"
Write-Host "Or skip Scream: powershell -ExecutionPolicy Bypass -File .\scripts\build-all-lab-targets.ps1 -SkipGcc"
exit 1
