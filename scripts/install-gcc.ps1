# Install MinGW gcc on Windows so Scream/native helpers can build.
# Idempotent. Prefer winget (WinLibs); fall back to Chocolatey or clear manual steps.
#
# Examples:
#   powershell -ExecutionPolicy Bypass -File .\scripts\install-gcc.ps1
#   powershell -ExecutionPolicy Bypass -File .\scripts\install-gcc.ps1 -Skip
#   powershell -ExecutionPolicy Bypass -File .\scripts\install-gcc.ps1 -Force
param(
    [switch]$Skip,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

# WinLibs: real MinGW-w64 gcc on PATH via winget (portable zip).
# Strawberry: MSI fallback that also ships gcc (C:\Strawberry\c\bin).
$WingetPackages = @(
    @{ Id = "BrechtSanders.WinLibs.POSIX.UCRT"; Name = "WinLibs MinGW (POSIX/UCRT)" },
    @{ Id = "StrawberryPerl.StrawberryPerl"; Name = "Strawberry Perl (includes gcc)" }
)

function Refresh-SessionPath {
    $machine = [Environment]::GetEnvironmentVariable("Path", "Machine")
    $user = [Environment]::GetEnvironmentVariable("Path", "User")
    $env:Path = (@($machine, $user) | Where-Object { $_ }) -join ";"
}

function Find-GccCandidates {
    $dirs = @(
        "C:\Strawberry\c\bin",
        "C:\mingw64\bin",
        "C:\mingw\bin",
        "C:\msys64\mingw64\bin",
        "C:\ProgramData\mingw64\mingw64\bin",
        "C:\Program Files\mingw-w64\*\mingw64\bin",
        "C:\Program Files\WinLibs\*\bin",
        "$env:LOCALAPPDATA\Microsoft\WinGet\Packages\BrechtSanders.WinLibs*\*\bin",
        "$env:LOCALAPPDATA\Microsoft\WinGet\Packages\BrechtSanders.WinLibs*\mingw64\bin",
        "$env:LOCALAPPDATA\Microsoft\WinGet\Links"
    )
    foreach ($pattern in $dirs) {
        Get-Item -Path $pattern -ErrorAction SilentlyContinue |
            ForEach-Object {
                $gccPath = Join-Path $_.FullName "gcc.exe"
                if (Test-Path $gccPath) { $gccPath }
            }
    }
}

function Test-GccAvailable {
    Refresh-SessionPath
    $cmd = Get-Command gcc -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }

    foreach ($candidate in (Find-GccCandidates)) {
        $bin = Split-Path $candidate -Parent
        if ($env:Path -notlike "*$bin*") {
            $env:Path = "$bin;$env:Path"
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
    } catch {
        Write-Host "gcc: $GccPath"
    }
}

function Ensure-UserPathEntry {
    param([string]$Dir)
    if (-not (Test-Path $Dir)) { return }
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if (-not $userPath) { $userPath = "" }
    $parts = $userPath -split ";" | Where-Object { $_ }
    if ($parts -contains $Dir) { return }
    $newPath = if ($userPath.TrimEnd(";")) { "$userPath;$Dir" } else { $Dir }
    [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
    Write-Host "Added to user PATH: $Dir"
    Refresh-SessionPath
}

function Install-ViaWinget {
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if (-not $winget) { return $false }

    foreach ($pkg in $WingetPackages) {
        Write-Host ""
        Write-Host ("Trying winget: {0} ({1})..." -f $pkg.Name, $pkg.Id) -ForegroundColor Cyan
        Write-Host "This may take a few minutes; Ctrl+C to cancel, then re-run or use -Skip."
        $args = @(
            "install", "--id", $pkg.Id,
            "-e", "--accept-package-agreements", "--accept-source-agreements",
            "--disable-interactivity"
        )
        & winget @args
        $code = $LASTEXITCODE
        # 0 = success, -1978335189 (0x8A15002B) often means already installed
        if ($code -ne 0 -and $code -ne -1978335189) {
            Write-Host ("[!] winget exit {0} for {1} - trying next option..." -f $code, $pkg.Id) -ForegroundColor Yellow
            continue
        }

        Refresh-SessionPath
        Start-Sleep -Seconds 1
        $gcc = Test-GccAvailable
        if ($gcc) {
            # Persist common WinLibs / Strawberry bin dirs for new shells
            foreach ($candidate in (Find-GccCandidates)) {
                Ensure-UserPathEntry (Split-Path $candidate -Parent)
            }
            return $true
        }

        Write-Host "[!] Package installed but gcc not on PATH yet - trying next / probing..." -ForegroundColor Yellow
    }
    return $false
}

function Install-ViaChocolatey {
    $choco = Get-Command choco -ErrorAction SilentlyContinue
    if (-not $choco) { return $false }

    Write-Host ""
    Write-Host "Trying Chocolatey: mingw..." -ForegroundColor Cyan
    & choco install mingw -y
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[!] choco mingw failed; trying strawberryperl..." -ForegroundColor Yellow
        & choco install strawberryperl -y
        if ($LASTEXITCODE -ne 0) { return $false }
    }

    Refresh-SessionPath
    Start-Sleep -Seconds 1
    $gcc = Test-GccAvailable
    if ($gcc) {
        foreach ($candidate in (Find-GccCandidates)) {
            Ensure-UserPathEntry (Split-Path $candidate -Parent)
        }
        return $true
    }
    return $false
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
    exit 0
}

if ($Force -and $existing) {
    Write-Host "gcc already present; -Force will still try package install / PATH refresh."
    Show-GccVersion $existing
}

Write-Host "gcc not found (or -Force). Installing MinGW gcc for Scream/native helpers..."
Write-Host "Preferred: winget WinLibs (BrechtSanders.WinLibs.POSIX.UCRT)"
Write-Host "Fallback:  Strawberry Perl via winget, then Chocolatey mingw/strawberryperl"
Write-Host ""

$ok = Install-ViaWinget
if (-not $ok) { $ok = Install-ViaChocolatey }

$gcc = Test-GccAvailable
if ($gcc) {
    Write-Host ""
    Write-Host "gcc ready for this session." -ForegroundColor Green
    Show-GccVersion $gcc
    Write-Host "If a new PowerShell window still lacks gcc, close and reopen the shell (PATH refresh)."
    exit 0
}

Write-Host ""
Write-Host "[!] Could not install gcc automatically." -ForegroundColor Yellow
Write-Host "    Manual options:"
Write-Host "      winget install -e --id BrechtSanders.WinLibs.POSIX.UCRT"
Write-Host "      winget install -e --id StrawberryPerl.StrawberryPerl"
Write-Host "      Or install from https://winlibs.com/ / https://strawberryperl.com/ then open a new shell."
Write-Host "    Then re-run: powershell -ExecutionPolicy Bypass -File .\scripts\build-screamcrash.ps1"
Write-Host "    Or skip Scream: powershell -ExecutionPolicy Bypass -File .\scripts\build-all-lab-targets.ps1 -SkipGcc"
exit 1
