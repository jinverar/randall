# Pull latest Randall source and rebuild CLI, Server, and lab targets.
# Does NOT re-download DynamoRIO, Sysinternals, gcc, etc. unless -InstallTools.
#
# Examples:
#   powershell -ExecutionPolicy Bypass -File .\scripts\update-lab.ps1
#   powershell -ExecutionPolicy Bypass -File .\scripts\update-lab.ps1 -InstallTools
#   powershell -ExecutionPolicy Bypass -File .\scripts\update-lab.ps1 -SkipPull
#   powershell -ExecutionPolicy Bypass -File .\scripts\update-lab.ps1 -SkipLabTargets
#   powershell -ExecutionPolicy Bypass -File .\scripts\update-lab.ps1 -SkipGitInstall
[CmdletBinding()]
param(
    [switch]$InstallTools,
    [switch]$SkipPull,
    [switch]$SkipLabTargets,
    [switch]$SkipGcc,
    [switch]$SkipGitInstall
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

function Refresh-SessionPath {
    $machine = [Environment]::GetEnvironmentVariable("Path", "Machine")
    $user = [Environment]::GetEnvironmentVariable("Path", "User")
    $env:Path = (@($machine, $user) | Where-Object { $_ }) -join ";"
}

function Add-SessionPathEntry {
    param([string]$Dir)
    if (-not $Dir -or -not (Test-Path $Dir)) { return $false }
    $norm = $Dir.TrimEnd('\')
    foreach ($part in ($env:Path -split ";")) {
        if ($part -and ($part.TrimEnd('\') -ieq $norm)) { return $false }
    }
    $env:Path = "$norm;$env:Path"
    return $true
}

function Find-GitCandidates {
    $candidates = [System.Collections.Generic.List[string]]::new()
    $dirs = @(
        "C:\Program Files\Git\cmd",
        "C:\Program Files\Git\bin",
        (Join-Path $env:LOCALAPPDATA "Programs\Git\cmd"),
        (Join-Path $env:LOCALAPPDATA "Programs\Git\bin"),
        "$env:LOCALAPPDATA\Microsoft\WinGet\Links",
        "$env:ProgramFiles\WinGet\Links"
    )
    foreach ($dir in $dirs) {
        if (-not (Test-Path $dir)) { continue }
        $gitExe = Join-Path $dir "git.exe"
        if ((Test-Path $gitExe) -and -not $candidates.Contains($gitExe)) {
            $candidates.Add($gitExe) | Out-Null
        }
    }
    foreach ($wgRoot in @(
            (Join-Path $env:LOCALAPPDATA "Microsoft\WinGet\Packages"),
            (Join-Path ${env:ProgramFiles} "WinGet\Packages")
        )) {
        if (-not (Test-Path $wgRoot)) { continue }
        Get-ChildItem -Path $wgRoot -Filter "git.exe" -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match 'Git\\cmd\\git\.exe$|Git\\bin\\git\.exe$|\\Git\.Git\\' } |
            Select-Object -First 4 |
            ForEach-Object {
                if (-not $candidates.Contains($_.FullName)) { $candidates.Add($_.FullName) | Out-Null }
            }
    }
    return $candidates
}

function Resolve-GitExecutable {
    Refresh-SessionPath
    $cmd = Get-Command git -ErrorAction SilentlyContinue
    if ($cmd -and $cmd.Source) { return $cmd.Source }

    foreach ($candidate in (Find-GitCandidates)) {
        $bin = Split-Path $candidate -Parent
        Add-SessionPathEntry $bin | Out-Null
        $cmd = Get-Command git -ErrorAction SilentlyContinue
        if ($cmd -and $cmd.Source) { return $cmd.Source }
        if (Test-Path $candidate) { return $candidate }
    }
    return $null
}

function Show-GitManualInstallHelp {
    Write-UpdateLog "" "Warn"
    Write-UpdateLog "[x] Git is required for git pull but was not found on PATH." "Error"
    Write-UpdateLog "    Install Git for Windows, then re-run this script:" "Warn"
    Write-UpdateLog "      winget install -e --id Git.Git --accept-package-agreements --accept-source-agreements" "Cyan"
    Write-UpdateLog "    Or download: https://git-scm.com/download/win" "Cyan"
    Write-UpdateLog "    Offline / no pull: re-run with -SkipPull (rebuild only; no source update)." "Warn"
    Write-UpdateLog "    Skip auto-install attempt: -SkipGitInstall" "Warn"
}

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

function Install-GitViaWinget {
    $winget = Test-WingetAvailable
    if (-not $winget) {
        Write-UpdateLog "[!] winget not available; cannot auto-install Git." "Warn"
        return $false
    }

    Write-UpdateLog "Git not found — installing Git for Windows via winget (Git.Git)..." "Cyan"
    $log = Join-Path $env:TEMP "randall-winget-git.log"
    $argSets = @(
        @("install", "-e", "--id", "Git.Git", "--accept-package-agreements", "--accept-source-agreements", "--scope", "user"),
        @("install", "-e", "--id", "Git.Git", "--accept-package-agreements", "--accept-source-agreements")
    )
    foreach ($wingetArgs in $argSets) {
        $prev = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        & winget @wingetArgs 2>&1 | Tee-Object -FilePath $log | ForEach-Object { Write-Host $_ }
        $code = $LASTEXITCODE
        $ErrorActionPreference = $prev
        if ($null -eq $code) { $code = 0 }
        if ($code -eq 0) {
            Write-UpdateLog "[ok] Git installed via winget." "Ok"
            return $true
        }
        Write-UpdateLog "[!] winget exit $code (see $log); trying next install mode..." "Warn"
    }
    return $false
}

function Ensure-GitForPull {
    $gitExe = Resolve-GitExecutable
    if ($gitExe) {
        Write-UpdateLog "Git: $gitExe" "Ok"
        return $gitExe
    }

    if ($SkipGitInstall) {
        Show-GitManualInstallHelp
        exit 1
    }

    if (-not (Install-GitViaWinget)) {
        Show-GitManualInstallHelp
        exit 1
    }

    Refresh-SessionPath
    $gitExe = Resolve-GitExecutable
    if (-not $gitExe) {
        Write-UpdateLog "[!] Git was installed but is not on PATH yet in this session." "Warn"
        Show-GitManualInstallHelp
        exit 1
    }

    Write-UpdateLog "Git: $gitExe" "Ok"
    return $gitExe
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
    $gitExe = Ensure-GitForPull
    & $gitExe -C $Root pull --ff-only
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
