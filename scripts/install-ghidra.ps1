# Download Ghidra into tools/ghidra-app (gitignored lab dependency).
# Randfuzz Script Manager Python importers stay in committed tools/ghidra/ - do not overwrite.
# Optional RE GUI (~560 MB); Ghidra 12.x needs JDK 21.
#
# Examples:
#   powershell -ExecutionPolicy Bypass -File .\scripts\install-ghidra.ps1
#   powershell -ExecutionPolicy Bypass -File .\scripts\install-ghidra.ps1 -Skip
#   powershell -ExecutionPolicy Bypass -File .\scripts\install-ghidra.ps1 -ZipPath C:\Users\007\Downloads\ghidra_12.1.2_PUBLIC_20260605.zip
#   powershell -ExecutionPolicy Bypass -File .\scripts\install-ghidra.ps1 -Force
#   powershell -ExecutionPolicy Bypass -File .\scripts\install-ghidra.ps1 -DragonDance
#   powershell -ExecutionPolicy Bypass -File .\scripts\install-ghidra.ps1 -GhidraMcp
[CmdletBinding()]
param(
    [string]$Version = "",
    [string]$ZipPath = "",
    [switch]$Skip,
    [switch]$Force,
    [switch]$SkipJdk,
    [switch]$DragonDance,
    [switch]$GhidraMcp
)

$ErrorActionPreference = "Stop"
$Root = Split-Path $PSScriptRoot -Parent
$Dest = Join-Path $Root "tools\ghidra-app"
$ToolsDir = Join-Path $Root "tools"
$ScriptsDir = Join-Path $Root "tools\ghidra"
$Marker = Join-Path $Dest "ghidraRun.bat"
$script:Results = [System.Collections.Generic.List[object]]::new()

function Write-GhidraLog {
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

function Format-Bytes {
    param([long]$Bytes)
    if ($Bytes -ge 1GB) { return "{0:N2} GB" -f ($Bytes / 1GB) }
    if ($Bytes -ge 1MB) { return "{0:N1} MB" -f ($Bytes / 1MB) }
    if ($Bytes -ge 1KB) { return "{0:N0} KB" -f ($Bytes / 1KB) }
    return "$Bytes B"
}

function Refresh-SessionPath {
    $machine = [Environment]::GetEnvironmentVariable("Path", "Machine")
    $user = [Environment]::GetEnvironmentVariable("Path", "User")
    $env:Path = (@($machine, $user) | Where-Object { $_ }) -join ";"
}

function Test-GhidraInstalled {
    param([string]$Path)
    return (Test-Path (Join-Path $Path "ghidraRun.bat")) -or (Test-Path (Join-Path $Path "ghidraRun"))
}

function Find-JavaHome {
    $jh = [Environment]::GetEnvironmentVariable("JAVA_HOME", "User")
    if (-not $jh) { $jh = [Environment]::GetEnvironmentVariable("JAVA_HOME", "Machine") }
    if ($jh -and (Test-Path (Join-Path $jh "bin\java.exe"))) { return $jh }

    Refresh-SessionPath
    $java = Get-Command java.exe -ErrorAction SilentlyContinue
    if ($java) {
        $bin = Split-Path $java.Source -Parent
        $home = Split-Path $bin -Parent
        if (Test-Path (Join-Path $home "bin\java.exe")) { return $home }
    }

    foreach ($root in @(
        ${env:ProgramFiles},
        ${env:ProgramFiles(x86)},
        (Join-Path $env:LOCALAPPDATA "Programs")
    )) {
        if (-not $root -or -not (Test-Path $root)) { continue }
        foreach ($pattern in @("Microsoft\jdk-*", "Eclipse Adoptium\jdk-*", "*jdk*")) {
            $hits = Get-ChildItem -Path $root -Directory -Filter $pattern -ErrorAction SilentlyContinue -Recurse -Depth 2
            foreach ($hit in $hits) {
                if (Test-Path (Join-Path $hit.FullName "bin\java.exe")) { return $hit.FullName }
            }
        }
    }
    return $null
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

function Invoke-WingetInstall {
    param([string]$PackageId, [string]$Name)
    $winget = Test-WingetAvailable
    if (-not $winget) {
        Write-GhidraLog "  winget not available." "Warn"
        return $false
    }

    Write-GhidraLog ("  winget install {0} ({1})..." -f $Name, $PackageId) "Cyan"
    $log = Join-Path $env:TEMP ("randall-winget-{0}.log" -f ($PackageId -replace '[^\w\.-]', '_'))
    $wingetArgs = @("install", "--id", $PackageId, "-e", "--accept-package-agreements", "--accept-source-agreements", "--disable-interactivity")
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
    if ($code -eq 0 -or $code -eq -1978335189) {
        Refresh-SessionPath
        return $true
    }
    Write-GhidraLog ("  winget failed for {0}. Log: {1}" -f $PackageId, $log) "Warn"
    return $false
}

function Ensure-Jdk {
    $home = Find-JavaHome
    if ($home -and -not $Force) {
        Write-GhidraLog "  JDK already present: $home" "Ok"
        Add-Result "JDK" "ok" $home
        return $home
    }

    if ($SkipJdk) {
        Write-GhidraLog "  -SkipJdk - Ghidra 12.x needs JDK 21 (https://adoptium.net/)" "Warn"
        Add-Result "JDK" "skipped" "-SkipJdk"
        return Find-JavaHome
    }

    Write-GhidraLog "Installing JDK 21 (Ghidra 12.x requirement)..." "Cyan"
    foreach ($pkg in @(
        @{ Id = "Microsoft.OpenJDK.21"; Name = "Microsoft OpenJDK 21" },
        @{ Id = "EclipseAdoptium.Temurin.21.JDK"; Name = "Temurin JDK 21" },
        @{ Id = "Microsoft.OpenJDK.17"; Name = "Microsoft OpenJDK 17 (may be too old for Ghidra 12)" }
    )) {
        if (Invoke-WingetInstall -PackageId $pkg.Id -Name $pkg.Name) {
            Start-Sleep -Seconds 2
            Refresh-SessionPath
            $home = Find-JavaHome
            if ($home) {
                [Environment]::SetEnvironmentVariable("JAVA_HOME", $home, "User")
                $env:JAVA_HOME = $home
                Write-GhidraLog "  JAVA_HOME -> $home" "Ok"
                Add-Result "JDK" "installed" $home
                return $home
            }
        }
    }

    Write-GhidraLog "  JDK not installed automatically." "Warn"
    Write-GhidraLog "  Manual: winget install Microsoft.OpenJDK.21  or  https://adoptium.net/temurin/releases/?version=21" "Warn"
    Add-Result "JDK" "failed" "install JDK 21 then re-run"
    return $null
}

function Download-WithProgress {
    param(
        [string]$Uri,
        [string]$OutFile,
        [Nullable[long]]$ExpectedBytes
    )

    $dir = Split-Path $OutFile -Parent
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
    }

    $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
    if ($curl) {
        Write-Host "Downloading with curl.exe (progress + resume)..."
        $prev = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        & curl.exe -L --fail --retry 5 --retry-delay 2 --retry-all-errors -C - --progress-bar -o $OutFile $Uri
        $code = $LASTEXITCODE
        $ErrorActionPreference = $prev
        if ($code -ne 0) { throw "curl.exe exit $code" }
        return
    }

    try {
        Import-Module BitsTransfer -ErrorAction Stop
        Write-Host "Downloading with BITS..."
        if ($ExpectedBytes) {
            Write-Host ("  Expected size: {0}" -f (Format-Bytes $ExpectedBytes))
        }
        Start-BitsTransfer -Source $Uri -Destination $OutFile -DisplayName "Ghidra" -Description "Randfuzz Ghidra zip"
        return
    } catch {
        Write-Host ("BITS unavailable ({0}); falling back to Invoke-WebRequest..." -f $_.Exception.Message) -ForegroundColor Yellow
    }

    Write-Host "Downloading with Invoke-WebRequest..."
    Invoke-WebRequest -Uri $Uri -OutFile $OutFile -UseBasicParsing
}

function Install-FromExtractRoot {
    param([string]$InnerPath)
    if (-not (Test-GhidraInstalled $InnerPath)) {
        throw "Unexpected layout - expected ghidraRun.bat under $InnerPath"
    }
    if (Test-Path $Dest) { Remove-Item $Dest -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $ToolsDir | Out-Null
    Move-Item $InnerPath $Dest
    [Environment]::SetEnvironmentVariable("GHIDRA_INSTALL_DIR", $Dest, "User")
    $env:GHIDRA_INSTALL_DIR = $Dest
    Write-GhidraLog "Installed Ghidra to $Dest" "Ok"
    Write-Host "  ghidraRun: $Marker"
}

function Expand-GhidraZip {
    param([string]$ZipFile)
    $extract = Join-Path $env:TEMP "ghidra-extract"
    if (Test-Path $extract) { Remove-Item $extract -Recurse -Force }
    Write-Host "Extracting $ZipFile ..."
    Expand-Archive -Path $ZipFile -DestinationPath $extract -Force
    $inner = Get-ChildItem $extract -Directory | Select-Object -First 1
    if (-not $inner) { throw "Unexpected zip layout - no top-level directory" }
    Install-FromExtractRoot $inner.FullName
    Remove-Item $extract -Recurse -Force -ErrorAction SilentlyContinue
}

function Write-ManualHints {
    Write-Host ""
    Write-GhidraLog "Manual install:" "Cyan"
    Write-Host "  1. Install JDK 21: winget install Microsoft.OpenJDK.21"
    Write-Host "  2. Download ghidra_*_PUBLIC_*.zip from https://github.com/NationalSecurityAgency/ghidra/releases"
    Write-Host "     (Assets drop-down - NOT 'Source code')"
    Write-Host "  3. Extract and move/rename the top-level folder to exactly tools\ghidra-app"
    Write-Host "     so tools\ghidra-app\ghidraRun.bat exists."
    Write-Host "  4. Script Manager -> add committed tools\ghidra\ (Randfuzz importers)."
    Write-Host "  Docs: docs/GHIDRA_INTEGRATION.md"
}

function Invoke-OptionalExtensions {
    param([switch]$DragonDance, [switch]$GhidraMcp)

    if (-not $DragonDance -and -not $GhidraMcp) { return 0 }
    if (-not (Test-GhidraInstalled $Dest) -and -not (Test-Path $Marker)) {
        Write-GhidraLog "Extension install skipped - Ghidra app not installed yet." "Warn"
        return 0
    }

    if ($DragonDance) {
        Write-Host ""
        Write-Host "======== Dragon Dance (optional extension) ========" -ForegroundColor Cyan
        $extScript = Join-Path $PSScriptRoot "install-ghidra-extensions.ps1"
        if (-not (Test-Path $extScript)) {
            Write-GhidraLog "Missing $extScript" "Warn"
            return 1
        }
        $extArgs = @("-File", $extScript)
        if ($Force) { $extArgs += "-Force" }
        if ($SkipJdk) { $extArgs += "-SkipJdk" }
        if ($GhidraMcp) { $extArgs += "-GhidraMcp" }
        $psExe = Get-Command powershell.exe -ErrorAction SilentlyContinue
        if ($psExe) {
            & $psExe.Source -NoProfile -ExecutionPolicy Bypass @extArgs
        } else {
            & $extScript -SkipGhidraMcp
        }
        if ($LASTEXITCODE -ne 0) { return $LASTEXITCODE }
    }

    if ($GhidraMcp) {
        Write-Host ""
        Write-Host "======== Ghidra MCP (optional companion) ========" -ForegroundColor Cyan
        $mcpScript = Join-Path $PSScriptRoot "install-ghidra-mcp.ps1"
        if (-not (Test-Path $mcpScript)) {
            Write-GhidraLog "Missing $mcpScript" "Warn"
            return 1
        }
        $mcpArgs = @("-File", $mcpScript)
        if ($Force) { $mcpArgs += "-Force" }
        $psExe = Get-Command powershell.exe -ErrorAction SilentlyContinue
        if ($psExe) {
            & $psExe.Source -NoProfile -ExecutionPolicy Bypass @mcpArgs
        } else {
            if ($Force) { & $mcpScript -Force }
            else { & $mcpScript }
        }
        return $LASTEXITCODE
    }

    return 0
}

# --- main ---

if ($Skip) {
    Write-GhidraLog "Skipping Ghidra install (-Skip)." "Warn"
    Add-Result "ghidra" "skipped" "-Skip"
    exit 0
}

Write-Host "Randfuzz Ghidra installer"
Write-Host "  App target:  $Dest"
Write-Host "  Scripts:     $ScriptsDir  (committed - Script Manager)"
Write-Host ""
Write-Host "IMPORTANT: large download (~560 MB). Optional unless you want the RE GUI."
Write-Host ""

if ((Test-Path $Marker) -and -not $Force) {
    Write-GhidraLog "Ghidra already installed: $Marker" "Ok"
    Add-Result "ghidra" "ok" $Marker
    Ensure-Jdk | Out-Null
    Write-Host ""
    Write-Host "Script Manager -> add: $ScriptsDir"
    Write-Host "Doctor: dotnet run --project src\Randall.Cli -- doctor -c projects\vulnserver.yaml"
    $ext = Invoke-OptionalExtensions -DragonDance:$DragonDance -GhidraMcp:$GhidraMcp
    if ($ext -ne 0) { exit $ext }
    exit 0
}

# Versioned extract already under tools/
if (-not $Force) {
    $existing = Get-ChildItem $ToolsDir -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like "ghidra_*" -and (Test-GhidraInstalled $_.FullName) } |
        Select-Object -First 1
    if ($existing -and $existing.FullName -ne $Dest) {
        Write-Host "Found existing extract: $($existing.FullName)"
        Install-FromExtractRoot $existing.FullName
        Add-Result "ghidra" "installed" $Marker
        Ensure-Jdk | Out-Null
        $ext = Invoke-OptionalExtensions -DragonDance:$DragonDance -GhidraMcp:$GhidraMcp
        if ($ext -ne 0) { exit $ext }
        exit 0
    }
}

$jdk = Ensure-Jdk
if (-not $jdk) {
    Write-GhidraLog "Continuing without confirmed JDK - Ghidra may fail to launch until JDK 21 is installed." "Warn"
}

New-Item -ItemType Directory -Force -Path $ToolsDir | Out-Null

$localZip = $ZipPath
if (-not $localZip) {
    $found = Get-ChildItem $ToolsDir -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like "ghidra_*_PUBLIC_*.zip" } |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
    if ($found) { $localZip = $found.FullName }
}

if ($localZip) {
    if (-not (Test-Path $localZip)) { throw "Zip not found: $localZip" }
    Write-Host "Using local zip: $localZip"
    Expand-GhidraZip $localZip
    Add-Result "ghidra" "installed" $Marker
    Write-Host ""
    Write-Host "Script Manager -> add: $ScriptsDir"
    Write-Host "Doctor: dotnet run --project src\Randall.Cli -- doctor -c projects\vulnserver.yaml"
    $ext = Invoke-OptionalExtensions -DragonDance:$DragonDance -GhidraMcp:$GhidraMcp
    if ($ext -ne 0) { exit $ext }
    exit 0
}

Write-Host "Fetching Ghidra release metadata from GitHub..."
$releaseUrl = if ($Version) {
    "https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/tags/$Version"
} else {
    "https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest"
}

$release = Invoke-RestMethod $releaseUrl
$asset = $release.assets | Where-Object { $_.name -like "ghidra_*_PUBLIC_*.zip" } | Select-Object -First 1
if (-not $asset) {
    throw "No ghidra_*_PUBLIC_*.zip asset on release $($release.tag_name)"
}

$zip = Join-Path $env:TEMP $asset.name
$expected = $null
if ($asset.size -and [long]$asset.size -gt 0) { $expected = [long]$asset.size }

if ((Test-Path $zip) -and -not $Force) {
    $len = (Get-Item $zip).Length
    if ($expected -and $len -eq $expected) {
        Write-Host ("Reusing complete download: {0} ({1})" -f $zip, (Format-Bytes $len))
        Expand-GhidraZip $zip
        Add-Result "ghidra" "installed" $Marker
        Write-Host ""
        Write-Host "Script Manager -> add: $ScriptsDir"
        $ext = Invoke-OptionalExtensions -DragonDance:$DragonDance -GhidraMcp:$GhidraMcp
        if ($ext -ne 0) { exit $ext }
        exit 0
    }
}

Write-Host "Asset: $($asset.name)"
if ($expected) { Write-Host ("Size:  {0}" -f (Format-Bytes $expected)) }
Write-Host "URL:   $($asset.browser_download_url)"
Write-Host "Cache: $zip"
Write-Host ""
Write-Host "Tips if this is too slow:"
Write-Host "  - Cancel (Ctrl+C), download from https://github.com/NationalSecurityAgency/ghidra/releases"
Write-Host "  - Pass -ZipPath <browser-downloaded zip>"
Write-Host "  - Skip for now: ...\install-ghidra.ps1 -Skip"
Write-Host ""

try {
    Download-WithProgress -Uri $asset.browser_download_url -OutFile $zip -ExpectedBytes $expected
} catch {
    Write-GhidraLog ("Download failed: {0}" -f $_.Exception.Message) "Warn"
    Write-ManualHints
    Add-Result "ghidra" "failed" $_.Exception.Message
    exit 1
}

Expand-GhidraZip $zip
Write-Host "Zip kept at $zip (safe to delete after a successful install)."
Add-Result "ghidra" "installed" $Marker

Write-Host ""
Write-Host "========== Ghidra summary =========="
foreach ($r in $script:Results) {
    $color = switch ($r.Status) {
        "ok" { "Green" }
        "installed" { "Green" }
        "skipped" { "DarkGray" }
        "note" { "Cyan" }
        default { "Yellow" }
    }
    Write-Host ("  [{0,-9}] {1,-10} {2}" -f $r.Status, $r.Name, $r.Detail) -ForegroundColor $color
}

Write-Host ""
Write-Host "Launch:  $Marker"
Write-Host "Scripts: Script Manager -> add directory $ScriptsDir"
Write-Host "Doctor:  dotnet run --project src\Randall.Cli -- doctor -c projects\vulnserver.yaml"
Write-Host "Docs:    docs/GHIDRA_INTEGRATION.md"

$failed = @($script:Results | Where-Object { $_.Status -eq "failed" })
if ($failed.Count -gt 0) { exit 1 }
$ext = Invoke-OptionalExtensions -DragonDance:$DragonDance -GhidraMcp:$GhidraMcp
if ($ext -ne 0) { exit $ext }
exit 0
