# Stage BinExport (Ghidra extension) for patch-hunt / BinDiff companion workflows.
# Randfuzz does NOT invoke BinDiff — this script caches the Ghidra extension zip and
# documents BinDiff install. JSON diff merge works without either tool.
#
# Examples:
#   powershell -ExecutionPolicy Bypass -File .\scripts\install-binexport.ps1
#   powershell -ExecutionPolicy Bypass -File .\scripts\install-binexport.ps1 -SkipDownload
#   powershell -ExecutionPolicy Bypass -File .\scripts\install-binexport.ps1 -InstallToGhidra
[CmdletBinding()]
param(
    [switch]$Skip,
    [switch]$SkipDownload,
    [switch]$InstallToGhidra,
    [switch]$Force,
    [string]$GhidraDir = ""
)

$ErrorActionPreference = "Stop"
$Root = Split-Path $PSScriptRoot -Parent
$BinExportRoot = Join-Path $Root "tools\binexport"
$DistDir = Join-Path $BinExportRoot "dist"
$MarkerPath = Join-Path $BinExportRoot "binexport.installed.json"

# Latest Ghidra Java extension artifact (BinExport 12, Ghidra 11.x — usually compatible with 12.x).
$ReleaseTag = "v12-20240417-ghidra_11.0.3"
$GhidraZipName = "BinExport_Ghidra-Java.zip"
$ReleaseUrl = "https://github.com/google/binexport/releases/download/$ReleaseTag/$GhidraZipName"

$script:Results = [System.Collections.Generic.List[object]]::new()

function Write-BinLog {
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

function Test-GhidraInstalled {
    param([string]$Path)
    return (Test-Path (Join-Path $Path "ghidraRun.bat")) -or (Test-Path (Join-Path $Path "ghidraRun"))
}

function Resolve-GhidraInstallDir {
    param([string]$Override = "")

    if ($Override -and (Test-GhidraInstalled $Override)) {
        return (Resolve-Path $Override).Path
    }

    foreach ($scope in @("User", "Machine")) {
        $envDir = [Environment]::GetEnvironmentVariable("GHIDRA_INSTALL_DIR", $scope)
        if ($envDir -and (Test-GhidraInstalled $envDir)) {
            return (Resolve-Path $envDir).Path
        }
    }

    $stable = Join-Path $Root "tools\ghidra-app"
    if (Test-GhidraInstalled $stable) {
        return (Resolve-Path $stable).Path
    }

    return $null
}

function Read-InstallMarker {
    if (-not (Test-Path $MarkerPath)) { return $null }
    try { return Get-Content $MarkerPath -Raw | ConvertFrom-Json } catch { return $null }
}

function Write-InstallMarker {
    param([hashtable]$Data)
    New-Item -ItemType Directory -Force -Path $BinExportRoot | Out-Null
    ($Data | ConvertTo-Json -Depth 4) | Set-Content -Path $MarkerPath -Encoding UTF8
}

function Ensure-GhidraZip {
    New-Item -ItemType Directory -Force -Path $DistDir | Out-Null
    $dest = Join-Path $DistDir $GhidraZipName

    $marker = Read-InstallMarker
    if (-not $Force -and (Test-Path $dest) -and $marker -and $marker.releaseTag -eq $ReleaseTag) {
        Write-BinLog "  Cached: $dest" "Ok"
        Add-Result "BinExport zip" "ok" $dest
        return $dest
    }

    if ($SkipDownload) {
        if (Test-Path $dest) {
            Add-Result "BinExport zip" "ok" $dest
            return $dest
        }
        Write-BinLog "  No cached zip — download manually from $ReleaseUrl" "Warn"
        Add-Result "BinExport zip" "failed" "missing — download from GitHub releases"
        return $null
    }

    Write-BinLog "Downloading BinExport Ghidra extension..." "Cyan"
    Write-Host "  $ReleaseUrl"
    try {
        Invoke-WebRequest -Uri $ReleaseUrl -OutFile $dest -UseBasicParsing
        Write-BinLog "  Saved: $dest" "Ok"
        Add-Result "BinExport zip" "installed" $dest
        return $dest
    } catch {
        Write-BinLog "  Download failed: $($_.Exception.Message)" "Warn"
        Add-Result "BinExport zip" "failed" $_.Exception.Message
        return $null
    }
}

function Install-ExtensionZip {
    param(
        [string]$ZipPath,
        [string]$GhidraInstall
    )

    $extensionsRoot = Join-Path $GhidraInstall "Ghidra\Extensions"
    if (-not (Test-Path $extensionsRoot)) {
        New-Item -ItemType Directory -Force -Path $extensionsRoot | Out-Null
    }

    $stage = Join-Path $env:TEMP ("randall-binexport-{0}" -f ([guid]::NewGuid().ToString("n")))
    New-Item -ItemType Directory -Force -Path $stage | Out-Null
    try {
        Expand-Archive -Path $ZipPath -DestinationPath $stage -Force
        $inner = Get-ChildItem $stage -Directory | Select-Object -First 1
        if (-not $inner) { throw "Unexpected zip layout in $ZipPath" }

        $dest = Join-Path $extensionsRoot $inner.Name
        if (Test-Path $dest) { Remove-Item $dest -Recurse -Force }
        Copy-Item $inner.FullName $dest -Recurse -Force
        Write-BinLog "Installed Ghidra extension: $dest" "Ok"
        return $dest
    } finally {
        Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Test-BinDiff {
    $envHome = [Environment]::GetEnvironmentVariable("BINDIFF_HOME", "User")
    if (-not $envHome) { $envHome = [Environment]::GetEnvironmentVariable("BINDIFF_HOME", "Machine") }
    if ($envHome) {
        $exe = Join-Path $envHome "bin\bindiff.exe"
        if (Test-Path $exe) { return $exe }
        $exe = Join-Path $envHome "bindiff.exe"
        if (Test-Path $exe) { return $exe }
    }

    $local = Join-Path $Root "tools\bindiff\bin\bindiff.exe"
    if (Test-Path $local) { return $local }

    $cmd = Get-Command bindiff.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }

    return $null
}

function Write-ManualHints {
    Write-Host ""
    Write-BinLog "Manual patch-hunt setup:" "Cyan"
    Write-Host "  1. Ghidra: File → Install Extensions → + → tools\binexport\dist\$GhidraZipName"
    Write-Host "  2. Export: right-click program → Export → Binary Export (v2) → .BinExport"
    Write-Host "  3. BinDiff: install from https://github.com/google/binexport (BinDiff bundle) or zynamics legacy"
    Write-Host "     bindiff primary.BinExport secondary.BinExport"
    Write-Host "  4. JSON-only (no BinDiff): randall stalk ghidra-diff -p P --from old.json --into new.json"
    Write-Host "  5. BSim: Ghidra → Analysis → BSim (built-in; PostgreSQL for large corpora)"
    Write-Host "  Docs: docs/GHIDRA_INTEGRATION.md#binexport--bindiff-patch-hunt"
}

# --- main ---

if ($Skip) {
    Write-BinLog "Skipping BinExport install (-Skip)." "Warn"
    exit 0
}

Write-Host "Randfuzz BinExport / BinDiff companion installer"
Write-Host "  Release:  $ReleaseTag"
Write-Host "  Staging:  $BinExportRoot"
Write-Host ""

$zip = Ensure-GhidraZip

$ghidraInstall = Resolve-GhidraInstallDir -Override $GhidraDir
if ($InstallToGhidra -and $ghidraInstall -and $zip) {
    try {
        $extDir = Install-ExtensionZip -ZipPath $zip -GhidraInstall $ghidraInstall
        Write-InstallMarker @{
            releaseTag       = $ReleaseTag
            ghidraZip        = $zip
            ghidraInstallDir = $ghidraInstall
            extensionDir     = $extDir
            installedAt      = (Get-Date).ToString("o")
        }
        Add-Result "Ghidra extension" "installed" $extDir
    } catch {
        Write-BinLog $_.Exception.Message "Error"
        Add-Result "Ghidra extension" "failed" $_.Exception.Message
    }
} elseif ($InstallToGhidra -and -not $ghidraInstall) {
    Write-BinLog "Ghidra not found — run scripts/install-ghidra.ps1 first" "Warn"
    Add-Result "Ghidra extension" "failed" "Ghidra not installed"
} else {
    Add-Result "Ghidra extension" "note" "run with -InstallToGhidra after Ghidra install"
}

$bindiff = Test-BinDiff
if ($bindiff) {
    Add-Result "BinDiff" "ok" $bindiff
} else {
    Add-Result "BinDiff" "note" "not on PATH — optional; JSON merge needs no binary"
}

Write-Host ""
Write-Host "========== BinExport summary =========="
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

Write-ManualHints

$failed = @($script:Results | Where-Object { $_.Status -eq "failed" })
if ($failed.Count -gt 0) { exit 1 }
exit 0
