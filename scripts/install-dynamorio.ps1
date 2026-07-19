# Download DynamoRIO into tools/dynamorio (gitignored lab dependency).
# Optional for coverage; Randfuzz finds crashes without it.
# IMPORTANT: the download is large and may take a while on slow networks.
#
# Primary paths:
#   powershell -ExecutionPolicy Bypass -File .\scripts\install-dynamorio.ps1
#   # Or manually: download DynamoRIO-Windows-*.zip from
#   #   https://github.com/DynamoRIO/dynamorio/releases
#   #   (URL: .../releases/download/<tag>/DynamoRIO-Windows-<version>.zip)
#   # IMPORTANT: rename/move the top-level DynamoRIO-Windows-* folder to
#   #   exactly tools\dynamorio (NOT tools\DynamoRIO-Windows-11.3.0 or any
#   #   versioned name) so tools\dynamorio\bin64\drrun.exe exists
#   powershell -ExecutionPolicy Bypass -File .\scripts\install-dynamorio.ps1 -ZipPath C:\Users\007\Downloads\DynamoRIO-Windows-11.3.0.zip
#   # Or drop a zip / extracted folder under tools\ then re-run (auto-detects + renames)
#
# Footnote — coverage later / skip for now:
#   powershell -ExecutionPolicy Bypass -File .\scripts\install-dynamorio.ps1 -Skip
param(
    [string]$Version = "",
    [string]$ZipPath = "",
    [switch]$Skip,
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$Root = Split-Path $PSScriptRoot -Parent
$Dest = Join-Path $Root "tools\dynamorio"
$ToolsDir = Join-Path $Root "tools"
$Marker = Join-Path $Dest "bin64\drrun.exe"

function Test-DynamoRioInstalled {
    param([string]$Path)
    return (Test-Path (Join-Path $Path "bin64\drrun.exe"))
}

function Install-FromExtractRoot {
    param([string]$InnerPath)
    if (-not (Test-DynamoRioInstalled $InnerPath)) {
        throw "Unexpected layout - expected bin64\drrun.exe under $InnerPath"
    }
    if (Test-Path $Dest) { Remove-Item $Dest -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $ToolsDir | Out-Null
    Move-Item $InnerPath $Dest
    Write-Host "Installed DynamoRIO to $Dest"
    Write-Host "drrun: $Marker"
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
        [string]$OutFile,
        [Nullable[long]]$ExpectedBytes
    )

    $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
    if ($curl) {
        Write-Host "Downloading with curl.exe (progress + resume)..."
        $curlArgs = @(
            "-L", "--fail", "--retry", "5", "--retry-delay", "2",
            "--retry-all-errors", "-C", "-",
            "--progress-bar",
            "-o", $OutFile,
            $Uri
        )
        & curl.exe @curlArgs
        if ($LASTEXITCODE -ne 0) {
            throw "curl.exe download failed (exit $LASTEXITCODE). Re-run to resume, or use -ZipPath / manual extract."
        }
        return
    }

    # BITS: background-friendly, often resumes better than IWR on slow links
    try {
        Import-Module BitsTransfer -ErrorAction Stop
        Write-Host "Downloading with BITS (Start-BitsTransfer)..."
        if ($ExpectedBytes) {
            Write-Host ("  Expected size: {0} - this can take a while on slow VM networks." -f (Format-Bytes $ExpectedBytes))
        }
        Start-BitsTransfer -Source $Uri -Destination $OutFile -DisplayName "DynamoRIO" -Description "Randfuzz DynamoRIO zip"
        return
    } catch {
        Write-Host ("BITS unavailable ({0}); falling back to Invoke-WebRequest..." -f $_.Exception.Message) -ForegroundColor Yellow
    }

    Write-Host "Downloading with Invoke-WebRequest (no resume - prefer curl.exe if this stalls)..."
    if ($ExpectedBytes) {
        Write-Host ("  Expected size: {0}" -f (Format-Bytes $ExpectedBytes))
    }
    $tmpPartial = "$OutFile.partial"
    try {
        Invoke-WebRequest -Uri $Uri -OutFile $tmpPartial -UseBasicParsing
        Move-Item -Force $tmpPartial $OutFile
    } catch {
        Remove-Item $tmpPartial -Force -ErrorAction SilentlyContinue
        throw
    }
}

function Expand-DynamoRioZip {
    param([string]$ZipFile)
    $extract = Join-Path $env:TEMP "dynamorio-extract"
    if (Test-Path $extract) { Remove-Item $extract -Recurse -Force }
    Write-Host "Extracting $ZipFile ..."
    Expand-Archive -Path $ZipFile -DestinationPath $extract -Force
    $inner = Get-ChildItem $extract -Directory | Select-Object -First 1
    if (-not $inner) { throw "Unexpected zip layout - no top-level directory" }
    Install-FromExtractRoot $inner.FullName
    Remove-Item $extract -Recurse -Force -ErrorAction SilentlyContinue
}

# --- skip / already installed ---
if ($Skip) {
    Write-Host "Skipping DynamoRIO install (-Skip). Coverage is optional; fuzzing works without it."
    exit 0
}

if ((Test-Path $Marker) -and -not $Force) {
    Write-Host "DynamoRIO already installed: $Marker"
    exit 0
}

# Already-extracted versioned folder under tools/
if (-not $Force) {
    $existing = Get-ChildItem $ToolsDir -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like "DynamoRIO*" -and (Test-DynamoRioInstalled $_.FullName) } |
        Select-Object -First 1
    if ($existing -and $existing.FullName -ne $Dest) {
        Write-Host "Found existing extract: $($existing.FullName)"
        if (Test-Path $Dest) { Remove-Item $Dest -Recurse -Force }
        Move-Item $existing.FullName $Dest
        Write-Host "Installed DynamoRIO to $Dest"
        Write-Host "drrun: $Marker"
        exit 0
    }
}

New-Item -ItemType Directory -Force -Path $ToolsDir | Out-Null

# Manual zip path or auto-detect under tools/
$localZip = $ZipPath
if (-not $localZip) {
    $found = Get-ChildItem $ToolsDir -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like "DynamoRIO-Windows-*.zip" } |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
    if ($found) { $localZip = $found.FullName }
}

if ($localZip) {
    if (-not (Test-Path $localZip)) { throw "Zip not found: $localZip" }
    Write-Host "Using local zip: $localZip"
    Expand-DynamoRioZip $localZip
    exit 0
}

Write-Host "Fetching DynamoRIO release metadata from GitHub..."
Write-Host 'IMPORTANT: large download - may take a while on slow networks. Patience is normal.'
Write-Host 'Or Ctrl+C and manually unzip, then rename to exactly tools\dynamorio (see tips below).'
$release = Invoke-RestMethod "https://api.github.com/repos/DynamoRIO/dynamorio/releases/latest"
if ($Version) {
    $release = Invoke-RestMethod "https://api.github.com/repos/DynamoRIO/dynamorio/releases/tags/$Version"
}

$asset = $release.assets | Where-Object { $_.name -eq "DynamoRIO-Windows-$($release.tag_name -replace '^cronbuild-','').zip" }
if (-not $asset) {
    $asset = $release.assets | Where-Object { $_.name -like "DynamoRIO-Windows-*.zip" } | Select-Object -First 1
}
if (-not $asset) {
    throw "No Windows zip asset found on release $($release.tag_name)"
}

# Stable cache path so re-runs can resume
$zip = Join-Path $env:TEMP $asset.name
$expected = $null
if ($asset.size -and [long]$asset.size -gt 0) { $expected = [long]$asset.size }

if ((Test-Path $zip) -and -not $Force) {
    $len = (Get-Item $zip).Length
    if ($expected -and $len -eq $expected) {
        Write-Host ("Reusing complete download: {0} ({1})" -f $zip, (Format-Bytes $len))
        Expand-DynamoRioZip $zip
        exit 0
    }
    if ($expected -and $len -gt 0 -and $len -lt $expected) {
        Write-Host ("Partial download found ({0} / {1}) - will resume." -f (Format-Bytes $len), (Format-Bytes $expected))
    } elseif ($len -gt 0 -and -not $expected) {
        Write-Host ("Existing file at {0} ({1}) - verifying / refreshing download..." -f $zip, (Format-Bytes $len))
    }
}

Write-Host "Asset: $($asset.name)"
if ($expected) {
    Write-Host ("Size:   {0} (large; slow networks may take many minutes)" -f (Format-Bytes $expected))
}
Write-Host "URL:    $($asset.browser_download_url)"
Write-Host "Cache:  $zip"
Write-Host ""
Write-Host "Tips if this is too slow:"
Write-Host '  - Cancel (Ctrl+C), download DynamoRIO-Windows-*.zip from'
Write-Host '      https://github.com/DynamoRIO/dynamorio/releases'
Write-Host '    (URL pattern: .../releases/download/<tag>/DynamoRIO-Windows-<version>.zip),'
Write-Host '    extract, then rename/move the top-level DynamoRIO-Windows-* folder'
Write-Host '    to exactly tools\dynamorio (IMPORTANT: NOT tools\DynamoRIO-Windows-11.3.0'
Write-Host '    or any versioned name) so tools\dynamorio\bin64\drrun.exe exists.'
Write-Host '  - Or pass a browser-downloaded zip:'
Write-Host '      powershell -ExecutionPolicy Bypass -File .\scripts\install-dynamorio.ps1 -ZipPath <path-to-zip>'
Write-Host '  - Coverage later / skip for now:  ...\install-dynamorio.ps1 -Skip'
Write-Host ""

try {
    Download-WithProgress -Uri $asset.browser_download_url -OutFile $zip -ExpectedBytes $expected
} catch {
    Write-Host ""
    Write-Host ("[!] Download failed: {0}" -f $_.Exception.Message) -ForegroundColor Yellow
    Write-Host "    Re-run to resume (curl/BITS), manual unzip into tools\dynamorio, -ZipPath, or -Skip." -ForegroundColor Yellow
    throw
}

if ($expected) {
    $got = (Get-Item $zip).Length
    if ($got -ne $expected) {
        throw ("Downloaded size mismatch: got {0}, expected {1}. Delete {2} and retry, or use -ZipPath." -f (Format-Bytes $got), (Format-Bytes $expected), $zip)
    }
}

Expand-DynamoRioZip $zip
# Keep the zip in TEMP for faster reinstall; user can delete manually
Write-Host "Zip kept at $zip (safe to delete after a successful install)."
