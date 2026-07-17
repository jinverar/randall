# Download DynamoRIO into tools/dynamorio (gitignored lab dependency).
param(
    [string]$Version = ""
)

$ErrorActionPreference = "Stop"
$Root = Split-Path $PSScriptRoot -Parent
$Dest = Join-Path $Root "tools\dynamorio"
$Marker = Join-Path $Dest "bin64\drrun.exe"

if (Test-Path $Marker) {
    Write-Host "DynamoRIO already installed: $Marker"
    exit 0
}

Write-Host "Fetching latest DynamoRIO release..."
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

$zip = Join-Path $env:TEMP "DynamoRIO-Windows-$([Guid]::NewGuid().ToString('N')).zip"
Write-Host "Downloading $($asset.name)..."
try {
    Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $zip -UseBasicParsing
} catch {
    Remove-Item $zip -Force -ErrorAction SilentlyContinue
    throw
}

$extract = Join-Path $env:TEMP "dynamorio-extract"
if (Test-Path $extract) { Remove-Item $extract -Recurse -Force }
Expand-Archive -Path $zip -DestinationPath $extract -Force

$inner = Get-ChildItem $extract -Directory | Select-Object -First 1
if (-not $inner) { throw "Unexpected zip layout" }

if (Test-Path $Dest) { Remove-Item $Dest -Recurse -Force }
New-Item -ItemType Directory -Force -Path (Split-Path $Dest) | Out-Null
Move-Item $inner.FullName $Dest

Remove-Item $zip -Force -ErrorAction SilentlyContinue
Remove-Item $extract -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "Installed DynamoRIO to $Dest"
Write-Host "drrun: $Marker"
