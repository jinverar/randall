# Stage optional Ghidra RE companions (GhidrAssist, C++ Class Analyzer).
# Document-first - Randfuzz does not invoke these from the fuzz loop.
#
# Examples:
#   powershell -ExecutionPolicy Bypass -File .\scripts\install-ghidra-re-companions.ps1
#   powershell -ExecutionPolicy Bypass -File .\scripts\install-ghidra-re-companions.ps1 -GhidrAssist
#   powershell -ExecutionPolicy Bypass -File .\scripts\install-ghidra-re-companions.ps1 -CppClassAnalyzer -InstallToGhidra
[CmdletBinding()]
param(
    [switch]$Skip,
    [switch]$GhidrAssist,
    [switch]$CppClassAnalyzer,
    [switch]$InstallToGhidra,
    [switch]$Force,
    [string]$GhidraDir = ""
)

$ErrorActionPreference = "Stop"
$Root = Split-Path $PSScriptRoot -Parent
$ExtRoot = Join-Path $Root "tools\ghidra-extensions"
$SrcDir = Join-Path $ExtRoot "src"
$MarkerPath = Join-Path $ExtRoot "re-companions.installed.json"

$DoAll = -not $GhidrAssist -and -not $CppClassAnalyzer

function Write-Log([string]$Message, [string]$Level = "Info") {
    switch ($Level) {
        "Warn"  { Write-Host $Message -ForegroundColor Yellow }
        "Ok"    { Write-Host $Message -ForegroundColor Green }
        "Cyan"  { Write-Host $Message -ForegroundColor Cyan }
        default { Write-Host $Message }
    }
}

function Test-GhidraInstalled([string]$Path) {
    return (Test-Path (Join-Path $Path "ghidraRun.bat")) -or (Test-Path (Join-Path $Path "ghidraRun"))
}

function Resolve-GhidraInstallDir([string]$Override = "") {
    if ($Override -and (Test-GhidraInstalled $Override)) { return $Override }
    $candidates = @(
        (Join-Path $Root "tools\ghidra-app"),
        $env:GHIDRA_INSTALL_DIR
    ) | Where-Object { $_ }
    foreach ($c in $candidates) {
        if (Test-GhidraInstalled $c) { return $c }
    }
    return $null
}

function Ensure-Clone([string]$Name, [string]$Url, [string]$Dest) {
    if (Test-Path $Dest) {
        Write-Log "  $Name already cloned: $Dest" "Ok"
        return
    }
    New-Item -ItemType Directory -Force -Path (Split-Path $Dest) | Out-Null
    Write-Log "  Cloning $Name ..."
    git clone --depth 1 $Url $Dest
    Write-Log "  Cloned $Name" "Ok"
}

if ($Skip) {
    Write-Log "Skipped ( -Skip ). See docs/GHIDRA_RE_COMPANIONS.md"
    exit 0
}

Write-Log "Randfuzz Ghidra RE companions (document + optional staging)" "Cyan"
Write-Log "Full guide: docs/GHIDRA_RE_COMPANIONS.md"
New-Item -ItemType Directory -Force -Path $SrcDir | Out-Null

$results = @()

if ($DoAll -or $GhidrAssist) {
    $dest = Join-Path $SrcDir "ghidrassist"
    Ensure-Clone "GhidrAssist" "https://github.com/jtang613/GhidrAssist.git" $dest
    Write-Log "  GhidrAssist: install release zip via Ghidra File -> Install Extensions" "Warn"
    Write-Log "  Configure LLM API key inside GhidrAssist settings (not stored by Randfuzz)" "Warn"
    $results += @{ Name = "ghidrassist"; Status = "staged"; Path = $dest }
}

if ($DoAll -or $CppClassAnalyzer) {
    $dest = Join-Path $SrcDir "class-analyzer"
    Ensure-Clone "C++ Class Analyzer" "https://github.com/vic4key/Class-Analyzer.git" $dest
    Write-Log "  Class Analyzer: buildExtension or use GitHub release zip for your Ghidra version" "Warn"
    $results += @{ Name = "cpp-class-analyzer"; Status = "staged"; Path = $dest }
}

$ghidra = Resolve-GhidraInstallDir $GhidraDir
if ($InstallToGhidra -and $null -eq $ghidra) {
    Write-Log "Ghidra not found under tools/ghidra-app - skip -InstallToGhidra" "Warn"
}
elseif ($InstallToGhidra -and $ghidra) {
    Write-Log "Manual step: File -> Install Extensions in Ghidra ($ghidra)" "Warn"
    Write-Log "Pre-built zips vary by Ghidra version - see each repo's releases." "Warn"
}

$marker = @{
    installedAt = (Get-Date).ToString("o")
    companions  = $results
    ghidraDir   = $ghidra
    docs        = "docs/GHIDRA_RE_COMPANIONS.md"
}
$marker | ConvertTo-Json -Depth 4 | Set-Content -Encoding UTF8 $MarkerPath
Write-Log "Marker: $MarkerPath" "Ok"
Write-Log "Done. These companions are optional RE tools - not required for fuzz." "Ok"
