# Opt-in installer for bethington/ghidra-mcp (Ghidra 12.x MCP companion).
# Builds from source with upstream setup tooling; idempotent via marker file.
#
# After install you MUST restart Ghidra, enable GhidraMCP (File → Configure), and start the
# HTTP server (Tools → GhidraMCP → Start MCP Server). Default: http://127.0.0.1:8089/
#
# Examples:
#   powershell -ExecutionPolicy Bypass -File .\scripts\install-ghidra-mcp.ps1
#   powershell -ExecutionPolicy Bypass -File .\scripts\install-ghidra-mcp.ps1 -Skip
#   powershell -ExecutionPolicy Bypass -File .\scripts\install-ghidra-mcp.ps1 -Force
#   powershell -ExecutionPolicy Bypass -File .\scripts\install-lab-tools.ps1 -Ghidra -GhidraMcp
[CmdletBinding()]
param(
    [switch]$Skip,
    [switch]$Force,
    [switch]$SkipPrereqs,
    [string]$GhidraDir = "",
    [string]$Tag = "v5.14.2"
)

$ErrorActionPreference = "Stop"
$Root = Split-Path $PSScriptRoot -Parent
$ExtRoot = Join-Path $Root "tools\ghidra-extensions"
$SrcDir = Join-Path $ExtRoot "src\ghidra-mcp"
$MarkerPath = Join-Path $ExtRoot "ghidra-mcp.installed.json"

$GhidraMcpRepo = "https://github.com/bethington/ghidra-mcp.git"

$script:Results = [System.Collections.Generic.List[object]]::new()

function Write-McpLog {
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

function Refresh-SessionPath {
    $machine = [Environment]::GetEnvironmentVariable("Path", "Machine")
    $user = [Environment]::GetEnvironmentVariable("Path", "User")
    $env:Path = (@($machine, $user) | Where-Object { $_ }) -join ";"
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

    $envDir = [Environment]::GetEnvironmentVariable("GHIDRA_INSTALL_DIR", "User")
    if (-not $envDir) { $envDir = [Environment]::GetEnvironmentVariable("GHIDRA_INSTALL_DIR", "Machine") }
    if ($envDir -and (Test-GhidraInstalled $envDir)) {
        return (Resolve-Path $envDir).Path
    }

    $stable = Join-Path $Root "tools\ghidra-app"
    if (Test-GhidraInstalled $stable) {
        return (Resolve-Path $stable).Path
    }

    $toolsDir = Join-Path $Root "tools"
    if (Test-Path $toolsDir) {
        $existing = Get-ChildItem $toolsDir -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like "ghidra_*" -and (Test-GhidraInstalled $_.FullName) } |
            Select-Object -First 1
        if ($existing) { return $existing.FullName }
    }

    return $null
}

function Find-Python310 {
    Refresh-SessionPath
    foreach ($cmd in @("python", "python3", "py")) {
        $exe = Get-Command $cmd -ErrorAction SilentlyContinue
        if (-not $exe) { continue }
        try {
            $verText = & $exe.Source -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>&1
            if ($LASTEXITCODE -ne 0) { continue }
            $ver = [version]$verText.Trim()
            if ($ver.Major -ge 3 -and $ver.Minor -ge 10) {
                return $exe.Source
            }
        } catch { }
    }
    return $null
}

function Read-InstallMarker {
    if (-not (Test-Path $MarkerPath)) { return $null }
    try {
        return Get-Content $MarkerPath -Raw | ConvertFrom-Json
    } catch {
        return $null
    }
}

function Write-InstallMarker {
    param([hashtable]$Data)
    New-Item -ItemType Directory -Force -Path $ExtRoot | Out-Null
    ($Data | ConvertTo-Json -Depth 4) | Set-Content -Path $MarkerPath -Encoding UTF8
}

function Ensure-GhidraMcpSource {
    param([string]$WantedTag)

    $git = Get-Command git -ErrorAction SilentlyContinue
    if (-not $git) {
        throw "git is required to clone ghidra-mcp ($GhidraMcpRepo)"
    }

    New-Item -ItemType Directory -Force -Path (Split-Path $SrcDir -Parent) | Out-Null

    if (-not (Test-Path (Join-Path $SrcDir ".git"))) {
        Write-McpLog "Cloning bethington/ghidra-mcp..." "Cyan"
        if (Test-Path $SrcDir) { Remove-Item $SrcDir -Recurse -Force }
        & git clone --filter=blob:none $GhidraMcpRepo $SrcDir
        if ($LASTEXITCODE -ne 0) { throw "git clone failed (exit $LASTEXITCODE)" }
    }

    Push-Location $SrcDir
    try {
        & git fetch --tags --depth 1 origin "refs/tags/$WantedTag" 2>&1 | Out-Null
        & git checkout "tags/$WantedTag" 2>&1 | ForEach-Object { Write-Host $_ }
        if ($LASTEXITCODE -ne 0) {
            Write-McpLog "Tag $WantedTag not found — using main branch." "Warn"
            & git checkout main 2>&1 | Out-Null
        }
        $head = (& git rev-parse HEAD).Trim()
        Write-McpLog "  Source at $head ($WantedTag)" "Ok"
        return $head
    } finally {
        Pop-Location
    }
}

function Invoke-SetupStep {
    param(
        [string]$PythonExe,
        [string]$Step,
        [string]$GhidraInstall
    )
    Push-Location $SrcDir
    try {
        Write-McpLog "python -m tools.setup $Step ..." "Cyan"
        & $PythonExe -m tools.setup $Step --ghidra-path $GhidraInstall
        if ($LASTEXITCODE -ne 0) {
            throw "tools.setup $Step failed (exit $LASTEXITCODE)"
        }
    } finally {
        Pop-Location
    }
}

function Write-ManualHints {
    Write-Host ""
    Write-McpLog "Manual Ghidra MCP install:" "Cyan"
    Write-Host "  Fork: https://github.com/bethington/ghidra-mcp (Ghidra 12.x; supersedes LaurieWired/GhidraMCP)"
    Write-Host "  1. Install Ghidra: .\scripts\install-ghidra.ps1"
    Write-Host "  2. Python 3.10+, Maven 3.9+, JDK 21"
    Write-Host "  3. git clone $GhidraMcpRepo"
    Write-Host "  4. python -m tools.setup ensure-prereqs --ghidra-path <tools\ghidra-app>"
    Write-Host "  5. python -m tools.setup build && python -m tools.setup deploy --ghidra-path <tools\ghidra-app>"
    Write-Host "  6. Restart Ghidra → File → Configure → enable GhidraMCP → Tools → GhidraMCP → Start MCP Server"
    Write-Host "  Query: randall ghidra mcp ping"
    Write-Host "  Docs: docs/GHIDRA_INTEGRATION.md#ghidra-mcp-companion"
}

# --- main ---

if ($Skip) {
    Write-McpLog "Skipping Ghidra MCP (-Skip)." "Warn"
    Add-Result "ghidra-mcp" "skipped" "-Skip"
    exit 0
}

Write-Host "Randfuzz Ghidra MCP installer (bethington/ghidra-mcp @ $Tag)"
Write-Host "  Staging: $ExtRoot"
Write-Host ""

$ghidraInstall = Resolve-GhidraInstallDir -Override $GhidraDir
if (-not $ghidraInstall) {
    Write-McpLog "Ghidra not found — install Ghidra first (scripts/install-ghidra.ps1)." "Warn"
    Write-ManualHints
    Add-Result "ghidra" "failed" "install Ghidra before ghidra-mcp"
    exit 1
}

Write-Host "  Ghidra: $ghidraInstall"

$marker = Read-InstallMarker
if ($marker -and -not $Force) {
    $sameTag = $marker.tag -eq $Tag
    $sameGhidra = $marker.ghidraInstallDir -eq $ghidraInstall
    if ($sameTag -and $sameGhidra) {
        Write-McpLog "Ghidra MCP already installed (marker present)." "Ok"
        Add-Result "ghidra-mcp" "ok" "$Tag @ $($marker.head)"
        Write-Host ""
        Write-Host "Restart Ghidra if you changed extensions. Enable plugin + Start MCP Server (port 8089 default)."
        Write-Host "Query: randall ghidra mcp ping"
        exit 0
    }
}

$python = Find-Python310
if (-not $python) {
    Write-McpLog "Python 3.10+ required (winget install Python.Python.3.12 or https://python.org)." "Warn"
    Write-ManualHints
    Add-Result "python" "failed" "Python 3.10+ required"
    exit 1
}
Write-Host "  Python: $python"
Add-Result "python" "ok" $python

try {
    $head = Ensure-GhidraMcpSource -WantedTag $Tag

    if (-not $SkipPrereqs) {
        Invoke-SetupStep -PythonExe $python -Step "preflight" -GhidraInstall $ghidraInstall
        Invoke-SetupStep -PythonExe $python -Step "ensure-prereqs" -GhidraInstall $ghidraInstall
    } else {
        Add-Result "ensure-prereqs" "skipped" "-SkipPrereqs"
    }

    Invoke-SetupStep -PythonExe $python -Step "build" -GhidraInstall $ghidraInstall
    Invoke-SetupStep -PythonExe $python -Step "deploy" -GhidraInstall $ghidraInstall

    Write-InstallMarker @{
        tag              = $Tag
        head             = $head
        repo             = $GhidraMcpRepo
        ghidraInstallDir = $ghidraInstall
        installedAt      = (Get-Date).ToString("o")
    }

    Add-Result "ghidra-mcp" "installed" "$Tag · $head"
} catch {
    Write-McpLog $_.Exception.Message "Error"
    Write-ManualHints
    Add-Result "ghidra-mcp" "failed" $_.Exception.Message
}

Write-Host ""
Write-Host "========== Ghidra MCP summary =========="
foreach ($r in $script:Results) {
    $color = switch ($r.Status) {
        "ok" { "Green" }
        "installed" { "Green" }
        "skipped" { "DarkGray" }
        "note" { "Cyan" }
        default { "Yellow" }
    }
    Write-Host ("  [{0,-9}] {1,-14} {2}" -f $r.Status, $r.Name, $r.Detail) -ForegroundColor $color
}

Write-Host ""
Write-Host "IMPORTANT: restart Ghidra after extension deploy."
Write-Host "  1. File → Configure → Configure All Plugins → enable GhidraMCP"
Write-Host "  2. Tools → GhidraMCP → Start MCP Server  (default http://127.0.0.1:8089/)"
Write-Host "  3. randall ghidra mcp ping"
Write-Host "  4. randall ghidra mcp callers --import memcpy"
Write-Host "Docs: docs/GHIDRA_INTEGRATION.md#ghidra-mcp-companion"

$failed = @($script:Results | Where-Object { $_.Status -eq "failed" })
if ($failed.Count -gt 0) { exit 1 }
exit 0
