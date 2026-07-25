# Build and stage Ghidra extensions for Randfuzz RE workflows (Dragon Dance for binary drcov).
# Requires a local Ghidra install (tools/ghidra-app or GHIDRA_INSTALL_DIR), JDK 21, Gradle 8.5+.
#
# Dragon Dance has no pre-built zip for Ghidra 12.x — this script clones upstream, runs
# Ghidra's buildExtension task, copies the zip to tools/ghidra-extensions/dist/, and
# extracts into <ghidra>/Ghidra/Extensions/ (same result as File → Install Extensions).
#
# Examples:
#   powershell -ExecutionPolicy Bypass -File .\scripts\install-ghidra-extensions.ps1
#   powershell -ExecutionPolicy Bypass -File .\scripts\install-ghidra-extensions.ps1 -Skip
#   powershell -ExecutionPolicy Bypass -File .\scripts\install-ghidra-extensions.ps1 -Force
#   powershell -ExecutionPolicy Bypass -File .\scripts\install-ghidra.ps1 -DragonDance
#   powershell -ExecutionPolicy Bypass -File .\scripts\install-ghidra-extensions.ps1 -GhidraMcp
#   powershell -ExecutionPolicy Bypass -File .\scripts\install-lab-tools.ps1 -Ghidra -GhidraExtensions -GhidraMcp
[CmdletBinding()]
param(
    [switch]$Skip,
    [switch]$Force,
    [switch]$SkipDragonDance,
    [switch]$GhidraMcp,
    [switch]$SkipJdk,
    [string]$GhidraDir = ""
)

$ErrorActionPreference = "Stop"
$Root = Split-Path $PSScriptRoot -Parent
$ExtRoot = Join-Path $Root "tools\ghidra-extensions"
$SrcDir = Join-Path $ExtRoot "src\dragondance"
$DistDir = Join-Path $ExtRoot "dist"
$MarkerPath = Join-Path $ExtRoot "dragondance.installed.json"

# Pinned upstream (last master commit as of research — build against your Ghidra version).
$DragonDanceRepo = "https://github.com/0ffffffffh/dragondance.git"
$DragonDanceSha = "19e2ecefe4a29e682dd571454cef05743d1f409d"

$script:Results = [System.Collections.Generic.List[object]]::new()

function Write-ExtLog {
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

function Get-GhidraApplicationVersion {
    param([string]$GhidraInstall)
    $props = Join-Path $GhidraInstall "Ghidra\application.properties"
    if (-not (Test-Path $props)) { return $null }
    foreach ($line in Get-Content $props) {
        if ($line -match '^\s*application\.version\s*=\s*(.+)\s*$') {
            return $Matches[1].Trim()
        }
    }
    return $null
}

function Get-GhidraGradleMin {
    param([string]$GhidraInstall)
    $props = Join-Path $GhidraInstall "Ghidra\application.properties"
    if (-not (Test-Path $props)) { return "8.5" }
    foreach ($line in Get-Content $props) {
        if ($line -match '^\s*application\.gradle\.min\s*=\s*(.+)\s*$') {
            return $Matches[1].Trim()
        }
    }
    return "8.5"
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
        Write-ExtLog "  winget not available." "Warn"
        return $false
    }
    Write-ExtLog ("  winget install {0} ({1})..." -f $Name, $PackageId) "Cyan"
    $prev = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        & winget @("install", "--id", $PackageId, "-e", "--accept-package-agreements", "--accept-source-agreements", "--disable-interactivity") 2>&1 | ForEach-Object { Write-Host $_ }
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
    return $false
}

function Ensure-Jdk {
    $home = Find-JavaHome
    if ($home -and -not $Force) {
        Write-ExtLog "  JDK present: $home" "Ok"
        Add-Result "JDK" "ok" $home
        return $home
    }

    if ($SkipJdk) {
        Write-ExtLog "  -SkipJdk — Ghidra extension build needs JDK 21" "Warn"
        Add-Result "JDK" "skipped" "-SkipJdk"
        return Find-JavaHome
    }

    Write-ExtLog "Ensuring JDK 21 for Gradle/Ghidra extension build..." "Cyan"
    foreach ($pkg in @(
        @{ Id = "Microsoft.OpenJDK.21"; Name = "Microsoft OpenJDK 21" },
        @{ Id = "EclipseAdoptium.Temurin.21.JDK"; Name = "Temurin JDK 21" }
    )) {
        if (Invoke-WingetInstall -PackageId $pkg.Id -Name $pkg.Name) {
            Start-Sleep -Seconds 2
            Refresh-SessionPath
            $home = Find-JavaHome
            if ($home) {
                [Environment]::SetEnvironmentVariable("JAVA_HOME", $home, "User")
                $env:JAVA_HOME = $home
                Add-Result "JDK" "installed" $home
                return $home
            }
        }
    }

    Write-ExtLog "  JDK 21 not found — install manually (winget install Microsoft.OpenJDK.21)" "Warn"
    Add-Result "JDK" "failed" "JDK 21 required"
    return $null
}

function Get-GradleVersion {
    param([string]$GradleExe)
    $prev = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $out = & $GradleExe -version 2>&1 | Out-String
        if ($out -match 'Gradle\s+(\d+(?:\.\d+)*)') {
            return [version]$Matches[1]
        }
    } catch { }
    finally { $ErrorActionPreference = $prev }
    return $null
}

function Ensure-Gradle {
    param([string]$MinVersionText)

    $minVer = [version]$MinVersionText
    Refresh-SessionPath
    $gradle = Get-Command gradle -ErrorAction SilentlyContinue
    if ($gradle) {
        $ver = Get-GradleVersion $gradle.Source
        if ($ver -and $ver -ge $minVer) {
            Write-ExtLog ("  Gradle {0} on PATH" -f $ver) "Ok"
            Add-Result "gradle" "ok" $gradle.Source
            return $gradle.Source
        }
        Write-ExtLog ("  Gradle {0} is older than required {1}" -f $ver, $minVer) "Warn"
    }

    Write-ExtLog ("Installing Gradle (>={0}) via winget..." -f $minVer) "Cyan"
    if (Invoke-WingetInstall -PackageId "Gradle.Gradle" -Name "Gradle") {
        Refresh-SessionPath
        $gradle = Get-Command gradle -ErrorAction SilentlyContinue
        if ($gradle) {
            $ver = Get-GradleVersion $gradle.Source
            if ($ver -and $ver -ge $minVer) {
                Add-Result "gradle" "installed" $gradle.Source
                return $gradle.Source
            }
        }
    }

    Write-ExtLog "  Gradle not available — install Gradle >= $minVer and re-run" "Warn"
    Add-Result "gradle" "failed" "Gradle >= $minVer required"
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

function Ensure-DragonDanceSource {
    $git = Get-Command git -ErrorAction SilentlyContinue
    if (-not $git) {
        throw "git is required to clone Dragon Dance ($DragonDanceRepo)"
    }

    New-Item -ItemType Directory -Force -Path (Split-Path $SrcDir -Parent) | Out-Null

    if (-not (Test-Path (Join-Path $SrcDir ".git"))) {
        Write-ExtLog "Cloning Dragon Dance..." "Cyan"
        if (Test-Path $SrcDir) { Remove-Item $SrcDir -Recurse -Force }
        & git clone --filter=blob:none $DragonDanceRepo $SrcDir
        if ($LASTEXITCODE -ne 0) { throw "git clone failed (exit $LASTEXITCODE)" }
    }

    Push-Location $SrcDir
    try {
        & git fetch --depth 1 origin $DragonDanceSha 2>&1 | Out-Null
        & git checkout $DragonDanceSha 2>&1 | ForEach-Object { Write-Host $_ }
        if ($LASTEXITCODE -ne 0) { throw "git checkout $DragonDanceSha failed" }
        $head = (& git rev-parse HEAD).Trim()
        Write-ExtLog "  Source at $head" "Ok"
        return $head
    } finally {
        Pop-Location
    }
}

function Build-DragonDanceExtension {
    param(
        [string]$GhidraInstall,
        [string]$GradleExe
    )

    Push-Location $SrcDir
    try {
        $env:GHIDRA_INSTALL_DIR = $GhidraInstall
        if ($env:JAVA_HOME) {
            $env:Path = "$(Join-Path $env:JAVA_HOME 'bin');$env:Path"
        }

        Write-ExtLog "Building Dragon Dance (gradle buildExtension)..." "Cyan"
        Write-Host "  GHIDRA_INSTALL_DIR=$GhidraInstall"
        & $GradleExe -PGHIDRA_INSTALL_DIR="$GhidraInstall" buildExtension --no-daemon
        if ($LASTEXITCODE -ne 0) {
            throw @"
gradle buildExtension failed (exit $LASTEXITCODE).
Dragon Dance targets Ghidra 9.x APIs; Ghidra 12 may need manual patches.
See docs/GHIDRA_INTEGRATION.md — primary Randfuzz path is Script Manager scripts;
Cartographer is a maintained drcov alternative if the build fails.
"@
        }

        $dist = Join-Path $SrcDir "dist"
        if (-not (Test-Path $dist)) { throw "Build succeeded but dist/ missing under $SrcDir" }
        $zip = Get-ChildItem $dist -Filter "*.zip" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if (-not $zip) { throw "No extension zip in $dist" }
        return $zip.FullName
    } finally {
        Pop-Location
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

    $stage = Join-Path $env:TEMP ("randall-ghidra-ext-{0}" -f ([guid]::NewGuid().ToString("n")))
    New-Item -ItemType Directory -Force -Path $stage | Out-Null
    try {
        Expand-Archive -Path $ZipPath -DestinationPath $stage -Force
        $inner = Get-ChildItem $stage -Directory | Select-Object -First 1
        if (-not $inner) { throw "Unexpected extension zip layout — no top-level directory in $ZipPath" }

        $dest = Join-Path $extensionsRoot $inner.Name
        if (Test-Path $dest) {
            Remove-Item $dest -Recurse -Force
        }
        Copy-Item $inner.FullName $dest -Recurse -Force
        Write-ExtLog "Installed extension folder: $dest" "Ok"
        return $dest
    } finally {
        Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Install-DragonDance {
    param([string]$GhidraInstall)

    $ghidraVersion = Get-GhidraApplicationVersion $GhidraInstall
    $gradleMin = Get-GhidraGradleMin $GhidraInstall

    $marker = Read-InstallMarker
    if ($marker -and -not $Force) {
        $sameSha = $marker.dragondanceSha -eq $DragonDanceSha
        $sameGhidra = $marker.ghidraInstallDir -eq $GhidraInstall
        $extOk = $marker.extensionDir -and (Test-Path $marker.extensionDir)
        if ($sameSha -and $sameGhidra -and $extOk) {
            Write-ExtLog "Dragon Dance already installed (marker + extension dir present)." "Ok"
            Add-Result "Dragon Dance" "ok" $marker.extensionDir
            return
        }
    }

    $jdk = Ensure-Jdk
    if (-not $jdk) {
        Add-Result "Dragon Dance" "failed" "JDK 21 required"
        return
    }

    $gradle = Ensure-Gradle -MinVersionText $gradleMin
    if (-not $gradle) {
        Add-Result "Dragon Dance" "failed" "Gradle >= $gradleMin required"
        return
    }

    $head = Ensure-DragonDanceSource
    $builtZip = Build-DragonDanceExtension -GhidraInstall $GhidraInstall -GradleExe $gradle

    New-Item -ItemType Directory -Force -Path $DistDir | Out-Null
    $cachedZip = Join-Path $DistDir (Split-Path $builtZip -Leaf)
    Copy-Item $builtZip $cachedZip -Force
    Write-ExtLog "Cached extension zip: $cachedZip" "Ok"

    $extDir = Install-ExtensionZip -ZipPath $cachedZip -GhidraInstall $GhidraInstall

    Write-InstallMarker @{
        dragondanceSha    = $DragonDanceSha
        dragondanceHead   = $head
        ghidraInstallDir  = $GhidraInstall
        ghidraVersion     = $ghidraVersion
        extensionZip      = $cachedZip
        extensionDir      = $extDir
        installedAt       = (Get-Date).ToString("o")
    }

    Add-Result "Dragon Dance" "installed" "$extDir · sha $DragonDanceSha"
}

function Write-ManualHints {
    Write-Host ""
    Write-ExtLog "Manual Dragon Dance install:" "Cyan"
    Write-Host "  1. Install Ghidra: .\scripts\install-ghidra.ps1"
    Write-Host "  2. Clone https://github.com/0ffffffffh/dragondance @ $DragonDanceSha"
    Write-Host "  3. gradle -PGHIDRA_INSTALL_DIR=<tools\ghidra-app> buildExtension"
    Write-Host "  4. Ghidra → File → Install Extensions → green + → select dist\*.zip → restart"
    Write-Host "  Primary Randfuzz path remains tools\ghidra\ Script Manager scripts."
    Write-Host "  Docs: docs/GHIDRA_INTEGRATION.md"
}

# --- main ---

if ($Skip) {
    Write-ExtLog "Skipping Ghidra extensions (-Skip)." "Warn"
    Add-Result "ghidra-extensions" "skipped" "-Skip"
    exit 0
}

Write-Host "Randfuzz Ghidra extensions installer"
Write-Host "  Dragon Dance SHA: $DragonDanceSha"
Write-Host "  Staging:          $ExtRoot"
Write-Host ""

$ghidraInstall = Resolve-GhidraInstallDir -Override $GhidraDir
if (-not $ghidraInstall) {
    Write-ExtLog "Ghidra not found — install Ghidra first (scripts/install-ghidra.ps1)." "Warn"
    Write-ManualHints
    Add-Result "ghidra" "failed" "install Ghidra before extensions"
    exit 1
}

Write-Host "  Ghidra:           $ghidraInstall"
$ver = Get-GhidraApplicationVersion $ghidraInstall
if ($ver) { Write-Host "  Ghidra version:   $ver" }
Write-Host ""

if (-not $SkipDragonDance) {
    try {
        Install-DragonDance -GhidraInstall $ghidraInstall
    } catch {
        Write-ExtLog $_.Exception.Message "Error"
        Write-ManualHints
        Add-Result "Dragon Dance" "failed" $_.Exception.Message
    }
} else {
    Add-Result "Dragon Dance" "skipped" "-SkipDragonDance"
}

if ($GhidraMcp) {
    $mcpScript = Join-Path $PSScriptRoot "install-ghidra-mcp.ps1"
    if (Test-Path $mcpScript) {
        Write-Host ""
        Write-Host "======== Ghidra MCP (bethington/ghidra-mcp) ========" -ForegroundColor Cyan
        $mcpArgs = @("-File", $mcpScript, "-GhidraDir", $ghidraInstall)
        if ($Force) { $mcpArgs += "-Force" }
        $psExe = Get-Command powershell.exe -ErrorAction SilentlyContinue
        if ($psExe) {
            & $psExe.Source -NoProfile -ExecutionPolicy Bypass @mcpArgs
        } else {
            if ($Force) { & $mcpScript -GhidraDir $ghidraInstall -Force }
            else { & $mcpScript -GhidraDir $ghidraInstall }
        }
        if ($LASTEXITCODE -ne 0) {
            Add-Result "Ghidra MCP" "failed" "install-ghidra-mcp.ps1 exit $LASTEXITCODE"
        } else {
            Add-Result "Ghidra MCP" "ok" "see install-ghidra-mcp.ps1 summary"
        }
    } else {
        Write-ExtLog "Missing $mcpScript" "Warn"
        Add-Result "Ghidra MCP" "failed" "missing install-ghidra-mcp.ps1"
    }
} else {
    Add-Result "Ghidra MCP" "skipped" "pass -GhidraMcp to install"
}

Write-Host ""
Write-Host "========== Ghidra extensions summary =========="
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
Write-Host "After first launch: CodeBrowser → File → Configure → enable Dragon Dance plugin if prompted."
Write-Host "Import binary drcov: Window → Dragon Dance → traces-binary/*.log from randall stalk capture-binary."
Write-Host "Primary stalk colors: Script Manager → tools\ghidra\ (RandfuzzImport*.py)."
Write-Host "Docs: docs/GHIDRA_INTEGRATION.md"

$failed = @($script:Results | Where-Object { $_.Status -eq "failed" })
if ($failed.Count -gt 0) { exit 1 }
exit 0
