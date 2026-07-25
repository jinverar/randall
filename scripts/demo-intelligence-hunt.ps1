# Operator 10-minute intelligence hunt (Windows).
# Optional build → Ghidra static map (if installed) → short brain-on fuzz → frontier + intel refresh.
#
# Examples:
#   powershell -ExecutionPolicy Bypass -File .\scripts\demo-intelligence-hunt.ps1
#   powershell -ExecutionPolicy Bypass -File .\scripts\demo-intelligence-hunt.ps1 -Project harness-demo
#   powershell -ExecutionPolicy Bypass -File .\scripts\demo-intelligence-hunt.ps1 -SkipBuild -Iterations 30
#   powershell -ExecutionPolicy Bypass -File .\scripts\demo-intelligence-hunt.ps1 -Project vulnserver
[CmdletBinding()]
param(
    [ValidateSet("file-text", "harness-demo", "vulnserver")]
    [string]$Project = "file-text",
    [switch]$SkipBuild,
    [int]$Iterations = 50
)

$ErrorActionPreference = "Continue"
$Root = Split-Path -Parent $PSScriptRoot
$Config = Join-Path $Root "projects\$Project.yaml"
$script:Steps = [System.Collections.Generic.List[object]]::new()

function Write-HuntLog {
    param([string]$Message, [string]$Level = "Info")
    switch ($Level) {
        "Warn"  { Write-Host $Message -ForegroundColor Yellow }
        "Error" { Write-Host $Message -ForegroundColor Red }
        "Ok"    { Write-Host $Message -ForegroundColor Green }
        "Cyan"  { Write-Host $Message -ForegroundColor Cyan }
        default { Write-Host $Message }
    }
}

function Add-Step {
    param(
        [string]$Name,
        [ValidateSet("ok", "skip", "fail")]
        [string]$Status,
        [string]$Detail = ""
    )
    $script:Steps.Add([pscustomobject]@{ Step = $Name; Status = $Status; Detail = $Detail }) | Out-Null
}

function Invoke-Randall {
    param([string[]]$CliArgs)
    Push-Location $Root
    try {
        & dotnet run --project (Join-Path $Root "src\Randall.Cli") -- @CliArgs
        return $LASTEXITCODE
    } finally {
        Pop-Location
    }
}

function Test-GhidraInstalled {
    $marker = Join-Path $Root "tools\ghidra-app\ghidraRun.bat"
    if (Test-Path $marker) { return $marker }

    $envHome = $env:GHIDRA_INSTALL_DIR
    if ($envHome) {
        $fromEnv = Join-Path $envHome "ghidraRun.bat"
        if (Test-Path $fromEnv) { return $fromEnv }
    }

    $ghidraCmd = Get-Command ghidraRun.bat -ErrorAction SilentlyContinue
    if ($ghidraCmd) { return $ghidraCmd.Source }

    return $null
}

function Get-AnalyzeBinary {
    param([string]$ProjectName)
    switch ($ProjectName) {
        "file-text" {
            $candidates = @(
                (Join-Path $Root "targets\file-text\app.exe"),
                (Join-Path $Root "targets\file-text\file-text.exe")
            )
            foreach ($p in $candidates) {
                if (Test-Path $p) { return $p }
            }
            return $null
        }
        "vulnserver" {
            $candidates = @(
                (Join-Path $Root "targets\vulnserver\randall-vulnserver.exe"),
                (Join-Path $Root "targets\vulnserver\vulnserver.exe")
            )
            foreach ($p in $candidates) {
                if (Test-Path $p) { return $p }
            }
            return $null
        }
        default { return $null }
    }
}

Set-Location $Root
Write-HuntLog ""
Write-HuntLog "======== Randfuzz operator intelligence hunt ========" "Cyan"
Write-HuntLog "Project: $Project · iterations: $Iterations · repo: $Root"
Write-HuntLog ""

if (-not (Test-Path $Config)) {
    Write-HuntLog "[x] Missing project config: $Config" "Error"
    exit 1
}

# --- dotnet build (soft-fail: fuzz may still work from prior build) ---
Write-HuntLog "======== dotnet build ========" "Cyan"
& dotnet build (Join-Path $Root "Randall.sln") -c Release --nologo -v q
if ($LASTEXITCODE -eq 0) {
    Add-Step "dotnet build" "ok" "Release"
} else {
    Add-Step "dotnet build" "fail" "exit $LASTEXITCODE — continuing with prior binaries if present"
    Write-HuntLog "[!] dotnet build failed — later steps may fail too" "Warn"
}

# --- optional target build ---
if (-not $SkipBuild) {
    Write-HuntLog ""
    Write-HuntLog "======== build target ($Project) ========" "Cyan"
    if ($Project -eq "file-text") {
        $buildScript = Join-Path $PSScriptRoot "build-file-text.ps1"
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $buildScript
        if ($LASTEXITCODE -eq 0) {
            Add-Step "build file-text" "ok" "targets\file-text\app.exe"
        } else {
            Add-Step "build file-text" "fail" "gcc missing? scripts\install-gcc.ps1"
            Write-HuntLog "[!] file-text build failed — fuzz may skip if binary missing" "Warn"
        }
    } elseif ($Project -eq "vulnserver") {
        $buildScript = Join-Path $PSScriptRoot "build-lab-targets.ps1"
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $buildScript vulnserver
        if ($LASTEXITCODE -eq 0) {
            Add-Step "build vulnserver" "ok" "targets\vulnserver\randall-vulnserver.exe"
        } else {
            Add-Step "build vulnserver" "fail" "scripts\build-lab-targets.ps1 vulnserver"
            Write-HuntLog "[!] vulnserver build failed — fuzz may skip if binary missing" "Warn"
        }
    } else {
        & dotnet build (Join-Path $Root "targets\Randall.HarnessDemo") -c Release --nologo
        if ($LASTEXITCODE -eq 0) {
            Add-Step "build harness-demo" "ok" "Randall.HarnessDemo Release"
        } else {
            Add-Step "build harness-demo" "fail" "exit $LASTEXITCODE"
            Write-HuntLog "[!] harness-demo build failed" "Warn"
        }
    }
} else {
    Add-Step "build target" "skip" "-SkipBuild"
    Write-HuntLog "======== build target ======== (skipped)" "Warn"
}

# --- Ghidra static map (optional) ---
Write-HuntLog ""
Write-HuntLog "======== stalk ghidra-analyze (optional) ========" "Cyan"
$ghidraRun = Test-GhidraInstalled
if (-not $ghidraRun) {
    Add-Step "ghidra-analyze" "skip" "Ghidra not installed — scripts\install-ghidra.ps1 or manual export"
    Write-HuntLog "[~] Ghidra not found — skipping static map (brain still runs on coverage/frontier/scream)" "Warn"
    Write-HuntLog "    Manual path: tools\ghidra\ RandfuzzExportAnalysis.py → data\stalk\$Project\randall-analysis.json" "Warn"
} elseif ($Project -ne "file-text") {
    Add-Step "ghidra-analyze" "skip" "native binary required — use -Project file-text for headless analyze"
    Write-HuntLog "[~] ghidra-analyze skipped for in-process harness (no native PE to analyze)" "Warn"
} else {
    $binary = Get-AnalyzeBinary $Project
    if (-not $binary) {
        Add-Step "ghidra-analyze" "skip" "binary missing — run build step first"
        Write-HuntLog "[~] No file-text binary — skipping ghidra-analyze" "Warn"
    } else {
        $analyzeArgs = @(
            "stalk", "ghidra-analyze",
            "-p", $Project,
            "-c", $Config,
            "--binary", $binary
        )
        $code = Invoke-Randall $analyzeArgs
        if ($code -eq 0) {
            Add-Step "ghidra-analyze" "ok" "data\stalk\$Project\randall-analysis.json"
        } else {
            Add-Step "ghidra-analyze" "fail" "exit $code — JDK/Ghidra headless issue"
            Write-HuntLog "[!] ghidra-analyze failed (soft-fail) — continuing hunt loop" "Warn"
        }
    }
}

# --- short fuzz (brain on by default; Scream wait on Windows native targets) ---
Write-HuntLog ""
Write-HuntLog "======== fuzz ($Iterations iters, brain on) ========" "Cyan"
$fuzzArgs = @(
    "fuzz",
    "-c", $Config,
    "--max-iterations", "$Iterations",
    "--verbose"
)
if ($Project -eq "file-text") {
    $fuzzArgs += @("--debugger", "wait")
    Write-HuntLog "Using --debugger wait (Scream) for native file-text target" "Cyan"
} elseif ($Project -eq "vulnserver") {
    Write-HuntLog "vulnserver: TCP lab target — brain on; Crashes harvest uses profile name '$Project' (YAML name:, not filename)" "Cyan"
} else {
    Write-HuntLog "harness-demo: in-process — Scream wait not applicable; brain still active" "Cyan"
}

$fuzzCode = Invoke-Randall $fuzzArgs
if ($fuzzCode -eq 0) {
    Add-Step "fuzz" "ok" "$Iterations iterations · fuzz.brain default on"
} else {
    Add-Step "fuzz" "fail" "exit $fuzzCode"
    Write-HuntLog "[!] fuzz failed — frontier/intel may be thin" "Warn"
}

# --- frontier ---
Write-HuntLog ""
Write-HuntLog "======== stalk frontier ========" "Cyan"
$frontierCode = Invoke-Randall @("stalk", "frontier", "-p", $Project)
if ($frontierCode -eq 0) {
    Add-Step "stalk frontier" "ok" "data\stalk\$Project\frontier.json"
} else {
    Add-Step "stalk frontier" "fail" "exit $frontierCode"
    Write-HuntLog "[!] stalk frontier failed (empty mode still possible without DynamoRIO)" "Warn"
}

# --- target intelligence refresh ---
Write-HuntLog ""
Write-HuntLog "======== stalk intel --refresh ========" "Cyan"
$intelCode = Invoke-Randall @("stalk", "intel", "-p", $Project, "--refresh")
if ($intelCode -eq 0) {
    Add-Step "stalk intel" "ok" "data\stalk\$Project\target_intelligence.json"
} else {
    Add-Step "stalk intel" "fail" "exit $intelCode"
    Write-HuntLog "[!] stalk intel refresh failed" "Warn"
}

# --- summary ---
Write-HuntLog ""
Write-HuntLog "======== hunt summary ========" "Cyan"
$failCount = 0
foreach ($s in $script:Steps) {
    $icon = switch ($s.Status) {
        "ok"   { "[ok]" }
        "skip" { "[~]" }
        default { "[x]" ; $failCount++ }
    }
    $detail = if ($s.Detail) { " — $($s.Detail)" } else { "" }
    Write-HuntLog ("  {0,-18} {1}{2}" -f $s.Step, $icon, $detail)
}

Write-HuntLog ""
Write-HuntLog "======== next (Scare Floor) ========" "Cyan"
Write-HuntLog "  1. dotnet run --project src\Randall.Server --urls http://127.0.0.1:5000"
Write-HuntLog "  2. Open Fuzz → Scare Floor for project '$Project'"
Write-HuntLog "  3. Crashes → Scream canisters: Live only (on while fuzzing) bottles by YAML profile name — e.g. file-text not file_text"
Write-HuntLog "  4. Look for **Brain** (lastBrainDecision / Why? terms) and **Scare Doors** (gray frontier rows)"
Write-HuntLog "  5. CLI: randall stalk frontier -p $Project  ·  GET /api/fuzz/brain?project=$Project"
Write-HuntLog ""
Write-HuntLog "Docs: docs\ROADMAP_INTELLIGENCE.md · docs\FUZZING.md#randallbrain-closed-loop-hunt-steering" "Cyan"

if ($failCount -gt 0) {
    Write-HuntLog "Completed with $failCount failed step(s) — review summary above (soft-fail demo)." "Warn"
    exit 2
}

Write-HuntLog "Hunt demo complete." "Ok"
exit 0
