# Uninstall Randfuzz lab artifacts from this machine: stop everything first
# (server, CLI fuzz/agent, vuln labs, recorders), then remove what the
# install-*.ps1 / build-*.ps1 scripts put in place. Safe by default:
#
#   - Never touches the git clone itself (src/, docs/, projects/, .git/)
#   - Never touches .NET SDK, Git, WinDbg/SDK debuggers, or other system-wide
#     packages - those are not owned by these install scripts
#   - Only removes tools\ / targets\ content that install-*.ps1 / build-*.ps1
#     put there (mirrors .gitignore), plus repo-local PATH entries it added
#   - data\ (crash dumps, corpus, runtime-slots.json) is left alone unless
#     you pass -RemoveData - that is fuzzing output, not an install artifact
#
# Examples:
#   powershell -ExecutionPolicy Bypass -File .\scripts\uninstall-lab.ps1
#   powershell -ExecutionPolicy Bypass -File .\scripts\uninstall-lab.ps1 -WhatIf
#   powershell -ExecutionPolicy Bypass -File .\scripts\uninstall-lab.ps1 -Force
#   powershell -ExecutionPolicy Bypass -File .\scripts\uninstall-lab.ps1 -KeepTools
#   powershell -ExecutionPolicy Bypass -File .\scripts\uninstall-lab.ps1 -KeepTargets
#   powershell -ExecutionPolicy Bypass -File .\scripts\uninstall-lab.ps1 -Force -RemoveData
#   powershell -ExecutionPolicy Bypass -File .\scripts\uninstall-lab.ps1 -StopOnly
[CmdletBinding()]
param(
    [switch]$Force,
    [switch]$WhatIf,
    [switch]$KeepTools,
    [switch]$KeepTargets,
    [switch]$RemoveData,
    [switch]$StopOnly
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$script:Results = [System.Collections.Generic.List[object]]::new()

function Write-UnLog {
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
        [ValidateSet("stopped", "removed", "skipped", "kept", "failed", "note")]
        [string]$Status,
        [string]$Detail = ""
    )
    $script:Results.Add([pscustomobject]@{ Name = $Name; Status = $Status; Detail = $Detail }) | Out-Null
}

# --- process / port teardown -------------------------------------------------

function Get-DotnetRandallProcesses {
    param([string]$Match)
    $hits = [System.Collections.Generic.List[object]]::new()
    try {
        Get-CimInstance Win32_Process -Filter "Name = 'dotnet.exe'" -ErrorAction SilentlyContinue |
            Where-Object { $_.CommandLine -and ($_.CommandLine -match $Match) } |
            ForEach-Object { $hits.Add($_) | Out-Null }
    } catch { }
    return $hits
}

function Stop-Pid {
    param([int]$ProcId, [string]$Why)
    try {
        $p = Get-Process -Id $ProcId -ErrorAction SilentlyContinue
        if (-not $p -or $p.HasExited) { return $false }
        try {
            $p.Kill($true)
        } catch {
            & taskkill.exe /PID $ProcId /T /F *> $null
        }
        $p.WaitForExit(5000) | Out-Null
        Write-Verbose ("Stopped PID {0} ({1})" -f $ProcId, $Why)
        return $true
    } catch {
        return $false
    }
}

function Stop-ByName {
    param([string[]]$Names)
    $count = 0
    foreach ($name in $Names) {
        Get-Process -Name $name -ErrorAction SilentlyContinue | ForEach-Object {
            if (Stop-Pid -ProcId $_.Id -Why $name) { $count++ }
        }
    }
    return $count
}

function Stop-PortListeners {
    param([int[]]$Ports)
    $killed = 0
    try {
        $netstat = & netstat.exe -ano 2>$null
    } catch {
        return 0
    }
    foreach ($line in $netstat) {
        foreach ($port in $Ports) {
            if ($line -match ("[:\s]{0}\s" -f $port) -and $line -match "LISTENING\s+(\d+)\s*$") {
                $procId = [int]$Matches[1]
                if (Stop-Pid -ProcId $procId -Why "port $port") { $killed++ }
            }
        }
    }
    return $killed
}

function Stop-RandallServer {
    Write-UnLog "======== Randall.Server / web UI ========" "Cyan"
    $procs = Get-DotnetRandallProcesses -Match "Randall\.Server"
    $n = 0
    foreach ($p in $procs) { if (Stop-Pid -ProcId $p.ProcessId -Why "Randall.Server") { $n++ } }
    $n += Stop-ByName -Names @("Randall.Server")
    # Standalone publish (randall pack) keeps the friendly launcher name too.
    $n += Stop-ByName -Names @("randall")
    if ($n -gt 0) {
        Write-UnLog ("  Stopped {0} process(es)" -f $n) "Ok"
        Add-Result "Randall.Server" "stopped" "$n process(es)"
    } else {
        Write-Host "  Not running"
        Add-Result "Randall.Server" "skipped" "not running"
    }
}

function Stop-RandallCli {
    Write-UnLog "======== Randall.Cli (fuzz / agent / serve sessions) ========" "Cyan"
    $procs = Get-DotnetRandallProcesses -Match "Randall\.Cli"
    $n = 0
    foreach ($p in $procs) { if (Stop-Pid -ProcId $p.ProcessId -Why "Randall.Cli") { $n++ } }
    if ($n -gt 0) {
        Write-UnLog ("  Stopped {0} process(es)" -f $n) "Ok"
        Add-Result "Randall.Cli" "stopped" "$n process(es)"
    } else {
        Write-Host "  Not running"
        Add-Result "Randall.Cli" "skipped" "not running"
    }
}

function Stop-LabsAndRuntime {
    Write-UnLog "======== Vuln labs / Target Runtime ========" "Cyan"

    $cliDll = Get-ChildItem -Path (Join-Path $Root "src\Randall.Cli\bin") -Filter "Randall.Cli.dll" -Recurse -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1

    $usedCli = $false
    if ($cliDll) {
        foreach ($sub in @("labs stop-all", "runtime stop-all", "recorders stop")) {
            try {
                Write-Host ("  dotnet {0} {1}" -f $cliDll.Name, $sub)
                $out = & dotnet $cliDll.FullName @($sub -split ' ') 2>&1
                $out | ForEach-Object { Write-Host ("    {0}" -f $_) }
                Add-Result $sub "stopped" "via Randall.Cli"
                $usedCli = $true
            } catch {
                Write-UnLog ("  [!] randall {0} failed: {1}" -f $sub, $_.Exception.Message) "Warn"
                Add-Result $sub "failed" $_.Exception.Message
            }
        }
    } else {
        Write-UnLog "  Randall.Cli.dll not built - falling back to raw process/port cleanup." "Warn"
    }

    # Always do a raw backstop pass too - covers orphans the CLI slot file
    # does not know about (killed -9, moved repo, never-managed processes).
    $labNames = @(
        "randall-vulnserver", "randall-vulnhttp", "randall-vulnftp", "randall-vulnssh",
        "randall-vulntftp", "randall-vulnrpc", "randall-vulnsmb", "randall-screamcrash",
        "scream_crash"
    )
    $n = Stop-ByName -Names $labNames
    $labPorts = @(9999, 8080, 2121, 2222, 6969, 1355, 4455)
    $n += Stop-PortListeners -Ports $labPorts

    if (-not $usedCli) {
        if ($n -gt 0) {
            Write-UnLog ("  Stopped {0} lab process(es)/listener(s) by name/port" -f $n) "Ok"
            Add-Result "labs stop-all" "stopped" "$n process(es) (raw fallback)"
        } else {
            Write-Host "  No lab processes running"
            Add-Result "labs stop-all" "skipped" "not running"
        }
    } elseif ($n -gt 0) {
        Write-UnLog ("  Backstop cleared {0} extra orphan(s)" -f $n) "Ok"
    }
}

function Stop-Recorders {
    Write-UnLog "======== Recorders (Procmon / DebugView / ProcDump / WPR / pktmon / tshark) ========" "Cyan"
    $n = Stop-ByName -Names @(
        "Procmon64", "Procmon", "procmon",
        "Dbgview", "dbgview", "Dbgview64",
        "procdump", "procdump64",
        "tshark", "dumpcap"
    )
    try {
        $wpr = Get-Command wpr.exe -ErrorAction SilentlyContinue
        if ($wpr) {
            & wpr.exe -cancel *> $null
        }
    } catch { }
    try {
        $pktmon = Get-Command pktmon.exe -ErrorAction SilentlyContinue
        if ($pktmon) {
            & pktmon.exe stop *> $null
        }
    } catch { }
    if ($n -gt 0) {
        Write-UnLog ("  Stopped {0} recorder process(es); issued wpr -cancel / pktmon stop" -f $n) "Ok"
        Add-Result "recorders" "stopped" "$n process(es) + wpr/pktmon cancel"
    } else {
        Write-Host "  No orphaned recorders found (wpr -cancel / pktmon stop still issued)"
        Add-Result "recorders" "skipped" "none running"
    }
}

# --- file / PATH removal ------------------------------------------------------

function Get-RemovalPlan {
    $items = [System.Collections.Generic.List[object]]::new()

    if (-not $KeepTools) {
        $toolsDir = Join-Path $Root "tools"
        $items.Add(@{ Kind = "dir";  Path = (Join-Path $toolsDir "dynamorio");    Label = "tools\dynamorio (DynamoRIO)" })
        $items.Add(@{ Kind = "glob"; Path = $toolsDir; Filter = "DynamoRIO-*";     Label = "tools\DynamoRIO-* (versioned extract)" })
        $items.Add(@{ Kind = "dir";  Path = (Join-Path $toolsDir "mingw64");      Label = "tools\mingw64 (WinLibs gcc)" })
        $items.Add(@{ Kind = "dir";  Path = (Join-Path $toolsDir "API Monitor"); Label = "tools\API Monitor" })
        $items.Add(@{ Kind = "glob"; Path = $toolsDir; Filter = "*.exe";          Label = "tools\*.exe (Sysinternals binaries)" })
        $items.Add(@{ Kind = "dir";  Path = (Join-Path $env:LOCALAPPDATA "Randfuzz"); Label = "%LOCALAPPDATA%\Randfuzz (fallback gcc install)" })
    }

    if (-not $KeepTargets) {
        foreach ($lab in @("vulnserver", "vulnhttp", "vulnftp", "vulnssh", "vulntftp", "vulnrpc", "vulnsmb", "screamcrash")) {
            $dir = Join-Path $Root "targets\$lab"
            $items.Add(@{ Kind = "globKeepGitkeep"; Path = $dir; Label = "targets\$lab\* (built lab binaries)" })
        }
    }

    if ($RemoveData) {
        $items.Add(@{ Kind = "dir"; Path = (Join-Path $Root "data"); Label = "data\ (crash dumps, corpus, runtime state)" })
    }

    return $items
}

function Resolve-PlanEntries {
    param($Plan)
    $entries = [System.Collections.Generic.List[object]]::new()
    foreach ($item in $Plan) {
        switch ($item.Kind) {
            "dir" {
                if (Test-Path -LiteralPath $item.Path) {
                    $entries.Add([pscustomobject]@{ Label = $item.Label; Paths = @($item.Path) })
                }
            }
            "glob" {
                $hits = Get-ChildItem -Path $item.Path -Filter $item.Filter -ErrorAction SilentlyContinue
                if ($hits) {
                    $entries.Add([pscustomobject]@{ Label = $item.Label; Paths = @($hits.FullName) })
                }
            }
            "globKeepGitkeep" {
                if (Test-Path -LiteralPath $item.Path) {
                    $hits = Get-ChildItem -Path $item.Path -Force -ErrorAction SilentlyContinue |
                        Where-Object { $_.Name -ne ".gitkeep" }
                    if ($hits) {
                        $entries.Add([pscustomobject]@{ Label = $item.Label; Paths = @($hits.FullName) })
                    }
                }
            }
        }
    }
    return $entries
}

function Remove-RepoPathEntries {
    $toolsMingwBin = Join-Path $Root "tools\mingw64\bin"
    $localMingwBin = Join-Path $env:LOCALAPPDATA "Randfuzz\mingw64\bin"
    $targets = @($toolsMingwBin, $localMingwBin) | ForEach-Object { $_.TrimEnd('\') }

    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ([string]::IsNullOrWhiteSpace($userPath)) { return }

    $parts = $userPath.Split(';', [System.StringSplitOptions]::RemoveEmptyEntries)
    $kept = $parts | Where-Object {
        $norm = $_.TrimEnd('\')
        -not ($targets | Where-Object { $_.Equals($norm, [StringComparison]::OrdinalIgnoreCase) })
    }

    if ($kept.Count -eq $parts.Count) {
        Add-Result "user PATH" "skipped" "no repo-local mingw entries found"
        return
    }

    $removedCount = $parts.Count - $kept.Count
    if ($WhatIf) {
        Write-UnLog ("  Would remove {0} repo-local mingw entrie(s) from user PATH" -f $removedCount) "Cyan"
        Add-Result "user PATH" "note" "-WhatIf: would remove $removedCount entrie(s)"
        return
    }

    [Environment]::SetEnvironmentVariable("Path", ($kept -join ';'), "User")
    Write-UnLog ("  Removed {0} repo-local mingw entrie(s) from user PATH (open a new shell)" -f $removedCount) "Ok"
    Add-Result "user PATH" "removed" "$removedCount entrie(s)"
}

# --- main ----------------------------------------------------------------

Write-Host "Randfuzz lab uninstaller"
Write-Host "  Repo: $Root"
if ($WhatIf) { Write-UnLog "  Mode: -WhatIf (dry run - nothing will be stopped or deleted)" "Cyan" }
Write-Host ""

if (-not $WhatIf) {
    Write-UnLog "== Stopping processes ==" "Cyan"
    Stop-RandallServer
    Stop-RandallCli
    Stop-LabsAndRuntime
    Stop-Recorders
} else {
    Write-UnLog "== Stopping processes == (skipped for -WhatIf; use -Force to actually stop+remove)" "Cyan"
}

if ($StopOnly) {
    Write-Host ""
    Write-Host "========== Summary (stop-only) =========="
    foreach ($r in $script:Results) {
        Write-Host ("  [{0,-8}] {1,-16} {2}" -f $r.Status, $r.Name, $r.Detail)
    }
    Write-Host ""
    Write-UnLog "-StopOnly requested - tools\ / targets\ left untouched." "Ok"
    exit 0
}

Write-Host ""
Write-UnLog "== Planning removal ==" "Cyan"
$plan = Get-RemovalPlan
$entries = Resolve-PlanEntries -Plan $plan

if ($entries.Count -eq 0) {
    Write-UnLog "Nothing to remove (tools\ / targets\ already clean, or -KeepTools/-KeepTargets given)." "Ok"
    Write-Host ""
    Write-Host "========== Summary =========="
    foreach ($r in $script:Results) {
        Write-Host ("  [{0,-8}] {1,-16} {2}" -f $r.Status, $r.Name, $r.Detail)
    }
    exit 0
}

Write-Host "Will remove:"
foreach ($e in $entries) {
    Write-Host ("  - {0}  ({1} item(s))" -f $e.Label, $e.Paths.Count)
}
if ($KeepTools)   { Write-Host "  (tools\ kept - -KeepTools)" -ForegroundColor DarkGray }
if ($KeepTargets) { Write-Host "  (targets\ kept - -KeepTargets)" -ForegroundColor DarkGray }
if (-not $RemoveData) { Write-Host "  (data\ kept - pass -RemoveData to also wipe crash/corpus/runtime state)" -ForegroundColor DarkGray }
Write-Host ""

if ($WhatIf) {
    Write-UnLog "-WhatIf: no files removed, no processes stopped, PATH unchanged." "Cyan"
    Remove-RepoPathEntries
    exit 0
}

if (-not $Force) {
    $answer = Read-Host "Proceed with removal above? [y/N]"
    if ($answer -notmatch '^(y|yes)$') {
        Write-UnLog "Aborted - no files removed. Re-run with -Force to skip this prompt." "Warn"
        exit 1
    }
}

Write-Host ""
Write-UnLog "== Removing files ==" "Cyan"
foreach ($e in $entries) {
    $ok = $true
    $detail = ""
    try {
        foreach ($p in $e.Paths) {
            if (Test-Path -LiteralPath $p -PathType Container) {
                Remove-Item -LiteralPath $p -Recurse -Force -ErrorAction Stop
            } else {
                Remove-Item -LiteralPath $p -Force -ErrorAction Stop
            }
        }
        $detail = "$($e.Paths.Count) item(s)"
    } catch {
        $ok = $false
        $detail = $_.Exception.Message
    }
    if ($ok) {
        Write-UnLog ("  [+] {0}" -f $e.Label) "Ok"
        Add-Result $e.Label "removed" $detail
    } else {
        Write-UnLog ("  [!] {0} - {1}" -f $e.Label, $detail) "Warn"
        Add-Result $e.Label "failed" $detail
    }
}

Write-Host ""
Write-UnLog "== Cleaning PATH ==" "Cyan"
Remove-RepoPathEntries

Write-Host ""
Write-Host "========== Summary =========="
foreach ($r in $script:Results) {
    $color = switch ($r.Status) {
        "removed" { "Green" }
        "stopped" { "Green" }
        "skipped" { "DarkGray" }
        "kept"    { "DarkGray" }
        "note"    { "Cyan" }
        default   { "Yellow" }
    }
    Write-Host ("  [{0,-8}] {1,-16} {2}" -f $r.Status, $r.Name, $r.Detail) -ForegroundColor $color
}

Write-Host ""
Write-Host "Not touched (by design):"
Write-Host "  - git clone source (src\, docs\, projects\, .git\)"
Write-Host "  - .NET SDK / Git / WinDbg Preview / Windows SDK debuggers / winget packages"
if (-not $RemoveData) { Write-Host "  - data\ (pass -RemoveData to also remove crash dumps / corpus / runtime state)" }
if ($KeepTools)   { Write-Host "  - tools\ (-KeepTools)" }
if ($KeepTargets) { Write-Host "  - targets\ built binaries (-KeepTargets)" }
Write-Host ""
Write-Host "Reinstall later:  powershell -ExecutionPolicy Bypass -File .\scripts\install-lab-tools.ps1"
Write-Host "Rebuild targets:  powershell -ExecutionPolicy Bypass -File .\scripts\build-all-lab-targets.ps1"

$failed = @($script:Results | Where-Object { $_.Status -eq "failed" })
if ($failed.Count -gt 0) { exit 1 }
exit 0
