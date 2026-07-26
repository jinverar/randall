# Build debugger regression corpus native fault harness (Windows + gcc).
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Src = Join-Path $Root "targets\debugger-corpus\debugger_corpus_fault.c"
$OutDir = Join-Path $Root "targets\debugger-corpus"
$OutExe = Join-Path $OutDir "debugger_corpus_fault.exe"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$machine = [Environment]::GetEnvironmentVariable("Path", "Machine")
$user = [Environment]::GetEnvironmentVariable("Path", "User")
$env:Path = (@($machine, $user) | Where-Object { $_ }) -join ";"
foreach ($bin in @(
        (Join-Path $Root "tools\mingw64\bin"),
        (Join-Path $env:LOCALAPPDATA "Randfuzz\mingw64\bin")
    )) {
    if (-not (Test-Path (Join-Path $bin "gcc.exe"))) { continue }
    $norm = $bin.TrimEnd('\')
    $present = $false
    foreach ($part in ($env:Path -split ";")) {
        if ($part -and ($part.TrimEnd('\') -ieq $norm)) { $present = $true; break }
    }
    if (-not $present) { $env:Path = "$norm;$env:Path" }
}

$Gcc = Get-Command gcc -ErrorAction SilentlyContinue
if (-not $Gcc) {
    Write-Host "[!] Skipping debugger-corpus harness - gcc not found." -ForegroundColor Yellow
    Write-Host "    Install: powershell -ExecutionPolicy Bypass -File .\scripts\install-gcc.ps1" -ForegroundColor Yellow
    exit 0
}

Write-Host "Building debugger_corpus_fault.exe..."
& gcc -O0 -o $OutExe $Src
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "Done: $OutExe"
Write-Host "Tests: dotnet test tests/Randall.Tests --filter DebuggerCorpus"
