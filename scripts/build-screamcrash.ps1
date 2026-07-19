# Build Randfuzz Scream regression lab binaries (native AV + optional TCP target).
# Native helpers need gcc (MinGW/Strawberry). Without gcc this script warns and exits 0
# so build-all-lab-targets can finish the other labs (vulnserver, etc.).
# Prefer: powershell -ExecutionPolicy Bypass -File .\scripts\install-gcc.ps1
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Project = Join-Path $Root "targets\Randall.ScreamCrash\Randall.ScreamCrash.csproj"
$NativeDir = Join-Path $Root "targets\Randall.ScreamCrash\native"
$OutDir = Join-Path $Root "targets\screamcrash"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

# Refresh PATH in case install-gcc.ps1 just ran in a parent script.
$machine = [Environment]::GetEnvironmentVariable("Path", "Machine")
$user = [Environment]::GetEnvironmentVariable("Path", "User")
$env:Path = (@($machine, $user) | Where-Object { $_ }) -join ";"

$Gcc = Get-Command gcc -ErrorAction SilentlyContinue
if (-not $Gcc) {
    Write-Host ""
    Write-Host '[!] Skipping ScreamCrash lab - gcc not found.' -ForegroundColor Yellow
    Write-Host '    Native helpers (scream_crash.exe / scream_av.dll) need MinGW or Strawberry Perl gcc on PATH.' -ForegroundColor Yellow
    Write-Host '    Install: powershell -ExecutionPolicy Bypass -File .\scripts\install-gcc.ps1' -ForegroundColor Yellow
    Write-Host '    Or skip:  powershell -ExecutionPolicy Bypass -File .\scripts\build-all-lab-targets.ps1 -SkipGcc' -ForegroundColor Yellow
    Write-Host ""
    exit 0
}

Write-Host "Building scream_crash.exe (native selftest AV)..."
& gcc -O0 -o (Join-Path $OutDir "scream_crash.exe") (Join-Path $NativeDir "scream_crash.c")
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "Building scream_av.dll (native AV helper for TCP target)..."
& gcc -shared -O0 -o (Join-Path $OutDir "scream_av.dll") (Join-Path $NativeDir "scream_av.c")
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "Building randall-screamcrash (TCP lab target)..."
dotnet publish $Project -c Release -r win-x64 --self-contained false -o $OutDir /p:UseAppHost=true
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "Done:"
Write-Host "  $(Join-Path $OutDir 'scream_crash.exe')"
Write-Host "  $(Join-Path $OutDir 'scream_av.dll')"
Write-Host "  $(Join-Path $OutDir 'randall-screamcrash.exe')"
Write-Host "Selftest: dotnet run --project src/Randall.Cli -- scream selftest"
Write-Host "Fuzz:     dotnet run --project src/Randall.Cli -- fuzz -c projects/screamcrash.yaml --debugger wait"
