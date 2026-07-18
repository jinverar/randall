# Build Randfuzz Scream regression lab binaries (native AV + optional TCP target)
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Project = Join-Path $Root "targets\Randall.ScreamCrash\Randall.ScreamCrash.csproj"
$NativeDir = Join-Path $Root "targets\Randall.ScreamCrash\native"
$OutDir = Join-Path $Root "targets\screamcrash"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$Gcc = Get-Command gcc -ErrorAction SilentlyContinue
if (-not $Gcc) {
    Write-Error "gcc not found (needed for native helpers). Install MinGW/Strawberry or add gcc to PATH."
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
