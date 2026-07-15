# Build Randall's custom vulnserver lab binary
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Project = Join-Path $Root "targets\Randall.Vulnserver\Randall.Vulnserver.csproj"
$OutDir = Join-Path $Root "targets\vulnserver"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

Write-Host "Building randall-vulnserver..."
dotnet publish $Project -c Release -r win-x64 --self-contained false -o $OutDir /p:UseAppHost=true
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$Exe = Join-Path $OutDir "randall-vulnserver.exe"
Write-Host "Done: $Exe"
Write-Host "Fuzz: dotnet run --project src/Randall.Cli -- fuzz -c projects/vulnserver.yaml"
