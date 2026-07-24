$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Project = Join-Path $Root "targets\Randall.VulnSmb\Randall.VulnSmb.csproj"
$OutDir = Join-Path $Root "targets\vulnsmb"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
Write-Host "Building randall-vulnsmb..."
dotnet publish $Project -c Release -r win-x64 --self-contained false -o $OutDir /p:UseAppHost=true
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host "Done: $(Join-Path $OutDir 'randall-vulnsmb.exe')"
