$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Project = Join-Path $Root "targets\Randall.VulnTftp\Randall.VulnTftp.csproj"
$OutDir = Join-Path $Root "targets\vulntftp"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
Write-Host "Building randall-vulntftp..."
dotnet publish $Project -c Release -r win-x64 --self-contained false -o $OutDir /p:UseAppHost=true
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host "Done: $(Join-Path $OutDir 'randall-vulntftp.exe')"
