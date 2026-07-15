# Publish a portable Randall lab folder (Windows x64, self-contained)

param(
    [string]$Output = "publish/standalone"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $root

Write-Host "Building portable pack → $Output"
dotnet run --project src/Randall.Cli -- pack -o $Output
Write-Host "Done. Run: $Output\start.cmd"
