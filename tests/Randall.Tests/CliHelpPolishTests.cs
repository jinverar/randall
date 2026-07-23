using System.Diagnostics;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

/// <summary>CLI -h polish: walk/ladder help must exit 0 without requiring a crash id.</summary>
[Collection("CliHelp")]
public class CliHelpPolishTests
{
    private static readonly Lazy<string> CliDll = new(BuildCliOnce);

    private static string BuildCliOnce()
    {
        var root = CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var csproj = Path.Combine(root, "src", "Randall.Cli", "Randall.Cli.csproj");
        Assert.True(File.Exists(csproj), "Randall.Cli.csproj missing");

        var psi = new ProcessStartInfo
        {
            FileName = "dotnet",
            Arguments = $"build \"{csproj}\" -c Debug --nologo -v q",
            WorkingDirectory = root,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        using var p = Process.Start(psi)!;
        var stdout = p.StandardOutput.ReadToEnd();
        var stderr = p.StandardError.ReadToEnd();
        Assert.True(p.WaitForExit(180_000), "dotnet build timed out");
        Assert.True(p.ExitCode == 0, $"build failed\n{stdout}\n{stderr}");

        var dll = Path.Combine(root, "src", "Randall.Cli", "bin", "Debug", "net8.0", "Randall.Cli.dll");
        Assert.True(File.Exists(dll), "Randall.Cli.dll missing after build");
        return dll;
    }

    [Theory]
    [InlineData("scream", "walk", "-h")]
    [InlineData("windbg", "walk", "-h")]
    [InlineData("gdb", "walk", "-h")]
    [InlineData("ladder", "diff", "-h")]
    [InlineData("rop", "from-crash", "-h")]
    public void SubcommandHelp_ExitsZero(string cmd, string sub, string flag)
    {
        var dll = CliDll.Value;
        var psi = new ProcessStartInfo
        {
            FileName = "dotnet",
            Arguments = $"\"{dll}\" {cmd} {sub} {flag}",
            WorkingDirectory = Path.GetDirectoryName(dll)!,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        using var p = Process.Start(psi)!;
        var stdout = p.StandardOutput.ReadToEnd();
        var stderr = p.StandardError.ReadToEnd();
        Assert.True(p.WaitForExit(30_000), "cli help timed out");
        Assert.True(p.ExitCode == 0,
            $"exit {p.ExitCode}\nstdout:\n{stdout}\nstderr:\n{stderr}");
        Assert.Contains("Usage", stdout + stderr, StringComparison.OrdinalIgnoreCase);
    }
}

[CollectionDefinition("CliHelp", DisableParallelization = true)]
public class CliHelpCollection { }
