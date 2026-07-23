using System.Diagnostics;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

/// <summary>CLI -h polish: walk/ladder help must exit 0 without requiring a crash id.</summary>
public class CliHelpPolishTests
{
    [Theory]
    [InlineData("scream", "walk", "-h")]
    [InlineData("windbg", "walk", "-h")]
    [InlineData("gdb", "walk", "-h")]
    [InlineData("ladder", "diff", "-h")]
    [InlineData("rop", "from-crash", "-h")]
    public void SubcommandHelp_ExitsZero(string cmd, string sub, string flag)
    {
        var root = CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var cli = Path.Combine(root, "src", "Randall.Cli", "Randall.Cli.csproj");
        Assert.True(File.Exists(cli), "Randall.Cli.csproj missing");

        var psi = new ProcessStartInfo
        {
            FileName = "dotnet",
            Arguments = $"run --project \"{cli}\" -- {cmd} {sub} {flag}",
            WorkingDirectory = root,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        using var p = Process.Start(psi)!;
        var stdout = p.StandardOutput.ReadToEnd();
        var stderr = p.StandardError.ReadToEnd();
        Assert.True(p.WaitForExit(120_000), "dotnet run timed out");
        Assert.True(p.ExitCode == 0,
            $"exit {p.ExitCode}\nstdout:\n{stdout}\nstderr:\n{stderr}");
        Assert.Contains("Usage", stdout + stderr, StringComparison.OrdinalIgnoreCase);
    }
}
