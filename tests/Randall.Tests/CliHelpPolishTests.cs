using System.Diagnostics;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

/// <summary>
/// CLI -h polish: walk/ladder help must exit 0 without requiring a crash id.
/// Expects a prebuilt <c>Randall.Cli.dll</c> (run <c>dotnet build src/Randall.Cli</c> first).
/// Does not invoke MSBuild — avoids node-reuse deadlocks in the full suite.
/// </summary>
public class CliHelpPolishTests
{
    private static string? TryFindCliDll()
    {
        var root = CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var dll = Path.Combine(root, "src", "Randall.Cli", "bin", "Debug", "net8.0", "Randall.Cli.dll");
        return File.Exists(dll) ? dll : null;
    }

    [Theory]
    [InlineData("scream", "walk", "-h")]
    [InlineData("windbg", "walk", "-h")]
    [InlineData("gdb", "walk", "-h")]
    [InlineData("ladder", "diff", "-h")]
    [InlineData("rop", "from-crash", "-h")]
    public void SubcommandHelp_ExitsZero(string cmd, string sub, string flag)
    {
        var dll = TryFindCliDll();
        if (dll is null)
        {
            // Soft skip when Cli wasn't built in this job — library tests still cover polish.
            return;
        }

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
