using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class DynamoRioRunnerTests
{
    [Fact]
    public void FindDrrunUnder_FindsBin64Drrun_InCapitalDynamoRIOHome()
    {
        var root = Path.Combine(Path.GetTempPath(), "randall-dr-" + Guid.NewGuid().ToString("N"));
        var home = Path.Combine(root, "DynamoRIO");
        var bin64 = Path.Combine(home, "bin64");
        Directory.CreateDirectory(bin64);
        var drrun = Path.Combine(bin64, OperatingSystem.IsWindows() ? "drrun.exe" : "drrun");
        File.WriteAllText(drrun, "stub");
        try
        {
            var found = DynamoRioRunner.FindDrrunUnder(home);
            Assert.Equal(drrun, found);
        }
        finally
        {
            try { Directory.Delete(root, true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void FindDrrunUnder_ReturnsNull_WhenOnlyDrconfigPresent()
    {
        var root = Path.Combine(Path.GetTempPath(), "randall-dr-" + Guid.NewGuid().ToString("N"));
        var home = Path.Combine(root, "DynamoRIO");
        var bin64 = Path.Combine(home, "bin64");
        Directory.CreateDirectory(bin64);
        File.WriteAllText(Path.Combine(bin64, OperatingSystem.IsWindows() ? "drconfig.exe" : "drconfig"), "stub");
        try
        {
            Assert.Null(DynamoRioRunner.FindDrrunUnder(home));
            Assert.True(DynamoRioRunner.LooksLikeDynamoRioHome(home));
        }
        finally
        {
            try { Directory.Delete(root, true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void EnumerateLocalHomes_IncludesBareDynamoRIO_AndVersioned()
    {
        var repo = Path.Combine(Path.GetTempPath(), "randall-repo-" + Guid.NewGuid().ToString("N"));
        var tools = Path.Combine(repo, "tools");
        var capital = Path.Combine(tools, "DynamoRIO");
        var versioned = Path.Combine(tools, "DynamoRIO-Windows-11.3.0");
        Directory.CreateDirectory(Path.Combine(capital, "bin64"));
        Directory.CreateDirectory(Path.Combine(versioned, "bin64"));
        try
        {
            var homes = DynamoRioRunner.EnumerateLocalHomes(repo, requireDirectory: true).ToList();
            Assert.Contains(homes, h => h.Equals(capital, StringComparison.OrdinalIgnoreCase));
            Assert.Contains(homes, h => h.Equals(versioned, StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            try { Directory.Delete(repo, true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void Diagnose_ReportsIncomplete_WhenHomeLacksDrrun()
    {
        var repo = Path.Combine(Path.GetTempPath(), "randall-repo-" + Guid.NewGuid().ToString("N"));
        var home = Path.Combine(repo, "tools", "DynamoRIO");
        Directory.CreateDirectory(Path.Combine(home, "bin64"));
        File.WriteAllText(Path.Combine(home, "bin64", OperatingSystem.IsWindows() ? "drinject.exe" : "drinject"), "stub");

        var prev = Environment.GetEnvironmentVariable("DYNAMORIO_HOME");
        Environment.SetEnvironmentVariable("DYNAMORIO_HOME", null);
        try
        {
            var status = DynamoRioRunner.Diagnose(repo);
            Assert.False(status.IsAvailable);
            Assert.Equal("incomplete", status.State);
            Assert.NotNull(status.HomePath);
            Assert.Contains("drrun", status.Detail, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            Environment.SetEnvironmentVariable("DYNAMORIO_HOME", prev);
            try { Directory.Delete(repo, true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void Diagnose_Ready_WhenDrrunUnderCapitalDynamoRIO()
    {
        var repo = Path.Combine(Path.GetTempPath(), "randall-repo-" + Guid.NewGuid().ToString("N"));
        var home = Path.Combine(repo, "tools", "DynamoRIO");
        var bin64 = Path.Combine(home, "bin64");
        Directory.CreateDirectory(bin64);
        var drrun = Path.Combine(bin64, OperatingSystem.IsWindows() ? "drrun.exe" : "drrun");
        File.WriteAllText(drrun, "stub");

        var prev = Environment.GetEnvironmentVariable("DYNAMORIO_HOME");
        Environment.SetEnvironmentVariable("DYNAMORIO_HOME", null);
        try
        {
            var status = DynamoRioRunner.Diagnose(repo);
            Assert.True(status.IsAvailable);
            Assert.Equal("ready", status.State);
            Assert.NotNull(status.DrrunPath);
            Assert.True(
                status.DrrunPath.Equals(drrun, StringComparison.OrdinalIgnoreCase),
                $"Expected drrun under DynamoRIO home, got {status.DrrunPath}");
            Assert.True(File.Exists(status.DrrunPath));
        }
        finally
        {
            Environment.SetEnvironmentVariable("DYNAMORIO_HOME", prev);
            try { Directory.Delete(repo, true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void BuildDrcovArgs_TextVsBinary()
    {
        var text = DynamoRioRunner.BuildDrcovArgs("/tmp/t", "/bin/app", "{file}", dumpText: true);
        Assert.Contains("-dump_text", text);
        Assert.Contains("-logdir", text);

        var binary = DynamoRioRunner.BuildDrcovArgs("/tmp/b", "/bin/app", "", dumpText: false);
        Assert.DoesNotContain("-dump_text", binary);
        Assert.Contains("-t drcov", binary);
    }
}
