using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class GhidraToolsTests
{
    [Fact]
    public void Discover_ScriptsDir_WhenRepoPresent()
    {
        var root = CrashCatalog.FindRepoRoot();
        if (root is null)
            return;

        var scripts = Path.Combine(root, "tools", "ghidra");
        if (!Directory.Exists(scripts))
            return;

        var d = GhidraTools.Discover(root);
        Assert.NotNull(d.ScriptsDir);
        Assert.True(Directory.Exists(d.ScriptsDir));
    }

    [Fact]
    public void Discover_FindsGhidraRunViaEnv()
    {
        var dir = Path.Combine(Path.GetTempPath(), "randall-ghidra-find-" + Guid.NewGuid().ToString("N"));
        var prev = Environment.GetEnvironmentVariable("GHIDRA_INSTALL_DIR");
        try
        {
            Directory.CreateDirectory(dir);
            var bat = Path.Combine(dir, OperatingSystem.IsWindows() ? "ghidraRun.bat" : "ghidraRun");
            File.WriteAllText(bat, "@echo off");
            Environment.SetEnvironmentVariable("GHIDRA_INSTALL_DIR", dir);

            var found = GhidraTools.Discover().GhidraRunPath;
            Assert.Equal(bat, found);
        }
        finally
        {
            Environment.SetEnvironmentVariable("GHIDRA_INSTALL_DIR", prev);
            if (Directory.Exists(dir))
                Directory.Delete(dir, true);
        }
    }

    [Fact]
    public void InstallHint_MentionsInstallScript()
    {
        var hint = GhidraTools.InstallHint;
        Assert.Contains("install-ghidra", hint, StringComparison.OrdinalIgnoreCase);
    }
}
