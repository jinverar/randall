using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class ScreamWatcherTests
{
    [Theory]
    [InlineData(0u, false)]
    [InlineData(1u, false)]
    [InlineData(0xC0000005u, true)]
    [InlineData(0xC0000409u, true)]
    [InlineData(139u, true)]
    public void IsCrashProcessExit_ClassifiesLabAndNativeCodes(uint exitCode, bool expectCrash)
    {
        Assert.Equal(expectCrash, ScreamWatcher.IsCrashProcessExit(exitCode));
    }

    [Fact]
    public void ReadExitProcessCode_ParsesEnvironmentExitAtUnionZero()
    {
        // x64 DEBUG_EVENT: union @16; DebugActiveProcess attach puts dwExitCode @ union+0
        // (not @ union+8 — that DWORD is zero for VulnDrone Environment.Exit crashes).
        var buf = new byte[64];
        BitConverter.GetBytes(0xC0000005u).CopyTo(buf, 16);
        Assert.Equal(0xC0000005u, ScreamWatcher.ReadExitProcessCode(buf));
        Assert.False(ScreamWatcher.IsCrashProcessExit(0));
        Assert.True(ScreamWatcher.IsCrashProcessExit(ScreamWatcher.ReadExitProcessCode(buf)));
    }

    [Fact]
    public void ReadExitProcessHandle_ParsesHandleAfterExitCode()
    {
        // Observed layout: dwExitCode @ union+0, hProcess @ union+8 (x64).
        var buf = new byte[64];
        BitConverter.GetBytes(0xC0000005u).CopyTo(buf, 16);
        BitConverter.GetBytes(0x00007F40D1ED0010L).CopyTo(buf, 24);
        Assert.Equal(0xC0000005u, ScreamWatcher.ReadExitProcessCode(buf));
        Assert.Equal(new IntPtr(0x00007F40D1ED0010L), ScreamWatcher.ReadExitProcessHandle(buf));
    }

    [Fact]
    public void ReadExitProcessCode_MatchesVulnDroneAttachProbeLayout()
    {
        // Raw union tail from VulnDrone Environment.Exit(0xC0000005) under DebugActiveProcess.
        var raw = "29-01-00-00-05-00-00-C0-00-00-00-00-00-00-00-00-00-00-00-00-10-ED-D1-40-FE-7F-00-00";
        var tail = raw.Split('-').Select(static b => Convert.ToByte(b, 16)).ToArray();
        var buf = new byte[64];
        Buffer.BlockCopy(tail, 0, buf, 12, tail.Length);
        Assert.Equal(0xC0000005u, ScreamWatcher.ReadExitProcessCode(buf));
        // Attach path: hProcess in the debug event is NULL (MSDN); dump falls back to OpenProcess.
        Assert.Equal(IntPtr.Zero, ScreamWatcher.ReadExitProcessHandle(buf));
    }
}

public class CrashDumpPathsTests
{
    [Fact]
    public void Sanitize_RejectsMissingAndEmptyFiles()
    {
        Assert.Null(CrashDumpPaths.Sanitize(null));
        Assert.Null(CrashDumpPaths.Sanitize(""));

        var dir = Path.Combine(Path.GetTempPath(), "randall-dump-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var empty = Path.Combine(dir, "empty.dmp");
            File.WriteAllBytes(empty, []);
            Assert.Null(CrashDumpPaths.Sanitize(empty));

            var ok = Path.Combine(dir, "ok.dmp");
            File.WriteAllBytes(ok, [1, 2, 3]);
            Assert.Equal(ok, CrashDumpPaths.Sanitize(ok));
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void TryDeleteEmpty_RemovesZeroBytePlaceholder()
    {
        var dir = Path.Combine(Path.GetTempPath(), "randall-dump-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var empty = Path.Combine(dir, "scream_1.dmp");
            File.WriteAllBytes(empty, []);
            CrashDumpPaths.TryDeleteEmpty(empty);
            Assert.False(File.Exists(empty));
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { /* ignore */ }
        }
    }
}
