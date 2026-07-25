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
    public void ReadExitProcessCode_ParsesExitCodeFromDebugEventUnion()
    {
        // x64 DEBUG_EVENT: union @16; EXIT_PROCESS_DEBUG_INFO hProcess (8) + dwExitCode @24
        var buf = new byte[64];
        BitConverter.GetBytes(0xC0000005u).CopyTo(buf, 24);
        var method = typeof(ScreamWatcher).GetMethod(
            "ReadExitProcessCode",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
        Assert.NotNull(method);
        var exit = (uint)(method!.Invoke(null, [buf]) ?? 0u);
        Assert.Equal(0xC0000005u, exit);
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
