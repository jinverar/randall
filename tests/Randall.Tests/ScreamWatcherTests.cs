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
