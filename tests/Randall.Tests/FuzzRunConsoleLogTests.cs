using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

/// <summary>
/// FuzzAnalystLog session tee is process-static — do not parallelize these tests.
/// </summary>
[Collection("FuzzRunConsoleLog")]
public class FuzzRunConsoleLogTests
{
    [Fact]
    public void Attach_TeesAnalystLog_WithoutAnsi()
    {
        var dir = Path.Combine(Path.GetTempPath(), "randall-fuzz-console-" + Guid.NewGuid().ToString("N"));
        try
        {
            using var log = FuzzRunConsoleLog.Attach(dir);
            Assert.Equal(Path.Combine(dir, FuzzRunConsoleLog.FileName), log.Path);
            FuzzAnalystLog.Info(null, "tee-smoke-line");
            FuzzAnalystLog.Crash(null, 7, "boom");

            var text = ReadShared(log.Path);
            Assert.Contains("tee-smoke-line", text);
            Assert.Contains("Crash Detected: 7: boom", text);
            Assert.Contains("[info]", text);
            Assert.Contains("[crash]", text);
            // File tee must stay greppable (no VT color prefixes from WriteConsole).
            Assert.True(text.IndexOf('\u001b') < 0, "fuzz-console.log must not contain ANSI ESC");
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); }
            catch { /* ignore */ }
        }
    }

    [Fact]
    public void Dispose_DetachesSessionLog_SoLaterEmitsSkipFile()
    {
        var dir = Path.Combine(Path.GetTempPath(), "randall-fuzz-console-" + Guid.NewGuid().ToString("N"));
        try
        {
            var log = FuzzRunConsoleLog.Attach(dir);
            FuzzAnalystLog.Info(null, "before-dispose");
            log.Dispose();
            FuzzAnalystLog.Info(null, "after-dispose-must-not-land");

            var text = File.ReadAllText(Path.Combine(dir, FuzzRunConsoleLog.FileName));
            Assert.Contains("before-dispose", text);
            Assert.DoesNotContain("after-dispose-must-not-land", text);
            Assert.Contains("fuzz console log ended", text);
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); }
            catch { /* ignore */ }
        }
    }

    /// <summary>Read while the run still holds the append handle (Windows needs ReadWrite share).</summary>
    private static string ReadShared(string path)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        using var sr = new StreamReader(fs);
        return sr.ReadToEnd();
    }
}

[CollectionDefinition("FuzzRunConsoleLog", DisableParallelization = true)]
public class FuzzRunConsoleLogCollection;
