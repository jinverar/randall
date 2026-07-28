using Xunit;

namespace Randall.Tests;

/// <summary>
/// Env-mutating symbol-path tests must not race each other or CdbProbeEngineTests
/// (parallel xunit workers share process environment).
/// </summary>
[Collection("DebuggerEnv")]
public class DebuggerSymbolPathTests
{
    private static readonly object EnvLock = DebuggerEnvGate.Lock;

    [Fact]
    public void GetEffectiveSymbolPath_UsesNtSymbolPathWhenSet()
    {
        lock (EnvLock)
        {
            var key = "_NT_SYMBOL_PATH";
            var prior = Environment.GetEnvironmentVariable(key);
            try
            {
                Environment.SetEnvironmentVariable(key, "srv*D:\\Custom*https://example.com/symbols");
                var path = Randall.Infrastructure.DebuggerTools.GetEffectiveSymbolPath();
                Assert.Equal("srv*D:\\Custom*https://example.com/symbols", path);
            }
            finally
            {
                Environment.SetEnvironmentVariable(key, prior);
            }
        }
    }

    [Fact]
    public void GetEffectiveSymbolPath_BuildsSrvPathWhenUnset()
    {
        lock (EnvLock)
        {
            var ntKey = "_NT_SYMBOL_PATH";
            var cacheKey = "RANDFUZZ_SYMBOL_CACHE";
            var offlineKey = "RANDFUZZ_NO_MS_SYMBOL_SERVER";
            var priorNt = Environment.GetEnvironmentVariable(ntKey);
            var priorCache = Environment.GetEnvironmentVariable(cacheKey);
            var priorOffline = Environment.GetEnvironmentVariable(offlineKey);
            var cacheDir = Path.Combine(Path.GetTempPath(), "randall-sym-" + Guid.NewGuid().ToString("N"));
            try
            {
                Environment.SetEnvironmentVariable(ntKey, null);
                Environment.SetEnvironmentVariable(offlineKey, null);
                Environment.SetEnvironmentVariable(cacheKey, cacheDir);

                var path = Randall.Infrastructure.DebuggerTools.GetEffectiveSymbolPath();
                Assert.Equal(
                    $"srv*{Path.GetFullPath(cacheDir)}*https://msdl.microsoft.com/download/symbols",
                    path);
            }
            finally
            {
                Environment.SetEnvironmentVariable(ntKey, priorNt);
                Environment.SetEnvironmentVariable(cacheKey, priorCache);
                Environment.SetEnvironmentVariable(offlineKey, priorOffline);
                try { if (Directory.Exists(cacheDir)) Directory.Delete(cacheDir, true); } catch { /* ignore */ }
            }
        }
    }

    [Fact]
    public void GetEffectiveSymbolPath_OfflineUsesCacheOnly()
    {
        lock (EnvLock)
        {
            var ntKey = "_NT_SYMBOL_PATH";
            var cacheKey = "RANDFUZZ_SYMBOL_CACHE";
            var offlineKey = "RANDFUZZ_NO_MS_SYMBOL_SERVER";
            var priorNt = Environment.GetEnvironmentVariable(ntKey);
            var priorCache = Environment.GetEnvironmentVariable(cacheKey);
            var priorOffline = Environment.GetEnvironmentVariable(offlineKey);
            var cacheDir = Path.Combine(Path.GetTempPath(), "randall-sym-off-" + Guid.NewGuid().ToString("N"));
            try
            {
                Environment.SetEnvironmentVariable(ntKey, null);
                Environment.SetEnvironmentVariable(cacheKey, cacheDir);
                Environment.SetEnvironmentVariable(offlineKey, "1");

                var path = Randall.Infrastructure.DebuggerTools.GetEffectiveSymbolPath();
                Assert.Equal(Path.GetFullPath(cacheDir), path);
            }
            finally
            {
                Environment.SetEnvironmentVariable(ntKey, priorNt);
                Environment.SetEnvironmentVariable(cacheKey, priorCache);
                Environment.SetEnvironmentVariable(offlineKey, priorOffline);
                try { if (Directory.Exists(cacheDir)) Directory.Delete(cacheDir, true); } catch { /* ignore */ }
            }
        }
    }

    [Fact]
    public void FormatSymbolCommandLineArgs_IncludesYAndSnul()
    {
        lock (EnvLock)
        {
            var args = Randall.Infrastructure.DebuggerTools.FormatSymbolCommandLineArgs();
            Assert.StartsWith("-y \"", args);
            Assert.Contains("-snul", args);
        }
    }
}

public static class DebuggerEnvGate
{
    public static readonly object Lock = new();
}

[CollectionDefinition("DebuggerEnv")]
public class DebuggerEnvCollection : ICollectionFixture<object>;
