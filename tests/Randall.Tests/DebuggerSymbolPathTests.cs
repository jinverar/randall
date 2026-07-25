using Xunit;

namespace Randall.Tests;

public class DebuggerSymbolPathTests
{
    [Fact]
    public void GetEffectiveSymbolPath_UsesNtSymbolPathWhenSet()
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

    [Fact]
    public void GetEffectiveSymbolPath_BuildsSrvPathWhenUnset()
    {
        var ntKey = "_NT_SYMBOL_PATH";
        var cacheKey = "RANDFUZZ_SYMBOL_CACHE";
        var offlineKey = "RANDFUZZ_NO_MS_SYMBOL_SERVER";
        var priorNt = Environment.GetEnvironmentVariable(ntKey);
        var priorCache = Environment.GetEnvironmentVariable(cacheKey);
        var priorOffline = Environment.GetEnvironmentVariable(offlineKey);
        try
        {
            Environment.SetEnvironmentVariable(ntKey, null);
            Environment.SetEnvironmentVariable(offlineKey, null);
            Environment.SetEnvironmentVariable(cacheKey, @"C:\TestSymbols");

            var path = Randall.Infrastructure.DebuggerTools.GetEffectiveSymbolPath();
            Assert.Equal(
                "srv*C:\\TestSymbols*https://msdl.microsoft.com/download/symbols",
                path);
        }
        finally
        {
            Environment.SetEnvironmentVariable(ntKey, priorNt);
            Environment.SetEnvironmentVariable(cacheKey, priorCache);
            Environment.SetEnvironmentVariable(offlineKey, priorOffline);
        }
    }

    [Fact]
    public void GetEffectiveSymbolPath_OfflineUsesCacheOnly()
    {
        var ntKey = "_NT_SYMBOL_PATH";
        var cacheKey = "RANDFUZZ_SYMBOL_CACHE";
        var offlineKey = "RANDFUZZ_NO_MS_SYMBOL_SERVER";
        var priorNt = Environment.GetEnvironmentVariable(ntKey);
        var priorCache = Environment.GetEnvironmentVariable(cacheKey);
        var priorOffline = Environment.GetEnvironmentVariable(offlineKey);
        try
        {
            Environment.SetEnvironmentVariable(ntKey, null);
            Environment.SetEnvironmentVariable(cacheKey, @"C:\OfflineSymbols");
            Environment.SetEnvironmentVariable(offlineKey, "1");

            var path = Randall.Infrastructure.DebuggerTools.GetEffectiveSymbolPath();
            Assert.Equal(@"C:\OfflineSymbols", path);
        }
        finally
        {
            Environment.SetEnvironmentVariable(ntKey, priorNt);
            Environment.SetEnvironmentVariable(cacheKey, priorCache);
            Environment.SetEnvironmentVariable(offlineKey, priorOffline);
        }
    }

    [Fact]
    public void FormatSymbolCommandLineArgs_IncludesYAndSnul()
    {
        var args = Randall.Infrastructure.DebuggerTools.FormatSymbolCommandLineArgs();
        Assert.StartsWith("-y \"", args);
        Assert.Contains("-snul", args);
    }
}
