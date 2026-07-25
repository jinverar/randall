using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class GhidraDebuggerCorrelationTests
{
    [Fact]
    public void ParseDebuggerAddress_ExtractsFromJson()
    {
        var raw = """{"staticAddress":"0x401234","ok":true}""";
        var addr = GhidraMcpClient.ParseDebuggerAddress(raw);
        Assert.Equal("0x401234", addr);
    }

    [Fact]
    public void ParseDebuggerAddress_ExtractsFromPlainText()
    {
        var addr = GhidraMcpClient.ParseDebuggerAddress("static address: 0x00401234");
        Assert.Equal("0x00401234", addr);
    }

    [Fact]
    public void ResolveDebuggerBaseUrl_HonorsEnv()
    {
        var prev = Environment.GetEnvironmentVariable("GHIDRA_DEBUGGER_URL");
        try
        {
            Environment.SetEnvironmentVariable("GHIDRA_DEBUGGER_URL", "http://127.0.0.1:9999");
            Assert.Equal("http://127.0.0.1:9999", GhidraMcpClient.ResolveDebuggerBaseUrl());
        }
        finally
        {
            Environment.SetEnvironmentVariable("GHIDRA_DEBUGGER_URL", prev);
        }
    }

    [Fact]
    public async Task AnnotateRipAsync_OfflineSoftFail()
    {
        var prevUrl = Environment.GetEnvironmentVariable("GHIDRA_MCP_URL");
        try
        {
            Environment.SetEnvironmentVariable("GHIDRA_MCP_URL", "http://127.0.0.1:1");
            var ann = await GhidraDebuggerCorrelation.AnnotateRipAsync("0x401000");
            Assert.Equal("none", ann.Source);
            Assert.Contains("No Ghidra context", ann.Summary);
        }
        finally
        {
            Environment.SetEnvironmentVariable("GHIDRA_MCP_URL", prevUrl);
        }
    }
}
