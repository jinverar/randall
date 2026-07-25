using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class GhidraMcpClientTests
{
    [Fact]
    public void ResolveBaseUrl_HonorsPortEnv()
    {
        var priorUrl = Environment.GetEnvironmentVariable("GHIDRA_MCP_URL");
        var priorPort = Environment.GetEnvironmentVariable("GHIDRA_MCP_PORT");
        try
        {
            Environment.SetEnvironmentVariable("GHIDRA_MCP_URL", null);
            Environment.SetEnvironmentVariable("GHIDRA_MCP_PORT", "9090");
            Assert.Equal("http://127.0.0.1:9090", GhidraMcpClient.ResolveBaseUrl());

            Environment.SetEnvironmentVariable("GHIDRA_MCP_URL", "http://127.0.0.1:7001/");
            Assert.Equal("http://127.0.0.1:7001", GhidraMcpClient.ResolveBaseUrl());
        }
        finally
        {
            Environment.SetEnvironmentVariable("GHIDRA_MCP_URL", priorUrl);
            Environment.SetEnvironmentVariable("GHIDRA_MCP_PORT", priorPort);
        }
    }

    [Fact]
    public void ParseImports_TextLines()
    {
        var raw = """
            recv @ 0x00402010 (WS2_32.dll)
            memcpy @ 0x00402018
            """;
        var imports = GhidraMcpClient.ParseImports(raw);
        Assert.Equal(2, imports.Count);
        Assert.Equal("recv", imports[0].Name);
        Assert.Equal("0x00402010", imports[0].Address);
        Assert.Equal("WS2_32.dll", imports[0].Library);
    }

    [Fact]
    public void ParseImports_JsonArray()
    {
        var raw = """
            [
              { "name": "strcpy", "address": "0x401000", "library": "MSVCRT" }
            ]
            """;
        var imports = GhidraMcpClient.ParseImports(raw);
        Assert.Single(imports);
        Assert.Equal("strcpy", imports[0].Name);
        Assert.Equal("0x401000", imports[0].Address);
    }

    [Fact]
    public async Task ParseXrefsAsync_TextLines()
    {
        var raw = """
            0x00401020 CALL
            0x00401500 DATA
            """;
        var xrefs = await GhidraMcpClient.ParseXrefsAsync(raw, CancellationToken.None);
        Assert.Equal(2, xrefs.Count);
        Assert.Equal("0x00401020", xrefs[0].FromAddress);
        Assert.Equal("call", xrefs[0].RefKind, ignoreCase: true);
    }

    [Fact]
    public async Task ProbeAsync_ReturnsUnavailableWhenOffline()
    {
        var priorUrl = Environment.GetEnvironmentVariable("GHIDRA_MCP_URL");
        try
        {
            Environment.SetEnvironmentVariable("GHIDRA_MCP_URL", "http://127.0.0.1:1");
            var probe = await GhidraMcpClient.ProbeAsync(CancellationToken.None);
            Assert.False(probe.Available);
            Assert.Contains("not reachable", probe.Message, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            Environment.SetEnvironmentVariable("GHIDRA_MCP_URL", priorUrl);
        }
    }
}
