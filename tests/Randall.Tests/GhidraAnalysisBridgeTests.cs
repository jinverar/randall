using System.Text.Json;
using Randall.Contracts;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class GhidraAnalysisBridgeTests
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    [Fact]
    public void ComputeFuzzPriority_WeightsSinksAndComplexity()
    {
        var low = GhidraAnalysisBridge.ComputeFuzzPriority(10, 4, [], false, 0);
        var high = GhidraAnalysisBridge.ComputeFuzzPriority(80, 40, ["memcpy", "strcpy"], true, 3);
        Assert.True(high > low);
        Assert.InRange(high, 1, 100);
    }

    [Fact]
    public void Enrich_RebuildsSinksFromFunctions()
    {
        var doc = new RandallAnalysisDocument(
            "1",
            @"C:\app.exe",
            null,
            "0x400000",
            "2026-01-01T00:00:00Z",
            "test",
            [
                new RandallAnalysisFunctionDto(
                    "parse", "0x401000", 128, 12, 20, 2, 3, true, true,
                    ["memcpy"], 0),
            ],
            [],
            [],
            [],
            []);

        var enriched = GhidraAnalysisBridge.Enrich(doc);
        Assert.True(enriched.Functions[0].FuzzPriority > 0);
        Assert.Contains(enriched.Sinks, s => s.Name.Contains("memcpy", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void TryLoad_RoundTripsSampleJson()
    {
        var root = CrashCatalog.FindRepoRoot();
        if (root is null)
            return;

        var project = "ghidra-bridge-test-" + Guid.NewGuid().ToString("N")[..8];
        var dir = Path.Combine(root, "data", "stalk", project);
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, GhidraAnalysisBridge.FileName);
        try
        {
            var sample = """
                {
                  "version": "1",
                  "binary": "demo.exe",
                  "imageBase": "0x400000",
                  "exportedAt": "2026-07-24T00:00:00Z",
                  "exporter": "unit-test",
                  "functions": [
                    {
                      "name": "handle_request",
                      "address": "0x401020",
                      "size": 256,
                      "basicBlockCount": 18,
                      "complexity": 34,
                      "callerCount": 1,
                      "calleeCount": 4,
                      "inputReachable": true,
                      "hasDangerousCalls": true,
                      "dangerousCalls": ["recv", "memcpy"],
                      "fuzzPriority": 88
                    }
                  ],
                  "imports": [
                    { "library": "WS2_32", "name": "recv", "address": "0x402000" }
                  ],
                  "exports": [],
                  "sinks": [
                    { "name": "memcpy", "address": "0x402010", "kind": "sink", "risk": 90, "callers": ["handle_request"] }
                  ],
                  "xrefs": []
                }
                """;
            File.WriteAllText(path, sample);

            var loaded = GhidraAnalysisBridge.TryLoad(project, root);
            Assert.NotNull(loaded);
            Assert.Single(loaded!.Functions);
            Assert.Equal("handle_request", loaded.Functions[0].Name);
            Assert.Equal(88, loaded.Functions[0].FuzzPriority);
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void BuildHeadlessCommand_IncludesScriptAndOutput()
    {
        var root = CrashCatalog.FindRepoRoot();
        if (root is null)
            return;

        var ghDir = Path.Combine(Path.GetTempPath(), "randall-gh-" + Guid.NewGuid().ToString("N"));
        var support = Path.Combine(ghDir, "support");
        Directory.CreateDirectory(support);
        var analyze = Path.Combine(support, OperatingSystem.IsWindows() ? "analyzeHeadless.bat" : "analyzeHeadless");
        File.WriteAllText(analyze, "@echo off");
        File.WriteAllText(Path.Combine(ghDir, "ghidraRun.bat"), "@echo off");

        var outJson = Path.Combine(Path.GetTempPath(), "out-" + Guid.NewGuid().ToString("N") + ".json");
        var binary = Path.Combine(Path.GetTempPath(), "demo.exe");
        File.WriteAllText(binary, "MZ");

        try
        {
            var discovery = new GhidraTools.Discovery(
                Path.Combine(ghDir, "ghidraRun.bat"), null,
                Path.Combine(root, "tools", "ghidra"), true, false);
            var cmd = GhidraAnalysisBridge.BuildHeadlessCommand(discovery, binary, outJson, root);
            Assert.Contains(GhidraAnalysisBridge.ScriptName, cmd.Arguments);
            Assert.Contains(outJson, cmd.Arguments);
            Assert.Contains("-deleteProject", cmd.Arguments);
        }
        finally
        {
            if (Directory.Exists(ghDir))
                Directory.Delete(ghDir, true);
            if (File.Exists(binary))
                File.Delete(binary);
        }
    }

    [Fact]
    public void OracleHints_SummarizeTopFunctions()
    {
        var root = CrashCatalog.FindRepoRoot();
        if (root is null)
            return;

        var project = "ghidra-hints-" + Guid.NewGuid().ToString("N")[..8];
        var dir = Path.Combine(root, "data", "stalk", project);
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, GhidraAnalysisBridge.FileName);
        try
        {
            var doc = new RandallAnalysisDocument(
                "1", "x.exe", null, "0x400000", "2026-01-01T00:00:00Z", "test",
                [
                    new RandallAnalysisFunctionDto("low", "0x1000", 10, 2, 4, 0, 1, false, false, [], 20),
                    new RandallAnalysisFunctionDto("hot", "0x2000", 200, 30, 50, 2, 5, true, true, ["strcpy"], 92),
                ],
                [], [], [], []);
            File.WriteAllText(path, JsonSerializer.Serialize(doc, JsonOptions));

            var hints = GhidraAnalysisOracleHints.TryBuild(project, root);
            Assert.NotNull(hints);
            Assert.Equal("hot", hints!.TopFunctions[0].Name);
            Assert.Contains("92/100", hints.Summary);
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void IsDangerousSink_MatchesMemcpy()
    {
        Assert.True(GhidraAnalysisBridge.IsDangerousSink("memcpy"));
        Assert.True(GhidraAnalysisBridge.IsInputSource("WSARecv"));
        Assert.False(GhidraAnalysisBridge.IsDangerousSink("strlen"));
    }
}
