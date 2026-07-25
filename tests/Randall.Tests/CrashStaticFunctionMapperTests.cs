using Randall.Contracts;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class CrashStaticFunctionMapperTests
{
    [Fact]
    public void GhidraMap_MatchesModuleRvaInsideFunction()
    {
        var root = CrashCatalog.FindRepoRoot();
        if (root is null)
            return;

        var project = "static-map-" + Guid.NewGuid().ToString("N")[..8];
        var dir = Path.Combine(root, "data", "stalk", project);
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, GhidraAnalysisBridge.FileName);
        try
        {
            File.WriteAllText(path, """
                {
                  "version": "2",
                  "binary": "target.exe",
                  "imageBase": "0x400000",
                  "exportedAt": "2026-07-24T00:00:00Z",
                  "functions": [
                    { "name": "parse_header", "address": "0x401000", "size": 64,
                      "basicBlockCount": 4, "complexity": 8, "callerCount": 1, "calleeCount": 1,
                      "inputReachable": false, "hasDangerousCalls": false, "dangerousCalls": [], "fuzzPriority": 40 },
                    { "name": "handle_request", "address": "0x401020", "size": 256,
                      "basicBlockCount": 18, "complexity": 34, "callerCount": 1, "calleeCount": 4,
                      "inputReachable": true, "hasDangerousCalls": true, "dangerousCalls": ["recv", "memcpy"], "fuzzPriority": 88 }
                  ],
                  "imports": [], "exports": [], "sinks": [], "xrefs": []
                }
                """);

            var triage = new CrashTriageDto(
                "access_violation", "high", "test", false, false, "k", null,
                "0xDEADBEEF", "target.exe+0x102A", "0x40104A", "0x7fff0010");
            var analysis = new CrashAnalysisDto(
                true, "x.dmp", "0xC0000005", "AV", "0xDEADBEEF", "target.exe+0x102A",
                new RegisterSnapshotDto("0x40104A", "0x7fff0010", null, null, null, null, null),
                [], null);

            var mapped = CrashStaticFunctionMapper.TryMapFromCrash(project, analysis, triage, root);

            Assert.NotNull(mapped);
            Assert.Equal("handle_request", mapped!.FunctionName);
            Assert.Equal("+0xA", mapped.Offset);
            Assert.Equal("ghidra", mapped.Source);
            Assert.Equal("rip", mapped.PcSource);
            Assert.Contains("memcpy", mapped.InstructionHint!, StringComparison.OrdinalIgnoreCase);
            Assert.Equal("handle_request+0xA (ghidra)", CrashStaticFunctionMapper.FormatOneLine(mapped));
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void GhidraMap_PrefersRipOverFaultAddress()
    {
        var root = CrashCatalog.FindRepoRoot();
        if (root is null)
            return;

        var project = "static-rip-" + Guid.NewGuid().ToString("N")[..8];
        var dir = Path.Combine(root, "data", "stalk", project);
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, GhidraAnalysisBridge.FileName);
        try
        {
            File.WriteAllText(path, """
                {
                  "version": "2",
                  "binary": "target.exe",
                  "imageBase": "0x400000",
                  "exportedAt": "2026-07-24T00:00:00Z",
                  "functions": [
                    { "name": "parse_header", "address": "0x401000", "size": 64,
                      "basicBlockCount": 4, "complexity": 8, "callerCount": 1, "calleeCount": 1,
                      "inputReachable": false, "hasDangerousCalls": false, "dangerousCalls": [], "fuzzPriority": 40 }
                  ],
                  "imports": [], "exports": [], "sinks": [], "xrefs": []
                }
                """);

            var triage = new CrashTriageDto(
                "access_violation", "high", "test", false, false, "k", null,
                "0x00000000", "target.exe+0x1008", "0x401008", null);
            var analysis = new CrashAnalysisDto(
                true, "x.dmp", "0xC0000005", "AV", "0x00000000", "target.exe+0x1008",
                new RegisterSnapshotDto("0x401008", null, null, null, null, null, null),
                [], null);

            var mapped = CrashStaticFunctionMapper.TryMapFromCrash(project, analysis, triage, root);

            Assert.NotNull(mapped);
            Assert.Equal("parse_header", mapped!.FunctionName);
            Assert.Equal("0x401008", mapped.PcAddress);
            Assert.Equal("+0x8", mapped.Offset);
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void NoPc_ReturnsNull()
    {
        var triage = new CrashTriageDto(
            "clean_exit", "low", "test", false, false, "k", null,
            null, null, null, null);
        Assert.Null(CrashStaticFunctionMapper.TryMapFromCrash("demo", null, triage));
    }

    [Fact]
    public void TryParseAddress_AcceptsHexWithPrefix()
    {
        Assert.True(CrashStaticFunctionMapper.TryParseAddress("0x401020", out var v));
        Assert.Equal(0x401020UL, v);
        Assert.True(CrashStaticFunctionMapper.TryParseAddress("401020", out v));
        Assert.Equal(0x401020UL, v);
        Assert.False(CrashStaticFunctionMapper.TryParseAddress("", out _));
    }

    [Fact]
    public void OracleHints_FindFunctionByAddress_UsesRange()
    {
        var doc = new RandallAnalysisDocument(
            "2", "x.exe", null, "0x400000", "2026-01-01T00:00:00Z", "test",
            [
                new RandallAnalysisFunctionDto(
                    "handler", "0x401000", 128, 8, 12, 0, 2, true, true, ["strcpy"], 75),
            ],
            [], [], [], []);

        var fn = GhidraAnalysisOracleHints.FindFunctionByAddress(doc, "0x40103C");
        Assert.NotNull(fn);
        Assert.Equal("handler", fn!.Name);
    }
}
