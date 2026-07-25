using Randall.Contracts;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class SourceSinkPathScorerTests
{
    [Fact]
    public void ScorePaths_FindsInputToSinkRoute()
    {
        var doc = new RandallAnalysisDocument(
            Version: "2",
            Binary: "lab.exe",
            BinarySha256: null,
            ImageBase: "0x400000",
            ExportedAt: "2026-01-01",
            Exporter: "test",
            Functions:
            [
                Fn("main", inputReachable: true),
                Fn("handle_request", inputReachable: true, dangerous: ["memcpy"]),
                Fn("parse", inputReachable: true),
            ],
            Imports: [new RandallAnalysisImportDto("libc", "recv", "0x401000")],
            Exports: [],
            Sinks:
            [
                new RandallAnalysisSinkDto("recv", "0x401000", "input", 40, ["main"]),
                new RandallAnalysisSinkDto("memcpy", "0x402000", "sink", 90, ["handle_request"]),
            ],
            Xrefs:
            [
                new RandallAnalysisXrefDto("main", "0x401100", "recv", "0x401000", "call"),
                new RandallAnalysisXrefDto("main", "0x401120", "handle_request", "0x401200", "call"),
                new RandallAnalysisXrefDto("handle_request", "0x401300", "memcpy", "0x402000", "call"),
            ],
            CallGraph:
            [
                new RandallAnalysisCallEdgeDto("main", "handle_request", "0x401120"),
                new RandallAnalysisCallEdgeDto("handle_request", "memcpy", "0x401300"),
            ]);

        var paths = SourceSinkPathScorer.ScorePaths(doc);
        Assert.NotEmpty(paths);
        var top = paths[0];
        Assert.Equal("recv", top.SourceSymbol);
        Assert.Equal("memcpy", top.SinkSymbol);
        Assert.True(top.PathScore > 0);
        Assert.Contains("main", top.PathFunctions, StringComparer.OrdinalIgnoreCase);
    }

    [Fact]
    public void PathScoreBonus_ReturnsPointsWhenFunctionOnPath()
    {
        var doc = new RandallAnalysisDocument(
            Version: "2",
            Binary: "lab.exe",
            BinarySha256: null,
            ImageBase: "0x400000",
            ExportedAt: "2026-01-01",
            Exporter: "test",
            Functions: [Fn("handle_request", inputReachable: true, dangerous: ["memcpy"])],
            Imports: [],
            Exports: [],
            Sinks:
            [
                new RandallAnalysisSinkDto("recv", "0x401000", "input", 40, []),
                new RandallAnalysisSinkDto("memcpy", "0x402000", "sink", 90, ["handle_request"]),
            ],
            Xrefs: [],
            CallGraph: [new RandallAnalysisCallEdgeDto("main", "handle_request", "0x401120")],
            SourceSinkPaths:
            [
                new RandallAnalysisSourceSinkPathDto(
                    "recv", "memcpy", 72, 2,
                    ["main", "handle_request", "memcpy"],
                    "recv → memcpy"),
            ]);

        var bonus = SourceSinkPathScorer.PathScoreBonus("handle_request", doc);
        Assert.InRange(bonus, 1, 15);
        Assert.Equal(0, SourceSinkPathScorer.PathScoreBonus("unrelated", doc));
    }

    private static RandallAnalysisFunctionDto Fn(
        string name,
        bool inputReachable = false,
        string[]? dangerous = null) =>
        new(
            name,
            "0x401200",
            64,
            4,
            10,
            1,
            1,
            inputReachable,
            dangerous is { Length: > 0 },
            dangerous ?? [],
            50);
}
