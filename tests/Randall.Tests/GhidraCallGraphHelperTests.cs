using Randall.Contracts;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class GhidraCallGraphHelperTests
{
    [Fact]
    public void TryFindCallPath_FindsInputToSinkChain()
    {
        var doc = new RandallAnalysisDocument(
            "2", "x.exe", null, "0x400000", "2026-01-01T00:00:00Z", "test",
            [
                new RandallAnalysisFunctionDto(
                    "main", "0x401000", 64, 3, 10, 0, 1, true, false, [], 40),
                new RandallAnalysisFunctionDto(
                    "handle", "0x402000", 128, 5, 30, 1, 2, true, true, ["memcpy"], 80),
            ],
            [],
            [],
            [
                new RandallAnalysisSinkDto("recv", "0x404000", "input", 40, ["main"]),
                new RandallAnalysisSinkDto("memcpy", "0x404010", "sink", 90, ["handle"]),
            ],
            [
                new RandallAnalysisXrefDto("main", "0x401000", "recv", "", "call"),
                new RandallAnalysisXrefDto("main", "0x401010", "handle", "", "call"),
                new RandallAnalysisXrefDto("handle", "0x402020", "memcpy", "", "call"),
            ],
            [
                new RandallAnalysisCallEdgeDto("main", "recv", "0x401000"),
                new RandallAnalysisCallEdgeDto("main", "handle", "0x401010"),
                new RandallAnalysisCallEdgeDto("handle", "memcpy", "0x402020"),
            ]);

        var path = GhidraCallGraphHelper.TryFindCallPath(doc, "recv", "memcpy");
        Assert.NotNull(path);
        Assert.Contains("handle", path!, StringComparer.OrdinalIgnoreCase);
        Assert.Equal("main → handle", GhidraCallGraphHelper.FormatCallPath(path!));
    }

    [Fact]
    public void FindNearestFrontier_PrefersSameFunction()
    {
        var frontier = new FrontierReportDto(
            "demo",
            "2026-01-01T00:00:00Z",
            "cfg",
            "2 doors",
            10,
            2,
            null,
            [
                new FrontierBranchDto("a", "cfg-branch", 40, 2, 0.5, 1, 0.8, "parse", "0x1", "0x2", null, ""),
                new FrontierBranchDto("b", "cfg-branch", 90, 1, 0.2, 2, 0.9, "handle", "0x3", "0x4", null, ""),
            ],
            "");

        var near = GhidraCallGraphHelper.FindNearestFrontier("handle", frontier);
        Assert.NotNull(near);
        Assert.Equal("handle", near!.FunctionName);
        Assert.Equal(90, near.Score);
    }
}
