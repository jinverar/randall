using System.Text.Json;
using Randall.Contracts;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class BarrierDiagnosisEngineTests
{
    [Fact]
    public void BuildFromSignals_EmptyFrontier_EmitsHighBarrier()
    {
        var frontier = new FrontierReportDto(
            "demo",
            DateTime.UtcNow.ToString("O"),
            "empty",
            "No gray doors",
            CoverageBlockCount: 0,
            FrontierCount: 0,
            AnalysisPath: null,
            Frontiers: [],
            WorkflowHint: "import analysis");

        var report = BarrierDiagnosisEngine.BuildFromSignals(
            "demo",
            frontier: frontier,
            mutatorRows: [],
            iterations: 100);

        Assert.True(report.Ok);
        Assert.Contains(report.Barriers, b => b.Kind == BarrierKind.EmptyFrontier && b.Severity == "high");
        Assert.All(report.Barriers, b =>
        {
            Assert.DoesNotContain("shellcode", b.Diagnosis, StringComparison.OrdinalIgnoreCase);
            Assert.All(b.SuggestedActions, a =>
                Assert.DoesNotContain("ROP", a, StringComparison.OrdinalIgnoreCase));
        });
    }

    [Fact]
    public void BuildFromSignals_StagnantCoverage_AndFlatCredit()
    {
        var rows = new List<MutatorCreditRowDto>
        {
            new("havoc", 40, 0, 0, 0, 1, 40, 1.0),
            new("bitflip", 40, 0, 0, 0, 1, 40, 1.0),
        };

        var report = BarrierDiagnosisEngine.BuildFromSignals(
            "stagnant",
            frontier: new FrontierReportDto(
                "stagnant", DateTime.UtcNow.ToString("O"), "cfg", "ok",
                10, 3, null,
                [new FrontierBranchDto("e1", "cfg-branch", 10, 1, 0.5, 1, 0.5, "f", "0x1", "0x2", null, "d")],
                "hint"),
            mutatorRows: rows,
            corpusFileCount: 0,
            coverageEdgeCount: 0,
            oracleFindingCount: 0,
            dictionaryTokenCount: 2,
            iterations: 80);

        Assert.Contains(report.Barriers, b => b.Kind == BarrierKind.StagnantCoverage);
        Assert.Contains(report.Barriers, b => b.Kind == BarrierKind.FlatMutatorCredit);
        Assert.Contains(report.Barriers, b => b.Kind == BarrierKind.QuietOracle);
        Assert.Contains(report.Barriers, b => b.Kind == BarrierKind.ThinDictionary);
        Assert.DoesNotContain(report.Barriers, b => b.Kind == BarrierKind.EmptyFrontier);
    }

    [Fact]
    public void Diagnose_Persists_UnderStalkAndCrashes()
    {
        var root = Path.Combine(Path.GetTempPath(), "randfuzz-barrier-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            const string project = "barrier-persist";
            var stalkDir = Path.Combine(root, "data", "stalk", project);
            Directory.CreateDirectory(stalkDir);

            // Empty frontier artifact on disk.
            var emptyFrontier = new FrontierReportDto(
                project, DateTime.UtcNow.ToString("O"), "empty", "none",
                0, 0, null, [], "hint");
            File.WriteAllText(
                Path.Combine(stalkDir, FrontierEngine.FileName),
                JsonSerializer.Serialize(emptyFrontier));

            var report = BarrierDiagnosisEngine.Diagnose(project, root, persist: true);
            Assert.True(report.Ok);
            Assert.Contains(report.Barriers, b => b.Kind == BarrierKind.EmptyFrontier);

            var stalkPath = BarrierDiagnosisEngine.StalkPath(project, root);
            Assert.True(File.Exists(stalkPath));
            var loaded = BarrierDiagnosisEngine.TryLoad(project, root);
            Assert.NotNull(loaded);
            Assert.Equal(report.Barriers.Count, loaded!.Barriers.Count);

            var crashPath = BarrierDiagnosisEngine.CrashesPath(project, root);
            Assert.True(File.Exists(crashPath));
        }
        finally
        {
            try { Directory.Delete(root, recursive: true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void IsFlatCredit_RequiresEnoughRuns()
    {
        var few = new List<MutatorCreditRowDto>
        {
            new("havoc", 2, 0, 0, 0, 1),
        };
        Assert.False(BarrierDiagnosisEngine.IsFlatCredit(few, iterationsHint: 2));

        var many = new List<MutatorCreditRowDto>
        {
            new("havoc", 30, 0, 0, 0, 1, 30, 1.0),
            new("bitflip", 30, 0, 0, 0, 1, 30, 1.0),
        };
        Assert.True(BarrierDiagnosisEngine.IsFlatCredit(many, iterationsHint: 60));
    }
}
