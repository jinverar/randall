using Randall.Contracts;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class CrashIntelligenceBuilderTests
{
    [Fact]
    public void Build_UniqueCrash_HasHighNoveltyAndScreamScore()
    {
        var id = Guid.NewGuid();
        var dir = Path.Combine(Path.GetTempPath(), "randall-intel-unique-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var inputPath = Path.Combine(dir, "x.bin");
        File.WriteAllBytes(inputPath, new byte[512]);
        try
        {
            var summary = new CrashSummaryDto(
                id, "demo", 42, "cmd/havoc", "abc123", inputPath,
                null, "-1073741819", null, null, "run-1", DateTimeOffset.UtcNow,
                "access_violation", "high", "0xDEAD", "AV", "demo|av|0xdead", true);

            var triage = new CrashTriageDto(
                "access_violation", "high", "test", true, false, "demo|av|0xdead",
                "AV", "0xDEAD", null, "0x401000", "0x7fff0010", 128, "depth");

            var sidecar = new CrashSidecarDto(
                id, "run-1", 42, "demo", "cmd", "havoc", ["cmd", "havoc", "expand"],
                "parent-hash", "corpus", [], "abc123", inputPath, 512, -1073741819,
                "AV", "tcp", null, 3, 120, "drcov", null, null, null, null,
                new TransportSnapshotDto("tcp", "127.0.0.1", 9999, false),
                new FuzzSnapshotDto(true, false, "projects/demo.yaml"),
                DateTimeOffset.UtcNow,
                null,
                new OracleScore(85, [new OracleScoreTerm("crash", 80, "AV")], "+80 crash"));

            var intel = CrashIntelligenceBuilder.Build(summary, triage, sidecar, 512, [summary]);

            Assert.Equal("high", intel.Severity);
            Assert.True(intel.Novelty >= 70);
            Assert.Equal(1, intel.SeenCount);
            Assert.Equal(3, intel.CoverageDelta);
            Assert.True(intel.Reproducible); // input file on disk
            Assert.False(intel.Minimized); // no *_minimized.bin — not "smallest alone"
            Assert.Equal(85, intel.OracleScore?.Total);
            Assert.Equal(128, intel.Offset);
            Assert.NotNull(intel.Lineage);
            Assert.Equal(3, intel.Lineage!.MutatorChain.Count);
            Assert.True(intel.Lineage.Partial);
            Assert.True(intel.ScreamScore > 40);
            Assert.NotNull(intel.PrimaryFault);
            Assert.Equal(FaultSignalKind.AccessViolation, intel.PrimaryFault!.Kind);
            Assert.NotNull(intel.FaultSignals);
            Assert.NotEmpty(intel.FaultSignals!);
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void Build_ClusteredCrash_LowersNoveltyAndMinimizedFlag()
    {
        var sharedKey = "proj|av|0x1000";
        var dir = Path.Combine(Path.GetTempPath(), "randall-intel-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var pathA = Path.Combine(dir, "a.bin");
        var pathB = Path.Combine(dir, "b.bin");
        File.WriteAllBytes(pathA, new byte[100]);
        File.WriteAllBytes(pathB, new byte[200]);
        try
        {
            var a = new CrashSummaryDto(
                Guid.NewGuid(), "proj", 1, "m", "h1", pathA,
                null, null, null, null, null, DateTimeOffset.UtcNow.AddHours(-2),
                null, "medium", null, null, sharedKey);
            var b = new CrashSummaryDto(
                Guid.NewGuid(), "proj", 2, "m", "h2", pathB,
                null, null, null, null, null, DateTimeOffset.UtcNow,
                null, "medium", null, null, sharedKey);

            var triage = new CrashTriageDto(
                "access_violation", "medium", "dup", false, false, sharedKey,
                null, null, null, null, null);

            var intelA = CrashIntelligenceBuilder.Build(a, triage, null, 100, [a, b]);
            var intelB = CrashIntelligenceBuilder.Build(b, triage, null, 200, [a, b]);

            Assert.Equal(2, intelA.SeenCount);
            Assert.True(intelA.Novelty < 70);
            Assert.True(intelB.Novelty < 70);
            // Smallest-in-cluster ≠ minimized; only *_minimized.bin counts.
            Assert.False(intelA.Minimized);
            Assert.False(intelB.Minimized);
            Assert.True(intelA.Reproducible);
            Assert.True(intelB.Reproducible);

            File.WriteAllBytes(CrashInputMinimizer.MinimizedPathFor(dir, a.Id), new byte[40]);
            var intelAMin = CrashIntelligenceBuilder.Build(a, triage, null, 100, [a, b]);
            Assert.True(intelAMin.Minimized);
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void WithListIntelligence_CopiesSummaryFields()
    {
        var summary = new CrashSummaryDto(
            Guid.NewGuid(), "p", 1, "m", "h", "f.bin",
            null, null, null, null, null, DateTimeOffset.UtcNow);
        var intel = new CrashIntelligenceDto(
            "low", 90, "k", 1, 2, "fn+0x10", 4, OracleScore.Empty,
            true, true, DateTimeOffset.UtcNow, 1, null, 55,
            new FaultSignal(FaultSignalKind.AccessViolation, 0.9, "high", FaultSignalSource.CrashTriage, "AV @ dead"),
            ResearchMaturity: "R3",
            ResearchMaturityLabel: "Input-attributed",
            ResearchMaturityRationale: "input region attributed to influenced program state");

        var enriched = CrashIntelligenceBuilder.WithListIntelligence(summary, intel);

        Assert.Equal(55, enriched.ScreamScore);
        Assert.Equal(90, enriched.Novelty);
        Assert.Equal(0, enriched.OracleScoreTotal);
        Assert.Equal(1, enriched.SeenCount);
        Assert.Equal("AccessViolation", enriched.PrimaryFaultKind);
        Assert.NotNull(enriched.PrimaryFaultSummary);
        Assert.Equal("R3", enriched.ResearchMaturity);
        Assert.Equal("Input-attributed", enriched.ResearchMaturityLabel);
    }
}
