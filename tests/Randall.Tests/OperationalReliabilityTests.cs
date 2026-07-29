using Randall.Contracts;
using Randall.Core;
using Randall.Infrastructure;
using Randall.Infrastructure.Mutators;
using Xunit;

namespace Randall.Tests;

/// <summary>
/// Operational reliability — cascade/journal honesty, corrupt sidecars, model bounds, Court linkage.
/// </summary>
public class OperationalReliabilityTests
{
    [Fact]
    public void Cascade_reject_requires_tcp_dead_without_dump_or_scream()
    {
        Assert.True(FuzzEngine.ShouldRejectCascadeCrash(
            crashed: true, tcpLike: true, connected: false,
            miniDumpPath: null, hasScreamException: false));

        Assert.False(FuzzEngine.ShouldRejectCascadeCrash(
            crashed: true, tcpLike: true, connected: true,
            miniDumpPath: null, hasScreamException: false));
        Assert.False(FuzzEngine.ShouldRejectCascadeCrash(
            crashed: true, tcpLike: true, connected: false,
            miniDumpPath: "x.dmp", hasScreamException: false));
        Assert.False(FuzzEngine.ShouldRejectCascadeCrash(
            crashed: true, tcpLike: true, connected: false,
            miniDumpPath: null, hasScreamException: true));
        Assert.False(FuzzEngine.ShouldRejectCascadeCrash(
            crashed: true, tcpLike: false, connected: false,
            miniDumpPath: null, hasScreamException: false));
        Assert.False(FuzzEngine.ShouldRejectCascadeCrash(
            crashed: false, tcpLike: true, connected: false,
            miniDumpPath: null, hasScreamException: false));
    }

    [Fact]
    public void Failed_iteration_journal_entry_is_not_a_crash()
    {
        var bounds = FuzzEngine.BuildFailedIterationEntry(
            42, isBounds: true, "Index was outside the bounds of the array",
            coverageEdges: 7, stalkBackend: "novelty", runId: "run-1");
        Assert.False(bounds.Crashed);
        Assert.Equal("error:bounds", bounds.Mutator);
        Assert.Contains("failed (bounds)", bounds.TargetDetail, StringComparison.Ordinal);
        Assert.Equal(42, bounds.Iteration);
        Assert.Equal(0, bounds.NewEdges);

        var other = FuzzEngine.BuildFailedIterationEntry(
            9, isBounds: false, "boom", 0, null, "");
        Assert.False(other.Crashed);
        Assert.Equal("error:exception", other.Mutator);
        Assert.StartsWith("failed:", other.TargetDetail);
    }

    [Fact]
    public void Cascade_rejected_result_journals_Crashed_false()
    {
        // Simulate engine post-cascade journal truth: rejected TCP-dead must not count.
        var rejected = FuzzEngine.ShouldRejectCascadeCrash(
            true, true, connected: false, null, false);
        Assert.True(rejected);

        var entry = new IterationLogEntry(
            11, DateTimeOffset.UtcNow, "TRUN", "havoc", ["havoc"],
            null, "seed", 64, "deadbeef",
            Crashed: false, // after cascade clear
            0, 0, 12,
            "not a crash (connection never established): connection refused",
            null, "novelty", null, "run-x", false);

        Assert.False(entry.Crashed);
        Assert.Contains("not a crash", entry.TargetDetail, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Research_sidecar_corrupt_soft_nulls_and_quarantines()
    {
        var dir = Path.Combine(Path.GetTempPath(), "randall-sidecar-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var id = Guid.NewGuid();
            var path = RootCauseEngine.PathFor(dir, id);
            File.WriteAllText(path, "\0\0partial-cdb{{{{");

            Assert.Null(RootCauseEngine.TryRead(path));
            Assert.True(File.Exists(path + ".corrupt"), "corrupt sidecar should be quarantined");
            Assert.False(File.Exists(path), "original corrupt file should be removed after quarantine");

            // Missing / empty → null, no throw.
            Assert.Null(InfluenceEngine.TryRead(InfluenceEngine.PathFor(dir, id)));
            Assert.Null(EvidenceFactBuilder.TryRead(EvidenceFactBuilder.PathFor(dir, id)));
            Assert.Null(ScreamInvestigator.TryRead(ScreamInvestigator.ObservationPathFor(dir, id)));
            Assert.Null(WindowsCdbCrashAnalysisWriter.TryRead(
                Path.Combine(dir, $"{id:N}_cdb_triage.json")));
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { /* */ }
        }
    }

    [Fact]
    public void Court_lineage_citation_does_not_confirm_write_claim()
    {
        var id = Guid.NewGuid();
        var primitives = new[]
        {
            new PrimitiveAssessmentDto(
                "prim-write", PrimitiveKind.InputInfluencedWrite, PrimitiveState.Observed,
                0.85, "write", null, ["lineage.mutatorChain"]),
        };
        var facts = new[]
        {
            new EvidenceFact(
                "lineage.mutatorChain", "havoc", "lineage", null,
                EvidenceObservationType.Observed, 0.8, DateTimeOffset.UtcNow),
            // Unrelated sensor in the bag must not free-pass a lineage-only citation.
            new EvidenceFact(
                "faultAddress", "0x41414141", "debugger", null,
                EvidenceObservationType.Observed, 0.9, DateTimeOffset.UtcNow),
        };
        var skeptic = new SkepticReportDto(
            true, id, "lab",
            [new SkepticChallengeDto(
                "skep-ok", "claim-1", ResearchClaimKind.InputInfluence,
                "offset influences fault", 75,
                "null: coincidental",
                new HypothesisExperimentDto(HypothesisExperimentKind.MinimizeHold, "neutralize", OffsetBytes: 4),
                "still faults", "clears",
                SkepticChallengeStatus.Survived, 83,
                Observation: "fault class unchanged after neutralize",
                At: DateTimeOffset.UtcNow)],
            "1 survived",
            DateTimeOffset.UtcNow);

        Assert.False(EvidenceCourt.IsCourtAdmissibleFact(facts[0]));
        Assert.False(EvidenceCourt.HasClaimSupportingEvidence(facts, cited: 0, primitives[0].EvidenceRefs));
        var court = EvidenceCourt.Evaluate(primitives, facts, skeptic);
        Assert.NotEqual(EvidenceCourtVerdict.Confirmed, court.Overall);
    }

    [Fact]
    public void Court_debugger_citation_can_confirm_write_claim()
    {
        var id = Guid.NewGuid();
        var primitives = new[]
        {
            new PrimitiveAssessmentDto(
                "prim-write", PrimitiveKind.InputInfluencedWrite, PrimitiveState.Observed,
                0.85, "write", null, ["debugger:faultAddress"]),
        };
        var facts = new[]
        {
            new EvidenceFact(
                "faultAddress", "0x41414141", "debugger", null,
                EvidenceObservationType.Observed, 0.9, DateTimeOffset.UtcNow),
        };
        var skeptic = new SkepticReportDto(
            true, id, "lab",
            [new SkepticChallengeDto(
                "skep-ok", "claim-1", ResearchClaimKind.InputInfluence,
                "offset influences fault", 75,
                "null: coincidental",
                new HypothesisExperimentDto(HypothesisExperimentKind.MinimizeHold, "neutralize", OffsetBytes: 4),
                "still faults", "clears",
                SkepticChallengeStatus.Survived, 83,
                Observation: "ok",
                At: DateTimeOffset.UtcNow)],
            "1 survived",
            DateTimeOffset.UtcNow);

        Assert.True(EvidenceCourt.IsAllowedSensorCitation("debugger:faultAddress"));
        var court = EvidenceCourt.Evaluate(primitives, facts, skeptic);
        Assert.Equal(EvidenceCourtVerdict.Confirmed, court.Overall);
    }

    [Fact]
    public void Png_structured_BuildPayload_never_throws_index_bounds()
    {
        var repo = FindRepoRoot();
        var proj = Path.Combine(repo, "projects", "file-text.yaml");
        var model = ProtocolLoader.Load(proj, "protocols/png_structured.yaml");
        var seeds = ProtocolLoader.LoadProtocolSeeds(proj, "protocols/png_structured.yaml");
        var names = new[]
        {
            "havoc", "bitflip", "interesting", "dictionary", "delete-range",
            "insert-at-offset", "replace-chunk", "clone-chunk", "move-chunk",
            "lengthen-near-field", "shorten-near-field",
        };
        var mutators = BuiltInMutators.Create(names, seed: 1);
        var fuzz = new FuzzConfig { HavocDepth = 8, LengthPolicy = "valid", ChecksumPolicy = "valid" };
        var throws = 0;
        foreach (var mut in mutators)
        {
            var rng = new Random(unchecked((int)HashCode.Combine(mut.Name.GetHashCode(StringComparison.Ordinal), 99)));
            for (var i = 0; i < 400; i++)
            {
                try
                {
                    var payload = ModelFuzzer.BuildPayload(model, seeds, mut, rng, fuzz);
                    Assert.NotNull(payload);
                }
                catch (IndexOutOfRangeException)
                {
                    throws++;
                }
                catch (ArgumentOutOfRangeException)
                {
                    throws++;
                }
            }
        }

        Assert.Equal(0, throws);
    }

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            if (File.Exists(Path.Combine(dir.FullName, "Randall.sln")))
                return dir.FullName;
            dir = dir.Parent;
        }

        throw new InvalidOperationException("repo root not found");
    }
}
