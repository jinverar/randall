using Randall.Contracts;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class PrimitiveEngineTests
{
    [Fact]
    public void Build_ascii_write_yields_write_candidate_and_maturity()
    {
        var id = Guid.NewGuid();
        var obs = ScreamInvestigator.ParseBlocks(
            "EXCEPTION_CODE: (c0000005) Access violation\n",
            exr: "Attempt to write to address 41414141\nParameter[1]: 41414141\n",
            regs: "rax=0000000041414141\nrip=00000000401020\n",
            stack: "00000000`0012ff00 00000000`00401000 lab!Parse+0x10",
            disasm: "00401020  mov dword ptr [rax], ecx");

        var root = RootCauseEngine.Build(id, "lab", null, null, obs, null, null);
        var influence = InfluenceEngine.Build(id, "lab", null, null, obs, null, null, null, null, null);
        var report = PrimitiveEngine.Build(id, "lab", influence, root, obs);

        Assert.True(report.Ok);
        Assert.True(report.Maturity >= ResearchMaturity.R1);
        Assert.Contains(report.Primitives, p =>
            p.Kind is PrimitiveKind.InputInfluencedWrite or PrimitiveKind.PointerControl
                or PrimitiveKind.RegisterControl);
        Assert.False(string.IsNullOrWhiteSpace(report.Summary));
        Assert.Contains("R", report.Maturity.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void Maturity_chip_and_teaching_labels_cover_R0_through_R7()
    {
        Assert.Equal("Crash", PrimitiveEngine.MaturityChipLabel(ResearchMaturity.R0));
        Assert.Equal("Triaged", PrimitiveEngine.MaturityChipLabel(ResearchMaturity.R1));
        Assert.Equal("Root cause", PrimitiveEngine.MaturityChipLabel(ResearchMaturity.R2));
        Assert.Equal("Attributed", PrimitiveEngine.MaturityChipLabel(ResearchMaturity.R3));
        Assert.Equal("Candidate", PrimitiveEngine.MaturityChipLabel(ResearchMaturity.R4));
        Assert.Equal("Observed", PrimitiveEngine.MaturityChipLabel(ResearchMaturity.R5));
        Assert.Equal("Confirmed", PrimitiveEngine.MaturityChipLabel(ResearchMaturity.R6));
        Assert.Equal("Research package", PrimitiveEngine.MaturityChipLabel(ResearchMaturity.R7));

        foreach (ResearchMaturity level in Enum.GetValues<ResearchMaturity>())
        {
            Assert.False(string.IsNullOrWhiteSpace(PrimitiveEngine.MaturityLabel(level)));
            Assert.False(string.IsNullOrWhiteSpace(PrimitiveEngine.MaturityTeachingBlurb(level)));
            Assert.Contains("R", level.ToString(), StringComparison.Ordinal);
        }
    }

    [Fact]
    public void PersistForCrash_round_trips_json()
    {
        var dir = Path.Combine(Path.GetTempPath(), "randfuzz-prim-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var id = Guid.NewGuid();
            var obs = ScreamInvestigator.ParseBlocks(
                "EXCEPTION_CODE: (c0000005)\n",
                exr: "Attempt to write to address 41414141\n",
                regs: "rip=0000000041414141\n");
            var report = PrimitiveEngine.PersistForCrash(dir, id, "lab", null, null, obs);
            var loaded = PrimitiveEngine.TryReadForCrash(dir, id);
            Assert.NotNull(loaded);
            Assert.Equal(report.Maturity, loaded!.Maturity);
            Assert.Equal(report.Summary, loaded.Summary);
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void Cannot_promote_past_R4_without_skeptic_survival()
    {
        var id = Guid.NewGuid();
        var influence = ObservedWriteInfluence(id);
        var without = PrimitiveEngine.Build(id, "lab", influence);

        Assert.Equal(ResearchMaturity.R4, without.Maturity);
        Assert.Contains("Skeptic gate", without.MaturityRationale, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(without.Primitives, p => p.State == PrimitiveState.Confirmed);
    }

    [Fact]
    public void Skeptic_survival_allows_R5_plus_promotion()
    {
        var id = Guid.NewGuid();
        var influence = ObservedWriteInfluence(id);
        var skeptic = SurvivedSkeptic(id);

        Assert.True(SkepticEngine.PassesPromotionGate(skeptic));
        var withGate = PrimitiveEngine.Build(id, "lab", influence, skeptic: skeptic);

        Assert.True(withGate.Maturity >= ResearchMaturity.R5);
        Assert.DoesNotContain("held at R4", withGate.MaturityRationale, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Falsified_skeptic_blocks_Confirmed_and_R5()
    {
        var id = Guid.NewGuid();
        var influence = new CrashInfluenceMapDto(
            true, id, "lab", "HIGH", "confirmed write",
            [new InfluenceLinkDto(
                "link-c",
                new InfluenceRegionDto(0, 4, 4, "ptr", null, null),
                new InfluencedStateDto(InfluencedStateKind.FaultAddress, "fault"),
                InfluenceConfirmationStatus.Confirmed,
                "input→fault address",
                [])],
            [],
            DateTimeOffset.UtcNow);

        var falsified = new SkepticReportDto(
            true, id, "lab",
            [new SkepticChallengeDto(
                "skep-1", "claim-1", ResearchClaimKind.RootCause,
                "write at offset", 80,
                "null",
                new HypothesisExperimentDto(HypothesisExperimentKind.MinimizeHold, "neutralize"),
                "survives", "falsified",
                SkepticChallengeStatus.Falsified, 55,
                Observation: "fault moved",
                At: DateTimeOffset.UtcNow)],
            "1 falsified",
            DateTimeOffset.UtcNow);

        Assert.False(SkepticEngine.PassesPromotionGate(falsified));
        var report = PrimitiveEngine.Build(id, "lab", influence, skeptic: falsified);

        Assert.Equal(ResearchMaturity.R4, report.Maturity);
        Assert.DoesNotContain(report.Primitives, p => p.State == PrimitiveState.Confirmed);
        Assert.Contains(report.Primitives, p => p.State == PrimitiveState.Observed);
    }

    private static CrashInfluenceMapDto ObservedWriteInfluence(Guid id) =>
        new(
            true, id, "lab", "HIGH", "observed write",
            [new InfluenceLinkDto(
                "link-o",
                new InfluenceRegionDto(4, 8, 4, "ptr", null, null),
                new InfluencedStateDto(InfluencedStateKind.FaultAddress, "fault"),
                InfluenceConfirmationStatus.Observed,
                "input→fault address",
                [])],
            [],
            DateTimeOffset.UtcNow);

    private static SkepticReportDto SurvivedSkeptic(Guid id) =>
        new(
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
}
