using Randall.Contracts;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class ResearchMaturityGateTests
{
    [Fact]
    public void Cannot_reach_R2_without_fault_insn_and_addr_or_value()
    {
        var id = Guid.NewGuid();
        // Debugger OK but no disasm → no parseable fault instruction.
        var obs = ScreamInvestigator.ParseBlocks(
            "EXCEPTION_CODE: (c0000005) Access violation\n",
            exr: "Attempt to write to address 00000000\nParameter[1]: 00000000\n",
            regs: "rip=0000000000401000\nrax=0\n");

        Assert.False(ResearchMaturityGates.HasFaultSiteEvidence(obs, facts: null));

        // Synthetic root-cause with category but no fault-site evidence → provisional R2 capped to R1.
        var root = new RootCauseAnalysisDto(
            true, id, "lab",
            new RootCauseCandidate(
                RootCauseCategory.UnexpectedObjectState,
                "lab!f", null, null, null, null, null,
                [], "MEDIUM", ["AV"], ["null write"], ["insn unknown"]),
            "null write — teaching stub",
            [],
            DateTimeOffset.UtcNow);

        Assert.False(ResearchMaturityGates.MeetsR2(root, obs, facts: null));

        var (gated, reason) = ResearchMaturityGates.Enforce(
            ResearchMaturity.R2, root, null, [], null, obs, [], null, null);
        Assert.Equal(ResearchMaturity.R1, gated);
        Assert.Contains("fault instruction", reason ?? "", StringComparison.OrdinalIgnoreCase);

        // No influence → no debugger-fallback primitives when influence unknown and no Bounds/SizeMismatch.
        // Force empty primitives path: influence null + root Unknown category would be R1;
        // use Enforce-proven path above as the machine gate. Also ensure Build never invents R2 here.
        var report = PrimitiveEngine.Build(id, "lab", influence: null, rootCause: root, debugger: obs);
        Assert.True(report.Maturity != ResearchMaturity.R2 || ResearchMaturityGates.HasFaultSiteEvidence(obs, report.Facts));
        if (report.Maturity == ResearchMaturity.R1)
            Assert.True(
                report.MaturityRationale.Contains("fault instruction", StringComparison.OrdinalIgnoreCase)
                || report.MaturityRationale.Contains("Triaged", StringComparison.OrdinalIgnoreCase)
                || report.MaturityRationale.Contains("held at R1", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void R2_allowed_with_fault_insn_and_address()
    {
        var id = Guid.NewGuid();
        var obs = ScreamInvestigator.ParseBlocks(
            "EXCEPTION_CODE: (c0000005) Access violation\n",
            exr: "Attempt to write to address 41414141\nParameter[1]: 41414141\n",
            regs: "rax=0000000041414141\nrip=0000000000401020\n",
            disasm: "00401020  mov dword ptr [rax], ecx");

        var root = RootCauseEngine.Build(id, "lab", null, null, obs, null, null);
        Assert.True(ResearchMaturityGates.HasFaultSiteEvidence(obs, null));
        Assert.True(ResearchMaturityGates.MeetsR2(root, obs, null));
    }

    [Fact]
    public void Cannot_reach_R5_without_counterfactual_and_skeptic()
    {
        var id = Guid.NewGuid();
        var influence = new CrashInfluenceMapDto(
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

        var facts = new[]
        {
            new EvidenceFact(
                "faultAddress", "0x41414141", "debugger", null,
                EvidenceObservationType.Observed, 0.9, DateTimeOffset.UtcNow),
        };

        // Observed influence alone → at most R4 without Skeptic/CF.
        var bare = PrimitiveEngine.Build(id, "lab", influence, facts: facts);
        Assert.True(bare.Maturity <= ResearchMaturity.R4);

        // Skeptic Survived but no counterfactual/delta language → still R4.
        var weakSkeptic = new SkepticReportDto(
            true, id, "lab",
            [new SkepticChallengeDto(
                "skep-weak", "claim-1", ResearchClaimKind.InputInfluence,
                "offset influences fault", 75,
                "null: coincidental",
                new HypothesisExperimentDto(HypothesisExperimentKind.MinimizeHold, "neutralize", OffsetBytes: 4),
                "still faults", "clears",
                SkepticChallengeStatus.Survived, 83,
                Observation: "challenge completed",
                At: DateTimeOffset.UtcNow)],
            "1 survived",
            DateTimeOffset.UtcNow);

        Assert.True(SkepticEngine.PassesPromotionGate(weakSkeptic));
        Assert.False(PrimitiveEngine.HasCounterfactualDeltaEvidence(weakSkeptic));
        Assert.False(ResearchMaturityGates.MeetsR5Plus(weakSkeptic, facts));

        var capped = PrimitiveEngine.Build(id, "lab", influence, skeptic: weakSkeptic, facts: facts);
        Assert.Equal(ResearchMaturity.R4, capped.Maturity);
    }

    [Fact]
    public void EvidenceLedger_maps_observation_types_to_kinds()
    {
        Assert.Equal(EvidenceKind.Observed, EvidenceLedger.KindFor(EvidenceObservationType.Observed));
        Assert.Equal(EvidenceKind.Confirmed, EvidenceLedger.KindFor(EvidenceObservationType.ExperimentallyConfirmed));
        Assert.Equal(EvidenceKind.Hypothesis, EvidenceLedger.KindFor(EvidenceObservationType.Hypothesized));
        Assert.Equal(EvidenceKind.Derived, EvidenceLedger.KindFor(EvidenceObservationType.Inferred, 0.8));
        Assert.Equal(EvidenceKind.Heuristic, EvidenceLedger.KindFor(EvidenceObservationType.Inferred, 0.4));

        var rows = EvidenceLedger.FromFacts(
        [
            new EvidenceFact("a", "1", "dbg", null, EvidenceObservationType.Observed, 0.9, DateTimeOffset.UtcNow),
            new EvidenceFact("b", "2", "hyp", null, EvidenceObservationType.Hypothesized, 0.5, DateTimeOffset.UtcNow),
        ]);
        Assert.Equal(2, rows.Count);
        Assert.Equal(EvidenceKind.Observed, rows[0].Kind);
        Assert.Equal(EvidenceKind.Hypothesis, rows[1].Kind);
    }
}
