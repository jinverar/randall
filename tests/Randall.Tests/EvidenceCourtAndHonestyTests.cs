using Randall.Contracts;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class EvidenceCourtAndHonestyTests
{
    [Fact]
    public void Counterfactual_sweep_offsets_vary_around_center()
    {
        var id = Guid.NewGuid();
        var payload = new byte[64];
        var plan = CounterfactualEngine.BuildPlan(id, "lab", payload, suspectedOffset: 40);

        var sweeps = plan.Probes.Where(p => p.Kind == HypothesisExperimentKind.SweepOffset).ToList();
        Assert.True(sweeps.Count >= 9);
        var offs = sweeps.Select(p => p.OffsetBytes).Distinct().OrderBy(x => x).ToList();
        Assert.Contains(40, offs);
        Assert.True(offs.Min() < 40);
        Assert.True(offs.Max() > 40);
        Assert.True(offs.Count > 1, "Off column must not be identical for every sweep");
    }

    [Fact]
    public void FormatRepeatability_shows_scheduled_vs_executed()
    {
        var id = Guid.NewGuid();
        var payload = new byte[32];
        payload[8] = 0xFF;
        var report = CounterfactualEngine.Evaluate(
            id, "lab", payload, p => p.Length > 8 && p[8] == 0xFF,
            suspectedOffset: 8, maxProbes: 5);

        var line = ExploitResearchPanelBuilder.FormatRepeatability(report);
        Assert.Contains("scheduled", line, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("executed", line, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("observed", line, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("unverified", line, StringComparison.OrdinalIgnoreCase);
        Assert.True(report.Probes.Count > report.ExperimentsExecuted);
    }

    [Fact]
    public void MapProbeOutcome_separates_crash_from_honesty()
    {
        Assert.Equal("Crash", ExploitResearchPanelBuilder.MapProbeOutcome(CounterfactualOutcome.StillCorrupt));
        Assert.Equal("No crash", ExploitResearchPanelBuilder.MapProbeOutcome(CounterfactualOutcome.SafeAdjacent));
        Assert.Equal("Pending", ExploitResearchPanelBuilder.MapProbeOutcome(CounterfactualOutcome.Pending));
        Assert.Equal("Timeout", ExploitResearchPanelBuilder.MapProbeOutcome(
            CounterfactualOutcome.Inconclusive, "harness timeout"));
    }

    [Fact]
    public void ControlTests_expose_varying_offsets_and_outcomes()
    {
        var id = Guid.NewGuid();
        var payload = new byte[32];
        payload[4] = 0xAA;
        var report = CounterfactualEngine.Evaluate(
            id, "lab", payload, _ => true, suspectedOffset: 4, maxProbes: 5);

        var tests = ExploitResearchPanelBuilder.BuildControlTests(report);
        Assert.NotEmpty(tests);
        Assert.Contains(tests, t => t.OffsetBytes != 4); // center±N
        Assert.All(tests.Where(t => t.Outcome is "Crash" or "No crash"), t =>
            Assert.Equal(nameof(ExploitClaimKind.Observed), t.Honesty));
    }

    [Fact]
    public void Lineage_attribution_without_debugger_is_MEDIUM_not_HIGH()
    {
        var id = Guid.NewGuid();
        var payload = new byte[32];
        var sidecar = new CrashSidecarDto(
            id, "run", 1, "lab", "CMD", "havoc",
            ["havoc"], null, "seed", [], "deadbeef", "x.bin", payload.Length,
            -1073741819, "ACCESS_VIOLATION", "detail", null, 0, 0, "native",
            null, null, null, null,
            new TransportSnapshotDto("file", "localhost", 0, false),
            new FuzzSnapshotDto(false, false, "projects/lab.yaml"),
            DateTimeOffset.UtcNow);

        var chain = new CrashCorruptionChainDto(
            true, id, "lab", "MEDIUM", "lineage only",
            null, "havoc", PatternDepthBytes: 0, PatternNote: null,
            MutatorLineage: ["havoc"],
            Steps: [new CorruptionChainStepDto(1, "mutation", "havoc", "step")],
            DebuggerDiagnosis: null, StackHash: null, At: DateTimeOffset.UtcNow,
            SuspectedMutatorStep: 0);

        var trace = BackwardTraceBuilder.Build(id, "lab", sidecar, debugger: null, null, chain, payload);
        var mut = Assert.Single(trace.Steps, s => s.Kind == "mutation");
        Assert.Equal("MEDIUM", mut.Confidence);
        Assert.Contains("lineage", mut.Detail ?? "", StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("introduced value seen at fault", mut.Detail ?? "", StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void RootCause_source_fn_is_not_mutator_name()
    {
        var id = Guid.NewGuid();
        var sidecar = new CrashSidecarDto(
            id, "run", 1, "lab", "CMD", "havoc",
            ["havoc"], null, "seed", [], "h", "x.bin", 8,
            -1073741819, "ACCESS_VIOLATION", "detail", null, 0, 0, "native",
            null, null, null, null,
            new TransportSnapshotDto("file", "localhost", 0, false),
            new FuzzSnapshotDto(false, false, "projects/lab.yaml"),
            DateTimeOffset.UtcNow);

        var root = RootCauseEngine.Build(id, "lab", sidecar, null, debugger: null, null, null);
        Assert.True(root.Ok);
        Assert.True(
            root.Candidate.SuspectedSourceFunction is null
            || !root.Candidate.SuspectedSourceFunction.Equals("havoc", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Court_oracle_score_alone_does_not_confirm()
    {
        var id = Guid.NewGuid();
        var primitives = new[]
        {
            new PrimitiveAssessmentDto(
                "prim-1", PrimitiveKind.InputInfluencedWrite, PrimitiveState.Observed,
                0.8, "write", null, ["oracle:score"]),
        };
        var oracleFacts = new[]
        {
            new EvidenceFact(
                "oracle.score", "72", "oracle", null,
                EvidenceObservationType.Inferred, 0.7, DateTimeOffset.UtcNow),
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

        Assert.False(EvidenceCourt.IsCourtAdmissibleFact(oracleFacts[0]));
        Assert.False(EvidenceCourt.PassesPromotionGate(skeptic, oracleFacts));
        var court = EvidenceCourt.Evaluate(primitives, oracleFacts, skeptic);
        Assert.NotEqual(EvidenceCourtVerdict.Confirmed, court.Overall);
    }

    [Fact]
    public void Court_rejects_honesty_colon_tags_as_citations()
    {
        Assert.False(EvidenceCourt.IsAllowedSensorCitation("honesty:null-write-gate"));
        Assert.False(EvidenceCourt.IsAllowedSensorCitation("court:rejected"));
        Assert.False(EvidenceCourt.IsAllowedSensorCitation("oracle:score"));
        Assert.True(EvidenceCourt.IsAllowedSensorCitation("debugger:faultAddress"));
        Assert.True(EvidenceCourt.IsAllowedSensorCitation("influence:link-o"));
    }

    [Fact]
    public void RootCause_write_av_without_control_does_not_claim_attacker_store()
    {
        var id = Guid.NewGuid();
        var obs = ScreamInvestigator.ParseBlocks(
            "EXCEPTION_CODE: (c0000005) Access violation\n",
            exr: "Parameter[0]: 00000001\nAttempt to write to address 00007ff812340000\n",
            regs: "rax=00007ff812340000 rcx=0000000000000001 rip=0000000000401000\n");

        Assert.False(RootCauseEngine.HasWriteControlEvidence(obs, null, null));
        var root = RootCauseEngine.Build(id, "lab", null, null, obs, null, null);
        Assert.True(root.Ok);
        Assert.DoesNotContain(
            root.Candidate.Inferences,
            i => i.Contains("attacker-controlled", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(
            root.Candidate.Inferences,
            i => i.Contains("control not established", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Fault_site_gate_ignores_unrelated_register_match()
    {
        var match = new RegisterPayloadMatchDto("rdx", "0x41414141", 4, 4, "dword");
        var obs = new DebuggerObservation(
            Ok: true,
            DumpPath: null,
            ObservationPath: null,
            ExceptionCode: "0xC0000005",
            ExceptionHint: "ACCESS_VIOLATION",
            Access: DebuggerAccessKind.Write,
            FaultAddress: null,
            FaultAddressClass: DebuggerAddressClass.Unknown,
            Rip: "0x401000",
            FaultingModule: "lab",
            FaultingFunction: "f",
            FunctionOffset: "+0x10",
            Stack: [],
            StackHash: null,
            RegistersText: "rdx=0000000041414141 rip=0000000000401000",
            DisasmNearRip: "00401000  mov dword ptr [rax], ecx",
            MemoryNearRsp: null,
            ModulesText: null,
            HeapProbeText: null,
            AddressQueryText: null,
            ExrText: null,
            ExploitableClassification: null,
            ExploitableDescription: null,
            HeapSignal: null,
            SuspectedInputInfluence: "LOW",
            ExploitabilityHint: "UNKNOWN",
            Confidence: 0.4,
            Diagnosis: "write",
            DebuggerScreamBonus: 0,
            AnalyzeTimedOut: false,
            Error: null,
            At: DateTimeOffset.UtcNow,
            RegisterMatches: [match]);

        // Instruction present but no fault address / written-value fact — R2 site incomplete.
        Assert.False(ResearchMaturityGates.HasFaultSiteEvidence(obs, facts: null));
        Assert.Null(ResearchMaturityGates.ResolveFaultValue(obs, facts: null));
    }

    [Fact]
    public void Heap_lifetime_link_not_Observed_from_unrelated_register_match()
    {
        var id = Guid.NewGuid();
        var payload = new byte[] { 0x41, 0x41, 0x41, 0x41, 0x00, 0x01 };
        var sidecar = new CrashSidecarDto(
            id, "run", 1, "lab", "CMD", "havoc",
            ["havoc"], null, "seed", [], "h", "x.bin", payload.Length,
            -1073741819, "ACCESS_VIOLATION", "detail", null, 0, 0, "native",
            null, null, null, null,
            new TransportSnapshotDto("tcp", "127.0.0.1", 9999, false),
            new FuzzSnapshotDto(false, false, "projects/lab.yaml"),
            DateTimeOffset.UtcNow);

        var obs = ScreamInvestigator.ParseBlocks(
            "EXCEPTION_CODE: (c0000005)\n",
            exr: "Attempt to write to address 0000012345678900\nParameter[0]: 00000001\n",
            regs: "rax=0000000041414141 rip=0000000000401000\n",
            heap: "Page Heap fingerprints detected\n",
            sidecar: sidecar);

        // Force heap signal without Freed/UAF class.
        obs = obs with { HeapSignal = "HEAP_CORRUPTION", FaultAddressClass = DebuggerAddressClass.Heapish };

        var map = InfluenceEngine.Build(id, "lab", sidecar, null, obs, null, payload: payload);
        var heap = map.Links.Where(l => l.State.Kind == InfluencedStateKind.HeapObject).ToList();
        Assert.NotEmpty(heap);
        Assert.All(heap, l => Assert.Equal(InfluenceConfirmationStatus.Candidate, l.Status));
        Assert.All(heap, l => Assert.Equal(InfluenceHonestyLabel.Hypothesized, l.Honesty));
    }

    [Fact]
    public void Stalk_crash_address_never_fakes_question_marks()
    {
        var label = StalkDashboard.FormatCrashNodeAddress(
            null, faultAddress: null, exceptionOrCode: "ACCESS_VIOLATION");
        Assert.Contains("PC unknown", label, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("????", label, StringComparison.Ordinal);

        var real = StalkDashboard.FormatCrashNodeAddress(
            null, faultAddress: "0x41414141", exceptionOrCode: "ACCESS_VIOLATION");
        Assert.Equal("0x41414141", real);
    }

    [Fact]
    public void StackState_marks_cyclic_slots_and_empty_gracefully()
    {
        var empty = ExploitResearchPanelBuilder.BuildStackState(null, null);
        Assert.False(empty.Ok);
        Assert.Contains("no stack data", empty.SummaryLine, StringComparison.OrdinalIgnoreCase);

        var pattern = System.Text.Encoding.ASCII.GetBytes(PatternTools.Create(80));
        var word = BitConverter.ToUInt64(pattern.AsSpan(16, 8));
        var lo = (uint)(word & 0xFFFFFFFF);
        var hi = (uint)(word >> 32);
        var dbg = ScreamInvestigator.ParseBlocks(
            "EXCEPTION_CODE: (c0000005)\n",
            regs: "rsp=000000000012FF00\nrip=0000000000401000\n",
            stack: "00000000`0012ff00 00000000`00401000 demo!f+0x10",
            disasm: "00401000 c3 ret",
            mem: $"00000000`0012ff00  {hi:x8}`{lo:x8}");

        var cyclic = ExploitResearchPanelBuilder.BuildCyclicAnalysis(
            dbg, pattern, "cyclic", null, null);
        var stack = ExploitResearchPanelBuilder.BuildStackState(dbg, cyclic);
        Assert.True(stack.Ok);
        Assert.Equal("Static", stack.ReconstructionKind);
        Assert.NotNull(stack.RspHex);
        Assert.NotEmpty(stack.TopFrames);
    }
}
