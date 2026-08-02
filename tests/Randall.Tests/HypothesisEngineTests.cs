using Randall.Contracts;
using Randall.Infrastructure;
using Randall.Infrastructure.Mutators;
using Xunit;

namespace Randall.Tests;

public class HypothesisEngineTests
{
    [Fact]
    public void Build_FromCorruptionChainAndDebugger_ProducesRankedHypotheses()
    {
        var id = Guid.NewGuid();
        var payload = new byte[64];
        BitConverter.TryWriteBytes(payload.AsSpan(40), 0x41414141u);

        var sidecar = new CrashSidecarDto(
            id, "run", 7, "lab", "HELLO", "expand",
            ["bitflip", "expand"], null, "seed", [], "DEADBEEF", "x.bin", payload.Length,
            -1073741819, "ACCESS_VIOLATION", "server exited", null, 0, 0, "native",
            null, null, null, null,
            new TransportSnapshotDto("tcp", "127.0.0.1", 9999, false),
            new FuzzSnapshotDto(false, false, "projects/lab.yaml"),
            DateTimeOffset.UtcNow);

        var debugger = ScreamInvestigator.ParseBlocks(
            "EXCEPTION_CODE: (c0000005) Access violation\n",
            exr: "Attempt to write to address 41414141\nParameter[1]: 41414141\n",
            regs: "rip=0000000041414141\n",
            stack: "00000000`0012ff00 00000000`00401000 lab!Parse+0x10",
            sidecar: sidecar);

        var triage = CrashTriage.Classify(null, sidecar, null, payload, debugger: debugger);
        var chain = CorruptionChainBuilder.Build(id, "lab", sidecar, debugger, triage, payload);
        var evolution = ScreamEvolutionBuilder.Build(
            id, "lab", sidecar, triage, debugger, chain, []);

        var set = HypothesisEngine.Build(
            id, "lab", sidecar, triage, debugger, chain, evolution,
            new OracleScore(42, [new OracleScoreTerm("violation", 20, "test")], "oracle"));

        Assert.True(set.Ok);
        Assert.Equal(HypothesisEngine.CurrentSchemaVersion, set.SchemaVersion);
        Assert.NotEmpty(set.Hypotheses);
        Assert.All(set.Hypotheses, h => Assert.InRange(h.SupportScore, 1, 100));
        Assert.All(set.Hypotheses, h => Assert.True(Guid.TryParseExact(h.Id, "N", out _)));
        Assert.Contains(set.Hypotheses, h => (h.TypeId ?? "").StartsWith("hyp-offset", StringComparison.Ordinal));
        Assert.Contains(set.Hypotheses, h => h.Experiment.Kind == HypothesisExperimentKind.SweepOffset);
        // Oracle type id reused across crashes — instance ids remain distinct.
        Assert.Contains(set.Hypotheses, h => h.TypeId == "hyp-oracle-correlate");

        var top = HypothesisEngine.TopPending(set);
        Assert.NotNull(top);
        Assert.Equal(set.Hypotheses[0].Id, top!.Id);
    }

    [Fact]
    public void Duplicate_HypothesisTypeId_Instances_RemainDistinct()
    {
        var a = BuildMinimalSet(Guid.NewGuid());
        var b = BuildMinimalSet(Guid.NewGuid());
        var oracleA = a.Hypotheses.First(h => h.TypeId == "hyp-oracle-correlate");
        var oracleB = b.Hypotheses.First(h => h.TypeId == "hyp-oracle-correlate");
        Assert.Equal("hyp-oracle-correlate", oracleA.TypeId);
        Assert.Equal(oracleA.TypeId, oracleB.TypeId);
        Assert.NotEqual(oracleA.Id, oracleB.Id);
    }

    [Fact]
    public void EnqueueAndDequeue_RoundTripsExperimentPlan()
    {
        var root = Path.Combine(Path.GetTempPath(), "hyp-queue-" + Guid.NewGuid().ToString("N"));
        const string project = "hyp-lab";
        try
        {
            var crashId = Guid.NewGuid();
            var instanceId = Guid.NewGuid().ToString("N");
            var hypothesis = new HypothesisDto(
                instanceId,
                crashId,
                "Test hypothesis statement",
                72,
                new HypothesisExperimentDto(
                    HypothesisExperimentKind.SweepOffset,
                    "sweep offset 40",
                    "bitflip",
                    40,
                    4),
                "Same crash class",
                HypothesisStatus.Proposed,
                TypeId: "hyp-test-1",
                Kind: HypothesisKind.TriggerSensitivity);

            HypothesisEngine.EnqueueFromHypothesis(project, hypothesis, 10, root);
            var snap = HypothesisEngine.TryLoadQueue(project, root);
            Assert.NotNull(snap);
            Assert.Single(snap!.Queue);
            Assert.Equal(72, snap.Queue[0].SupportScore);

            var plan = HypothesisEngine.TryDequeuePlan(project, root);
            Assert.NotNull(plan);
            Assert.Equal(instanceId, plan!.HypothesisId);
            Assert.Equal(HypothesisExperimentKind.SweepOffset, plan.Experiment.Kind);
        }
        finally
        {
            try { Directory.Delete(root, true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void ApplyExperiment_SweepOffset_FlipsDeterministicByte()
    {
        var payload = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
        var experiment = new HypothesisExperimentDto(
            HypothesisExperimentKind.SweepOffset,
            "sweep",
            "bitflip",
            5,
            2);

        var a = HypothesisEngine.ApplyExperiment(payload, experiment, 0, new Random(1))!;
        var b = HypothesisEngine.ApplyExperiment(payload, experiment, 0, new Random(1))!;

        Assert.Equal(a, b);
        Assert.NotEqual(payload, a);
    }

    [Fact]
    public void RecordOutcome_ExitAlone_DoesNotConfirm()
    {
        var root = Path.Combine(Path.GetTempPath(), "hyp-outcome-" + Guid.NewGuid().ToString("N"));
        const string project = "hyp-out";
        var crashId = Guid.NewGuid();
        try
        {
            var crashesDir = Path.Combine(root, "data", "crashes", project);
            Directory.CreateDirectory(crashesDir);

            var instanceId = Guid.NewGuid().ToString("N");
            var hypothesis = new HypothesisDto(
                instanceId,
                crashId,
                "Replay lineage",
                60,
                new HypothesisExperimentDto(HypothesisExperimentKind.ReplayLineage, "replay", "havoc"),
                "Crash reproduces",
                HypothesisStatus.Proposed,
                TypeId: "hyp-out-1",
                Kind: HypothesisKind.ReplaySamePrimaryFault,
                ExpectedPredicate: new ExpectedPredicate(HypothesisPredicateKind.SamePrimaryFault),
                BaselineFault: new FaultIdentitySnapshot(
                    ExitCode: -1073741819,
                    CrashClass: "ACCESS_VIOLATION",
                    FaultModule: "lab",
                    FaultOffset: "0x10",
                    AccessKind: "Write",
                    HasVerifiedPrimaryFault: true));

            HypothesisEngine.Write(crashesDir, new HypothesisSetDto(
                true, crashId, project, [hypothesis], DateTimeOffset.UtcNow,
                SchemaVersion: HypothesisEngine.CurrentSchemaVersion));

            HypothesisEngine.EnqueueFromHypothesis(project, hypothesis, 5, root);
            var plan = HypothesisEngine.TryDequeuePlan(project, root)!;

            // Exit-only observation (historical FuzzEngine path) — must not Confirm.
            HypothesisEngine.RecordOutcome(
                project, plan, 6, crashed: true, "ACCESS_VIOLATION", "-1073741819", root);

            var set = HypothesisEngine.TryReadForCrash(crashesDir, crashId);
            Assert.NotNull(set);
            var updated = set!.Hypotheses[0];
            Assert.NotEqual(HypothesisStatus.Confirmed, updated.Status);
            Assert.Equal(HypothesisStatus.Supported, updated.Status);
            Assert.Contains("not Confirmed", updated.Result!.Observation ?? "", StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            try { Directory.Delete(root, true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void Progression_Cannot_Confirm_From_Exit_Alone()
    {
        var hyp = new HypothesisDto(
            Guid.NewGuid().ToString("N"),
            Guid.NewGuid(),
            "Family progression",
            70,
            new HypothesisExperimentDto(HypothesisExperimentKind.HoldMutator, "hold", "cyclic"),
            "Momentum rises",
            HypothesisStatus.Proposed,
            TypeId: "hyp-write-progression",
            Kind: HypothesisKind.FamilyProgression,
            ExpectedPredicate: new ExpectedPredicate(
                HypothesisPredicateKind.FamilyProgressionAdvanced,
                MinMomentum: 40,
                FamilyId: "fam-1"),
            BaselineFault: new FaultIdentitySnapshot(
                ExitCode: -1073741819, FamilyId: "fam-1", FaultModule: "lab",
                HasVerifiedPrimaryFault: true));

        var observed = new FaultIdentitySnapshot(
            ExitCode: -1073741819,
            CrashClass: "ACCESS_VIOLATION",
            HasVerifiedPrimaryFault: false);

        var result = HypothesisEngine.EvaluateOutcome(
            hyp, crashed: true, observed, remainingBudgetAfter: 2, HypothesisExperimentKind.HoldMutator);

        Assert.NotEqual(HypothesisStatus.Confirmed, result.Status);
        Assert.Contains(result.SupportReasons ?? [], r => r.Contains("not-confirmed", StringComparison.OrdinalIgnoreCase)
            || r.Contains("family-progression", StringComparison.OrdinalIgnoreCase)
            || r.Contains("abnormal-exit", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Same_Exit_Different_PrimaryFault_Not_Reproduction_Confirmed()
    {
        var baseline = new FaultIdentitySnapshot(
            ExitCode: -1073741819,
            FaultModule: "lab",
            FaultOffset: "0x10",
            AccessKind: "Write",
            HasVerifiedPrimaryFault: true);
        var observed = new FaultIdentitySnapshot(
            ExitCode: -1073741819,
            FaultModule: "ntdll",
            FaultOffset: "0x99",
            AccessKind: "Read",
            HasVerifiedPrimaryFault: true);

        var cmp = HypothesisEngine.CompareFaults(baseline, observed);
        Assert.True(cmp.ExitMatches);
        Assert.False(cmp.PrimaryFaultMatches);

        var hyp = new HypothesisDto(
            Guid.NewGuid().ToString("N"), Guid.NewGuid(), "Replay same fault", 65,
            new HypothesisExperimentDto(HypothesisExperimentKind.ReplayLineage, "replay"),
            "same primary fault", HypothesisStatus.Proposed,
            TypeId: "hyp-hold-x", Kind: HypothesisKind.ReplaySamePrimaryFault,
            ExpectedPredicate: new ExpectedPredicate(HypothesisPredicateKind.SamePrimaryFault, baseline),
            BaselineFault: baseline);

        var result = HypothesisEngine.EvaluateOutcome(
            hyp, true, observed, 1, HypothesisExperimentKind.ReplayLineage);
        Assert.NotEqual(HypothesisStatus.Confirmed, result.Status);
    }

    [Fact]
    public void Three_NoCrash_Weakens_Flaky_Not_Refuted()
    {
        var root = Path.Combine(Path.GetTempPath(), "hyp-refute-" + Guid.NewGuid().ToString("N"));
        const string project = "hyp-refute";
        var crashId = Guid.NewGuid();
        try
        {
            var crashesDir = Path.Combine(root, "data", "crashes", project);
            Directory.CreateDirectory(crashesDir);

            var instanceId = Guid.NewGuid().ToString("N");
            var hypothesis = new HypothesisDto(
                instanceId, crashId, "Offset sweep should crash", 62,
                new HypothesisExperimentDto(HypothesisExperimentKind.SweepOffset, "sweep", "bitflip", 8, 2, BudgetIterations: 1),
                "Crash reproduces", HypothesisStatus.Proposed,
                TypeId: "hyp-refute-1",
                Kind: HypothesisKind.TriggerSensitivity,
                ExpectedPredicate: new ExpectedPredicate(HypothesisPredicateKind.TriggerSensitiveRegion));

            HypothesisEngine.Write(crashesDir, new HypothesisSetDto(
                true, crashId, project, [hypothesis], DateTimeOffset.UtcNow,
                SchemaVersion: HypothesisEngine.CurrentSchemaVersion));
            HypothesisEngine.EnqueueFromHypothesis(project, hypothesis, 5, root);
            var plan = HypothesisEngine.TryDequeuePlan(project, root)!;

            HypothesisEngine.RecordOutcome(project, plan, 6, crashed: false, crashClass: null, faultDetail: null, root);

            var set = HypothesisEngine.TryReadForCrash(crashesDir, crashId);
            Assert.NotNull(set);
            var updated = set!.Hypotheses[0];
            Assert.Equal(HypothesisStatus.Weakened, updated.Status);
            Assert.NotEqual(HypothesisStatus.Refuted, updated.Status);
            Assert.True(updated.SupportScore < 62);
        }
        finally { try { Directory.Delete(root, true); } catch { } }
    }

    [Fact]
    public void Oracle_Correlation_Cannot_Gain_Support_From_SafeAdjacent()
    {
        var crashId = Guid.NewGuid();
        var oracle = new HypothesisDto(
            Guid.NewGuid().ToString("N"), crashId, "Oracle correlates with mutator", 62,
            new HypothesisExperimentDto(HypothesisExperimentKind.ReplayLineage, "replay"),
            "campaign correlation", HypothesisStatus.Proposed,
            TypeId: "hyp-oracle-correlate",
            Kind: HypothesisKind.MutatorCorrelation,
            ExpectedPredicate: new ExpectedPredicate(HypothesisPredicateKind.MutatorCorrelationCampaign));

        var trigger = new HypothesisDto(
            Guid.NewGuid().ToString("N"), crashId, "Trigger sensitive region", 55,
            new HypothesisExperimentDto(HypothesisExperimentKind.CounterfactualSafeAdjacent, "cf", OffsetBytes: 8),
            "safe-adjacent", HypothesisStatus.Proposed,
            TypeId: "hyp-cf-trigger-8",
            Kind: HypothesisKind.TriggerSensitivity,
            ExpectedPredicate: new ExpectedPredicate(HypothesisPredicateKind.TriggerSensitiveRegion));

        var set = new HypothesisSetDto(true, crashId, "lab", [oracle, trigger], DateTimeOffset.UtcNow,
            SchemaVersion: HypothesisEngine.CurrentSchemaVersion);

        var probe = new CounterfactualProbeDto(
            "p1", HypothesisExperimentKind.SweepOffset, 0, 8, 1,
            "Bit-flip", CounterfactualOutcome.SafeAdjacent);
        var report = new CounterfactualReportDto(
            true, crashId, "lab", 8, "boundary",
            probe, [probe],
            SafeAdjacentCount: 1, StillCorruptCount: 0, Confidence: "MEDIUM", At: DateTimeOffset.UtcNow,
            LiveExecuted: true, ExperimentsExecuted: 1);

        Assert.False(HypothesisExperimentRegistry.IsAllowed(oracle, HypothesisExperimentKind.CounterfactualSafeAdjacent));
        Assert.False(HypothesisExperimentRegistry.AllowsCounterfactualSafeAdjacent(oracle));
        Assert.True(HypothesisExperimentRegistry.AllowsCounterfactualSafeAdjacent(trigger));

        var updatedIds = new List<string>();
        var after = HypothesisEngine.ApplyCounterfactualSupport(set, report, updatedIds);

        var oracleAfter = after.Hypotheses.First(h => h.TypeId == "hyp-oracle-correlate");
        var triggerAfter = after.Hypotheses.First(h => h.TypeId == "hyp-cf-trigger-8");
        Assert.Equal(62, oracleAfter.SupportScore);
        Assert.Equal(HypothesisStatus.Proposed, oracleAfter.Status);
        Assert.True(triggerAfter.SupportScore > 55);
        Assert.Equal(HypothesisStatus.Supported, triggerAfter.Status);
        Assert.DoesNotContain(oracleAfter.Id, updatedIds);
        Assert.Contains(triggerAfter.Id, updatedIds);
    }

    [Fact]
    public void Invalidated_Evidence_Propagates()
    {
        var factId = "debugger.access:Write";
        var hyp = new HypothesisDto(
            Guid.NewGuid().ToString("N"), Guid.NewGuid(), "stmt", 70,
            new HypothesisExperimentDto(HypothesisExperimentKind.SweepOffset, "s"),
            "expect", HypothesisStatus.Proposed,
            TypeId: "hyp-offset-1",
            Kind: HypothesisKind.TriggerSensitivity,
            EvidenceRefs: [new HypothesisEvidenceRef(factId)]);
        var set = new HypothesisSetDto(true, hyp.CrashId!.Value, "lab", [hyp], DateTimeOffset.UtcNow,
            SchemaVersion: 2);
        var after = HypothesisEngine.PropagateInvalidatedEvidence(set, new HashSet<string> { factId });
        Assert.Equal(HypothesisStatus.Invalidated, after.Hypotheses[0].Status);
        Assert.True(after.Hypotheses[0].EvidenceRefs![0].Invalidated);
    }

    [Fact]
    public void Missing_Debugger_Artifacts_Block_Capability_Hyps()
    {
        var id = Guid.NewGuid();
        var sidecar = new CrashSidecarDto(
            id, "run", 1, "lab", "X", "havoc",
            ["havoc"], null, "seed", [], "AA", "x.bin", 8,
            -1073741819, "ACCESS_VIOLATION", "exit", null, 0, 0, "native",
            null, null, null, null,
            new TransportSnapshotDto("tcp", "127.0.0.1", 1, false),
            new FuzzSnapshotDto(false, false, "projects/lab.yaml"),
            DateTimeOffset.UtcNow);

        var set = HypothesisEngine.Build(
            id, "lab", sidecar, triage: null, debugger: null,
            corruptionChain: null, evolution: null,
            oracleScore: new OracleScore(50, [new OracleScoreTerm("x", 20, null)], "o"));

        Assert.False(set.Ok);
        Assert.Empty(set.Hypotheses);
        Assert.NotNull(set.Manifest);
        Assert.False(set.Manifest!.HasVerifiedPrimaryFault);
        Assert.Contains("primary fault", set.Error ?? "", StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Legacy_SchemaV1_Confirmed_Migrates_To_LegacyUnverified()
    {
        var crashId = Guid.NewGuid();
        var legacy = new HypothesisSetDto(
            true, crashId, "lab",
            [
                new HypothesisDto(
                    "hyp-oracle-correlate", crashId, "legacy", 80,
                    new HypothesisExperimentDto(HypothesisExperimentKind.ReplayLineage, "r"),
                    "expect", HypothesisStatus.Confirmed),
            ],
            DateTimeOffset.UtcNow,
            SchemaVersion: 1);

        var migrated = HypothesisEngine.MigrateIfNeeded(legacy);
        Assert.Equal(2, migrated.SchemaVersion);
        Assert.Single(migrated.Hypotheses);
        Assert.Equal("hyp-oracle-correlate", migrated.Hypotheses[0].TypeId);
        Assert.True(Guid.TryParseExact(migrated.Hypotheses[0].Id, "N", out _));
        Assert.Equal(HypothesisStatus.LegacyUnverified, migrated.Hypotheses[0].Status);
        Assert.True(migrated.Hypotheses[0].LegacyUnverified);
        Assert.NotEqual(HypothesisStatus.Confirmed, migrated.Hypotheses[0].Status);
    }

    [Fact]
    public void Ledger_PersistsUnderHypothesesDir()
    {
        var root = Path.Combine(Path.GetTempPath(), "hyp-ledger-" + Guid.NewGuid().ToString("N"));
        const string project = "hyp-ledger";
        var crashId = Guid.NewGuid();
        try
        {
            var crashesDir = Path.Combine(root, "data", "crashes", project);
            Directory.CreateDirectory(crashesDir);
            var hypothesis = new HypothesisDto(
                Guid.NewGuid().ToString("N"), crashId, "Ledger test", 70,
                new HypothesisExperimentDto(HypothesisExperimentKind.ReplayLineage, "replay", "havoc"),
                "Crash reproduces", HypothesisStatus.Proposed,
                TypeId: "hyp-ledger-1");
            HypothesisEngine.Write(crashesDir, new HypothesisSetDto(
                true, crashId, project, [hypothesis], DateTimeOffset.UtcNow,
                SchemaVersion: HypothesisEngine.CurrentSchemaVersion));

            Assert.True(File.Exists(HypothesisEngine.LedgerPath(crashesDir)));
            var ledger = HypothesisEngine.TryLoadLedger(crashesDir);
            Assert.NotNull(ledger);
            Assert.Single(ledger!.Entries);
        }
        finally { try { Directory.Delete(root, true); } catch { } }
    }

    [Fact]
    public void HuntPolicy_NeedsExperiment_WhenTopHypothesisAboveThreshold()
    {
        var root = Path.Combine(Path.GetTempPath(), "hyp-hunt-" + Guid.NewGuid().ToString("N"));
        const string project = "hunt-hyp";
        try
        {
            var crashId = Guid.NewGuid();
            var crashesDir = Path.Combine(root, "data", "crashes", project);
            Directory.CreateDirectory(crashesDir);
            var instanceId = Guid.NewGuid().ToString("N");
            var hypothesis = new HypothesisDto(
                instanceId, crashId, "Stalled family needs sweep", 68,
                new HypothesisExperimentDto(HypothesisExperimentKind.SweepOffset, "sweep", "bitflip", 12, 4),
                "Momentum rises", HypothesisStatus.Proposed,
                TypeId: "hyp-hunt-top",
                Kind: HypothesisKind.TriggerSensitivity);
            HypothesisEngine.Write(crashesDir, new HypothesisSetDto(
                true, crashId, project, [hypothesis], DateTimeOffset.UtcNow,
                SchemaVersion: HypothesisEngine.CurrentSchemaVersion));

            var policy = HuntPolicyEngine.Evaluate(new HuntPolicyEngine.Context(
                new RandallBrain.Signals(true, "test", null, null, null, [], []),
                [new MutatorCreditRowDto("havoc", 12, 4, 1, 80, 6)], null,
                BuiltInMutators.Create(["havoc", "bitflip"], seed: 1), 0.5, 3, Project: project, RepoRoot: root));

            Assert.True(policy.NeedsExperiment);
            Assert.Equal(instanceId, policy.TopHypothesisId);
        }
        finally { try { Directory.Delete(root, true); } catch { } }
    }

    private static HypothesisSetDto BuildMinimalSet(Guid id)
    {
        var payload = new byte[64];
        BitConverter.TryWriteBytes(payload.AsSpan(40), 0x41414141u);
        var sidecar = new CrashSidecarDto(
            id, "run", 7, "lab", "HELLO", "expand",
            ["bitflip", "expand"], null, "seed", [], "DEADBEEF", "x.bin", payload.Length,
            -1073741819, "ACCESS_VIOLATION", "server exited", null, 0, 0, "native",
            null, null, null, null,
            new TransportSnapshotDto("tcp", "127.0.0.1", 9999, false),
            new FuzzSnapshotDto(false, false, "projects/lab.yaml"),
            DateTimeOffset.UtcNow);
        var debugger = ScreamInvestigator.ParseBlocks(
            "EXCEPTION_CODE: (c0000005) Access violation\n",
            exr: "Attempt to write to address 41414141\nParameter[1]: 41414141\n",
            regs: "rip=0000000041414141\n",
            stack: "00000000`0012ff00 00000000`00401000 lab!Parse+0x10",
            sidecar: sidecar);
        var triage = CrashTriage.Classify(null, sidecar, null, payload, debugger: debugger);
        var chain = CorruptionChainBuilder.Build(id, "lab", sidecar, debugger, triage, payload);
        return HypothesisEngine.Build(
            id, "lab", sidecar, triage, debugger, chain, null,
            new OracleScore(42, [new OracleScoreTerm("violation", 20, "test")], "oracle"));
    }
}
