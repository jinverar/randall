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
        Assert.NotEmpty(set.Hypotheses);
        Assert.All(set.Hypotheses, h => Assert.InRange(h.ConfidencePercent, 1, 100));
        Assert.Contains(set.Hypotheses, h => h.Id.StartsWith("hyp-offset", StringComparison.Ordinal));
        Assert.Contains(set.Hypotheses, h => h.Experiment.Kind == HypothesisExperimentKind.SweepOffset);

        var top = HypothesisEngine.TopPending(set);
        Assert.NotNull(top);
        Assert.Equal(set.Hypotheses[0].Id, top!.Id);
    }

    [Fact]
    public void EnqueueAndDequeue_RoundTripsExperimentPlan()
    {
        var root = Path.Combine(Path.GetTempPath(), "hyp-queue-" + Guid.NewGuid().ToString("N"));
        const string project = "hyp-lab";
        try
        {
            var crashId = Guid.NewGuid();
            var hypothesis = new HypothesisDto(
                "hyp-test-1",
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
                HypothesisStatus.Pending);

            HypothesisEngine.EnqueueFromHypothesis(project, hypothesis, 10, root);
            var snap = HypothesisEngine.TryLoadQueue(project, root);
            Assert.NotNull(snap);
            Assert.Single(snap!.Queue);
            Assert.Equal(72, snap.Queue[0].ConfidencePercent);

            var plan = HypothesisEngine.TryDequeuePlan(project, root);
            Assert.NotNull(plan);
            Assert.Equal("hyp-test-1", plan!.HypothesisId);
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
    public void RecordOutcome_UpdatesConfidenceOnCrash()
    {
        var root = Path.Combine(Path.GetTempPath(), "hyp-outcome-" + Guid.NewGuid().ToString("N"));
        const string project = "hyp-out";
        var crashId = Guid.NewGuid();
        try
        {
            var crashesDir = Path.Combine(root, "data", "crashes", project);
            Directory.CreateDirectory(crashesDir);

            var hypothesis = new HypothesisDto(
                "hyp-out-1",
                crashId,
                "Replay lineage",
                60,
                new HypothesisExperimentDto(HypothesisExperimentKind.ReplayLineage, "replay", "havoc"),
                "Crash reproduces",
                HypothesisStatus.Pending);

            HypothesisEngine.Write(crashesDir, new HypothesisSetDto(
                true, crashId, project, [hypothesis], DateTimeOffset.UtcNow));

            HypothesisEngine.EnqueueFromHypothesis(project, hypothesis, 5, root);
            var plan = HypothesisEngine.TryDequeuePlan(project, root)!;

            HypothesisEngine.RecordOutcome(
                project, plan, 6, crashed: true, "ACCESS_VIOLATION", "write fault", root);

            var set = HypothesisEngine.TryReadForCrash(crashesDir, crashId);
            Assert.NotNull(set);
            var updated = set!.Hypotheses[0];
            Assert.True(updated.ConfidencePercent >= 60);
            Assert.NotNull(updated.Result);
            Assert.Equal(HypothesisStatus.Confirmed, updated.Result!.Status);
        }
        finally
        {
            try { Directory.Delete(root, true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void RecordOutcome_RefutesWhenNoCrashAfterBudget()
    {
        var root = Path.Combine(Path.GetTempPath(), "hyp-refute-" + Guid.NewGuid().ToString("N"));
        const string project = "hyp-refute";
        var crashId = Guid.NewGuid();
        try
        {
            var crashesDir = Path.Combine(root, "data", "crashes", project);
            Directory.CreateDirectory(crashesDir);

            var hypothesis = new HypothesisDto(
                "hyp-refute-1", crashId, "Offset sweep should crash", 62,
                new HypothesisExperimentDto(HypothesisExperimentKind.SweepOffset, "sweep", "bitflip", 8, 2, BudgetIterations: 1),
                "Crash reproduces", HypothesisStatus.Pending);

            HypothesisEngine.Write(crashesDir, new HypothesisSetDto(true, crashId, project, [hypothesis], DateTimeOffset.UtcNow));
            HypothesisEngine.EnqueueFromHypothesis(project, hypothesis, 5, root);
            var plan = HypothesisEngine.TryDequeuePlan(project, root)!;

            HypothesisEngine.RecordOutcome(project, plan, 6, crashed: false, crashClass: null, faultDetail: null, root);

            var set = HypothesisEngine.TryReadForCrash(crashesDir, crashId);
            Assert.NotNull(set);
            var updated = set!.Hypotheses[0];
            Assert.Equal(HypothesisStatus.Refuted, updated.Status);
            Assert.Equal(62, updated.Result!.ConfidenceBefore);
            Assert.True(updated.ConfidencePercent < 62);
            Assert.Null(HypothesisEngine.TryDequeuePlan(project, root));
        }
        finally { try { Directory.Delete(root, true); } catch { } }
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
                "hyp-ledger-1", crashId, "Ledger test", 70,
                new HypothesisExperimentDto(HypothesisExperimentKind.ReplayLineage, "replay", "havoc"),
                "Crash reproduces", HypothesisStatus.Pending);
            HypothesisEngine.Write(crashesDir, new HypothesisSetDto(true, crashId, project, [hypothesis], DateTimeOffset.UtcNow));

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
            var hypothesis = new HypothesisDto(
                "hyp-hunt-top", crashId, "Stalled family needs sweep", 68,
                new HypothesisExperimentDto(HypothesisExperimentKind.SweepOffset, "sweep", "bitflip", 12, 4),
                "Momentum rises", HypothesisStatus.Pending);
            HypothesisEngine.Write(crashesDir, new HypothesisSetDto(true, crashId, project, [hypothesis], DateTimeOffset.UtcNow));

            var policy = HuntPolicyEngine.Evaluate(new HuntPolicyEngine.Context(
                new RandallBrain.Signals(true, "test", null, null, null, [], []),
                [new MutatorCreditRowDto("havoc", 12, 4, 1, 80, 6)], null,
                BuiltInMutators.Create(["havoc", "bitflip"], seed: 1), 0.5, 3, Project: project, RepoRoot: root));

            Assert.True(policy.NeedsExperiment);
            Assert.Equal("hyp-hunt-top", policy.TopHypothesisId);
        }
        finally { try { Directory.Delete(root, true); } catch { } }
    }
}
