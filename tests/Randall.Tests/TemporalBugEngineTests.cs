using Randall.Contracts;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class TemporalBugEngineTests
{
    [Fact]
    public void Build_emits_corruption_crash_rootcause_timeline()
    {
        var id = Guid.NewGuid();
        var payload = new byte[64];
        BitConverter.TryWriteBytes(payload.AsSpan(40), 0x41414141u);

        var sidecar = new CrashSidecarDto(
            id, "run", 3, "lab", "HELLO", "expand",
            ["bitflip", "expand"], null, "seed", [], "DEADBEEF", "x.bin", payload.Length,
            -1073741819, "ACCESS_VIOLATION", "detail", null, 0, 0, "native",
            null, null, null, null,
            new TransportSnapshotDto("tcp", "127.0.0.1", 9999, false),
            new FuzzSnapshotDto(false, false, "projects/lab.yaml"),
            DateTimeOffset.UtcNow);

        var obs = ScreamInvestigator.ParseBlocks(
            "EXCEPTION_CODE: (c0000005) Access violation\n",
            exr: "Attempt to write to address 41414141\nParameter[1]: 41414141\n",
            regs: "rax=0000000041414141\nrip=00000000401020\n",
            stack: "00000000`0012ff00 00000000`00401000 lab!Parse+0x10",
            disasm: "00401020  mov dword ptr [rax], ecx",
            sidecar: sidecar);

        var triage = CrashTriage.Classify(null, sidecar, null, payload, debugger: obs);
        var chain = CorruptionChainBuilder.Build(id, "lab", sidecar, obs, triage, payload);
        var trace = BackwardTraceBuilder.Build(id, "lab", sidecar, obs, triage, chain, payload);
        var root = RootCauseEngine.Build(id, "lab", sidecar, triage, obs, chain, trace);
        var report = TemporalBugEngine.Build(id, "lab", trace, chain, root);

        Assert.True(report.Ok);
        Assert.Contains(report.Timeline, e => e.Phase == TemporalPhase.Corruption);
        Assert.Contains(report.Timeline, e => e.Phase == TemporalPhase.Crash);
        Assert.Contains(report.Timeline, e => e.Phase == TemporalPhase.RootCause);
        Assert.True(report.Timeline.Select(e => e.Order).SequenceEqual(
            report.Timeline.Select(e => e.Order).OrderBy(o => o)));
        Assert.Contains("Temporal timeline", report.Summary, StringComparison.OrdinalIgnoreCase);
        Assert.Null(report.DeepScreamPlaybookNotes);
    }

    [Fact]
    public void Build_deep_scream_marked_adds_ttd_playbook_notes()
    {
        var id = Guid.NewGuid();
        var chain = new CrashCorruptionChainDto(
            true, id, "lab", "MEDIUM", "field → register → AV",
            "len", "expand", 40, null, ["expand"],
            [new CorruptionChainStepDto(1, "input", "length field mutated", "offset 4")],
            "write AV", "hash", DateTimeOffset.UtcNow);

        var root = new RootCauseAnalysisDto(
            true, id, "lab",
            new RootCauseCandidate(
                RootCauseCategory.BoundsViolation,
                "Parse", "recv", "memcpy", "len@4", null, "mov [rax],ecx",
                [], "HIGH",
                ["write AV"], ["out-of-bounds write candidate"], ["exact allocator unknown"]),
            "Bounds violation at Parse — educational summary.",
            At: DateTimeOffset.UtcNow);

        var deep = new DeepScreamDto(
            Ok: true,
            IsCandidate: true,
            CrashId: id,
            Project: "lab",
            ScreamScore: 88,
            SeenCount: 2,
            Reproducible: true,
            Minimized: false,
            EligibilityReasons: ["high scream"],
            MissingReasons: [],
            IsMarked: true,
            TtdToolsPresent: true,
            TtdLaunchNote: "Record with windbg -g -G then replay.",
            At: DateTimeOffset.UtcNow);

        var report = TemporalBugEngine.Build(id, "lab", null, chain, root, deep);

        Assert.True(report.Ok);
        Assert.NotNull(report.DeepScreamPlaybookNotes);
        Assert.Contains("TTD", report.DeepScreamPlaybookNotes!, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Rewind", report.DeepScreamPlaybookNotes!, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("teaching", report.DeepScreamPlaybookNotes!, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("shellcode", report.DeepScreamPlaybookNotes!, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(report.Timeline, e => e.Phase == TemporalPhase.RootCause
            && e.Label.Contains("BoundsViolation", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void PersistForCrash_round_trips_json()
    {
        var dir = Path.Combine(Path.GetTempPath(), "randfuzz-temporal-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var id = Guid.NewGuid();
            var chain = new CrashCorruptionChainDto(
                true, id, "lab", "LOW", "minimal chain",
                null, null, null, null, [],
                [new CorruptionChainStepDto(1, "input", "seed bytes", null)],
                null, null, DateTimeOffset.UtcNow);

            var written = TemporalBugEngine.PersistForCrash(dir, id, "lab", null, chain, null);
            var loaded = TemporalBugEngine.TryReadForCrash(dir, id);

            Assert.True(File.Exists(TemporalBugEngine.PathFor(dir, id)));
            Assert.NotNull(loaded);
            Assert.Equal(written.Summary, loaded!.Summary);
            Assert.Equal(written.Timeline.Count, loaded.Timeline.Count);
            Assert.Equal(TemporalPhase.Corruption, loaded.Timeline[0].Phase);
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void Build_insufficient_evidence_returns_ok_false()
    {
        var id = Guid.NewGuid();
        var report = TemporalBugEngine.Build(id, "lab", null, null, null);

        Assert.False(report.Ok);
        Assert.Empty(report.Timeline);
        Assert.Contains("Insufficient evidence", report.Summary);
    }
}
