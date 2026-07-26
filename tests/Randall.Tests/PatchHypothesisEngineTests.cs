using Randall.Contracts;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class PatchHypothesisEngineTests
{
    [Fact]
    public void Build_bounds_violation_suggests_bounds_check_study_text()
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
        var primitives = PrimitiveEngine.Build(id, "lab", influence, root, obs);
        var hypo = PatchHypothesisEngine.Build(id, "lab", root, influence, primitives, null, obs);

        Assert.True(hypo.Ok);
        Assert.Equal(RootCauseCategory.BoundsViolation, hypo.Category);
        Assert.Contains("bounds", hypo.RemediationText, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("length", hypo.RemediationText, StringComparison.OrdinalIgnoreCase);
        Assert.True(hypo.VerifyAgainstPatchedLab);
        Assert.Contains("differential", hypo.VerifyAgainstPatchedLabHook, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("patched", hypo.VerifyAgainstPatchedLabHook, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("shellcode", hypo.RemediationText, StringComparison.OrdinalIgnoreCase);
        Assert.NotEmpty(hypo.EvidenceRefs);
    }

    [Fact]
    public void Build_lifetime_violation_suggests_free_use_audit_text()
    {
        var id = Guid.NewGuid();
        const string addressQuery = """
            000001a2`3b4c5000 :
               Free memory
            """;
        var obs = ScreamInvestigator.ParseBlocks(
            "EXCEPTION_CODE: (c0000005) Access violation\n",
            exr: "Attempt to read from address 000001a23b4c5000\n",
            regs: "rcx=000001a23b4c5000\nrip=00007ff612345678\n",
            address: addressQuery,
            heap: "use after free detected");

        var root = RootCauseEngine.Build(id, "lab", null, null, obs, null, null);
        var hypo = PatchHypothesisEngine.Build(id, "lab", root, null, null, null, obs);

        Assert.True(hypo.Ok);
        Assert.Equal(RootCauseCategory.LifetimeViolation, hypo.Category);
        Assert.Contains("free", hypo.RemediationText, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("use", hypo.RemediationText, StringComparison.OrdinalIgnoreCase);
        Assert.True(hypo.VerifyAgainstPatchedLab);
        Assert.Contains("experiment", hypo.VerifyAgainstPatchedLabHook, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void PersistForCrash_round_trips_json()
    {
        var dir = Path.Combine(Path.GetTempPath(), "randfuzz-patch-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var id = Guid.NewGuid();
            var obs = ScreamInvestigator.ParseBlocks(
                "EXCEPTION_CODE: (c0000005)\n",
                exr: "Attempt to write to address 41414141\n",
                regs: "rip=0000000041414141\n");
            var root = RootCauseEngine.Build(id, "lab", null, null, obs, null, null);
            var written = PatchHypothesisEngine.PersistForCrash(dir, id, "lab", root, debugger: obs);
            var loaded = PatchHypothesisEngine.TryReadForCrash(dir, id);

            Assert.True(File.Exists(PatchHypothesisEngine.PathFor(dir, id)));
            Assert.NotNull(loaded);
            Assert.Equal(written.RemediationText, loaded!.RemediationText);
            Assert.Equal(written.Confidence, loaded.Confidence);
            Assert.Equal(written.VerifyAgainstPatchedLab, loaded.VerifyAgainstPatchedLab);
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
        var hypo = PatchHypothesisEngine.Build(id, "lab", null);

        Assert.False(hypo.Ok);
        Assert.Contains("Insufficient evidence", hypo.RemediationText);
        Assert.False(hypo.VerifyAgainstPatchedLab);
    }

    [Fact]
    public void PatchAnalysisWorkflow_from_diff_emits_security_and_fuzz_hints()
    {
        var baseline = Doc(
            Fn("handle", "0x401000", 100, 10, 20, dangerous: ["memcpy"], inputReachable: true, priority: 70),
            Fn("old_only", "0x402000", 50, 5, 8, priority: 40));
        var current = Doc(
            Fn("handle", "0x401000", 180, 14, 35, dangerous: ["memcpy"], inputReachable: true, priority: 85),
            Fn("new_fn", "0x403000", 64, 6, 12, inputReachable: true, priority: 65));

        var merged = GhidraAnalysisDiff.MergeDiff(current, baseline, @"C:\baseline.json");
        var summary = PatchAnalysisWorkflow.BuildFromDiff(merged, @"C:\current.json", @"C:\baseline.json");

        Assert.True(summary.Ok);
        Assert.NotEmpty(summary.SecurityRelevantFunctionHints);
        Assert.NotEmpty(summary.FuzzTargetHints);
        Assert.Contains(summary.TopChanged, c => c.Name == "handle");
        Assert.Contains("Patch analysis", summary.Summary, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void PatchAnalysisWorkflow_persist_round_trips()
    {
        var path = Path.Combine(Path.GetTempPath(), "randfuzz-paw-" + Guid.NewGuid().ToString("N") + ".json");
        try
        {
            var baseline = Doc(Fn("a", "0x401000", 10, 2, 4, priority: 20));
            var current = Doc(Fn("a", "0x401000", 80, 10, 20, dangerous: ["strcpy"], priority: 80));
            var merged = GhidraAnalysisDiff.MergeDiff(current, baseline, "baseline.json");
            var summary = PatchAnalysisWorkflow.BuildFromDiff(merged);
            PatchAnalysisWorkflow.Write(path, summary);
            var loaded = PatchAnalysisWorkflow.TryRead(path);

            Assert.NotNull(loaded);
            Assert.Equal(summary.Summary, loaded!.Summary);
            Assert.Equal(summary.SecurityRelevantFunctionHints.Count, loaded.SecurityRelevantFunctionHints.Count);
        }
        finally
        {
            if (File.Exists(path))
                File.Delete(path);
        }
    }

    private static RandallAnalysisDocument Doc(params RandallAnalysisFunctionDto[] functions) =>
        new(
            "1",
            "demo.exe",
            null,
            "0x400000",
            "2026-01-01T00:00:00Z",
            "test",
            functions,
            [],
            [],
            [],
            []);

    private static RandallAnalysisFunctionDto Fn(
        string name,
        string address,
        int size,
        int bb,
        int complexity,
        IReadOnlyList<string>? dangerous = null,
        bool inputReachable = false,
        int priority = 0) =>
        new(
            name,
            address,
            size,
            bb,
            complexity,
            0,
            0,
            inputReachable,
            dangerous is { Count: > 0 },
            dangerous ?? [],
            priority);
}
