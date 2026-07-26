using Randall.Contracts;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class ResearchPackageReportBuilderTests
{
    [Fact]
    public void BuildForCrash_includes_advisor_packages_and_ethics_note()
    {
        var id = Guid.NewGuid();
        var advisor = new ExploitabilityAdvisorDto(
            true,
            id,
            "lab",
            ExploitabilityAdvisorLabel.Study,
            "MEDIUM",
            [TeachingPackages.BoundsStudy, TeachingPackages.NoWeaponization],
            ["ascii write suggests bounds study"],
            ["debugger:write"],
            DateTimeOffset.UtcNow,
            "Study bounds");

        var report = ResearchPackageReportBuilder.BuildForCrash(id, "lab", advisor);

        Assert.True(report.Ok);
        Assert.StartsWith("RF-", report.ReportId);
        Assert.Contains(report.Packages, p => p.Title.Contains("bounds", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(report.Packages, p => p.Id == "pkg-ethics");
        Assert.DoesNotContain("shellcode", report.Summary, StringComparison.OrdinalIgnoreCase);
        Assert.All(report.Packages, p =>
        {
            // Ethics package mentions forbidden words as a teaching reminder — skip it.
            if (p.Id == "pkg-ethics") return;
            Assert.DoesNotContain("ROP", p.Description, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("shellcode", p.Description, StringComparison.OrdinalIgnoreCase);
        });
    }

    [Fact]
    public void PersistForCrash_round_trips()
    {
        var dir = Path.Combine(Path.GetTempPath(), "randfuzz-rpkg-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var id = Guid.NewGuid();
            var written = ResearchPackageReportBuilder.PersistForCrash(dir, id, "lab");
            var loaded = ResearchPackageReportBuilder.TryRead(
                ResearchPackageReportBuilder.PathForCrash(dir, id));
            Assert.NotNull(loaded);
            Assert.Equal(written.Summary, loaded!.Summary);
            Assert.Equal(written.Packages.Count, loaded.Packages.Count);
            Assert.Equal(written.ReportId, loaded.ReportId);
            Assert.Equal(1, loaded.SchemaVersion);
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void BuildForCrash_from_fixture_fills_rf_sections()
    {
        var id = Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
        var payload = new byte[] { 0x41, 0x41, 0x41, 0x41, 0x10, 0x00, 0x00, 0x00 };

        var obs = ScreamInvestigator.ParseBlocks(
            "EXCEPTION_CODE: (c0000005) Access violation\n",
            exr: "Attempt to write to address 41414141\nParameter[1]: 41414141\n",
            regs: "rax=0000000041414141\nrip=00000000401020\n");

        var root = RootCauseEngine.Build(id, "harness-demo", null, null, obs, null, null);
        var influence = InfluenceEngine.Build(id, "harness-demo", null, null, obs, null, null, null, null, payload);
        var primitives = PrimitiveEngine.Build(id, "harness-demo", influence, root, obs);
        var plan = ResearchPlannerEngine.Build(id, "harness-demo", root, influence, primitives);
        var skeptic = SkepticEngine.ApplyObservation(
            SkepticEngine.Build(id, "harness-demo", plan, root, influence, primitives),
            SkepticEngine.Build(id, "harness-demo", plan, root, influence, primitives).Challenges[0].Id,
            SkepticChallengeStatus.Survived,
            "fault class unchanged after neutralize");

        var hyp = new HypothesisSetDto(
            true, id, "harness-demo",
            [new HypothesisDto(
                "h-bounds",
                id,
                "Length at +4 drives the write fault",
                72,
                new HypothesisExperimentDto(HypothesisExperimentKind.SweepOffset, "sweep len", OffsetBytes: 4),
                "flip clears fault",
                HypothesisStatus.Partial,
                new HypothesisResultDto(
                    HypothesisStatus.Partial, 80, "counterfactual safe-adjacent", null,
                    DateTimeOffset.UtcNow, 72))],
            DateTimeOffset.UtcNow);

        var cf = CounterfactualEngine.Evaluate(
            id, "harness-demo", payload, p => p.Length > 4 && p[4] == 0x10, suspectedOffset: 4, maxProbes: 3);

        var patch = PatchHypothesisEngine.Build(id, "harness-demo", root, influence, primitives);
        var advisor = ExploitabilityAdvisor.Build(id, "harness-demo", root, influence, primitives, obs, skeptic: skeptic);

        var sidecar = new CrashSidecarDto(
            id, "run-fixture", 42, "harness-demo", "main", "havoc",
            ["seed", "havoc"], "parenthash", "seed", [], "deadbeef",
            "data/crashes/harness-demo/deadbeef.bin", payload.Length,
            1, "ACCESS_VIOLATION", "harness crashed", null, 3, 100,
            "none", null, null, null, null,
            new TransportSnapshotDto("file", "", 0, false),
            new FuzzSnapshotDto(true, false, "projects/harness-demo.yaml"),
            DateTimeOffset.UtcNow);

        var report = ResearchPackageReportBuilder.BuildForCrash(
            id, "harness-demo", advisor, plan, patch,
            sidecar: sidecar,
            debugger: obs,
            rootCause: root,
            influence: influence,
            primitives: primitives,
            hypotheses: hyp,
            skeptic: skeptic,
            counterfactual: cf,
            payload: payload,
            inputHash: "deadbeef");

        Assert.Equal("RF-AAAAAAAA", report.ReportId);
        Assert.False(string.IsNullOrWhiteSpace(report.Target));
        Assert.Contains("havoc", report.Discovery!, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Mutator chain", report.MutationAncestry!, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("deadbeef", report.MinimalRepro!, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Write", report.DebuggerEvidence!, StringComparison.OrdinalIgnoreCase);
        Assert.False(string.IsNullOrWhiteSpace(report.RootCause));
        Assert.False(string.IsNullOrWhiteSpace(report.Influence));
        Assert.False(string.IsNullOrWhiteSpace(report.Primitive));
        Assert.False(string.IsNullOrWhiteSpace(report.Mitigations));
        Assert.NotEmpty(report.Experiments);
        Assert.Contains(report.Confirmed, c => c.Contains("Skeptic", StringComparison.OrdinalIgnoreCase));
        Assert.False(string.IsNullOrWhiteSpace(report.Maturity));
        Assert.NotEmpty(report.OpenQuestions);
        Assert.Contains("Conceptual", report.SuggestedRemediation!, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("shellcode", report.SuggestedRemediation!, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("RF-AAAAAAAA", report.Summary);

        var md = ResearchPackageReportBuilder.ToMarkdown(report);
        Assert.Contains("# RF-AAAAAAAA", md);
        Assert.Contains("## Root cause", md);
        Assert.Contains("no shellcode", md, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void FormatReportId_uses_crash_guid_prefix()
    {
        var id = Guid.Parse("01234567-89ab-cdef-0123-456789abcdef");
        Assert.Equal("RF-01234567", ResearchPackageReportBuilder.FormatReportId(id));
    }
}
