using System.Diagnostics;
using System.Text;
using Randall.Contracts;
using Randall.Infrastructure;
using Randall.Infrastructure.Mutators;
using Xunit;

namespace Randall.Tests;

/// <summary>
/// Stabilization: managed harness-demo known-bad → crash → research stack persist → reload.
/// Does not require native dumps (Win+Linux CI). Debugger observation is the same ParseBlocks
/// fixture used by unit tests — stands in for Scream Investigator when no minidump exists.
/// </summary>
public class ResearchPipelineEndToEndTests
{
    // CrashyParser / ToyParser bug body (projects/harness-demo.yaml).
    private static readonly byte[] KnownBad = Encoding.ASCII.GetBytes("A\0CRASH");

    [Fact]
    public async Task Harness_known_bad_input_runs_research_pipeline_and_reload_matches()
    {
        var root = CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        EnsureHarnessDemoBuilt(root);

        var yamlPath = Path.Combine(root, "projects", "harness-demo.yaml");
        Assert.True(File.Exists(yamlPath), $"missing {yamlPath}");

        var project = ProjectLoader.Load(yamlPath);
        await using var session = InProcessSession.Start(project, yamlPath);

        var run = await session.RunAsync(KnownBad, CancellationToken.None);
        Assert.True(run.Crashed, "known-bad A\\0CRASH must crash harness-demo");

        var dir = Path.Combine(Path.GetTempPath(), "randall-research-e2e-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var store = new CrashStore(dir);
            var hash = InputHash.StackHash(KnownBad);
            var saved = store.Save(
                project.Name,
                iteration: 1,
                mutator: "dictionary",
                input: KnownBad,
                exitCode: run.ExitCode,
                triageTag: "harness",
                runId: "e2e-research",
                buildSidecar: id => new CrashSidecarDto(
                    id,
                    "e2e-research",
                    1,
                    project.Name,
                    "fuzz",
                    "dictionary",
                    ["bitflip", "dictionary"],
                    "parent-seed-hash",
                    "seed",
                    ["seeds/harness_ok.bin"],
                    hash,
                    Path.Combine(dir, $"{project.Name}_1_{hash}.bin"),
                    KnownBad.Length,
                    run.ExitCode,
                    "InvalidOperationException",
                    run.Detail ?? "harness-demo in-process",
                    "harness",
                    0,
                    0,
                    "none",
                    null,
                    null,
                    null,
                    null,
                    new TransportSnapshotDto("harness", "", 0, false),
                    new FuzzSnapshotDto(false, false, yamlPath),
                    DateTimeOffset.UtcNow));

            Assert.True(File.Exists(saved.InputPath));
            var sidecar = CrashSidecarWriter.TryRead(saved.SidecarPath);
            Assert.NotNull(sidecar);

            // Managed harness has no minidump; fixture mirrors production debugger sensor.
            var debugger = ScreamInvestigator.ParseBlocks(
                "EXCEPTION_CODE: (c0000005) Access violation\n",
                exr: "Attempt to write to address 41414141\nParameter[1]: 41414141\n",
                regs: "rax=0000000041414141\nrip=00000000401020\n",
                stack: "00000000`0012ff00 00000000`00401000 harness!Parse+0x10",
                disasm: "00401020  mov dword ptr [rax], ecx",
                sidecar: sidecar);

            var summary = new CrashSummaryDto(
                saved.Id,
                project.Name,
                1,
                "dictionary",
                hash,
                saved.InputPath,
                null,
                run.ExitCode?.ToString(),
                "harness",
                saved.SidecarPath,
                "e2e-research",
                DateTimeOffset.UtcNow);

            var triage = CrashTriage.Classify(null, sidecar, summary, KnownBad, debugger: debugger);
            Assert.NotNull(triage);

            // Production order from FuzzEngine.TryPersistHypotheses / TryPersistResearchStack.
            var hypotheses = HypothesisEngine.PersistForCrash(
                dir, saved.Id, project.Name, sidecar, triage, debugger, null, null);
            var rootCause = RootCauseEngine.PersistForCrash(
                dir, saved.Id, project.Name, sidecar, triage, debugger, null, null);
            var factsForInfluence = EvidenceFactBuilder.CollectFacts(
                saved.Id, project.Name, sidecar, triage, debugger, hypotheses: hypotheses);
            var influence = InfluenceEngine.PersistForCrash(
                dir, saved.Id, project.Name, sidecar, triage, debugger, null,
                hypotheses: hypotheses, externalFacts: factsForInfluence, payload: KnownBad);
            var evidence = EvidenceFactBuilder.PersistForCrash(
                dir, saved.Id, project.Name, sidecar, triage, debugger, hypotheses: hypotheses);
            var primitives = PrimitiveEngine.PersistForCrash(
                dir, saved.Id, project.Name, influence, rootCause, debugger, null, triage,
                evidence.Facts, hypotheses);
            var plan = ResearchPlannerEngine.PersistForCrash(
                dir, saved.Id, project.Name, rootCause, influence, primitives, hypotheses);
            var skeptic = SkepticEngine.PersistForCrash(
                dir, saved.Id, project.Name, plan, rootCause, influence, primitives);

            Assert.True(File.Exists(HypothesisEngine.PathFor(dir, saved.Id)));
            Assert.True(File.Exists(RootCauseEngine.PathFor(dir, saved.Id)));
            Assert.True(File.Exists(InfluenceEngine.PathFor(dir, saved.Id)));
            Assert.True(File.Exists(EvidenceFactBuilder.PathFor(dir, saved.Id)));
            Assert.True(File.Exists(PrimitiveEngine.PathFor(dir, saved.Id)));
            Assert.True(File.Exists(ResearchPlannerEngine.PathFor(dir, saved.Id)));
            Assert.True(File.Exists(SkepticEngine.PathFor(dir, saved.Id)));

            Assert.True(evidence.Ok);
            Assert.Contains(evidence.Facts, f => f.Name == "lineage.mutatorChain");
            Assert.Contains(evidence.Facts, f => f.Name == "lineage.parentInputHash");
            Assert.True(rootCause.Ok);
            Assert.True(primitives.Maturity >= ResearchMaturity.R0);
            Assert.Equal(1, primitives.SchemaVersion);
            Assert.True(plan.Ok);
            Assert.NotEmpty(plan.Claims);
            Assert.True(skeptic.Ok);
            Assert.NotEmpty(skeptic.Challenges);

            var intel = CrashIntelligenceBuilder.Build(
                summary, triage, sidecar, KnownBad.Length, [summary],
                debugger: debugger, hypotheses: hypotheses, rootCause: rootCause,
                evidenceFacts: evidence.Facts, primitives: primitives);
            Assert.NotNull(intel.Lineage);
            Assert.True(intel.ScreamScore >= 0);
            Assert.Equal(primitives.Maturity.ToString(), intel.ResearchMaturity);

            // Reload — same case identity and non-dropped fields.
            var hyp2 = HypothesisEngine.TryReadForCrash(dir, saved.Id);
            var root2 = RootCauseEngine.TryRead(RootCauseEngine.PathFor(dir, saved.Id));
            var inf2 = InfluenceEngine.TryRead(InfluenceEngine.PathFor(dir, saved.Id));
            var ev2 = EvidenceFactBuilder.TryReadForCrash(dir, saved.Id);
            var prim2 = PrimitiveEngine.TryReadForCrash(dir, saved.Id);
            var plan2 = ResearchPlannerEngine.TryReadForCrash(dir, saved.Id);
            var sk2 = SkepticEngine.TryReadForCrash(dir, saved.Id);

            Assert.NotNull(hyp2);
            Assert.NotNull(root2);
            Assert.NotNull(inf2);
            Assert.NotNull(ev2);
            Assert.NotNull(prim2);
            Assert.NotNull(plan2);
            Assert.NotNull(sk2);

            Assert.Equal(saved.Id, hyp2!.CrashId);
            Assert.Equal(saved.Id, root2!.CrashId);
            Assert.Equal(saved.Id, inf2!.CrashId);
            Assert.Equal(saved.Id, ev2!.CrashId);
            Assert.Equal(saved.Id, prim2!.CrashId);
            Assert.Equal(saved.Id, plan2!.CrashId);
            Assert.Equal(saved.Id, sk2!.CrashId);

            Assert.Equal(project.Name, hyp2.Project);
            Assert.Equal(project.Name, root2.Project);
            Assert.Equal(project.Name, prim2.Project);

            Assert.Equal(1, hyp2.SchemaVersion);
            Assert.Equal(1, root2.SchemaVersion);
            Assert.Equal(1, inf2.SchemaVersion);
            Assert.Equal(1, ev2.SchemaVersion);
            Assert.Equal(1, prim2.SchemaVersion);
            Assert.Equal(1, plan2.SchemaVersion);
            Assert.Equal(1, sk2.SchemaVersion);

            Assert.Equal(rootCause.Candidate.Category, root2.Candidate.Category);
            Assert.Equal(rootCause.EducationalSummary, root2.EducationalSummary);
            Assert.Equal(influence.Links.Count, inf2.Links.Count);
            Assert.Equal(evidence.Facts.Count, ev2.Facts.Count);
            Assert.Equal(primitives.Maturity, prim2.Maturity);
            Assert.Equal(primitives.MaturityLabel, prim2.MaturityLabel);
            Assert.Equal(primitives.Summary, prim2.Summary);
            Assert.Equal(plan.Objective, plan2.Objective);
            Assert.Equal(plan.Claims.Count, plan2.Claims.Count);
            Assert.Equal(skeptic.Challenges.Count, sk2.Challenges.Count);
            Assert.Equal(hypotheses.Hypotheses.Count, hyp2.Hypotheses.Count);
            Assert.Contains(ev2.Facts, f => f.Name == "lineage.mutatorChain");
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { /* ignore */ }
        }
    }

    private static void EnsureHarnessDemoBuilt(string root)
    {
        var dll = Path.Combine(
            root, "targets", "Randall.HarnessDemo", "bin", "Release", "net8.0", "Randall.HarnessDemo.dll");
        if (File.Exists(dll))
            return;

        var csproj = Path.Combine(root, "targets", "Randall.HarnessDemo", "Randall.HarnessDemo.csproj");
        Assert.True(File.Exists(csproj), $"missing harness project {csproj}");
        var psi = new ProcessStartInfo("dotnet", $"build \"{csproj}\" -c Release --nologo")
        {
            WorkingDirectory = root,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        using var p = Process.Start(psi)!;
        Assert.True(p.WaitForExit(120_000), "harness-demo build timed out");
        Assert.Equal(0, p.ExitCode);
        Assert.True(File.Exists(dll), "harness-demo Release build did not produce DLL");
    }
}
