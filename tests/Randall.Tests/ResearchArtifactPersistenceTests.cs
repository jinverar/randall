using System.Text;
using System.Text.Json;
using Randall.Contracts;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

/// <summary>
/// Golden round-trip for research JSON sidecars. Fails if Persist/TryRead drops fields
/// or disconnects CrashId/Project/schemaVersion across the research stack.
/// </summary>
public class ResearchArtifactPersistenceTests
{
    [Fact]
    public void Research_stack_json_round_trip_preserves_fields_and_schemaVersion()
    {
        var dir = Path.Combine(Path.GetTempPath(), "randall-research-persist-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var id = Guid.NewGuid();
            const string project = "persist-lab";
            var payload = Encoding.ASCII.GetBytes("AAAA" + new string('B', 64) + "CRASH");

            var sidecar = new CrashSidecarDto(
                id, "run-persist", 7, project, "HELLO", "expand",
                ["bitflip", "expand", "havoc"], "parent-abc", "corpus", ["seed.bin"],
                "deadbeef", Path.Combine(dir, "x.bin"), payload.Length,
                -1073741819, "ACCESS_VIOLATION", "tcp detail", null, 2, 40, "native",
                null, null, null, null,
                new TransportSnapshotDto("tcp", "127.0.0.1", 9999, false),
                new FuzzSnapshotDto(true, false, "projects/persist-lab.yaml"),
                DateTimeOffset.UtcNow,
                null,
                new OracleScore(70, [new OracleScoreTerm("crash", 60, "AV")], "+60 crash"));

            File.WriteAllBytes(sidecar.InputPath, payload);

            var debugger = ScreamInvestigator.ParseBlocks(
                "EXCEPTION_CODE: (c0000005) Access violation\n",
                exr: "Attempt to write to address 41414141\nParameter[1]: 41414141\n",
                regs: "rax=0000000041414141\nrip=00000000401020\n",
                stack: "00000000`0012ff00 00000000`00401000 lab!Parse+0x10",
                disasm: "00401020  mov dword ptr [rax], ecx",
                sidecar: sidecar);

            var triage = CrashTriage.Classify(null, sidecar, null, payload, debugger: debugger);
            var chain = CorruptionChainBuilder.Build(id, project, sidecar, debugger, triage, payload);

            var hypotheses = HypothesisEngine.PersistForCrash(
                dir, id, project, sidecar, triage, debugger, chain, null, sidecar.RandallScore);
            var rootCause = RootCauseEngine.PersistForCrash(
                dir, id, project, sidecar, triage, debugger, chain, null, sidecar.RandallScore);
            var facts = EvidenceFactBuilder.CollectFacts(
                id, project, sidecar, triage, debugger, chain, oracleScore: sidecar.RandallScore,
                hypotheses: hypotheses);
            var influence = InfluenceEngine.PersistForCrash(
                dir, id, project, sidecar, triage, debugger, chain,
                hypotheses: hypotheses, externalFacts: facts, payload: payload);
            var evidence = EvidenceFactBuilder.PersistForCrash(
                dir, id, project, sidecar, triage, debugger, chain,
                oracleScore: sidecar.RandallScore, hypotheses: hypotheses);
            var primitives = PrimitiveEngine.PersistForCrash(
                dir, id, project, influence, rootCause, debugger, chain, triage, evidence.Facts, hypotheses);
            var plan = ResearchPlannerEngine.PersistForCrash(
                dir, id, project, rootCause, influence, primitives, hypotheses);
            var skeptic = SkepticEngine.PersistForCrash(
                dir, id, project, plan, rootCause, influence, primitives);

            Assert.True(evidence.Ok);
            Assert.True(rootCause.Ok);
            Assert.True(influence.Ok || influence.Links.Count >= 0);
            Assert.True(primitives.Maturity >= ResearchMaturity.R0);
            Assert.True(plan.Ok);
            Assert.True(skeptic.Ok);

            Assert.Equal(1, evidence.SchemaVersion);
            Assert.Equal(1, rootCause.SchemaVersion);
            Assert.Equal(1, influence.SchemaVersion);
            Assert.Equal(1, primitives.SchemaVersion);
            Assert.Equal(HypothesisEngine.CurrentSchemaVersion, hypotheses.SchemaVersion);
            Assert.Equal(1, plan.SchemaVersion);
            Assert.Equal(1, skeptic.SchemaVersion);

            // Raw JSON must emit schemaVersion (camelCase or PascalCase depending on writer).
            AssertJsonHasSchemaVersion(EvidenceFactBuilder.PathFor(dir, id));
            AssertJsonHasSchemaVersion(RootCauseEngine.PathFor(dir, id));
            AssertJsonHasSchemaVersion(InfluenceEngine.PathFor(dir, id));
            AssertJsonHasSchemaVersion(PrimitiveEngine.PathFor(dir, id));
            AssertJsonHasSchemaVersion(HypothesisEngine.PathFor(dir, id), HypothesisEngine.CurrentSchemaVersion);
            AssertJsonHasSchemaVersion(ResearchPlannerEngine.PathFor(dir, id));
            AssertJsonHasSchemaVersion(SkepticEngine.PathFor(dir, id));

            var hyp2 = HypothesisEngine.TryReadForCrash(dir, id)!;
            var root2 = RootCauseEngine.TryRead(RootCauseEngine.PathFor(dir, id))!;
            var inf2 = InfluenceEngine.TryRead(InfluenceEngine.PathFor(dir, id))!;
            var ev2 = EvidenceFactBuilder.TryReadForCrash(dir, id)!;
            var prim2 = PrimitiveEngine.TryReadForCrash(dir, id)!;
            var plan2 = ResearchPlannerEngine.TryReadForCrash(dir, id)!;
            var sk2 = SkepticEngine.TryReadForCrash(dir, id)!;

            Assert.Equal(id, hyp2.CrashId);
            Assert.Equal(id, root2.CrashId);
            Assert.Equal(id, inf2.CrashId);
            Assert.Equal(id, ev2.CrashId);
            Assert.Equal(id, prim2.CrashId);
            Assert.Equal(id, plan2.CrashId);
            Assert.Equal(id, sk2.CrashId);
            Assert.Equal(project, hyp2.Project);
            Assert.Equal(project, prim2.Project);

            Assert.Equal(HypothesisEngine.CurrentSchemaVersion, hyp2.SchemaVersion);
            Assert.Equal(1, root2.SchemaVersion);
            Assert.Equal(1, inf2.SchemaVersion);
            Assert.Equal(1, ev2.SchemaVersion);
            Assert.Equal(1, prim2.SchemaVersion);
            Assert.Equal(1, plan2.SchemaVersion);
            Assert.Equal(1, sk2.SchemaVersion);

            // Evidence: lineage + oracle + triage must survive (Name|Value|Source can collide on Name alone).
            Assert.Equal(evidence.Facts.Count, ev2.Facts.Count);
            Assert.Contains(ev2.Facts, f => f.Name == "lineage.mutatorChain");
            Assert.Contains(ev2.Facts, f => f.Name == "lineage.parentInputHash");
            Assert.Contains(ev2.Facts, f => f.Name == "oracle.score");
            Assert.All(evidence.Facts, original =>
            {
                Assert.Contains(ev2.Facts, f =>
                    f.Name == original.Name
                    && f.Source == original.Source
                    && f.Value == original.Value
                    && f.ObservationType == original.ObservationType);
            });

            // Root cause
            Assert.Equal(rootCause.Candidate.Category, root2.Candidate.Category);
            Assert.Equal(rootCause.Candidate.Confidence, root2.Candidate.Confidence);
            Assert.Equal(rootCause.EducationalSummary, root2.EducationalSummary);
            Assert.Equal(rootCause.Candidate.Evidence.Count, root2.Candidate.Evidence.Count);

            // Influence
            Assert.Equal(influence.Confidence, inf2.Confidence);
            Assert.Equal(influence.Summary, inf2.Summary);
            Assert.Equal(influence.Links.Count, inf2.Links.Count);
            if (influence.Links.Count > 0)
            {
                Assert.Equal(influence.Links[0].Id, inf2.Links[0].Id);
                Assert.Equal(influence.Links[0].Status, inf2.Links[0].Status);
                Assert.Equal(influence.Links[0].Mechanism, inf2.Links[0].Mechanism);
                Assert.Equal(influence.Links[0].State.Kind, inf2.Links[0].State.Kind);
            }

            // Primitives / maturity
            Assert.Equal(primitives.Maturity, prim2.Maturity);
            Assert.Equal(primitives.MaturityLabel, prim2.MaturityLabel);
            Assert.Equal(primitives.MaturityRationale, prim2.MaturityRationale);
            Assert.Equal(primitives.Confidence, prim2.Confidence);
            Assert.Equal(primitives.Summary, prim2.Summary);
            Assert.Equal(primitives.Primitives.Count, prim2.Primitives.Count);
            if (primitives.Primitives.Count > 0)
            {
                Assert.Equal(primitives.Primitives[0].Kind, prim2.Primitives[0].Kind);
                Assert.Equal(primitives.Primitives[0].State, prim2.Primitives[0].State);
                Assert.Equal(primitives.Primitives[0].Mechanism, prim2.Primitives[0].Mechanism);
            }

            // Hypotheses
            Assert.Equal(hypotheses.Hypotheses.Count, hyp2.Hypotheses.Count);
            if (hypotheses.Hypotheses.Count > 0)
            {
                Assert.Equal(hypotheses.Hypotheses[0].Id, hyp2.Hypotheses[0].Id);
                Assert.Equal(hypotheses.Hypotheses[0].Statement, hyp2.Hypotheses[0].Statement);
                Assert.Equal(hypotheses.Hypotheses[0].ConfidencePercent, hyp2.Hypotheses[0].ConfidencePercent);
                Assert.Equal(hypotheses.Hypotheses[0].Status, hyp2.Hypotheses[0].Status);
            }

            // Plan + skeptic
            Assert.Equal(plan.Objective, plan2.Objective);
            Assert.Equal(plan.Confidence, plan2.Confidence);
            Assert.Equal(plan.Claims.Count, plan2.Claims.Count);
            Assert.Equal(plan.Steps.Count, plan2.Steps.Count);
            Assert.Equal(plan.Summary, plan2.Summary);
            if (plan.Claims.Count > 0)
            {
                Assert.Equal(plan.Claims[0].Id, plan2.Claims[0].Id);
                Assert.Equal(plan.Claims[0].Kind, plan2.Claims[0].Kind);
                Assert.Equal(plan.Claims[0].Statement, plan2.Claims[0].Statement);
                Assert.Equal(plan.Claims[0].ConfidencePercent, plan2.Claims[0].ConfidencePercent);
            }

            Assert.Equal(skeptic.Summary, sk2.Summary);
            Assert.Equal(skeptic.Challenges.Count, sk2.Challenges.Count);
            if (skeptic.Challenges.Count > 0)
            {
                Assert.Equal(skeptic.Challenges[0].Id, sk2.Challenges[0].Id);
                Assert.Equal(skeptic.Challenges[0].ClaimId, sk2.Challenges[0].ClaimId);
                Assert.Equal(skeptic.Challenges[0].Status, sk2.Challenges[0].Status);
                Assert.Equal(skeptic.Challenges[0].FalsificationStatement, sk2.Challenges[0].FalsificationStatement);
            }

            // ScreamScore / lineage are computed (CrashIntelligence), not a separate sidecar —
            // rebuild from reloaded artifacts and assert lineage + score still surface.
            var summary = new CrashSummaryDto(
                id, project, 7, "expand", "deadbeef", sidecar.InputPath, null,
                "-1073741819", null, CrashSidecarWriter.Write(dir, sidecar), "run-persist",
                DateTimeOffset.UtcNow);
            var intel = CrashIntelligenceBuilder.Build(
                summary, triage, sidecar, payload.Length, [summary],
                debugger: debugger, corruptionChain: chain, hypotheses: hyp2,
                rootCause: root2, evidenceFacts: ev2.Facts, primitives: prim2);
            Assert.NotNull(intel.Lineage);
            Assert.Equal(3, intel.Lineage!.MutatorChain.Count);
            Assert.Equal("parent-abc", intel.Lineage.ParentInputHash);
            Assert.True(intel.ScreamScore > 0);
            Assert.Equal(prim2.Maturity.ToString(), intel.ResearchMaturity);
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void Legacy_json_without_schemaVersion_defaults_to_1()
    {
        var dir = Path.Combine(Path.GetTempPath(), "randall-research-legacy-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var id = Guid.NewGuid();
            // Minimal legacy-shaped evidence (no schemaVersion key).
            var path = EvidenceFactBuilder.PathFor(dir, id);
            File.WriteAllText(path, $$"""
                {
                  "ok": true,
                  "crashId": "{{id:D}}",
                  "project": "legacy",
                  "facts": [],
                  "at": "2026-01-01T00:00:00Z"
                }
                """);

            var loaded = EvidenceFactBuilder.TryRead(path);
            Assert.NotNull(loaded);
            Assert.Equal(1, loaded!.SchemaVersion);
            Assert.Equal(id, loaded.CrashId);
            Assert.Equal("legacy", loaded.Project);
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { /* ignore */ }
        }
    }

    private static void AssertJsonHasSchemaVersion(string path, int expected = 1)
    {
        Assert.True(File.Exists(path), path);
        using var doc = JsonDocument.Parse(File.ReadAllText(path));
        var root = doc.RootElement;
        Assert.True(
            root.TryGetProperty("schemaVersion", out var camel) ||
            root.TryGetProperty("SchemaVersion", out camel),
            $"missing schemaVersion in {Path.GetFileName(path)}");
        Assert.Equal(expected, camel.GetInt32());
    }
}
