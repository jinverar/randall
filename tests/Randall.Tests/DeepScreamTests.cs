using Randall.Contracts;
using Randall.Infrastructure;
using Randall.Infrastructure.Magician;
using Xunit;

namespace Randall.Tests;

public class DeepScreamTests
{
    [Fact]
    public void IsCandidate_RequiresHighScoreUniqueRepro()
    {
        Assert.True(DeepScreamBuilder.IsCandidate(72, 1, true));
        Assert.False(DeepScreamBuilder.IsCandidate(54, 1, true));
        Assert.False(DeepScreamBuilder.IsCandidate(72, 2, true));
        Assert.False(DeepScreamBuilder.IsCandidate(72, 1, false));
    }

    [Fact]
    public void Evaluate_EligibleListsReasonsAndLinks()
    {
        var id = Guid.NewGuid();
        var dir = Path.Combine(Path.GetTempPath(), "randall-deep-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var dto = DeepScreamBuilder.Evaluate(
                id, "lab", 68, 1, true, true, crashesDir: dir,
                semanticFingerprint: "exc=access_violation", familyId: "fam-1", isMarked: true);
            Assert.True(dto.IsCandidate);
            Assert.True(dto.IsMarked);
            Assert.Equal(HypothesisEngine.PathFor(dir, id), dto.HypothesisPath);
        }
        finally { try { Directory.Delete(dir, true); } catch { } }
    }

    [Fact]
    public void FamilyDedup_SuppressesSecondCrashUnlessMomentumJumps()
    {
        var dir = Path.Combine(Path.GetTempPath(), "randall-deep-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var first = Guid.NewGuid();
            var second = Guid.NewGuid();
            const string family = "fam-dedup";
            var evo1 = new ScreamEvolutionDto(true, first, "lab", family, "label", 1, null, null,
                42, "warming", ScreamProgressionStep.WriteViolation, null, 1, [first], 1, "warm", DateTimeOffset.UtcNow);
            DeepScreamBuilder.PersistForCrash(dir, first, "lab", 70, 1, true, true, familyId: family, evolution: evo1);
            var (_, suppressed, prior, _) = DeepScreamBuilder.ResolveFamilyMark(
                dir, second, 72, 1, true, family, evo1 with { CrashId = second, MomentumScore = 44 });
            Assert.True(suppressed);
            Assert.Equal(first, prior);
            var (marked, suppressed2, _, reason) = DeepScreamBuilder.ResolveFamilyMark(
                dir, second, 72, 1, true, family, evo1 with { CrashId = second, MomentumScore = 60 });
            Assert.True(marked);
            Assert.False(suppressed2);
            Assert.Contains("momentum jump", reason!, StringComparison.OrdinalIgnoreCase);
        }
        finally { try { Directory.Delete(dir, true); } catch { } }
    }

    [Fact]
    public void DebuggerTools_ProbeTtd_ReturnsSummary()
    {
        Assert.False(string.IsNullOrWhiteSpace(DebuggerTools.ProbeTtd().Summary));
    }

    [Fact]
    public void DeepScreamOnCrash_requires_marked_crash()
    {
        var dir = Path.Combine(Path.GetTempPath(), "randall-deep-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var root = CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
            var yaml = Path.Combine(root, "projects", "file-text.yaml");
            if (!File.Exists(yaml)) return;

            var project = ProjectLoader.Load(yaml);
            project.Fuzz.RewindScream = true;
            project.Fuzz.CrashesDir = dir;
            project.Magician ??= new MagicianConfig();
            project.Magician.Enabled = true;
            project.Magician.AllowRewindScream = true;
            project.Magician.PersistSpells = false;

            var id = Guid.NewGuid();
            var marked = DeepScreamBuilder.PersistForCrash(
                dir, id, project.Name, 72, 1, true, true, dumpPath: "fake.dmp");
            var cast = MagicianEngine.DeepScreamOnCrash(project, yaml, id, "fake.dmp", "fake.bin", marked, null);
            Assert.NotNull(cast);
            Assert.Contains(cast!.Spells, s => s.Spell == "rewindScream");
            Assert.True(File.Exists(DeepScreamBuilder.TtdHintPathFor(dir, id)));
            var playbook = File.ReadAllText(DeepScreamBuilder.TtdHintPathFor(dir, id));
            Assert.Contains("Exploit-focused backward queries", playbook, StringComparison.OrdinalIgnoreCase);
        }
        finally { try { Directory.Delete(dir, true); } catch { } }
    }

    [Fact]
    public void ProbeTtd_ReportsCanRecordAndReplay()
    {
        var probe = DebuggerTools.ProbeTtd();
        Assert.False(string.IsNullOrWhiteSpace(probe.Summary));
        if (probe.Present)
        {
            Assert.True(probe.CanRecord);
            if (probe.WinDbgPreviewPath is not null)
                Assert.True(probe.CanReplay);
        }
    }

    [Fact]
    public void WriteTtdOperatorHint_includes_backward_queries_and_query_script()
    {
        var dir = Path.Combine(Path.GetTempPath(), "randall-deep-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var id = Guid.NewGuid();
            var dump = Path.Combine(dir, $"{id:N}.dmp");
            File.WriteAllText(dump, "fake");
            var dto = DeepScreamBuilder.Evaluate(id, "lab", 70, 1, true, true, dump, dir, isMarked: true,
                ttdToolsPresent: true, ttdToolsSummary: "test tools");
            var path = DeepScreamBuilder.WriteTtdOperatorHint(dir, id, "lab", dto, dump, "input.bin");
            var text = File.ReadAllText(path);
            Assert.Contains("Exploit-focused backward queries", text, StringComparison.OrdinalIgnoreCase);
            Assert.True(File.Exists(DeepScreamBuilder.TtdQueryScriptPathFor(dir, id)));
            var script = File.ReadAllText(DeepScreamBuilder.TtdQueryScriptPathFor(dir, id));
            Assert.Contains("RANDFUZZ DEEP SCREAM TTD", script, StringComparison.OrdinalIgnoreCase);
        }
        finally { try { Directory.Delete(dir, true); } catch { } }
    }

    [Fact]
    public void DeepScreamOnCrash_skips_when_not_marked()
    {
        var dir = Path.Combine(Path.GetTempPath(), "randall-deep-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var root = CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
            var yaml = Path.Combine(root, "projects", "file-text.yaml");
            if (!File.Exists(yaml)) return;

            var project = ProjectLoader.Load(yaml);
            project.Fuzz.RewindScream = true;
            project.Fuzz.CrashesDir = dir;
            project.Magician ??= new MagicianConfig();
            project.Magician.Enabled = true;
            project.Magician.AllowRewindScream = true;

            var id = Guid.NewGuid();
            var candidate = DeepScreamBuilder.PersistForCrash(
                dir, id, project.Name, 72, 2, true, true, dumpPath: "fake.dmp");
            Assert.False(candidate.IsMarked);
            var cast = MagicianEngine.DeepScreamOnCrash(project, yaml, id, "fake.dmp", null, candidate, null);
            Assert.Null(cast);
        }
        finally { try { Directory.Delete(dir, true); } catch { } }
    }
}
