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
            var dump = Path.Combine(dir, "crash.dmp");
            File.WriteAllText(dump, "fake");

            var dto = DeepScreamBuilder.Evaluate(
                id, "lab", screamScore: 68, seenCount: 1, reproducible: true, minimized: true,
                dumpPath: dump, crashesDir: dir);

            Assert.True(dto.IsCandidate);
            Assert.Contains(dto.EligibilityReasons, r => r.Contains("screamScore"));
            Assert.Contains(dto.EligibilityReasons, r => r.Contains("unique"));
            Assert.Contains(dto.EligibilityReasons, r => r.Contains("reproducible"));
            Assert.Contains(dto.EligibilityReasons, r => r.Contains("minimized"));
            Assert.Empty(dto.MissingReasons);
            Assert.Equal(dump, dto.DumpPath);
            Assert.Equal(ScreamEvolutionBuilder.PathFor(dir, id), dto.EvolutionPath);
            Assert.Equal(CorruptionChainBuilder.PathFor(dir, id), dto.CorruptionChainPath);
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void Evaluate_NotEligibleRecordsMissingReasons()
    {
        var dto = DeepScreamBuilder.Evaluate(
            Guid.NewGuid(), "lab", screamScore: 40, seenCount: 4, reproducible: false, minimized: false);

        Assert.False(dto.IsCandidate);
        Assert.NotEmpty(dto.MissingReasons);
    }

    [Fact]
    public void PersistRoundTrip_WritesDeepScreamJson()
    {
        var id = Guid.NewGuid();
        var dir = Path.Combine(Path.GetTempPath(), "randall-deep-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var written = DeepScreamBuilder.PersistForCrash(
                dir, id, "lab", screamScore: 60, seenCount: 1, reproducible: true, minimized: false);
            var path = DeepScreamBuilder.PathFor(dir, id);
            Assert.True(File.Exists(path));
            var read = DeepScreamBuilder.TryRead(path);
            Assert.NotNull(read);
            Assert.True(read!.IsCandidate);
            Assert.Equal(written.ScreamScore, read.ScreamScore);
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void CrashIntelligenceBuilder_FlagsDeepScreamCandidate()
    {
        var id = Guid.NewGuid();
        var summary = new CrashSummaryDto(
            id, "demo", 42, "cmd/havoc", "abc123", "x.bin",
            null, "-1073741819", null, null, "run-1", DateTimeOffset.UtcNow,
            "access_violation", "high", "0xDEAD", "AV", "demo|av|0xdead", true);

        var triage = new CrashTriageDto(
            "access_violation", "high", "test", true, false, "demo|av|0xdead",
            "AV", "0xDEAD", null, "0x401000", "0x7fff0010", 128, "depth");

        var sidecar = new CrashSidecarDto(
            id, "run-1", 42, "demo", "cmd", "havoc", ["cmd", "havoc", "expand"],
            "parent-hash", "corpus", [], "abc123", "x.bin", 512, -1073741819,
            "AV", "tcp", null, 3, 120, "drcov", null, null, null, null,
            new TransportSnapshotDto("tcp", "127.0.0.1", 9999, false),
            new FuzzSnapshotDto(true, false, "projects/demo.yaml"),
            DateTimeOffset.UtcNow,
            null,
            new OracleScore(85, [new OracleScoreTerm("crash", 80, "AV")], "+80 crash"));

        var intel = CrashIntelligenceBuilder.Build(summary, triage, sidecar, 512, [summary]);

        Assert.True(intel.DeepScreamCandidate);
        Assert.NotNull(intel.DeepScreamSummary);
        Assert.Contains("Deep Scream", intel.DeepScreamSummary!);
    }

    [Fact]
    public void RewindScreamOnCrash_requires_deep_scream_candidate()
    {
        var root = CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var yaml = Path.Combine(root, "projects", "file-text.yaml");
        if (!File.Exists(yaml))
            return;

        var project = ProjectLoader.Load(yaml);
        project.Fuzz.RewindScream = true;
        project.Magician ??= new MagicianConfig();
        project.Magician.Enabled = true;
        project.Magician.AllowRewindScream = true;
        project.Magician.PersistSpells = false;

        var id = Guid.NewGuid();
        var notEligible = DeepScreamBuilder.Evaluate(
            id, project.Name, screamScore: 30, seenCount: 1, reproducible: true, minimized: false);
        Assert.Null(MagicianEngine.RewindScreamOnCrash(
            project, yaml, id, "fake.dmp", notEligible, progress: null));

        var crashesDir = ProjectLoader.ResolvePath(yaml, project.Fuzz.CrashesDir);
        var eligible = DeepScreamBuilder.PersistForCrash(
            crashesDir, id, project.Name, screamScore: 72, seenCount: 1,
            reproducible: true, minimized: true, dumpPath: "fake.dmp");

        var cast = MagicianEngine.RewindScreamOnCrash(
            project, yaml, id, "fake.dmp", eligible, progress: null);

        Assert.NotNull(cast);
        Assert.Contains(cast!.Spells, s => s.Spell == "rewindScream");
        var ttdPath = DeepScreamBuilder.TtdHintPathFor(crashesDir, id);
        Assert.True(File.Exists(ttdPath));
        var updated = DeepScreamBuilder.TryRead(DeepScreamBuilder.PathFor(crashesDir, id));
        Assert.NotNull(updated?.TtdHintPath);
    }
}
