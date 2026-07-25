using Randall.Contracts;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class ScareDoorProgressTests
{
    [Fact]
    public void RecordPinnedIteration_IncrementsAttemptsAndPersists()
    {
        var root = NewTempRoot();
        try
        {
            const string project = "scare-pressure";
            WriteFrontier(root, project, "0x401020", 77);
            var focus = new BrainFocusDto(project, DateTimeOffset.UtcNow, "frontier", "parse → 0x401020", "0x401020");
            ScareDoorProgressStore.RecordPinnedIteration(project, focus, FrontierEngine.TryLoad(project, root), 1, "havoc", "seedabc123", 0, false, 12, root);
            ScareDoorProgressStore.RecordPinnedIteration(project, focus, FrontierEngine.TryLoad(project, root), 2, "splice", "seeddef456", 3, true, 15, root);
            var door = ScareDoorProgressStore.TryLoad(project, root)!.Doors.Values.First();
            Assert.Equal(2, door.Attempts);
            Assert.Equal("splice", door.BestMutation);
            Assert.True(door.ProgressFraction > 0);
        }
        finally { TryDelete(root); }
    }

    [Fact]
    public void EnrichReport_MergesProgressIntoFrontierBranches()
    {
        var root = NewTempRoot();
        try
        {
            const string project = "scare-enrich";
            WriteFrontier(root, project, "0x401030", 65);
            var focus = new BrainFocusDto(project, DateTimeOffset.UtcNow, "frontier", "Unopened door → 0x401030", "0x401030");
            ScareDoorProgressStore.RecordPinnedIteration(project, focus, FrontierEngine.TryLoad(project, root), 5, "bitflip", "abc", 2, true, 20, root);
            var branch = FrontierEngine.TryLoad(project, root)!.Frontiers.First();
            Assert.Equal(1, branch.Attempts);
            Assert.True(branch.ProgressFraction > 0);
        }
        finally { TryDelete(root); }
    }

    [Fact]
    public void StalkIntelligenceBuilder_ExposesPressureFieldsOnFrontierTargets()
    {
        var root = NewTempRoot();
        try
        {
            const string project = "scare-intel";
            WriteFrontier(root, project, "0x401040", 80);
            var focus = new BrainFocusDto(project, DateTimeOffset.UtcNow, "frontier", "parse → 0x401040", "0x401040");
            ScareDoorProgressStore.RecordPinnedIteration(project, focus, FrontierEngine.TryLoad(project, root), 1, "havoc", "seed1", 1, true, 8, root);
            var dto = StalkIntelligenceBuilder.Build(project, root);
            var t = dto.Targets.First(x => x.Kind == "frontier");
            Assert.Equal(1, t.Attempts);
            Assert.Equal("havoc", t.BestMutation);
            Assert.True(t.ProgressFraction > 0);
        }
        finally { TryDelete(root); }
    }

    private static void WriteFrontier(string root, string project, string toAddress, int score)
    {
        Directory.CreateDirectory(Path.Combine(root, "data", "stalk", project));
        FrontierEngine.Save(new FrontierReportDto(project, "2026-01-01T00:00:00Z", "cfg", "test", 2, 1, null,
            [new FrontierBranchDto($"parse:0x401010->{toAddress}", "cfg-branch", score, 3, 0.6, 2, 0.7, "parse", "0x401010", toAddress, null, "Uncovered BB", 2, 0)], "hint"), root);
    }

    private static string NewTempRoot() { var r = Path.Combine(Path.GetTempPath(), "randall-scare-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(r); return r; }
    private static void TryDelete(string root) { try { Directory.Delete(root, true); } catch { } }
}
