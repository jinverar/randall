using Randall.Contracts;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class BugGenealogyEngineTests
{
    [Fact]
    public void BuildFromMembers_groups_shared_root_cause_and_function()
    {
        var a = Guid.NewGuid();
        var b = Guid.NewGuid();
        var c = Guid.NewGuid();

        var members = new List<GenealogyMemberDto>
        {
            new(a, GenealogyFailureKind.Crash, "k1", "fam-a", "Parse", RootCauseCategory.BoundsViolation, "pattern@40", null),
            new(b, GenealogyFailureKind.Crash, "k1", "fam-a", "Parse", RootCauseCategory.BoundsViolation, "pattern@44", null),
            new(c, GenealogyFailureKind.SilentFinding, "k2", null, "Other", RootCauseCategory.LifetimeViolation, "uaf", "silent-scream"),
        };

        var report = BugGenealogyEngine.BuildFromMembers("lab", members);

        Assert.True(report.Ok);
        Assert.Equal(3, report.FailureCount);
        Assert.True(report.ProbableVulnCount >= 2);
        Assert.Contains("probable vuln", report.Summary, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(report.Lineages, l =>
            l.Category == RootCauseCategory.BoundsViolation &&
            l.FaultingFunction == "Parse" &&
            l.FailureCount == 2);
        Assert.Contains(report.Lineages, l => l.Members.Any(m => m.Kind == GenealogyFailureKind.SilentFinding));
    }

    [Fact]
    public void BuildFromMembers_empty_is_ok_with_zero_counts()
    {
        var report = BugGenealogyEngine.BuildFromMembers("lab", []);
        Assert.True(report.Ok);
        Assert.Equal(0, report.ProbableVulnCount);
        Assert.Equal(0, report.FailureCount);
        Assert.Empty(report.Lineages);
    }

    [Fact]
    public void Persist_round_trips_json()
    {
        var dir = Path.Combine(Path.GetTempPath(), "randfuzz-genealogy-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var members = new List<GenealogyMemberDto>
            {
                new(Guid.NewGuid(), GenealogyFailureKind.Crash, "c", null, "Foo", RootCauseCategory.SizeMismatch, null, null),
                new(Guid.NewGuid(), GenealogyFailureKind.Crash, "c", null, "Foo", RootCauseCategory.SizeMismatch, null, null),
            };
            var report = BugGenealogyEngine.BuildFromMembers("lab", members);
            BugGenealogyEngine.Write(dir, report);
            var loaded = BugGenealogyEngine.TryRead(BugGenealogyEngine.PathFor(dir));

            Assert.NotNull(loaded);
            Assert.Equal(report.ProbableVulnCount, loaded!.ProbableVulnCount);
            Assert.Equal(report.FailureCount, loaded.FailureCount);
            Assert.Equal(report.Lineages.Count, loaded.Lineages.Count);
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { /* ignore */ }
        }
    }
}
