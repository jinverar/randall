using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class StalkIntelligenceBuilderTests
{
    [Fact]
    public void Build_MutatorCreditOnly_DoesNotSetHasData()
    {
        var repo = Path.Combine(Path.GetTempPath(), "randall-stalk-intel-" + Guid.NewGuid().ToString("N"));
        var project = "intel-mutator-only";
        var runsDir = Path.Combine(repo, "data", "runs", project + "_20260101_120000_abc");
        Directory.CreateDirectory(runsDir);
        File.WriteAllText(Path.Combine(runsDir, "mutator_stats.json"),
            """
            {"project":"intel-mutator-only","biasEnabled":true,"mutators":[{"name":"havoc","runs":3,"newEdges":0,"uniqueCrashes":0,"score":0,"selectionWeight":1}]}
            """);
        File.WriteAllText(Path.Combine(runsDir, "run.json"),
            """
            {"runId":"intel-mutator-only_20260101_120000_abc","startedAt":"2026-01-01T12:00:00Z","iterations":3,"crashesFound":0,"stalkBackend":"none"}
            """);

        var projectsDir = Path.Combine(repo, "projects");
        Directory.CreateDirectory(projectsDir);
        File.WriteAllText(Path.Combine(projectsDir, project + ".yaml"),
            $"""
            name: {project}
            kind: file
            target:
              executable: ../targets/file-text/app.exe
            fuzz:
              runsDir: ../data/runs
            """);

        try
        {
            var dto = StalkIntelligenceBuilder.Build(project, repo);
            Assert.False(dto.HasData);
            Assert.Empty(dto.Targets);
            Assert.Contains("Mutator credit", dto.Summary, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            try { Directory.Delete(repo, true); } catch { /* ignore */ }
        }
    }
}
