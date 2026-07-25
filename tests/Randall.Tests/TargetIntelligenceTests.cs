using Randall.Contracts;
using Randall.Infrastructure;
using Randall.Infrastructure.Mutators;
using Xunit;

namespace Randall.Tests;

public class CanisterMoodScorerTests
{
    [Theory]
    [InlineData(0, 0, 0, "laughter")]
    [InlineData(1, 0, 0, "watching")]
    [InlineData(3, 0, 0, "toxic")]
    [InlineData(8, 0, 0, "virulent")]
    [InlineData(2, 1, 0, "toxic")]
    [InlineData(1, 0, 1, "eip")]
    public void Score_MatchesUiThresholds(int unique, int critical, int ip, string expected) =>
        Assert.Equal(expected, CanisterMoodScorer.Score(unique, critical, ip));
}

public class CrashLineageResolverTests
{
    [Fact]
    public void Resolve_WithoutJournal_FallsBackToSidecarChain()
    {
        var sidecar = new CrashSidecarDto(
            Guid.NewGuid(), "run-1", 5, "demo", "cmd", "havoc", ["havoc", "expand"],
            "parent", "corpus", [], "hash", "x.bin", 10, null,
            null, "detail", null, 0, 0, "none", null, null, null, null,
            new TransportSnapshotDto("tcp", "127.0.0.1", 1, false),
            new FuzzSnapshotDto(false, false, "p.yaml"),
            DateTimeOffset.UtcNow);

        var lineage = CrashLineageResolver.Resolve(sidecar);
        Assert.NotNull(lineage);
        Assert.Equal(2, lineage!.MutatorChain.Count);
        Assert.True(lineage.Partial);
        Assert.Equal("corpus", lineage.SeedSource);
    }

    [Fact]
    public void Resolve_WithJournal_ReplaysParentChain()
    {
        var repo = Path.Combine(Path.GetTempPath(), "randall-lineage-" + Guid.NewGuid().ToString("N"));
        var runId = "demo_20260101_120000_abc";
        var runDir = Path.Combine(repo, "data", "runs", runId);
        Directory.CreateDirectory(runDir);

        var seedHash = InputHash.StackHash(new byte[] { 1, 2, 3 }.AsMemory());
        var midHash = InputHash.StackHash(new byte[] { 9, 9, 9 }.AsMemory());
        var crashHash = InputHash.StackHash(new byte[] { 0x41, 0x41, 0x41 }.AsMemory());

        File.WriteAllText(Path.Combine(runDir, "iterations.jsonl"), string.Join('\n', new[]
        {
            """{"iteration":1,"at":"2026-01-01T12:00:00Z","command":"cmd","mutator":"seed","mutatorChain":["seed"],"parentInputHash":null,"seedSource":"corpus","payloadLength":3,"payloadHash":"SEED","crashed":false,"newEdges":0,"totalEdges":0,"elapsedMs":1,"targetDetail":"","exitCode":0,"stalkBackend":"none","tracePath":null,"runId":"run","dryRun":false}""".Replace("SEED", seedHash),
            $$"""{"iteration":2,"at":"2026-01-01T12:00:01Z","command":"cmd","mutator":"havoc","mutatorChain":["havoc"],"parentInputHash":"{{seedHash}}","seedSource":"corpus","payloadLength":3,"payloadHash":"{{midHash}}","crashed":false,"newEdges":0,"totalEdges":0,"elapsedMs":1,"targetDetail":"","exitCode":0,"stalkBackend":"none","tracePath":null,"runId":"run","dryRun":false}""",
            $$"""{"iteration":3,"at":"2026-01-01T12:00:02Z","command":"cmd","mutator":"expand","mutatorChain":["expand"],"parentInputHash":"{{midHash}}","seedSource":"corpus","payloadLength":3,"payloadHash":"{{crashHash}}","crashed":true,"newEdges":0,"totalEdges":0,"elapsedMs":1,"targetDetail":"crash","exitCode":-1,"stalkBackend":"none","tracePath":null,"runId":"run","dryRun":false}""",
        }) + Environment.NewLine);

        try
        {
            var sidecar = new CrashSidecarDto(
                Guid.NewGuid(), runId, 3, "demo", "cmd", "expand", ["expand"],
                midHash, "corpus", [], crashHash, "x.bin", 10, -1,
                null, "crash", null, 0, 0, "none", null, null, null, null,
                new TransportSnapshotDto("tcp", "127.0.0.1", 1, false),
                new FuzzSnapshotDto(false, false, "p.yaml"),
                DateTimeOffset.UtcNow);

            var lineage = CrashLineageResolver.Resolve(sidecar, repo);
            Assert.NotNull(lineage);
            Assert.False(lineage!.Partial);
            Assert.Equal(["seed", "havoc", "expand"], lineage.MutatorChain);
        }
        finally
        {
            try { Directory.Delete(repo, true); } catch { /* ignore */ }
        }
    }
}

public class TargetIntelligenceBuilderTests
{
    [Fact]
    public void Build_PersistsProfileJson()
    {
        var repo = Path.Combine(Path.GetTempPath(), "randall-tintel-" + Guid.NewGuid().ToString("N"));
        var project = "tintel-demo";
        var stalkDir = Path.Combine(repo, "data", "stalk", project);
        Directory.CreateDirectory(stalkDir);

        File.WriteAllText(Path.Combine(stalkDir, "frontier.json"),
            """
            {"project":"tintel-demo","scoredAt":"2026-01-01","mode":"empty","summary":"0 doors","coverageBlockCount":0,"frontierCount":2,"analysisPath":null,"frontiers":[],"workflowHint":"run fuzz"}
            """);

        try
        {
            var profile = TargetIntelligenceBuilder.Build(project, repo, persist: true);
            Assert.Equal(project, profile.Project);
            Assert.NotNull(profile.Frontier);
            Assert.Equal(2, profile.Frontier!.Count);

            var path = TargetIntelligenceBuilder.ProfilePath(project, repo);
            Assert.True(File.Exists(path));

            var loaded = TargetIntelligenceBuilder.TryLoad(project, repo);
            Assert.NotNull(loaded);
            Assert.Equal(profile.Summary, loaded!.Summary);
        }
        finally
        {
            try { Directory.Delete(repo, true); } catch { /* ignore */ }
        }
    }
}
