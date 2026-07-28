using Randall.Contracts;
using Randall.Infrastructure;

namespace Randall.Infrastructure;

public static class CorpusStats
{
    public static CorpusStatsDto ForProject(string projectName, string? repoRoot = null)
    {
        repoRoot ??= CrashCatalog.FindRepoRoot();
        if (repoRoot is null)
            return new CorpusStatsDto(projectName, 0, 0, 0, DynamoRioRunner.Discover().IsAvailable);

        var corpusDir = Path.Combine(repoRoot, "data", "corpus", projectName);
        var tracker = new CorpusTracker(corpusDir);
        tracker.Load();

        var edgesPath = Path.Combine(corpusDir, "edges.txt");
        var edgeCount = File.Exists(edgesPath) ? File.ReadLines(edgesPath).Count(l => !string.IsNullOrWhiteSpace(l)) : 0;
        var pathsPath = Path.Combine(corpusDir, "paths.txt");
        var semantic = File.Exists(pathsPath)
            ? File.ReadLines(pathsPath).Count(l => !string.IsNullOrWhiteSpace(l))
            : 0;
        var dynamo = DynamoRioRunner.Discover().IsAvailable;
        var kind = edgeCount > 0 ? "bb-edges"
            : semantic > 0 ? "path-novelty"
            : "unavailable";

        return new CorpusStatsDto(
            projectName,
            tracker.SeedFileCount,
            tracker.SeenCount,
            edgeCount,
            dynamo,
            CoverageBlocks: edgeCount,
            SemanticStageHits: semantic,
            CoverageKind: kind);
    }
}
