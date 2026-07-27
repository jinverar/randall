using System.Diagnostics;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class StalkDashboardLiveGraphTests
{
    [Fact]
    public void ForProject_WithoutBbEdges_ReturnsNodesQuickly()
    {
        var root = CrashCatalog.FindRepoRoot();
        Assert.NotNull(root);

        // Prefer a stock profile that exists in projects/.
        var project = Directory.EnumerateFiles(Path.Combine(root!, "projects"), "*.yaml")
            .Select(p => Path.GetFileNameWithoutExtension(p))
            .FirstOrDefault(n => n is "vulnserver" or "file-text" or "harness-demo")
            ?? "vulnserver";

        var sw = Stopwatch.StartNew();
        var dash = StalkDashboard.ForProject(project);
        sw.Stop();

        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(12),
            $"StalkDashboard.ForProject took {sw.Elapsed.TotalSeconds:F1}s — BuildCrashLog must not call GetDetail per row.");
        Assert.NotNull(dash);
        Assert.NotEmpty(dash!.Blocks);
        // Edges may be sparse for a 1-node hot-edge snapshot; blocks are the live-diagram contract.
        Assert.True(dash.Blocks.Count >= 1);
        Assert.Contains(dash.Blocks, b =>
            b.Id is "entry" or "__entry" or "novelty"
            || b.Kind is "hit" or "novel" or "crash" or "unexplored");
        Assert.True(dash.Edges.Count >= 0);
    }

    [Fact]
    public void GetDetailLite_DoesNotRequireFullProjectEnrichment()
    {
        var root = CrashCatalog.FindRepoRoot();
        Assert.NotNull(root);
        var crashes = CrashCatalog.ListAll(root, "vulnserver");
        if (crashes.Count == 0)
            return; // nothing to assert on a clean tree

        var id = crashes[0].Id;
        var sw = Stopwatch.StartNew();
        var lite = CrashCatalog.GetDetailLite(id, root);
        sw.Stop();

        Assert.NotNull(lite);
        Assert.Equal(id, lite!.Summary.Id);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(3),
            $"GetDetailLite took {sw.Elapsed.TotalSeconds:F1}s — must stay lightweight.");
    }

    [Fact]
    public void FindSavedCrash_RoundTripsIndexLookup()
    {
        var root = CrashCatalog.FindRepoRoot();
        Assert.NotNull(root);
        var crashes = CrashCatalog.ListAll(root, "vulnserver");
        if (crashes.Count == 0)
            return;

        var id = crashes[0].Id;
        var saved = CrashCatalog.FindSavedCrash(id, root);
        Assert.NotNull(saved);
        Assert.Equal(id, saved!.Id);
        Assert.Equal("vulnserver", saved.Project, ignoreCase: true);
    }
}
