using System.Text.Json;
using Randall.Contracts;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class FuzzSessionArchiveTests
{
    [Fact]
    public void ImportFolder_Recursive_FindsRunJsonTrees()
    {
        var root = Path.Combine(Path.GetTempPath(), "randfuzz-sess-" + Guid.NewGuid().ToString("N"));
        var repo = Path.Combine(root, "repo");
        var inbound = Path.Combine(root, "inbound");
        try
        {
            Directory.CreateDirectory(repo);
            File.WriteAllText(Path.Combine(repo, "Randall.sln"), "Microsoft Visual Studio Solution File");
            Directory.CreateDirectory(Path.Combine(repo, "data", "runs"));
            Directory.CreateDirectory(Path.Combine(repo, "data", "sessions"));

            var nested = Path.Combine(inbound, "campaign-a", "batch-1", "demo_20260101_120000_abc");
            Directory.CreateDirectory(nested);
            var runId = "demo_20260101_120000_abc";
            var manifest = new FuzzRunManifestDto(
                runId,
                "demo",
                "tcp",
                Path.Combine(repo, "projects", "demo.yaml"),
                DateTimeOffset.UtcNow.AddMinutes(-10),
                DateTimeOffset.UtcNow,
                false,
                true,
                "novelty",
                "test",
                42,
                3,
                [new HotEdgeDto("mod+0x1000", 9)]);
            File.WriteAllText(
                Path.Combine(nested, "run.json"),
                JsonSerializer.Serialize(manifest, new JsonSerializerOptions { WriteIndented = true }));
            File.WriteAllText(Path.Combine(nested, "iterations.jsonl"), "{\"iteration\":1}\n");

            var result = FuzzSessionArchive.Import(
                new FuzzSessionImportRequest(inbound, Recursive: true, OverwriteFiles: true),
                repo);

            Assert.Equal(1, result.ImportedRuns);
            Assert.Contains(runId, result.RunIds);
            Assert.True(File.Exists(Path.Combine(repo, "data", "runs", runId, "run.json")));

            var listed = FuzzSessionArchive.List("demo", repo);
            Assert.Contains(listed.Sessions, s => s.RunId == runId && s.Iterations == 42);

            var opened = FuzzSessionArchive.Open(runId, repo);
            Assert.Equal(runId, opened.RunId);
            Assert.Equal("demo", opened.Project);
            Assert.Equal(runId, FuzzSessionArchive.GetOpenState(repo).RunId);

            var closed = FuzzSessionArchive.Close(repo);
            Assert.Null(closed.RunId);

            var saved = FuzzSessionArchive.Save(new FuzzSessionSaveRequest(runId, "demo", "unit-label"), repo);
            Assert.Equal("unit-label", saved.Label);
            Assert.True(Directory.Exists(saved.SavedDir));
            Assert.True(File.Exists(Path.Combine(saved.SavedDir, "session.json")));

            var exported = FuzzSessionArchive.Export(
                new FuzzSessionExportRequest(runId, Path.Combine(root, "out.zip"), IncludeLinkedCrashes: false),
                repo);
            Assert.True(File.Exists(exported.Path));
            Assert.True(exported.SizeBytes > 0);
        }
        finally
        {
            try { Directory.Delete(root, recursive: true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void LoadManifest_ReturnsNull_WhenMissing()
    {
        var root = Path.Combine(Path.GetTempPath(), "randfuzz-sess-miss-" + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(root);
            File.WriteAllText(Path.Combine(root, "Randall.sln"), "x");
            Assert.Null(FuzzSessionArchive.LoadManifest("nope", root));
        }
        finally
        {
            try { Directory.Delete(root, recursive: true); } catch { /* ignore */ }
        }
    }
}
