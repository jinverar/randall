using System.Text.Json;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>Phase 15 — Append-only execution journal under data/runs/.</summary>
public sealed class FuzzRunJournal
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = false };

    private readonly string _runDir;
    private readonly string _iterationsPath;
    private readonly FuzzRunManifestDto _manifest;

    public string RunId => _manifest.RunId;
    public string RunDirectory => _runDir;

    private FuzzRunJournal(string runDir, FuzzRunManifestDto manifest)
    {
        _runDir = runDir;
        _manifest = manifest;
        _iterationsPath = Path.Combine(runDir, "iterations.jsonl");
    }

    public static FuzzRunJournal Start(
        ProjectConfig project,
        string yamlPath,
        bool dryRun,
        bool coverageGuided,
        string stalkBackend)
    {
        var repoRoot = ProjectLoader.ResolveProjectRoot(yamlPath);
        var runsRoot = ProjectLoader.ResolvePath(yamlPath, project.Fuzz.RunsDir);
        Directory.CreateDirectory(runsRoot);

        var runId = $"{project.Name}_{DateTime.UtcNow:yyyyMMdd_HHmmss}_{Guid.NewGuid():N}";
        var runDir = Path.Combine(runsRoot, runId);
        Directory.CreateDirectory(runDir);

        var manifest = new FuzzRunManifestDto(
            runId,
            project.Name,
            project.Kind,
            Path.GetFullPath(yamlPath),
            DateTimeOffset.UtcNow,
            null,
            dryRun,
            coverageGuided,
            stalkBackend,
            stalkBackend == StalkBackend.External ? StalkBackend.ExternalNote : "",
            0,
            0);

        File.WriteAllText(
            Path.Combine(runDir, "run.json"),
            JsonSerializer.Serialize(manifest, new JsonSerializerOptions { WriteIndented = true }));

        return new FuzzRunJournal(runDir, manifest);
    }

    public void LogIteration(IterationLogEntry entry)
    {
        File.AppendAllText(_iterationsPath, JsonSerializer.Serialize(entry, JsonOptions) + Environment.NewLine);
    }

    public void Complete(int iterations, int crashesFound)
    {
        var done = _manifest with
        {
            CompletedAt = DateTimeOffset.UtcNow,
            Iterations = iterations,
            CrashesFound = crashesFound,
        };
        File.WriteAllText(
            Path.Combine(_runDir, "run.json"),
            JsonSerializer.Serialize(done, new JsonSerializerOptions { WriteIndented = true }));
    }
}
