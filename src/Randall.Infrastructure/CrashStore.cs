using System.Text.Json;
using Randall.Contracts;
using Randall.Infrastructure.Mutators;

namespace Randall.Infrastructure;

public sealed record SavedCrash(
    Guid Id,
    string Project,
    int Iteration,
    string Mutator,
    string InputHash,
    string InputPath,
    string? TargetExitCode,
    string? MiniDumpPath,
    string? TriageTag,
    string? SidecarPath,
    string? RunId,
    DateTimeOffset At);

public sealed record SavedCrashResult(SavedCrash Crash, bool IsNew);

public sealed class CrashStore(string crashesDir)
{
    private readonly string _indexPath = Path.Combine(crashesDir, "index.jsonl");

    public void Ensure()
    {
        Directory.CreateDirectory(crashesDir);
    }

    public SavedCrash? FindByHash(string hash, string project)
    {
        return List(project).FirstOrDefault(c =>
            c.InputHash.Equals(hash, StringComparison.OrdinalIgnoreCase));
    }

    public SavedCrash Save(
        string project,
        int iteration,
        string mutator,
        byte[] input,
        int? exitCode,
        string? miniDumpPath = null,
        string? triageTag = null,
        string? runId = null,
        Func<Guid, CrashSidecarDto>? buildSidecar = null) =>
        SaveEx(project, iteration, mutator, input, exitCode, miniDumpPath, triageTag, runId, buildSidecar).Crash;

    /// <summary>Save crash; <see cref="SavedCrashResult.IsNew"/> is false when input hash already exists.</summary>
    public SavedCrashResult SaveEx(
        string project,
        int iteration,
        string mutator,
        byte[] input,
        int? exitCode,
        string? miniDumpPath = null,
        string? triageTag = null,
        string? runId = null,
        Func<Guid, CrashSidecarDto>? buildSidecar = null)
    {
        Ensure();
        var hash = InputHash.StackHash(input);
        var existing = FindByHash(hash, project);
        if (existing is not null)
            return new SavedCrashResult(existing, false);

        var id = Guid.NewGuid();
        var fileName = $"{project}_{iteration}_{hash}.bin";
        var inputPath = Path.Combine(crashesDir, fileName);
        File.WriteAllBytes(inputPath, input);

        string? sidecarPath = null;
        if (buildSidecar is not null)
            sidecarPath = CrashSidecarWriter.Write(crashesDir, buildSidecar(id));

        var record = new SavedCrash(
            id,
            project,
            iteration,
            mutator,
            hash,
            inputPath,
            exitCode?.ToString(),
            miniDumpPath,
            triageTag,
            sidecarPath,
            runId,
            DateTimeOffset.UtcNow);
        File.AppendAllText(_indexPath, JsonSerializer.Serialize(record) + Environment.NewLine);
        return new SavedCrashResult(record, true);
    }

    public IReadOnlyList<SavedCrash> List(string? project = null)
    {
        if (!File.Exists(_indexPath))
            return [];
        var list = new List<SavedCrash>();
        foreach (var line in File.ReadLines(_indexPath))
        {
            if (string.IsNullOrWhiteSpace(line))
                continue;
            var c = JsonSerializer.Deserialize<SavedCrash>(line);
            if (c is null)
                continue;
            if (project is null || c.Project.Equals(project, StringComparison.OrdinalIgnoreCase))
                list.Add(c);
        }
        return list;
    }
}
