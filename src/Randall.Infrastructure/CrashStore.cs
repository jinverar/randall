using System.Text.Json;
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
    DateTimeOffset At);

public sealed class CrashStore(string crashesDir)
{
    private readonly string _indexPath = Path.Combine(crashesDir, "index.jsonl");

    public void Ensure()
    {
        Directory.CreateDirectory(crashesDir);
    }

    public SavedCrash Save(string project, int iteration, string mutator, byte[] input, int? exitCode)
    {
        Ensure();
        var id = Guid.NewGuid();
        var hash = InputHash.StackHash(input);
        var fileName = $"{project}_{iteration}_{hash}.bin";
        var inputPath = Path.Combine(crashesDir, fileName);
        File.WriteAllBytes(inputPath, input);
        var record = new SavedCrash(
            id,
            project,
            iteration,
            mutator,
            hash,
            inputPath,
            exitCode?.ToString(),
            DateTimeOffset.UtcNow);
        File.AppendAllText(_indexPath, JsonSerializer.Serialize(record) + Environment.NewLine);
        return record;
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
