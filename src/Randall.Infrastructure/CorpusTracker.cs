using Randall.Infrastructure.Mutators;

namespace Randall.Infrastructure;

/// <summary>Leg 4 — Stalk: track seen inputs and drcov traces for corpus priority.</summary>
public sealed class CorpusTracker(string corpusDir)
{
    private readonly HashSet<string> _seen = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<byte[]> _priority = [];
    private readonly string _statePath = Path.Combine(corpusDir, "corpus_state.txt");

    public void Load()
    {
        Directory.CreateDirectory(corpusDir);
        if (!File.Exists(_statePath))
            return;
        foreach (var line in File.ReadLines(_statePath))
        {
            if (!string.IsNullOrWhiteSpace(line))
                _seen.Add(line.Trim());
        }

        foreach (var file in Directory.EnumerateFiles(corpusDir, "priority_*.bin"))
        {
            try { _priority.Add(File.ReadAllBytes(file)); }
            catch { /* skip */ }
        }
    }

    public bool IsNew(byte[] input)
    {
        var hash = InputHash.StackHash(input);
        return !_seen.Contains(hash);
    }

    public void SaveInteresting(byte[] input, string label)
    {
        var hash = InputHash.StackHash(input);
        if (!_seen.Add(hash))
            return;
        var path = Path.Combine(corpusDir, $"{label}_{hash}.bin");
        File.WriteAllBytes(path, input);
        File.AppendAllText(_statePath, hash + Environment.NewLine);
    }

    public void AddPriority(byte[] input)
    {
        SaveInteresting(input, "priority");
        _priority.Add(input);
    }

    public byte[] PickSeed(IReadOnlyList<byte[]> seeds, Random rng)
    {
        if (_priority.Count > 0 && rng.NextDouble() < 0.65)
            return _priority[rng.Next(_priority.Count)];
        return seeds[rng.Next(seeds.Count)];
    }

    public int SeenCount => _seen.Count;
    public int PriorityCount => _priority.Count;
    public int SeedFileCount => Directory.Exists(corpusDir)
        ? Directory.EnumerateFiles(corpusDir, "*.bin").Count()
        : 0;
}
