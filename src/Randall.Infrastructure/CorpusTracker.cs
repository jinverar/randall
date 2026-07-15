using Randall.Infrastructure.Mutators;

namespace Randall.Infrastructure;

/// <summary>Leg 4 — Stalk: track seen inputs and drcov traces for corpus priority.</summary>
public sealed class CorpusTracker(string corpusDir)
{
    private readonly HashSet<string> _seen = new(StringComparer.OrdinalIgnoreCase);
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
    }

    public bool IsNew(byte[] input)
    {
        var hash = InputHash.StackHash(input);
        return _seen.Add(hash);
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

    public int SeenCount => _seen.Count;
}
