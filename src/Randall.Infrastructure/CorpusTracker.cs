using Randall.Infrastructure.Mutators;

namespace Randall.Infrastructure;

/// <summary>Leg 4 — Stalk: track seen inputs and drcov traces for corpus priority.</summary>
public sealed class CorpusTracker(string corpusDir)
{
    private readonly HashSet<string> _seen = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<byte[]> _priority = [];
    private readonly Dictionary<string, int> _energy = new(StringComparer.OrdinalIgnoreCase);
    private readonly string _statePath = Path.Combine(corpusDir, "corpus_state.txt");
    private readonly string _energyPath = Path.Combine(corpusDir, "corpus_energy.txt");

    public void Load()
    {
        Directory.CreateDirectory(corpusDir);
        if (File.Exists(_statePath))
        {
            foreach (var line in File.ReadLines(_statePath))
            {
                if (!string.IsNullOrWhiteSpace(line))
                    _seen.Add(line.Trim());
            }
        }

        if (File.Exists(_energyPath))
        {
            foreach (var line in File.ReadLines(_energyPath))
            {
                var parts = line.Split('=', 2);
                if (parts.Length == 2 && int.TryParse(parts[1], out var energy))
                    _energy[parts[0].Trim()] = energy;
            }
        }

        foreach (var file in Directory.EnumerateFiles(corpusDir, "priority_*.bin"))
        {
            try
            {
                var bytes = File.ReadAllBytes(file);
                _priority.Add(bytes);
                var hash = InputHash.StackHash(bytes);
                if (!_energy.ContainsKey(hash))
                    _energy[hash] = 2;
            }
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
        if (!_energy.ContainsKey(hash))
            _energy[hash] = 1;
    }

    public void AddPriority(byte[] input)
    {
        SaveInteresting(input, "priority");
        _priority.Add(input);
        BoostEnergy(input, 4);
    }

    public void BoostEnergy(byte[] input, int amount = 1)
    {
        var hash = InputHash.StackHash(input);
        _energy[hash] = _energy.GetValueOrDefault(hash) + amount;
        PersistEnergy();
    }

    public byte[] PickSeed(IReadOnlyList<byte[]> seeds, Random rng, bool powerSchedule = true)
    {
        if (_priority.Count > 0 && rng.NextDouble() < 0.65)
        {
            if (powerSchedule && _energy.Count > 0)
                return WeightedPick(_priority, rng);
            return _priority[rng.Next(_priority.Count)];
        }
        return seeds[rng.Next(seeds.Count)];
    }

    public byte[] PickAny(IReadOnlyList<byte[]> seeds, Random rng, bool powerSchedule = true)
    {
        if (_priority.Count > 0 && rng.NextDouble() < 0.5)
        {
            if (powerSchedule && _energy.Count > 0)
                return WeightedPick(_priority, rng);
            return _priority[rng.Next(_priority.Count)];
        }
        return seeds[rng.Next(seeds.Count)];
    }

    private byte[] WeightedPick(IReadOnlyList<byte[]> pool, Random rng)
    {
        var total = 0;
        var weights = new int[pool.Count];
        for (var i = 0; i < pool.Count; i++)
        {
            var hash = InputHash.StackHash(pool[i]);
            var w = Math.Max(1, _energy.GetValueOrDefault(hash));
            weights[i] = w;
            total += w;
        }

        var roll = rng.Next(total);
        var acc = 0;
        for (var i = 0; i < pool.Count; i++)
        {
            acc += weights[i];
            if (roll < acc)
                return pool[i];
        }
        return pool[^1];
    }

    private void PersistEnergy()
    {
        var lines = _energy.Select(kv => $"{kv.Key}={kv.Value}");
        File.WriteAllLines(_energyPath, lines);
    }

    public int SeenCount => _seen.Count;
    public int PriorityCount => _priority.Count;
    public int SeedFileCount => Directory.Exists(corpusDir)
        ? Directory.EnumerateFiles(corpusDir, "*.bin").Count()
        : 0;
}
