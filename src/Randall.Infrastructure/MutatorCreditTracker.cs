using System.Text.Json;
using Randall.Contracts;
using Randall.Core;

namespace Randall.Infrastructure;

/// <summary>
/// Bandit-lite mutator credit: track productive mutators and softly bias selection energy.
/// Persists cumulative stats under corpus dir; per-run JSON under data/runs/.
/// </summary>
public sealed class MutatorCreditTracker
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    private readonly Dictionary<string, MutatorCreditEntry> _entries = new(StringComparer.OrdinalIgnoreCase);
    private readonly string? _persistPath;
    private readonly bool _biasEnabled;

    public MutatorCreditTracker(string? persistPath, bool biasEnabled = true)
    {
        _persistPath = persistPath;
        _biasEnabled = biasEnabled;
        if (persistPath is not null)
            Load();
    }

    public bool BiasEnabled => _biasEnabled;

    /// <summary>Cumulative score from edges and unique crashes.</summary>
    public static double ComputeScore(int newEdges, int uniqueCrashes) =>
        newEdges * 10.0 + uniqueCrashes * 100.0;

    public IMutator Pick(IReadOnlyList<IMutator> mutators, Random rng, HuntPolicyDecision? policy = null)
    {
        if (mutators.Count == 0)
            throw new InvalidOperationException("No mutators available.");
        if (mutators.Count == 1 || !_biasEnabled)
            return mutators[rng.Next(mutators.Count)];
        return WeightedPick(mutators, rng, policy);
    }

    /// <summary>
    /// Boost mutator credit when scream evolution shows a warming lineage (READ→WRITE→controlled).
    /// </summary>
    public void RecordEvolutionWarmth(
        IReadOnlyList<string> mutatorChain,
        int momentumScore,
        int progressionDelta)
    {
        if (!_biasEnabled || momentumScore < 40 || progressionDelta <= 0)
            return;

        var bonusEdges = Math.Min(5, momentumScore / 20 + progressionDelta);
        foreach (var name in mutatorChain)
        {
            if (string.IsNullOrWhiteSpace(name))
                continue;
            if (name.StartsWith("joker:", StringComparison.OrdinalIgnoreCase))
                continue;

            var entry = GetOrCreate(name);
            entry.NewEdges += bonusEdges;
            entry.Score = ComputeScore(entry.NewEdges, entry.UniqueCrashes);
        }
    }

    public int GetLineageWeightBoost(IReadOnlyList<string> mutatorChain, int momentumScore)
    {
        if (!_biasEnabled || momentumScore < 40 || mutatorChain.Count == 0)
            return 0;
        return Math.Min(8, momentumScore / 12 + mutatorChain.Count);
    }

    /// <summary>Record one iteration outcome for the primary mutator.</summary>
    public void Record(string mutatorName, int newEdges, bool uniqueCrash)
    {
        var entry = GetOrCreate(mutatorName);
        entry.Runs++;
        entry.NewEdges += Math.Max(0, newEdges);
        if (newEdges <= 0 && !uniqueCrash)
            entry.StaleRuns++;
        if (uniqueCrash)
            entry.UniqueCrashes++;
        entry.Score = ComputeScore(entry.NewEdges, entry.UniqueCrashes);
    }

    /// <summary>
    /// Record iteration outcome; on unique crash, also credit every mutator in the lineage chain
    /// (excluding joker wrappers already expanded in the chain).
    /// </summary>
    public void RecordWithChain(
        string primaryMutator,
        IReadOnlyList<string> mutatorChain,
        int newEdges,
        bool uniqueCrash)
    {
        Record(primaryMutator, newEdges, uniqueCrash);
        if (!uniqueCrash || mutatorChain.Count <= 1)
            return;

        foreach (var name in mutatorChain)
        {
            if (string.IsNullOrWhiteSpace(name))
                continue;
            if (name.StartsWith("joker:", StringComparison.OrdinalIgnoreCase))
                continue;
            if (name.Equals(primaryMutator, StringComparison.OrdinalIgnoreCase))
                continue;

            var entry = GetOrCreate(name);
            entry.UniqueCrashes++;
            entry.Score = ComputeScore(entry.NewEdges, entry.UniqueCrashes);
        }
    }

    public int GetSelectionWeight(string mutatorName, HuntPolicyDecision? policy = null)
    {
        if (!_entries.TryGetValue(mutatorName, out var entry) || entry.Runs <= 0)
            return 1;
        var avg = entry.Score / entry.Runs;
        var weight = Math.Max(1, (int)avg + 1);

        if (entry.StaleRuns >= 5 && entry.NewEdges <= 1)
            weight = Math.Max(1, weight - Math.Min(6, entry.StaleRuns / 3));

        if (entry.FailureRate >= 0.9 && entry.Runs >= 8)
            weight = Math.Max(1, weight - 3);

        if (policy?.Mode == HuntExecutionMode.LineageBreed
            && policy.PreferredMutator?.Equals(mutatorName, StringComparison.OrdinalIgnoreCase) == true)
            weight += 4;

        if (policy?.Mode == HuntExecutionMode.HavocExplore
            && mutatorName.Equals("havoc", StringComparison.OrdinalIgnoreCase))
            weight += 3;

        return Math.Max(1, weight);
    }

    public IReadOnlyList<MutatorCreditRowDto> SnapshotRows()
    {
        return _entries.Values
            .OrderByDescending(e => e.Score)
            .ThenByDescending(e => e.NewEdges)
            .ThenBy(e => e.Name, StringComparer.OrdinalIgnoreCase)
            .Select(e => new MutatorCreditRowDto(
                e.Name, e.Runs, e.NewEdges, e.UniqueCrashes, e.Score, GetSelectionWeight(e.Name),
                e.StaleRuns, e.FailureRate))
            .ToList();
    }

    public void Save()
    {
        if (_persistPath is null)
            return;
        var dir = Path.GetDirectoryName(_persistPath);
        if (!string.IsNullOrEmpty(dir))
            Directory.CreateDirectory(dir);
        var lines = _entries.Values
            .OrderBy(e => e.Name, StringComparer.OrdinalIgnoreCase)
            .Select(e => FormatPersistLine(e));
        File.WriteAllLines(_persistPath, lines);
    }

    public static void ApplyMemoryDecay(string persistPath, double factor)
    {
        if (factor >= 0.999 || !File.Exists(persistPath)) return;
        var lines = new List<string>();
        foreach (var line in File.ReadAllLines(persistPath))
        {
            if (string.IsNullOrWhiteSpace(line) || line.TrimStart().StartsWith('#')) { lines.Add(line); continue; }
            if (!TryParsePersistLine(line, out var entry)) { lines.Add(line); continue; }
            entry.Score = Math.Round(entry.Score * factor, 2);
            entry.NewEdges = (int)Math.Round(entry.NewEdges * factor);
            entry.UniqueCrashes = (int)Math.Max(0, Math.Round(entry.UniqueCrashes * factor));
            lines.Add(FormatPersistLine(entry));
        }
        File.WriteAllLines(persistPath, lines);
    }

    public void WriteRunJson(string runDir)
    {
        Directory.CreateDirectory(runDir);
        var dto = new MutatorCreditRunDto(_biasEnabled, SnapshotRows());
        File.WriteAllText(
            Path.Combine(runDir, "mutator_stats.json"),
            JsonSerializer.Serialize(dto, JsonOptions));
    }

    public string FormatLeaderboard()
    {
        var rows = SnapshotRows();
        if (rows.Count == 0)
            return "Mutator credit: (no iterations recorded)";

        var lines = new List<string>
        {
            _biasEnabled
                ? "Mutator credit (bandit-lite bias on):"
                : "Mutator credit (bias off — stats only):",
        };
        var rank = 1;
        foreach (var row in rows)
        {
            lines.Add(
                $"  {rank,2}. {row.Name,-12} runs={row.Runs,5} edges={row.NewEdges,4} " +
                $"uniqCrash={row.UniqueCrashes,2} score={row.Score,7:0} weight={row.SelectionWeight}");
            rank++;
        }
        return string.Join(Environment.NewLine, lines);
    }

    private IMutator WeightedPick(IReadOnlyList<IMutator> mutators, Random rng, HuntPolicyDecision? policy = null)
    {
        var total = 0;
        var weights = new int[mutators.Count];
        for (var i = 0; i < mutators.Count; i++)
        {
            var w = GetSelectionWeight(mutators[i].Name, policy);
            weights[i] = w;
            total += w;
        }

        var roll = rng.Next(total);
        var acc = 0;
        for (var i = 0; i < mutators.Count; i++)
        {
            acc += weights[i];
            if (roll < acc)
                return mutators[i];
        }
        return mutators[^1];
    }

    private MutatorCreditEntry GetOrCreate(string name)
    {
        if (!_entries.TryGetValue(name, out var entry))
        {
            entry = new MutatorCreditEntry { Name = name };
            _entries[name] = entry;
        }
        return entry;
    }

    private void Load()
    {
        if (_persistPath is null || !File.Exists(_persistPath))
            return;
        foreach (var line in File.ReadAllLines(_persistPath))
        {
            if (string.IsNullOrWhiteSpace(line) || line.TrimStart().StartsWith('#'))
                continue;
            if (!TryParsePersistLine(line, out var entry))
                continue;
            _entries[entry.Name] = entry;
        }
    }

    internal static string FormatPersistLine(MutatorCreditEntry entry) =>
        $"{entry.Name} runs={entry.Runs} newEdges={entry.NewEdges} uniqueCrashes={entry.UniqueCrashes} " +
        $"score={entry.Score:0} staleRuns={entry.StaleRuns}";

    internal static bool TryParsePersistLine(string line, out MutatorCreditEntry entry)
    {
        entry = new MutatorCreditEntry();
        var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2)
            return false;
        entry.Name = parts[0];
        foreach (var part in parts.Skip(1))
        {
            var eq = part.IndexOf('=');
            if (eq <= 0)
                continue;
            var key = part[..eq];
            var val = part[(eq + 1)..];
            switch (key)
            {
                case "runs":
                    if (int.TryParse(val, out var runs)) entry.Runs = runs;
                    break;
                case "newEdges":
                    if (int.TryParse(val, out var edges)) entry.NewEdges = edges;
                    break;
                case "uniqueCrashes":
                    if (int.TryParse(val, out var crashes)) entry.UniqueCrashes = crashes;
                    break;
                case "score":
                    if (double.TryParse(val, out var score)) entry.Score = score;
                    break;
                case "staleRuns":
                    if (int.TryParse(val, out var stale)) entry.StaleRuns = stale;
                    break;
            }
        }
        if (entry.Score <= 0 && (entry.NewEdges > 0 || entry.UniqueCrashes > 0))
            entry.Score = ComputeScore(entry.NewEdges, entry.UniqueCrashes);
        entry.RecomputeFailureRate();
        return !string.IsNullOrWhiteSpace(entry.Name);
    }

    internal sealed class MutatorCreditEntry
    {
        public string Name { get; set; } = "";
        public int Runs { get; set; }
        public int NewEdges { get; set; }
        public int UniqueCrashes { get; set; }
        public int StaleRuns { get; set; }
        public double Score { get; set; }

        public double FailureRate =>
            Runs <= 0 ? 0 : Math.Clamp((double)StaleRuns / Runs, 0, 1);

        public void RecomputeFailureRate() { /* computed property */ }
    }
}
