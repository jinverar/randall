using System.Text.Json;
using Randall.Contracts;
using Randall.Core;

namespace Randall.Infrastructure;

public sealed class MutatorChainTracker
{
    private const double PureTransitionRoll = 0.12;
    private const double TransitionBoostCap = 0.18;

    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    private readonly Dictionary<string, ChainEntry> _pairs = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, ChainEntry> _triples = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, TransitionEntry> _transitions = new(StringComparer.OrdinalIgnoreCase);
    private readonly string? _persistPath;
    private readonly bool _biasEnabled;

    public MutatorChainTracker(string? persistPath, bool biasEnabled = true)
    {
        _persistPath = persistPath;
        _biasEnabled = biasEnabled;
        if (persistPath is not null)
            Load();
    }

    public bool BiasEnabled => _biasEnabled;

    public static double ComputeScore(int newEdges, int uniqueCrashes) =>
        MutatorCreditTracker.ComputeScore(newEdges, uniqueCrashes);

    public void RecordLineage(IReadOnlyList<string> chain, int newEdges, bool uniqueCrash)
    {
        var names = NormalizeChain(chain);
        if (names.Count == 0)
            return;

        var edgeDelta = Math.Max(0, newEdges);
        for (var i = 0; i < names.Count - 1; i++)
        {
            CreditEntry(_pairs, FormatPair(names[i], names[i + 1]), [names[i], names[i + 1]], edgeDelta, uniqueCrash);
            CreditTransition(names[i], names[i + 1], edgeDelta, uniqueCrash);
        }

        if (names.Count >= 3)
        {
            var tripleKey = FormatTriple(names[^3], names[^2], names[^1]);
            CreditEntry(_triples, tripleKey, [names[^3], names[^2], names[^1]], edgeDelta, uniqueCrash);
        }
    }

    public IMutator BlendPick(IReadOnlyList<IMutator> mutators, MutatorCreditTracker credit, string? previousMutator, Random rng)
    {
        if (mutators.Count == 0)
            throw new InvalidOperationException("No mutators available.");
        if (mutators.Count == 1)
            return mutators[0];
        if (!_biasEnabled)
            return credit.Pick(mutators, rng);

        if (!string.IsNullOrWhiteSpace(previousMutator)
            && rng.NextDouble() < PureTransitionRoll
            && TryPickTransition(mutators, previousMutator, rng, out var transitionPick))
            return transitionPick;

        return WeightedBlendPick(mutators, credit, previousMutator, rng);
    }

    public IReadOnlyList<MutatorChainRowDto> SnapshotRows() =>
        _pairs.Values.Concat(_triples.Values).Select(ToRow)
            .OrderByDescending(r => r.Score).ThenByDescending(r => r.NewEdges)
            .ThenBy(r => r.DisplayLabel, StringComparer.OrdinalIgnoreCase).ToList();

    public void Save()
    {
        if (_persistPath is null) return;
        var dir = Path.GetDirectoryName(_persistPath);
        if (!string.IsNullOrEmpty(dir))
            Directory.CreateDirectory(dir);
        File.WriteAllText(_persistPath, JsonSerializer.Serialize(BuildStoreDto(), JsonOptions));
    }

    public void WriteRunJson(string runDir)
    {
        Directory.CreateDirectory(runDir);
        File.WriteAllText(Path.Combine(runDir, "mutator_chains.json"), JsonSerializer.Serialize(BuildStoreDto(), JsonOptions));
    }

    public string FormatLeaderboard()
    {
        var rows = SnapshotRows();
        if (rows.Count == 0)
            return "Mutator chains: (no lineage recorded)";
        var lines = new List<string>
        {
            _biasEnabled ? "Mutator chains (pair/triple bias on):" : "Mutator chains (bias off — stats only):",
        };
        var rank = 1;
        foreach (var row in rows.Take(12))
        {
            lines.Add($"  {rank,2}. {row.DisplayLabel,-28} runs={row.Runs,5} edges={row.NewEdges,4} uniqCrash={row.UniqueCrashes,2} score={row.Score,7:0} weight={row.SelectionWeight}");
            rank++;
        }
        return string.Join(Environment.NewLine, lines);
    }

    private MutatorChainStoreDto BuildStoreDto() => new(
        _biasEnabled,
        _pairs.Values.Select(ToRow).OrderByDescending(r => r.Score).ToList(),
        _triples.Values.Select(ToRow).OrderByDescending(r => r.Score).ToList(),
        BuildTransitionRows());

    private IMutator WeightedBlendPick(IReadOnlyList<IMutator> mutators, MutatorCreditTracker credit, string? previousMutator, Random rng)
    {
        var total = 0;
        var weights = new int[mutators.Count];
        for (var i = 0; i < mutators.Count; i++)
        {
            var w = credit.GetSelectionWeight(mutators[i].Name);
            if (!string.IsNullOrWhiteSpace(previousMutator))
                w += (int)Math.Round(w * GetTransitionBoost(previousMutator, mutators[i].Name));
            weights[i] = Math.Max(1, w);
            total += weights[i];
        }
        var roll = rng.Next(total);
        var acc = 0;
        for (var i = 0; i < mutators.Count; i++)
        {
            acc += weights[i];
            if (roll < acc) return mutators[i];
        }
        return mutators[^1];
    }

    private bool TryPickTransition(IReadOnlyList<IMutator> mutators, string previousMutator, Random rng, out IMutator pick)
    {
        pick = mutators[0];
        if (!_transitions.TryGetValue(previousMutator, out var entry) || entry.Outcomes.Count == 0)
            return false;
        var total = entry.Outcomes.Values.Sum(o => Math.Max(1, o.Runs));
        var roll = rng.Next(total);
        var acc = 0;
        foreach (var (next, outcome) in entry.Outcomes.OrderByDescending(kv => kv.Value.Score))
        {
            acc += Math.Max(1, outcome.Runs);
            if (roll >= acc) continue;
            var resolved = mutators.FirstOrDefault(m => m.Name.Equals(next, StringComparison.OrdinalIgnoreCase));
            if (resolved is null) return false;
            pick = resolved;
            return true;
        }
        return false;
    }

    private double GetTransitionBoost(string previousMutator, string nextMutator)
    {
        if (!_transitions.TryGetValue(previousMutator, out var entry)) return 0;
        if (!entry.Outcomes.TryGetValue(nextMutator, out var outcome) || outcome.Runs <= 0) return 0;
        var p = outcome.Score / Math.Max(1.0, entry.TotalScore);
        return Math.Min(TransitionBoostCap, p * TransitionBoostCap);
    }

    private void CreditTransition(string from, string to, int newEdges, bool uniqueCrash)
    {
        if (!_transitions.TryGetValue(from, out var entry))
        {
            entry = new TransitionEntry { From = from };
            _transitions[from] = entry;
        }
        if (!entry.Outcomes.TryGetValue(to, out var outcome))
        {
            outcome = new ChainEntry { Key = to, Chain = [to] };
            entry.Outcomes[to] = outcome;
        }
        outcome.Runs++;
        outcome.NewEdges += newEdges;
        if (uniqueCrash) outcome.UniqueCrashes++;
        outcome.Score = ComputeScore(outcome.NewEdges, outcome.UniqueCrashes);
        entry.TotalScore += ComputeScore(newEdges, uniqueCrash ? 1 : 0);
    }

    private static void CreditEntry(Dictionary<string, ChainEntry> map, string key, IReadOnlyList<string> chain, int newEdges, bool uniqueCrash)
    {
        if (!map.TryGetValue(key, out var entry))
        {
            entry = new ChainEntry { Key = key, Chain = chain.ToList() };
            map[key] = entry;
        }
        entry.Runs++;
        entry.NewEdges += newEdges;
        if (uniqueCrash) entry.UniqueCrashes++;
        entry.Score = ComputeScore(entry.NewEdges, entry.UniqueCrashes);
    }

    private static MutatorChainRowDto ToRow(ChainEntry entry)
    {
        var label = entry.Chain.Count switch
        {
            2 => FormatPair(entry.Chain[0], entry.Chain[1]),
            3 => FormatTriple(entry.Chain[0], entry.Chain[1], entry.Chain[2]),
            _ => entry.Key,
        };
        var weight = entry.Runs <= 0 ? 1 : Math.Max(1, (int)(entry.Score / entry.Runs) + 1);
        return new MutatorChainRowDto(entry.Chain, entry.Runs, entry.NewEdges, entry.UniqueCrashes, entry.Score, weight, label);
    }

    private IReadOnlyList<MutatorChainTransitionRowDto> BuildTransitionRows() =>
        _transitions.Values.SelectMany(t => t.Outcomes.Select(o => new MutatorChainTransitionRowDto(
            t.From, o.Key, o.Value.Runs, o.Value.NewEdges, o.Value.UniqueCrashes, o.Value.Score)))
            .OrderByDescending(r => r.Score).ThenBy(r => r.From, StringComparer.OrdinalIgnoreCase)
            .ThenBy(r => r.To, StringComparer.OrdinalIgnoreCase).ToList();

    private void Load()
    {
        if (_persistPath is null || !File.Exists(_persistPath)) return;
        try
        {
            var dto = JsonSerializer.Deserialize<MutatorChainStoreDto>(File.ReadAllText(_persistPath), JsonOptions);
            if (dto is null) return;
            foreach (var row in dto.Pairs) RestoreRow(_pairs, row);
            foreach (var row in dto.Triples) RestoreRow(_triples, row);
            foreach (var row in dto.Transitions)
            {
                if (!_transitions.TryGetValue(row.From, out var entry))
                {
                    entry = new TransitionEntry { From = row.From };
                    _transitions[row.From] = entry;
                }
                entry.Outcomes[row.To] = new ChainEntry
                {
                    Key = row.To, Chain = [row.To], Runs = row.Runs, NewEdges = row.NewEdges,
                    UniqueCrashes = row.UniqueCrashes, Score = row.Score,
                };
                entry.TotalScore += row.Score;
            }
        }
        catch { }
    }

    private static void RestoreRow(Dictionary<string, ChainEntry> map, MutatorChainRowDto row)
    {
        var key = row.Chain.Count switch
        {
            2 => FormatPair(row.Chain[0], row.Chain[1]),
            3 => FormatTriple(row.Chain[0], row.Chain[1], row.Chain[2]),
            _ => row.DisplayLabel,
        };
        map[key] = new ChainEntry
        {
            Key = key, Chain = row.Chain.ToList(), Runs = row.Runs, NewEdges = row.NewEdges,
            UniqueCrashes = row.UniqueCrashes, Score = row.Score,
        };
    }

    private static List<string> NormalizeChain(IReadOnlyList<string> chain)
    {
        var names = new List<string>();
        foreach (var name in chain)
        {
            if (string.IsNullOrWhiteSpace(name)) continue;
            if (name.StartsWith("joker:", StringComparison.OrdinalIgnoreCase)) continue;
            names.Add(name);
        }
        return names;
    }

    private static string FormatPair(string a, string b) => $"{a}→{b}";
    private static string FormatTriple(string a, string b, string c) => $"{a}→{b}→{c}";

    private sealed class ChainEntry
    {
        public string Key { get; set; } = "";
        public List<string> Chain { get; set; } = [];
        public int Runs { get; set; }
        public int NewEdges { get; set; }
        public int UniqueCrashes { get; set; }
        public double Score { get; set; }
    }

    private sealed class TransitionEntry
    {
        public string From { get; set; } = "";
        public Dictionary<string, ChainEntry> Outcomes { get; } = new(StringComparer.OrdinalIgnoreCase);
        public double TotalScore { get; set; }
    }
}
