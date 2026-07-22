using System.Text;
using System.Text.Json;
using Randall.Contracts;
using Randall.Core;

namespace Randall.Infrastructure.Magician;

/// <summary>
/// Live Joker trick for one fuzz iteration — chaotic decisions, not Magician spells.
/// </summary>
public sealed class JokerTrick
{
    public required string Id { get; init; }
    public required string TrickName { get; init; }
    public required IMutator PrimaryMutator { get; init; }
    public required List<string> MutatorChain { get; init; }
    public required int ChaosLevel { get; init; }
    public required string Detail { get; init; }
    public double? FlowBiasOverride { get; init; }
    public double? GraphBiasOverride { get; init; }
    public bool WildBytes { get; init; }
}

/// <summary>
/// Joker engine — throws very random fuzzing decisions at the program.
/// Distinct from the Magician (who intervenes deliberately). The Magician may
/// <c>summonJoker</c>, watch tricks, and capitalize on crashes.
/// </summary>
public static class JokerEngine
{
    private static readonly string[] TrickNames =
    [
        "card-shuffle",
        "whoopee-cushion",
        "rubber-chicken",
        "pie-in-face",
        "banana-peel",
        "confetti-cannon",
        "wrong-door",
        "laugh-track",
    ];

    public static bool IsEnabled(ProjectConfig project) =>
        project.Joker is { Enabled: true } ||
        (project.Joker?.EncoreIterations > 0);

    public static JokerConfig GetConfig(ProjectConfig project) =>
        project.Joker ??= new JokerConfig();

    /// <summary>Effective hijack chance (encore boosts after Magician summon).</summary>
    public static double EffectiveChance(ProjectConfig project)
    {
        var cfg = GetConfig(project);
        if (cfg.EncoreIterations > 0)
            return Math.Clamp(cfg.EncoreChance, 0, 1);
        if (!cfg.Enabled)
            return 0;
        return Math.Clamp(cfg.Chance, 0, 1);
    }

    public static bool ShouldPlay(ProjectConfig project, Random rng) =>
        rng.NextDouble() < EffectiveChance(project);

    /// <summary>
    /// Start a chaotic trick: pick a primary mutator (biased wild) and optional bias flips.
    /// Call <see cref="FinishTrick"/> after the normal payload is built to stack more chaos.
    /// </summary>
    public static JokerTrick StartTrick(
        ProjectConfig project,
        IReadOnlyList<IMutator> mutators,
        Random rng)
    {
        var cfg = GetConfig(project);
        if (cfg.EncoreIterations > 0)
            cfg.EncoreIterations--;

        if (mutators.Count == 0)
            throw new InvalidOperationException("Joker needs at least one mutator");

        // Bias toward noisy mutators when present.
        var preferred = mutators
            .Where(m => m.Name is "havoc" or "interesting" or "dictionary" or "splice" or "expand" or "insert")
            .ToList();
        var pool = preferred.Count > 0 && rng.NextDouble() < 0.7 ? preferred : mutators.ToList();
        var primary = pool[rng.Next(pool.Count)];

        var chaos = 1 + rng.Next(1, Math.Max(2, cfg.MaxStack + 1));
        var trick = TrickNames[rng.Next(TrickNames.Length)];
        double? flowOverride = null;
        double? graphOverride = null;
        if (cfg.FlipSessionBias && rng.NextDouble() < 0.45)
        {
            flowOverride = rng.NextDouble();
            graphOverride = rng.NextDouble();
        }

        return new JokerTrick
        {
            Id = Guid.NewGuid().ToString("N")[..10],
            TrickName = trick,
            PrimaryMutator = primary,
            MutatorChain = [primary.Name],
            ChaosLevel = chaos,
            Detail = $"joker:{trick} primary={primary.Name} chaos={chaos}",
            FlowBiasOverride = flowOverride,
            GraphBiasOverride = graphOverride,
            WildBytes = cfg.WildBytes,
        };
    }

    /// <summary>Stack extra random mutators + optional wild bytes onto the payload.</summary>
    public static byte[] FinishTrick(
        JokerTrick trick,
        byte[] payload,
        IReadOnlyList<IMutator> mutators,
        Random rng,
        JokerConfig cfg)
    {
        var buf = payload;
        var stack = Math.Clamp(trick.ChaosLevel, 1, Math.Max(1, cfg.MaxStack));
        for (var i = 1; i < stack && mutators.Count > 0; i++)
        {
            var m = mutators[rng.Next(mutators.Count)];
            try
            {
                buf = m.Mutate(buf).ToArray();
                trick.MutatorChain.Add(m.Name);
            }
            catch
            {
                /* skip broken mutator on empty/short buffers */
            }
        }

        if (trick.WildBytes && rng.NextDouble() < 0.65)
            buf = SprinkleWildBytes(buf, rng);

        trick.MutatorChain.Insert(0, $"joker:{trick.TrickName}");
        return buf;
    }

    public static void PersistWatch(string directory, JokerActDto act)
    {
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "joker_watch.jsonl");
        var json = JsonSerializer.Serialize(act, new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            WriteIndented = false,
        });
        File.AppendAllText(path, json + Environment.NewLine);
    }

    public static IReadOnlyList<JokerActDto> ListWatch(string directory, int take = 200)
    {
        var path = Path.Combine(directory, "joker_watch.jsonl");
        if (!File.Exists(path))
            return [];
        var list = new List<JokerActDto>();
        var opts = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
        foreach (var line in File.ReadLines(path))
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            try
            {
                var a = JsonSerializer.Deserialize<JokerActDto>(line, opts);
                if (a is not null) list.Add(a);
            }
            catch { /* skip */ }
        }
        return list.OrderByDescending(a => a.At).Take(take).ToList();
    }

    public static string Describe()
    {
        var sb = new StringBuilder();
        sb.AppendLine("Joker — chaotic random fuzz tricks (docs/MAGICIAN.md#joker)");
        sb.AppendLine();
        sb.AppendLine("Not the Magician. The Joker hijacks iterations with stacked mutators,");
        sb.AppendLine("wild bytes, and funny session-bias flips. Magician summons / watches /");
        sb.AppendLine("capitalizes on any crashes the Joker finds.");
        sb.AppendLine();
        sb.AppendLine("YAML: joker: { enabled: true, chance: 0.12, maxStack: 4 }");
        sb.AppendLine("Magician: summonJoker · watchJoker · capitalizeJokerCrashes");
        return sb.ToString();
    }

    private static byte[] SprinkleWildBytes(byte[] input, Random rng)
    {
        var len = Math.Max(1, input.Length + rng.Next(-8, 64));
        var buf = new byte[len];
        var copy = Math.Min(input.Length, buf.Length);
        Buffer.BlockCopy(input, 0, buf, 0, copy);
        var n = 1 + rng.Next(3, 24);
        for (var i = 0; i < n; i++)
            buf[rng.Next(buf.Length)] = (byte)rng.Next(256);
        // Occasional comedy: plant a joke marker.
        if (rng.NextDouble() < 0.2 && buf.Length >= 4)
        {
            var joke = "LOL!"u8.ToArray();
            var at = rng.Next(0, buf.Length - joke.Length + 1);
            Buffer.BlockCopy(joke, 0, buf, at, joke.Length);
        }
        return buf;
    }
}
