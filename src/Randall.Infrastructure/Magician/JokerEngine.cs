using System.Text;
using System.Text.Json;
using Randall.Contracts;
using Randall.Core;

namespace Randall.Infrastructure.Magician;

/// <summary>
/// Live Joker strategy for one fuzz iteration — high-entropy mutation stacking.
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
/// Joker engine — high-entropy / multi-mutator iterations.
/// Distinct from Magician (campaign adjustments from Oracle needs). Magician may
/// enable Joker, sample its iterations, and follow up on crashes it finds.
/// </summary>
public static class JokerEngine
{
    public static bool IsEnabled(ProjectConfig project) =>
        project.Joker is { Enabled: true } ||
        (project.Joker?.EncoreIterations > 0);

    public static JokerConfig GetConfig(ProjectConfig project) =>
        project.Joker ??= new JokerConfig();

    /// <summary>Effective hijack chance (encore boosts after Magician enables Joker).</summary>
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
    /// Start a high-entropy iteration: pick a primary mutator (biased wild) and optional bias flips.
    /// Call <see cref="FinishTrick"/> after the normal payload is built to stack more mutators.
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
        double? flowOverride = null;
        double? graphOverride = null;
        var biasFlip = false;
        if (cfg.FlipSessionBias && rng.NextDouble() < 0.45)
        {
            flowOverride = rng.NextDouble();
            graphOverride = rng.NextDouble();
            biasFlip = true;
        }

        var strategy = NameStrategy(primary.Name, chaos, cfg.WildBytes, biasFlip);

        return new JokerTrick
        {
            Id = Guid.NewGuid().ToString("N")[..10],
            TrickName = strategy,
            PrimaryMutator = primary,
            MutatorChain = [primary.Name],
            ChaosLevel = chaos,
            Detail = $"strategy={strategy} primary={primary.Name} stack={chaos} wild={cfg.WildBytes} biasFlip={biasFlip}",
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
        sb.AppendLine("Joker — high-entropy multi-mutator iterations (docs/MAGICIAN.md#joker)");
        sb.AppendLine();
        sb.AppendLine("Not Magician. Joker occasionally hijacks an iteration: stacked mutators,");
        sb.AppendLine("random wild bytes, and optional session flow/graph bias overrides.");
        sb.AppendLine("Magician can enable Joker, sample its runs, and follow up on crashes.");
        sb.AppendLine();
        sb.AppendLine("YAML: joker: { enabled: true, chance: 0.12, maxStack: 4 }");
        sb.AppendLine("Magician: allowSummonJoker · watchJoker · capitalizeJokerCrashes");
        return sb.ToString();
    }

    /// <summary>Stable analysis label for crash notes / verbose logs (not comedy names).</summary>
    public static string NameStrategy(string primary, int stack, bool wild, bool biasFlip)
    {
        var parts = new List<string> { $"stack-{primary}" };
        if (stack > 2)
            parts.Add($"x{stack}");
        if (wild)
            parts.Add("wild");
        if (biasFlip)
            parts.Add("bias");
        return string.Join("+", parts);
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
        return buf;
    }
}
