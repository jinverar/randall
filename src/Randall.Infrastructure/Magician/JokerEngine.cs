using System.Text;
using System.Text.Json;
using Randall.Contracts;
using Randall.Core;

namespace Randall.Infrastructure.Magician;

public sealed record JokerTrick
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
    public string? PlayMode { get; set; }
    public string? CardId { get; set; }
    public bool Legendary { get; set; }
}

public static class JokerEngine
{
    private static readonly string[] TrickNames =
    [
        "card-shuffle", "whoopee-cushion", "rubber-chicken", "pie-in-face",
        "banana-peel", "confetti-cannon", "wrong-door", "laugh-track",
    ];

    public static bool IsEnabled(ProjectConfig project) =>
        project.Joker is { Enabled: true } || (project.Joker?.EncoreIterations > 0);

    public static JokerConfig GetConfig(ProjectConfig project) =>
        project.Joker ??= new JokerConfig();

    public static double EffectiveChance(ProjectConfig project)
    {
        var cfg = GetConfig(project);
        if (cfg.EncoreIterations > 0) return Math.Clamp(cfg.EncoreChance, 0, 1);
        if (!cfg.Enabled) return 0;
        return Math.Clamp(cfg.Chance, 0, 1);
    }

    public static bool ShouldPlay(ProjectConfig project, Random rng) =>
        rng.NextDouble() < EffectiveChance(project);

    public static void QueueDeckDraw(ProjectConfig project, bool legendary = false) =>
        JokerCardDeck.QueueDeckDraw(project, legendary);

    public static JokerTrick StartTrick(
        ProjectConfig project, IReadOnlyList<IMutator> mutators, Random rng, JokerCardDeck? deck = null)
    {
        var cfg = GetConfig(project);
        if (cfg.EncoreIterations > 0) cfg.EncoreIterations--;

        if (mutators.Count == 0)
            throw new InvalidOperationException("Joker needs at least one mutator");

        string? queuedMode = null;
        var legendaryDraw = false;
        if (cfg.DeckDrawQueue > 0)
        {
            cfg.DeckDrawQueue--;
            queuedMode = "replay";
            legendaryDraw = cfg.DeckDrawLegendary;
            cfg.DeckDrawLegendary = false;
        }

        if (deck is not null && cfg.DeckEnabled)
        {
            var draw = queuedMode is not null
                ? deck.Draw(project, mutators, rng, forcedMode: queuedMode, legendaryOnly: legendaryDraw)
                : deck.Draw(project, mutators, rng);
            return BuildTrickFromDraw(draw, mutators, rng, cfg);
        }

        var trick = BuildClassicTrick(mutators, rng, cfg);
        if (queuedMode is not null) trick.PlayMode = queuedMode;
        return trick;
    }

    public static byte[] FinishTrick(JokerTrick trick, byte[] payload, IReadOnlyList<IMutator> mutators, Random rng, JokerConfig cfg)
    {
        var buf = payload;
        var stack = Math.Clamp(trick.ChaosLevel, 1, Math.Max(1, cfg.MaxStack));
        for (var i = 1; i < stack && mutators.Count > 0; i++)
        {
            var m = mutators[rng.Next(mutators.Count)];
            try { buf = m.Mutate(buf).ToArray(); trick.MutatorChain.Add(m.Name); } catch { }
        }
        if (trick.WildBytes && rng.NextDouble() < 0.65) buf = SprinkleWildBytes(buf, rng);
        trick.MutatorChain.Insert(0, $"joker:{trick.TrickName}");
        return buf;
    }

    public static void PersistWatch(string directory, JokerActDto act)
    {
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "joker_watch.jsonl");
        var json = JsonSerializer.Serialize(act, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, WriteIndented = false });
        File.AppendAllText(path, json + Environment.NewLine);
    }

    public static IReadOnlyList<JokerActDto> ListWatch(string directory, int take = 200)
    {
        var path = Path.Combine(directory, "joker_watch.jsonl");
        if (!File.Exists(path)) return [];
        var list = new List<JokerActDto>();
        var opts = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
        foreach (var line in File.ReadLines(path))
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            try { var a = JsonSerializer.Deserialize<JokerActDto>(line, opts); if (a is not null) list.Add(a); } catch { }
        }
        return list.OrderByDescending(a => a.At).Take(take).ToList();
    }

    public static string Describe()
    {
        var sb = new StringBuilder();
        sb.AppendLine("Joker — chaotic random fuzz tricks (docs/MAGICIAN.md#joker)");
        sb.AppendLine();
        sb.AppendLine("YAML: joker: { enabled: true, chance: 0.12, maxStack: 4 }");
        return sb.ToString();
    }

    private static JokerTrick BuildClassicTrick(IReadOnlyList<IMutator> mutators, Random rng, JokerConfig cfg)
    {
        var preferred = mutators.Where(m => m.Name is "havoc" or "interesting" or "dictionary" or "splice" or "expand" or "insert").ToList();
        var pool = preferred.Count > 0 && rng.NextDouble() < 0.7 ? preferred : mutators.ToList();
        var primary = pool[rng.Next(pool.Count)];
        var chaos = 1 + rng.Next(1, Math.Max(2, cfg.MaxStack + 1));
        var trick = TrickNames[rng.Next(TrickNames.Length)];
        double? flowOverride = null, graphOverride = null;
        if (cfg.FlipSessionBias && rng.NextDouble() < 0.45) { flowOverride = rng.NextDouble(); graphOverride = rng.NextDouble(); }
        return new JokerTrick
        {
            Id = Guid.NewGuid().ToString("N")[..10], TrickName = trick, PrimaryMutator = primary,
            MutatorChain = [primary.Name], ChaosLevel = chaos,
            Detail = $"joker:{trick} primary={primary.Name} chaos={chaos}",
            FlowBiasOverride = flowOverride, GraphBiasOverride = graphOverride, WildBytes = cfg.WildBytes, PlayMode = "chaos",
        };
    }

    private static JokerTrick BuildTrickFromDraw(JokerCardDrawDto draw, IReadOnlyList<IMutator> mutators, Random rng, JokerConfig cfg)
    {
        var recipe = draw.Recipe.Count > 0 ? draw.Recipe : [mutators[0].Name];
        var primary = mutators.FirstOrDefault(m => m.Name.Equals(recipe[0], StringComparison.OrdinalIgnoreCase)) ?? mutators[rng.Next(mutators.Count)];
        var trickName = draw.SourceCard?.TrickName ?? TrickNames[rng.Next(TrickNames.Length)];
        double? flowOverride = null, graphOverride = null;
        if (draw.FlipSessionBias && rng.NextDouble() < 0.45) { flowOverride = rng.NextDouble(); graphOverride = rng.NextDouble(); }
        return new JokerTrick
        {
            Id = Guid.NewGuid().ToString("N")[..10], TrickName = trickName, PrimaryMutator = primary,
            MutatorChain = recipe.ToList(), ChaosLevel = draw.ChaosLevel, Detail = draw.Detail,
            FlowBiasOverride = flowOverride, GraphBiasOverride = graphOverride, WildBytes = draw.WildBytes,
            PlayMode = draw.PlayMode, CardId = draw.SourceCard?.Id, Legendary = draw.SourceCard?.Legendary ?? false,
        };
    }

    private static byte[] SprinkleWildBytes(byte[] input, Random rng)
    {
        var len = Math.Max(1, input.Length + rng.Next(-8, 64));
        var buf = new byte[len];
        Buffer.BlockCopy(input, 0, buf, 0, Math.Min(input.Length, buf.Length));
        for (var i = 0; i < 1 + rng.Next(3, 24); i++) buf[rng.Next(buf.Length)] = (byte)rng.Next(256);
        return buf;
    }
}
