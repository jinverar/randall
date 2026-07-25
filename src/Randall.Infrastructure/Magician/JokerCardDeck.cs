using System.Text.Json;
using Randall.Contracts;
using Randall.Core;

namespace Randall.Infrastructure.Magician;

/// <summary>
/// Persistent Joker Card deck — chaos / remix / replay draws with legendary promotion.
/// Stored under crashes/_magician/joker_deck.json (max 64 cards).
/// </summary>
public sealed class JokerCardDeck
{
    public const int MaxCards = 64;
    public const int StateVersion = 1;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
    };

    private readonly string _path;
    private readonly List<JokerCardRecordDto> _cards;

    public IReadOnlyList<JokerCardRecordDto> Cards => _cards;

    public JokerCardDeck(string path)
    {
        _path = path;
        _cards = Load(path);
    }

    public static string DefaultPath(string directory) =>
        Path.Combine(directory, "joker_deck.json");

    public static string SelectPlayMode(JokerConfig cfg, Random rng)
    {
        var chaos = Math.Max(0, cfg.ChaosWeight);
        var remix = Math.Max(0, cfg.RemixWeight);
        var replay = Math.Max(0, cfg.ReplayWeight);
        var total = chaos + remix + replay;
        if (total <= 0)
        {
            chaos = 70;
            remix = 20;
            replay = 10;
            total = 100;
        }

        var roll = rng.NextDouble() * total;
        if (roll < chaos)
            return "chaos";
        if (roll < chaos + remix)
            return "remix";
        return "replay";
    }

    public static void QueueDeckDraw(ProjectConfig project, bool legendary = false)
    {
        var cfg = JokerEngine.GetConfig(project);
        cfg.DeckDrawQueue++;
        if (legendary)
            cfg.DeckDrawLegendary = true;
    }

    public JokerCardDrawDto Draw(
        ProjectConfig project,
        IReadOnlyList<IMutator> mutators,
        Random rng,
        string? forcedMode = null,
        bool legendaryOnly = false)
    {
        var mode = forcedMode ?? SelectPlayMode(JokerEngine.GetConfig(project), rng);

        return mode switch
        {
            "remix" => DrawRemix(project, mutators, rng),
            "replay" => DrawReplay(project, mutators, rng, legendaryOnly),
            _ => DrawChaos(project, mutators, rng),
        };
    }

    public void RecordOutcome(
        ProjectConfig project,
        JokerTrick trick,
        JokerTrickOutcome outcome,
        string playMode)
    {
        var cfg = JokerEngine.GetConfig(project);
        var now = DateTimeOffset.UtcNow;
        var delta = ScoreDelta(outcome);
        var productive = IsProductive(outcome);
        var recipe = SanitizeRecipe(trick.MutatorChain);

        var idx = string.IsNullOrWhiteSpace(trick.CardId)
            ? -1
            : _cards.FindIndex(c => c.Id.Equals(trick.CardId, StringComparison.OrdinalIgnoreCase));

        if (idx >= 0)
        {
            var card = _cards[idx];
            var score = card.Score + delta;
            var productiveUses = card.ProductiveUses + (productive ? 1 : 0);
            var legendary = card.Legendary ||
                            (score >= cfg.LegendaryScoreThreshold &&
                             productiveUses >= cfg.LegendaryMinProductiveUses);

            _cards[idx] = card with
            {
                Score = score,
                NewEdges = card.NewEdges + outcome.NewEdges,
                UniqueScreams = card.UniqueScreams + (outcome.UniqueCrash ? 1 : 0),
                ScareDoorHits = card.ScareDoorHits + (outcome.NewCoverage ? 1 : 0),
                OracleDelta = card.OracleDelta + outcome.OracleScoreDelta,
                ProductiveUses = productiveUses,
                Legendary = legendary,
                LastUsedAt = now,
                Recipe = recipe.Count > 0 ? recipe : card.Recipe,
            };
        }
        else
        {
            var id = Guid.NewGuid().ToString("N")[..10];
            var score = delta;
            var productiveUses = productive ? 1 : 0;
            var legendary = score >= cfg.LegendaryScoreThreshold &&
                            productiveUses >= cfg.LegendaryMinProductiveUses;

            _cards.Add(new JokerCardRecordDto(
                id,
                trick.TrickName,
                recipe,
                trick.ChaosLevel,
                trick.WildBytes,
                cfg.FlipSessionBias,
                score,
                outcome.NewEdges,
                outcome.UniqueCrash ? 1 : 0,
                outcome.NewCoverage ? 1 : 0,
                outcome.OracleScoreDelta,
                productiveUses,
                legendary,
                now,
                now));

            trick.CardId = id;
        }

        TrimToMax();
        Persist();
    }

    private JokerCardDrawDto DrawChaos(ProjectConfig project, IReadOnlyList<IMutator> mutators, Random rng)
    {
        var cfg = JokerEngine.GetConfig(project);
        var preferred = mutators
            .Where(m => m.Name is "havoc" or "interesting" or "dictionary" or "splice" or "expand" or "insert")
            .ToList();
        var pool = preferred.Count > 0 && rng.NextDouble() < 0.7 ? preferred : mutators.ToList();
        var primary = pool[rng.Next(pool.Count)];
        var chaos = 1 + rng.Next(1, Math.Max(2, cfg.MaxStack + 1));
        var recipe = new List<string> { primary.Name };

        return new JokerCardDrawDto(
            "chaos",
            null,
            recipe,
            chaos,
            cfg.WildBytes,
            cfg.FlipSessionBias,
            $"joker:chaos primary={primary.Name} chaos={chaos}");
    }

    private JokerCardDrawDto DrawRemix(ProjectConfig project, IReadOnlyList<IMutator> mutators, Random rng)
    {
        var source = PickCard(rng, legendaryOnly: false);
        if (source is null)
            return DrawChaos(project, mutators, rng);

        var recipe = source.Recipe.ToList();
        if (recipe.Count == 0)
            return DrawChaos(project, mutators, rng);

        if (recipe.Count > 1 && rng.NextDouble() < 0.55)
        {
            var i = rng.Next(recipe.Count);
            var j = rng.Next(recipe.Count);
            (recipe[i], recipe[j]) = (recipe[j], recipe[i]);
        }
        else if (mutators.Count > 0)
        {
            var idx = rng.Next(recipe.Count);
            recipe[idx] = mutators[rng.Next(mutators.Count)].Name;
        }

        return new JokerCardDrawDto(
            "remix",
            source,
            recipe,
            source.ChaosLevel,
            source.WildBytes,
            source.FlipSessionBias,
            $"joker:remix card={source.Id} legendary={source.Legendary}");
    }

    private JokerCardDrawDto DrawReplay(
        ProjectConfig project,
        IReadOnlyList<IMutator> mutators,
        Random rng,
        bool legendaryOnly)
    {
        var source = PickCard(rng, legendaryOnly);
        if (source is null)
            return DrawChaos(project, mutators, rng);

        return new JokerCardDrawDto(
            "replay",
            source,
            source.Recipe,
            source.ChaosLevel,
            source.WildBytes,
            source.FlipSessionBias,
            $"joker:replay card={source.Id} legendary={source.Legendary}");
    }

    private JokerCardRecordDto? PickCard(Random rng, bool legendaryOnly)
    {
        var pool = legendaryOnly
            ? _cards.Where(c => c.Legendary).ToList()
            : _cards.ToList();
        if (pool.Count == 0)
            return legendaryOnly ? _cards.OrderByDescending(c => c.Score).FirstOrDefault() : null;
        if (pool.Count == 1)
            return pool[0];

        var total = pool.Sum(c => Math.Max(1.0, c.Score));
        var roll = rng.NextDouble() * total;
        foreach (var card in pool)
        {
            roll -= Math.Max(1.0, card.Score);
            if (roll <= 0)
                return card;
        }

        return pool[^1];
    }

    private void TrimToMax()
    {
        while (_cards.Count > MaxCards)
        {
            var victim = _cards
                .Where(c => !c.Legendary)
                .OrderBy(c => c.Score)
                .ThenBy(c => c.LastUsedAt)
                .FirstOrDefault();
            if (victim is null)
                break;
            _cards.Remove(victim);
        }

        if (_cards.Count > MaxCards)
            _cards.RemoveRange(0, _cards.Count - MaxCards);
    }

    private void Persist()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        var state = new JokerDeckStateDto(StateVersion, DateTimeOffset.UtcNow, _cards.ToList());
        File.WriteAllText(_path, JsonSerializer.Serialize(state, JsonOptions));
    }

    private static List<JokerCardRecordDto> Load(string path)
    {
        if (!File.Exists(path))
            return [];

        try
        {
            var dto = JsonSerializer.Deserialize<JokerDeckStateDto>(File.ReadAllText(path), JsonOptions);
            return dto?.Cards?.ToList() ?? [];
        }
        catch
        {
            return [];
        }
    }

    private static List<string> SanitizeRecipe(IReadOnlyList<string> chain) =>
        chain
            .Where(n => !string.IsNullOrWhiteSpace(n) && !n.StartsWith("joker:", StringComparison.OrdinalIgnoreCase))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

    private static double ScoreDelta(JokerTrickOutcome outcome) =>
        outcome.NewEdges * 5
        + (outcome.UniqueCrash ? 25 : 0)
        + (outcome.NewCoverage ? 12 : 0)
        + outcome.OracleScoreDelta
        + (outcome.Crashed ? 10 : 0);

    private static bool IsProductive(JokerTrickOutcome outcome) =>
        outcome.NewCoverage || outcome.NewEdges > 0 || outcome.UniqueCrash || outcome.Crashed;
}
