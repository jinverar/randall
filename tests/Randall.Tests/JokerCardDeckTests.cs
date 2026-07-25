using Randall.Contracts;
using Randall.Core;
using Randall.Infrastructure.Magician;
using Randall.Infrastructure.Mutators;
using Xunit;

namespace Randall.Tests;

public class JokerCardDeckTests
{
    private static List<IMutator> TestMutators() =>
        BuiltInMutators.Create(["havoc", "interesting", "bitflip"], context: null).ToList();

    [Fact]
    public void SelectPlayMode_RespectsWeights()
    {
        var cfg = new JokerConfig
        {
            ChaosWeight = 1.0,
            RemixWeight = 0,
            ReplayWeight = 0,
        };
        var rng = new Random(42);
        for (var i = 0; i < 50; i++)
            Assert.Equal("chaos", JokerCardDeck.SelectPlayMode(cfg, rng));

        cfg = new JokerConfig { ChaosWeight = 0, RemixWeight = 1, ReplayWeight = 0 };
        rng = new Random(42);
        for (var i = 0; i < 50; i++)
            Assert.Equal("remix", JokerCardDeck.SelectPlayMode(cfg, rng));
    }

    [Fact]
    public void RecordOutcome_ScoresAndPromotesLegendary()
    {
        var dir = Path.Combine(Path.GetTempPath(), "joker-deck-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var path = JokerCardDeck.DefaultPath(dir);
        var deck = new JokerCardDeck(path);
        var project = new ProjectConfig
        {
            Name = "t",
            Joker = new JokerConfig
            {
                LegendaryScoreThreshold = 50,
                LegendaryMinProductiveUses = 2,
            },
        };
        var mutators = TestMutators();
        var trick = JokerEngine.StartTrick(project, mutators, new Random(0), deck);

        deck.RecordOutcome(
            project,
            trick,
            new JokerTrickOutcome(3, true, true, 10, true),
            "chaos");

        Assert.Single(deck.Cards);
        var card = deck.Cards[0];
        Assert.True(card.Score >= 50);
        Assert.Equal(1, card.UniqueScreams);

        deck.RecordOutcome(
            project,
            trick with { CardId = card.Id },
            new JokerTrickOutcome(2, false, true, 0, false),
            "remix");

        var updated = deck.Cards.Single(c => c.Id == card.Id);
        Assert.True(updated.Legendary);
        Assert.True(updated.ProductiveUses >= 2);
    }

    [Fact]
    public void Draw_RemixUsesKnownRecipe()
    {
        var dir = Path.Combine(Path.GetTempPath(), "joker-deck-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var deck = new JokerCardDeck(JokerCardDeck.DefaultPath(dir));
        var project = new ProjectConfig { Name = "t", Joker = new JokerConfig() };
        var mutators = TestMutators();

        var seedTrick = new JokerTrick
        {
            Id = "seed01",
            TrickName = "card-shuffle",
            PrimaryMutator = mutators[0],
            MutatorChain = ["interesting", "havoc"],
            ChaosLevel = 3,
            Detail = "test",
            WildBytes = true,
        };
        deck.RecordOutcome(
            project,
            seedTrick,
            new JokerTrickOutcome(5, true, true, 8, true),
            "chaos");

        var draw = deck.Draw(project, mutators, new Random(1), forcedMode: "remix");
        Assert.Equal("remix", draw.PlayMode);
        Assert.NotEmpty(draw.Recipe);
    }

    [Fact]
    public void QueueDeckDraw_ForcesMagicianMode()
    {
        var project = new ProjectConfig
        {
            Name = "t",
            Joker = new JokerConfig { DeckDrawQueue = 0 },
        };
        JokerCardDeck.QueueDeckDraw(project, legendary: true);
        Assert.Equal(1, project.Joker!.DeckDrawQueue);
        Assert.True(project.Joker.DeckDrawLegendary);

        var mutators = TestMutators();
        var trick = JokerEngine.StartTrick(project, mutators, new Random(0));
        Assert.Equal("replay", trick.PlayMode);
    }

    [Fact]
    public void Deck_PersistsToDisk()
    {
        var dir = Path.Combine(Path.GetTempPath(), "joker-deck-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var path = JokerCardDeck.DefaultPath(dir);
        var project = new ProjectConfig { Name = "t", Joker = new JokerConfig() };
        var mutators = TestMutators();

        var deck = new JokerCardDeck(path);
        var trick = JokerEngine.StartTrick(project, mutators, new Random(0), deck);
        deck.RecordOutcome(
            project,
            trick,
            new JokerTrickOutcome(4, false, true, 5, false),
            "chaos");

        var reloaded = new JokerCardDeck(path);
        Assert.Single(reloaded.Cards);
        Assert.True(File.Exists(path));
    }
}
