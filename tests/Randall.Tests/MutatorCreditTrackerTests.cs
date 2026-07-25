using Randall.Infrastructure;
using Randall.Infrastructure.Mutators;
using Randall.Core;
using Xunit;

namespace Randall.Tests;

public class MutatorCreditTrackerTests
{
    [Theory]
    [InlineData(0, 0, 0)]
    [InlineData(3, 0, 30)]
    [InlineData(0, 1, 100)]
    [InlineData(5, 2, 250)]
    public void ComputeScore_EdgesAndCrashes(int edges, int crashes, double expected)
    {
        Assert.Equal(expected, MutatorCreditTracker.ComputeScore(edges, crashes));
    }

    [Fact]
    public void Record_AccumulatesRunsEdgesAndUniqueCrashes()
    {
        var tracker = new MutatorCreditTracker(persistPath: null, biasEnabled: true);
        tracker.Record("bitflip", newEdges: 2, uniqueCrash: false);
        tracker.Record("bitflip", newEdges: 0, uniqueCrash: true);
        tracker.Record("havoc", newEdges: 1, uniqueCrash: false);

        var rows = tracker.SnapshotRows();
        var bitflip = rows.Single(r => r.Name == "bitflip");
        var havoc = rows.Single(r => r.Name == "havoc");

        Assert.Equal(2, bitflip.Runs);
        Assert.Equal(2, bitflip.NewEdges);
        Assert.Equal(1, bitflip.UniqueCrashes);
        Assert.Equal(120, bitflip.Score);
        Assert.Equal(1, havoc.Runs);
        Assert.Equal(10, havoc.Score);
    }

    [Fact]
    public void SelectionWeight_UsesAverageScorePerRun()
    {
        var tracker = new MutatorCreditTracker(persistPath: null, biasEnabled: true);
        tracker.Record("hot", newEdges: 10, uniqueCrash: false);   // score 100, avg 100
        tracker.Record("cold", newEdges: 0, uniqueCrash: false);  // score 0

        Assert.Equal(101, tracker.GetSelectionWeight("hot"));
        Assert.Equal(1, tracker.GetSelectionWeight("cold"));
    }

    [Fact]
    public void Pick_FavorsProductiveMutator_WhenBiasEnabled()
    {
        var rng = new Random(42);
        var dir = Path.Combine(Path.GetTempPath(), "randall-credit-" + Guid.NewGuid().ToString("N"));
        var persist = Path.Combine(dir, "mutator_credit.txt");
        try
        {
            var tracker = new MutatorCreditTracker(persist, biasEnabled: true);
            tracker.Record("bitflip", newEdges: 20, uniqueCrash: false);
            tracker.Record("truncate", newEdges: 0, uniqueCrash: false);

            var mutators = new List<IMutator>
            {
                new BitFlipMutator(rng),
                new TruncateMutator(rng),
            };

            var bitflipPicks = 0;
            for (var i = 0; i < 200; i++)
            {
                if (tracker.Pick(mutators, rng).Name == "bitflip")
                    bitflipPicks++;
            }

            Assert.True(bitflipPicks >= 120, $"expected bias toward bitflip, got {bitflipPicks}/200");
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { /* */ }
        }
    }

    [Fact]
    public void SaveAndLoad_PersistsAcrossRuns()
    {
        var dir = Path.Combine(Path.GetTempPath(), "randall-credit-" + Guid.NewGuid().ToString("N"));
        var persist = Path.Combine(dir, "mutator_credit.txt");
        try
        {
            var first = new MutatorCreditTracker(persist, biasEnabled: true);
            first.Record("expand", newEdges: 4, uniqueCrash: true);
            first.Save();

            var second = new MutatorCreditTracker(persist, biasEnabled: true);
            var row = second.SnapshotRows().Single();
            Assert.Equal("expand", row.Name);
            Assert.Equal(1, row.Runs);
            Assert.Equal(4, row.NewEdges);
            Assert.Equal(1, row.UniqueCrashes);
            Assert.Equal(140, row.Score);
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { /* */ }
        }
    }

    [Fact]
    public void RecordWithChain_CreditsUniqueCrashToLineageMutators()
    {
        var tracker = new MutatorCreditTracker(persistPath: null, biasEnabled: true);
        tracker.RecordWithChain("expand", ["seed", "havoc", "expand"], newEdges: 2, uniqueCrash: true);

        var rows = tracker.SnapshotRows().ToDictionary(r => r.Name, StringComparer.OrdinalIgnoreCase);
        Assert.Equal(1, rows["expand"].UniqueCrashes);
        Assert.Equal(1, rows["seed"].UniqueCrashes);
        Assert.Equal(1, rows["havoc"].UniqueCrashes);
        Assert.Equal(0, rows["seed"].Runs);
        Assert.Equal(1, rows["expand"].Runs);
    }

    [Fact]
    public void RecordWithChain_SkipsJokerWrappersOnUniqueCrash()
    {
        var tracker = new MutatorCreditTracker(persistPath: null, biasEnabled: true);
        tracker.RecordWithChain("havoc", ["joker:double", "bitflip", "havoc"], newEdges: 0, uniqueCrash: true);

        var rows = tracker.SnapshotRows();
        Assert.DoesNotContain(rows, r => r.Name.StartsWith("joker:", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(1, rows.Single(r => r.Name == "bitflip").UniqueCrashes);
    }

    [Fact]
    public void WriteRunJson_WritesLeaderboardFile()
    {
        var runDir = Path.Combine(Path.GetTempPath(), "randall-credit-run-" + Guid.NewGuid().ToString("N"));
        try
        {
            var tracker = new MutatorCreditTracker(persistPath: null, biasEnabled: true);
            tracker.Record("dictionary", newEdges: 1, uniqueCrash: false);
            tracker.WriteRunJson(runDir);

            var path = Path.Combine(runDir, "mutator_stats.json");
            Assert.True(File.Exists(path));
            var text = File.ReadAllText(path);
            Assert.Contains("dictionary", text, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("BiasEnabled", text, StringComparison.Ordinal);
        }
        finally
        {
            try { Directory.Delete(runDir, true); } catch { /* */ }
        }
    }
}
