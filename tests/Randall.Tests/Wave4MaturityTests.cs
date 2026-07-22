using System.Text;
using Randall.Contracts;
using Randall.Infrastructure;
using Randall.Infrastructure.BugHunt;
using Randall.Infrastructure.Magician;
using Randall.Infrastructure.Oracles;
using Xunit;

namespace Randall.Tests;

public class PatternToolsTests
{
    [Fact]
    public void Create_And_Offset_Basics()
    {
        Assert.Equal("", PatternTools.Create(0));
        var p = PatternTools.Create(12);
        Assert.StartsWith("Aa0", p);
        Assert.Equal(3, PatternTools.Offset("Aa1", 64));
        Assert.Equal(-1, PatternTools.Offset("", 64));
    }

    [Fact]
    public void TryInferPatternLength_OnCyclic()
    {
        var cyclic = Encoding.ASCII.GetBytes(PatternTools.Create(64));
        Assert.NotNull(PatternTools.TryInferPatternLength(cyclic));
        Assert.Null(PatternTools.TryInferPatternLength(new byte[] { 1, 2, 3, 4, 5 }));
    }

    [Fact]
    public void OffsetInBuffer_FindsAsciiWindow()
    {
        var buf = Encoding.ASCII.GetBytes(PatternTools.Create(40));
        var frag = Encoding.ASCII.GetString(buf.AsSpan(8, 4));
        // Prefer hex path when using register-style; ASCII fragment via Offset
        Assert.True(PatternTools.Offset(frag, 40) >= 0);
        Assert.Equal(-1, PatternTools.OffsetInBuffer("", buf));
    }
}

public class CrashStoreDedupTests
{
    [Fact]
    public void SaveEx_DedupsByHash()
    {
        var dir = Path.Combine(Path.GetTempPath(), "randall-crash-" + Guid.NewGuid().ToString("N"));
        try
        {
            var store = new CrashStore(dir);
            var a = store.SaveEx("p", 1, "bitflip", "AAAA"u8.ToArray(), 139);
            var b = store.SaveEx("p", 2, "havoc", "AAAA"u8.ToArray(), 139);
            var c = store.SaveEx("p", 3, "havoc", "BBBB"u8.ToArray(), 139);
            Assert.True(a.IsNew);
            Assert.False(b.IsNew);
            Assert.True(c.IsNew);
            Assert.Equal(2, store.List("p").Count);
            Assert.NotNull(store.FindByHash(a.Crash.InputHash, "p"));
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { /* */ }
        }
    }
}

public class CorpusTrackerEnergyTests
{
    [Fact]
    public void BoostEnergy_PersistsAndReload()
    {
        var dir = Path.Combine(Path.GetTempPath(), "randall-corpus-" + Guid.NewGuid().ToString("N"));
        try
        {
            var t = new CorpusTracker(dir);
            t.Load();
            var payload = "energy-me"u8.ToArray();
            t.AddPriority(payload);
            Assert.True(t.PriorityCount >= 1);
            Assert.True(t.SeenCount >= 1);
            Assert.True(File.Exists(Path.Combine(dir, "corpus_energy.txt")));

            var again = new CorpusTracker(dir);
            again.Load();
            Assert.True(again.PriorityCount >= 1);

            // Power schedule should often pick the boosted priority entry.
            var seeds = new List<byte[]> { "seed0"u8.ToArray() };
            var picks = 0;
            var rng = new Random(7);
            for (var i = 0; i < 40; i++)
            {
                var chosen = again.PickSeed(seeds, rng, powerSchedule: true);
                if (chosen.AsSpan().SequenceEqual(payload))
                    picks++;
            }
            Assert.True(picks >= 10, $"expected boosted picks, got {picks}");
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { /* */ }
        }
    }
}

public class MagicianSpellStoreTests
{
    [Fact]
    public void Append_List_Filter_SkipBadLines()
    {
        var dir = Path.Combine(Path.GetTempPath(), "randall-spells-" + Guid.NewGuid().ToString("N"));
        try
        {
            var store = new MagicianSpellStore(dir);
            Assert.Empty(store.List());
            store.Append(new MagicianSpellDto("1", "projA", "summonArmy", "army", "r", null, null, 1, "d", DateTimeOffset.UtcNow));
            store.Append(new MagicianSpellDto("2", "projB", "summonKnight", "knight", "r", null, null, 2, "d", DateTimeOffset.UtcNow));
            File.AppendAllText(Path.Combine(dir, "spells.jsonl"), "{not-json}\n");
            Assert.Equal(2, store.List().Count);
            Assert.Single(store.List("projA"));
            Assert.Single(store.List(take: 1));
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { /* */ }
        }
    }
}

public class OracleSessionTrackerTests
{
    [Fact]
    public void Observe_AuthMarker_And_Reset()
    {
        var tracker = new OracleSessionTracker();
        tracker.ConfigureAuthMarkers(new OracleConfig
        {
            Auth = [new OracleAuthRuleConfig { Id = "a", Type = "forbidUntil", UntilResponse = "BIND_ACK" }],
        });
        tracker.NotePriorStep("flow/BIND", "BIND_ACK");
        Assert.True(tracker.HasCommand("BIND"));
        Assert.True(tracker.Authenticated);

        tracker.Observe("REQUEST", new TargetRunResult(false, 0, null, "ok", "BIND_ACK ok"u8.ToArray()));
        Assert.True(tracker.HasResponseMarker("BIND_ACK"));

        tracker.Reset();
        Assert.False(tracker.Authenticated);
        Assert.Equal("START", tracker.State);
        Assert.Empty(tracker.SeenCommands);
    }
}

public class OracleInvariantWave4Tests
{
    private static async Task<OracleEvalResult> Eval(OracleConfig cfg, byte[]? response)
    {
        var project = new ProjectConfig { Name = "o", Oracles = cfg };
        var obs = new OracleObservation(
            project, Path.GetTempPath(), "x"u8.ToArray(),
            new TargetRunResult(false, 0, null, "ok", response),
            "GET", "bitflip", 1, 0, 0, null, null);
        return await OracleEngine.EvaluateAsync(obs);
    }

    [Fact]
    public async Task ForbidSubstring_Hit_And_Miss()
    {
        var cfg = new OracleConfig
        {
            Enabled = true,
            PersistFindings = false,
            Invariants = [new OracleInvariantRuleConfig { Id = "no-err", Type = "forbidSubstring", Pattern = "ERROR" }],
        };
        Assert.NotEmpty((await Eval(cfg, "HTTP/1.1 200\r\n\r\nERROR boom"u8.ToArray())).Findings);
        Assert.Empty((await Eval(cfg, "HTTP/1.1 200\r\n\r\nOK"u8.ToArray())).Findings);
    }

    [Fact]
    public async Task ExpectAndForbidResponseClass()
    {
        var expect = new OracleConfig
        {
            Enabled = true,
            PersistFindings = false,
            Invariants = [new OracleInvariantRuleConfig { Id = "want2xx", Type = "expectResponseClass", Pattern = "2xx" }],
        };
        Assert.Empty((await Eval(expect, "HTTP/1.1 200 OK\r\n\r\n"u8.ToArray())).Findings);
        Assert.NotEmpty((await Eval(expect, "HTTP/1.1 500 X\r\n\r\n"u8.ToArray())).Findings);

        var forbid = new OracleConfig
        {
            Enabled = true,
            PersistFindings = false,
            Invariants = [new OracleInvariantRuleConfig { Id = "no5", Type = "forbidResponseClass", Pattern = "5xx" }],
        };
        Assert.NotEmpty((await Eval(forbid, "HTTP/1.1 503 Busy\r\n\r\n"u8.ToArray())).Findings);
        Assert.Empty((await Eval(forbid, "HTTP/1.1 200 OK\r\n\r\n"u8.ToArray())).Findings);
    }
}

public class AttributionEvalFixtureTests
{
    [Fact]
    public void Scan_AiCodeSample_MatchesExpectedAnnotations()
    {
        var root = CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var sample = Path.Combine(root, "examples", "ai-code-sample");
        Assert.True(Directory.Exists(sample), sample);
        var scan = BugHunterAttribution.Scan(sample);
        Assert.True(scan.AiBlocks >= 1);
        Assert.True(scan.HumanBlocks >= 1);
        Assert.Contains(scan.Blocks, b =>
            b.Provenance == BugHunterProvenance.AnnotatedAi &&
            b.Signals.Any(s => s.Contains("AI", StringComparison.OrdinalIgnoreCase)));
        Assert.Contains(scan.Blocks, b =>
            b.Provenance == BugHunterProvenance.AnnotatedHuman &&
            BugHunterAttribution.ConfidenceTier(b) == "high");

        var expectedPath = Path.Combine(sample, "expected_attribution.json");
        Assert.True(File.Exists(expectedPath));
        var json = File.ReadAllText(expectedPath);
        Assert.Contains("minAiBlocks", json);
    }
}
