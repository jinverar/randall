using System.Text;
using Randall.Contracts;
using Randall.Core;
using Randall.Infrastructure;
using Randall.Infrastructure.Magician;
using Randall.Infrastructure.Mutators;
using Randall.Infrastructure.Oracles;
using Xunit;

namespace Randall.Tests;

public class HttpFramingTests
{
    [Fact]
    public void TrySyncContentLength_RewritesBodyLength()
    {
        var raw = "POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\n\r\nHELLO"u8.ToArray();
        var synced = HttpFraming.TrySyncContentLength(raw);
        var text = Encoding.ASCII.GetString(synced);
        Assert.Contains("Content-Length: 5", text);
        Assert.EndsWith("HELLO", text);
    }

    [Fact]
    public void TrySyncContentLength_SkipsChunkedAndMissing()
    {
        var chunked = "POST /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nHELLO\r\n"u8.ToArray();
        Assert.Same(chunked, HttpFraming.TrySyncContentLength(chunked)); // returns same ref when unchanged early… may copy
        var chunkedOut = HttpFraming.TrySyncContentLength(chunked);
        Assert.Equal(chunked, chunkedOut);

        var noCl = "GET / HTTP/1.1\r\nHost: h\r\n\r\n"u8.ToArray();
        Assert.Equal(noCl, HttpFraming.TrySyncContentLength(noCl));
    }

    [Theory]
    [InlineData("HTTP/1.1 200 OK\r\n\r\n", "2xx")]
    [InlineData("HTTP/1.0 404 Not Found\r\n\r\n", "4xx")]
    [InlineData("HTTP/1.1 503 Busy\r\n\r\n", "5xx")]
    [InlineData("not http", "non-http")]
    public void StatusClass_Parses(string response, string expected) =>
        Assert.Equal(expected, HttpFraming.StatusClass(Encoding.ASCII.GetBytes(response)));

    [Fact]
    public void StatusClass_Empty()
    {
        Assert.Equal("empty", HttpFraming.StatusClass(null));
        Assert.Equal("empty", HttpFraming.StatusClass([]));
    }

    [Fact]
    public void LooksLikeHttpRequest_Heuristic()
    {
        Assert.True(HttpFraming.LooksLikeHttpRequest("GET / HTTP/1.1\r\n\r\n"u8));
        Assert.True(HttpFraming.LooksLikeHttpRequest("POST /a HTTP/1.1\r\n\r\n"u8));
        Assert.False(HttpFraming.LooksLikeHttpRequest("SMB...."u8));
        Assert.False(HttpFraming.LooksLikeHttpRequest("G"u8));
    }
}

public class OracleNeedsTests
{
    private static OracleFindingDto Finding(string cls, string sev, string id = "r1") =>
        new("f1", "proj", id, cls, sev, 0.9, "hash", null, null, 1, "exp", "act", null, null, null, 1, DateTimeOffset.UtcNow);

    [Fact]
    public void FromFindings_AuthViolation_MapsCoreNeeds()
    {
        var needs = OracleNeeds.FromFindings([Finding("auth", "violation")]);
        var reqs = needs.Select(n => n.Request).ToHashSet(StringComparer.OrdinalIgnoreCase);
        Assert.Contains("energy", reqs);
        Assert.Contains("dictionary", reqs);
        Assert.Contains("hunter", reqs);
        Assert.Contains("bots", reqs);
    }

    [Fact]
    public void FromFindings_InvariantHard_IncludesRearm()
    {
        var needs = OracleNeeds.FromFindings([Finding("invariant", "violation")]);
        Assert.Contains(needs, n => n.Request == "rearm");
    }

    [Fact]
    public void FromFindings_DedupesSameRule()
    {
        var f = Finding("structure", "nearMiss");
        var needs = OracleNeeds.FromFindings([f, f]);
        Assert.Equal(needs.Count, needs.Select(n => $"{n.Request}:{n.RuleId}").Distinct().Count());
    }
}

public class MagicianJokerTests
{
    [Fact]
    public void Joker_EffectiveChance_UsesEncore()
    {
        var p = new ProjectConfig { Name = "t", Joker = new JokerConfig { Enabled = true, Chance = 0.1, EncoreIterations = 2, EncoreChance = 0.9 } };
        Assert.Equal(0.9, JokerEngine.EffectiveChance(p));
        var muts = BuiltInMutators.Create(["bitflip", "havoc"], seed: 1).ToList();
        var trick = JokerEngine.StartTrick(p, muts, new Random(0));
        Assert.StartsWith(trick.PrimaryMutator.Name, string.Join(',', trick.MutatorChain));
        Assert.True(trick.ChaosLevel >= 1);
        Assert.Equal(1, p.Joker!.EncoreIterations); // decremented
    }

    [Fact]
    public void Joker_ShouldPlay_RespectsChanceBounds()
    {
        var never = new ProjectConfig { Name = "t", Joker = new JokerConfig { Enabled = true, Chance = 0 } };
        var always = new ProjectConfig { Name = "t", Joker = new JokerConfig { Enabled = true, Chance = 1 } };
        var rng = new Random(42);
        Assert.False(JokerEngine.ShouldPlay(never, rng));
        Assert.True(JokerEngine.ShouldPlay(always, rng));
    }

    [Fact]
    public void Magician_CastNeed_ArmyAndKnight()
    {
        var project = new ProjectConfig
        {
            Name = "t",
            Magician = new MagicianConfig { Enabled = true, PersistSpells = false, AllowSummonArmy = true, AllowSummonKnight = true },
            Mutators = ["bitflip"],
            Fuzz = new FuzzConfig { CoverageGuided = false },
        };
        var army = MagicianEngine.CastNeed(project, Path.GetTempPath(), "army");
        Assert.Contains(army.Spells, s => s.Spell.Contains("Army", StringComparison.OrdinalIgnoreCase) || s.Spell == "summonArmy");
        Assert.Contains(project.Mutators, m => m is "havoc" or "interesting" or "dictionary");

        var knight = MagicianEngine.CastNeed(project, Path.GetTempPath(), "knight");
        Assert.Contains(knight.Spells, s => s.Spell == "summonKnight");
        Assert.True(project.Fuzz.CoverageGuided);
    }

    [Fact]
    public void Magician_DescribeCatalog_MentionsJoker()
    {
        var cat = MagicianEngine.DescribeCatalog();
        Assert.Contains("summonJoker", cat);
        Assert.Contains("capitalizeJoker", cat);
    }

    [Fact]
    public void Joker_StrategyName_IsAnalytical()
    {
        Assert.Equal("stack-havoc", JokerEngine.NameStrategy("havoc", 2, false, false));
        Assert.Equal("stack-havoc+x4+wild", JokerEngine.NameStrategy("havoc", 4, true, false));
        Assert.Equal("stack-interesting+x3+wild+bias", JokerEngine.NameStrategy("interesting", 3, true, true));

        var p = new ProjectConfig
        {
            Name = "t",
            Joker = new JokerConfig { Enabled = true, Chance = 1, MaxStack = 3, WildBytes = true, FlipSessionBias = false },
        };
        var muts = BuiltInMutators.Create(["havoc", "bitflip"], seed: 1).ToList();
        var trick = JokerEngine.StartTrick(p, muts, new Random(1));
        Assert.StartsWith("stack-", trick.TrickName);
        Assert.DoesNotContain("laugh", trick.TrickName);
        Assert.DoesNotContain("pie", trick.TrickName);
        Assert.Contains("primary=", trick.Detail);
    }
}

public class StalkProfileTests
{
    [Fact]
    public void Apply_RewritesFuzzSettings()
    {
        var project = new ProjectConfig { Name = "t", Mutators = ["bitflip"] };
        var basic = StalkProfiles.Apply(project, "basic");
        Assert.Equal(100, project.Fuzz.MaxIterations);
        Assert.Equal(2, project.Fuzz.HavocDepth);
        Assert.False(project.Fuzz.PowerSchedule);
        Assert.Equal(["bitflip", "insert"], project.Mutators);

        StalkProfiles.Apply(project, "fuzzier", coverageAvailable: true);
        Assert.True(project.Fuzz.CoverageGuided);
        Assert.True(project.Fuzz.PowerSchedule);
        Assert.Contains("splice", project.Mutators);
        Assert.Equal("basic", basic.Name);
    }

    [Theory]
    [InlineData("basic", true)]
    [InlineData("FUZZ", true)]
    [InlineData("nope", false)]
    public void IsKnown(string name, bool ok) => Assert.Equal(ok, StalkProfiles.IsKnown(name));
}

public class PortablePackerRidTests
{
    [Fact]
    public void DefaultRid_IsNonEmpty()
    {
        var rid = PortablePacker.DefaultRid();
        Assert.False(string.IsNullOrWhiteSpace(rid));
        Assert.Contains(rid.Split('-')[0], new[] { "win", "linux", "osx" });
    }
}
