using System.Text;
using Randall.Contracts;
using Randall.Infrastructure;
using Randall.Infrastructure.BugHunt;
using Randall.Infrastructure.Oracles;
using Xunit;

namespace Randall.Tests;

public class OracleVulnserverTruthTests
{
    private static OracleObservation Obs(
        ProjectConfig project,
        byte[] payload,
        TargetRunResult result,
        string? command = "TRUN",
        int newEdges = 0) =>
        new(
            project,
            Path.GetTempPath(),
            payload,
            result,
            command,
            "havoc",
            1,
            newEdges,
            0,
            null,
            null);

    [Fact]
    public async Task LengthPrefix_DoesNotFire_OnTrunAsciiWithoutModeled()
    {
        // "TRUN /.:/AAAA" — first 4 bytes are ASCII command, not a uint32 length (0x4E555254).
        var payload = Encoding.ASCII.GetBytes("TRUN /.:/AAAA");
        var project = new ProjectConfig
        {
            Name = "vulnserver",
            Kind = "tcp",
            Oracles = new OracleConfig
            {
                Enabled = true,
                AuthEnabled = false,
                PersistFindings = false,
                Integer =
                [
                    new OracleIntegerRuleConfig
                    {
                        Id = "ai-length-prefix",
                        Type = "lengthPrefix",
                        Offset = 0,
                        Width = 4,
                        Endian = "le",
                        Covers = "rest",
                        MaxPlausible = 1_048_576,
                        Modeled = false, // unmodeled — must not fire
                        Experimental = true,
                        Severity = "violation",
                    },
                ],
            },
        };

        var eval = await OracleEngine.EvaluateAsync(Obs(
            project,
            payload,
            new TargetRunResult(false, 0, null, "ok", "TRUN COMPLETE"u8.ToArray(), Connected: true, PayloadSent: true)));

        Assert.DoesNotContain(eval.Findings, f => f.RuleId == "ai-length-prefix");
    }

    [Fact]
    public async Task LengthPrefix_DoesNotFire_OnAsciiEvenWhenModeled_IfCommandPrefix()
    {
        var payload = Encoding.ASCII.GetBytes("GTER AAAA");
        var project = new ProjectConfig
        {
            Name = "vulnserver",
            Kind = "tcp",
            Oracles = new OracleConfig
            {
                Enabled = true,
                PersistFindings = false,
                Integer =
                [
                    new OracleIntegerRuleConfig
                    {
                        Id = "modeled-len",
                        Type = "lengthPrefix",
                        Offset = 0,
                        Width = 4,
                        Endian = "le",
                        Covers = "rest",
                        Modeled = true,
                        Severity = "violation",
                    },
                ],
            },
        };

        var eval = await OracleEngine.EvaluateAsync(Obs(
            project,
            payload,
            new TargetRunResult(false, 0, null, "ok", "GTER COMPLETE"u8.ToArray(), Connected: true, PayloadSent: true),
            "GTER"));

        Assert.DoesNotContain(eval.Findings, f => f.RuleId == "modeled-len");
    }

    [Fact]
    public async Task AuthRules_Skipped_WhenAuthDisabled()
    {
        var project = new ProjectConfig
        {
            Name = "vulnserver",
            Kind = "tcp",
            Oracles = new OracleConfig
            {
                Enabled = true,
                AuthEnabled = false,
                PersistFindings = false,
                Auth =
                [
                    new OracleAuthRuleConfig
                    {
                        Id = "ai-no-success-before-auth",
                        Type = "forbidUntil",
                        ForbidResponse = "OK",
                        UntilResponse = "AUTH",
                        Severity = "violation",
                    },
                ],
            },
        };

        // Vulnserver-style "TRUN COMPLETE" / banner with OK substring must not auth-FP.
        var eval = await OracleEngine.EvaluateAsync(Obs(
            project,
            "TRUN /.:/x"u8.ToArray(),
            new TargetRunResult(false, 0, null, "ok", "TRUN COMPLETE OK"u8.ToArray(), Connected: true, PayloadSent: true)));

        Assert.DoesNotContain(eval.Findings, f => f.RuleClass == "AuthRule");
    }

    [Fact]
    public void BugHunterPack_DoesNotAutoArm_AuthOrLengthPrefix()
    {
        var merged = BugHunterOracleSuggestions.MergeInto(new OracleConfig { Enabled = false });
        Assert.False(merged.AuthEnabled);
        Assert.Empty(merged.Auth);
        Assert.Empty(merged.Integer);
        Assert.DoesNotContain(merged.Metamorphic, m => !m.Experimental);
    }

    [Fact]
    public void CrashScore_Outranks_BogusLengthPrefixFp()
    {
        var lengthFp = new OracleFindingDto(
            Guid.NewGuid().ToString("N"), "vulnserver", "ai-length-prefix", "IntegerRule",
            "violation", 0.85, "hash", "TRUN", "havoc", 1,
            "expected", "claimed=1314016852", null, "integer.lengthPrefix",
            "coverage-unavailable", 1, DateTimeOffset.UtcNow, Experimental: true);

        var fpScore = OracleScorer.Score(
            Obs(
                new ProjectConfig { Name = "vulnserver", Oracles = new OracleConfig { Enabled = true } },
                "TRUN /.:/AAAA"u8.ToArray(),
                new TargetRunResult(false, 0, null, "ok", "TRUN COMPLETE"u8.ToArray())),
            [lengthFp],
            OracleSeverity.Violation);

        var crashScore = OracleScorer.PreferCrash(
            fpScore,
            "Access Violation",
            newEdgesAtCrash: 0,
            crashed: true);

        Assert.True(fpScore.Total < 30, $"experimental FP should be low, got {fpScore.Total}");
        Assert.True(crashScore.Total >= 90, $"crash should dominate, got {crashScore.Total}");
        Assert.True(crashScore.Total > fpScore.Total);
    }

    [Fact]
    public void AsciiCommandPrefix_Detects_TrunGterHter()
    {
        Assert.True(OracleEngine.LooksLikeAsciiCommandPrefix("TRUN"u8.ToArray(), 0, 4));
        Assert.True(OracleEngine.LooksLikeAsciiCommandPrefix("GTER"u8.ToArray(), 0, 4));
        Assert.True(OracleEngine.LooksLikeAsciiCommandPrefix("HTER"u8.ToArray(), 0, 4));
        Assert.True(OracleEngine.LooksLikeAsciiCommandLine("TRUN /.:/AAAA"u8.ToArray()));
        // Binary length 0x00000100 LE
        Assert.False(OracleEngine.LooksLikeAsciiCommandPrefix([0x00, 0x01, 0x00, 0x00], 0, 4));
    }

    [Fact]
    public void FindingStore_Aggregates_SameInputHash()
    {
        var dir = Path.Combine(Path.GetTempPath(), "randall-oracle-" + Guid.NewGuid().ToString("N"));
        try
        {
            var store = new OracleFindingStore(dir);
            var baseFinding = new OracleFindingDto(
                Guid.NewGuid().ToString("N"), "vulnserver", "rule-x", "InvariantRule",
                "nearMiss", 0.5, "abc123", "TRUN", "havoc", 1,
                "exp", "act", null, null, "coverage-unavailable", 1, DateTimeOffset.UtcNow);

            store.AppendOrAggregate(baseFinding);
            var second = store.AppendOrAggregate(baseFinding with
            {
                Id = Guid.NewGuid().ToString("N"),
                Iteration = 99,
                At = DateTimeOffset.UtcNow,
            });

            var list = store.List("vulnserver");
            Assert.Single(list);
            Assert.Equal(2, list[0].ReproductionCount);
            Assert.Equal(2, second.ReproductionCount);
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { /* ignore */ }
        }
    }
}
