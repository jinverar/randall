using Randall.Contracts;
using Randall.Infrastructure;
using Randall.Infrastructure.Oracles;
using Xunit;

namespace Randall.Tests;

public class OracleScoreTests
{
    private static OracleObservation Obs(
        byte[] payload,
        TargetRunResult result,
        int newEdges = 0) =>
        new(
            new ProjectConfig { Name = "score-lab", Oracles = new OracleConfig { Enabled = true } },
            Path.GetTempPath(),
            payload,
            result,
            "GET",
            "bitflip",
            1,
            newEdges,
            100,
            null,
            null);

    [Fact]
    public void Score_EmptyObservation_ReturnsZero()
    {
        var score = OracleScorer.Score(
            Obs([], new TargetRunResult(false, 0, null, "ok")), [], OracleSeverity.None);
        Assert.Equal(0, score.Total);
    }

    [Fact]
    public void Score_NewCoverage_AddsUpToThirtyPoints()
    {
        var score = OracleScorer.Score(
            Obs([], new TargetRunResult(false, 0, null, "ok"), newEdges: 3),
            [], OracleSeverity.None);
        Assert.Equal(30, score.Total);
    }

    [Fact]
    public void Score_Violation_AddsThirtyFivePoints()
    {
        var findings = new List<OracleFindingDto> { MakeFinding("need-ok", "InvariantRule", "violation") };
        var score = OracleScorer.Score(
            Obs("x"u8.ToArray(), new TargetRunResult(false, 0, null, "ok", "NOPE"u8.ToArray())),
            findings, OracleSeverity.Violation);
        Assert.Equal(35, score.Total);
    }

    [Fact]
    public void Score_StateAuthViolation_AddsTwentyPointBonus()
    {
        var findings = new List<OracleFindingDto> { MakeFinding("no-bind", "AuthRule", "violation") };
        var score = OracleScorer.Score(
            Obs([], new TargetRunResult(false, 0, null, "ok", "RPC_OK"u8.ToArray())),
            findings, OracleSeverity.Violation);
        Assert.Equal(55, score.Total);
    }

    [Fact]
    public async Task EvaluateAsync_AttachesScoreToResult()
    {
        var project = new ProjectConfig
        {
            Name = "score-lab",
            Oracles = new OracleConfig
            {
                Enabled = true,
                PersistFindings = false,
                Invariants =
                [
                    new OracleInvariantRuleConfig
                    {
                        Id = "need-ok",
                        Type = "expectSubstring",
                        Pattern = "OK",
                        Severity = "violation",
                    },
                ],
            },
        };
        var obs = new OracleObservation(
            project, Path.GetTempPath(), "hi"u8.ToArray(),
            new TargetRunResult(false, 0, null, "ok", "NOPE"u8.ToArray()),
            "GET", "bitflip", 1, 2, 50, null, null);
        var eval = await OracleEngine.EvaluateAsync(obs);
        Assert.Equal(eval.Score.Total, eval.InterestingnessScore);
        Assert.True(eval.Score.Total >= 35);
    }

    private static OracleFindingDto MakeFinding(string ruleId, string ruleClass, string severity) =>
        new(
            Guid.NewGuid().ToString("N"), "score-lab", ruleId, ruleClass, severity, 0.9,
            "hash", "GET", "bitflip", 1, "expected", "actual", null, null, "edges=0", 1,
            DateTimeOffset.UtcNow);
}
