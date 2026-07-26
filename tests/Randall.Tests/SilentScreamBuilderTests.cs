using Randall.Contracts;
using Randall.Infrastructure.Mutators;
using Randall.Infrastructure;
using Randall.Infrastructure.Oracles;
using Xunit;

namespace Randall.Tests;

public class SilentScreamBuilderTests
{
    [Fact]
    public void Qualifies_requires_violation_score_and_invariant_class()
    {
        var low = new OracleEvalResult(
            OracleSeverity.NearMiss,
            new OracleScore(50, [], "near"),
            [MakeFinding("InvariantRule", "nearMiss")],
            false, 0, "near", []);
        Assert.False(SilentScreamBuilder.Qualifies(low));

        var ok = new OracleEvalResult(
            OracleSeverity.Violation,
            new OracleScore(55, [], "violation"),
            [MakeFinding("InvariantRule", "violation")],
            true, 8, "auth bypass", []);
        Assert.True(SilentScreamBuilder.Qualifies(ok));

        var noInvariant = new OracleEvalResult(
            OracleSeverity.Violation,
            new OracleScore(60, [], "violation"),
            [MakeFinding("MetamorphicRule", "violation")],
            true, 8, "meta", []);
        Assert.False(SilentScreamBuilder.Qualifies(noInvariant));
    }

    [Fact]
    public void Promote_bottles_oracle_violation_without_dump()
    {
        var dir = Path.Combine(Path.GetTempPath(), "randall-silent-" + Guid.NewGuid().ToString("N"));
        try
        {
            var store = new CrashStore(dir);
            var project = new ProjectConfig
            {
                Name = "silent-lab",
                Kind = "file",
                Academy = new AcademyConfig { SilentScreams = true },
            };
            var payload = "ORACLE_BAD"u8.ToArray();
            var hash = InputHash.StackHash(payload);
            var eval = new OracleEvalResult(
                OracleSeverity.Violation,
                new OracleScore(72, [new OracleScoreTerm("invariant", 40, "forbid")], "forbidden response"),
                [MakeFinding("InvariantRule", "violation")],
                true, 8, "forbidden token", []);

            var result = SilentScreamBuilder.Promote(
                project,
                yamlPath: dir,
                store,
                dir,
                iteration: 3,
                mutatorLabel: "cmd/bitflip",
                commandName: "cmd",
                mutatorName: "bitflip",
                payload,
                hash,
                new TargetRunResult(false, 0, null, "ok"),
                eval,
                mutatorChain: ["bitflip"],
                parentInputHash: null,
                seedSource: "seed",
                seedFiles: [],
                newEdges: 2,
                totalEdges: 10,
                coverageGuided: false,
                dryRun: false,
                stalkBackend: "none",
                iterTracePath: null,
                runId: "run-1");

            Assert.NotNull(result);
            Assert.True(result!.IsNew);
            Assert.Null(result.Crash.MiniDumpPath);
            Assert.Equal(SilentScreamBuilder.TriageTag, result.Crash.TriageTag);

            var sidecar = CrashSidecarWriter.TryRead(result.Crash.SidecarPath!);
            Assert.NotNull(sidecar);
            Assert.True(sidecar!.SilentScream);
            Assert.Equal(72, sidecar.RandallScore?.Total);

            var triage = CrashTriage.Classify(null, sidecar, new CrashSummaryDto(
                result.Crash.Id, project.Name, 3, "cmd/bitflip", hash, result.Crash.InputPath,
                null, "0", SilentScreamBuilder.TriageTag, result.Crash.SidecarPath, "run-1",
                DateTimeOffset.UtcNow));
            Assert.Equal("oracle_only", triage.Class);

            Assert.True(File.Exists(RootCauseEngine.PathFor(dir, result.Crash.Id)));
            Assert.True(File.Exists(InfluenceEngine.PathFor(dir, result.Crash.Id)));
            Assert.True(File.Exists(EvidenceFactBuilder.PathFor(dir, result.Crash.Id)));
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { /* */ }
        }
    }

    private static OracleFindingDto MakeFinding(string ruleClass, string severity) =>
        new(
            Guid.NewGuid().ToString("N"),
            "silent-lab",
            "rule-1",
            ruleClass,
            severity,
            0.9,
            "abc",
            "cmd",
            "bitflip",
            1,
            "expect ok",
            "got bad",
            null,
            null,
            null,
            1,
            DateTimeOffset.UtcNow);
}

public class AcademyModeTests
{
    [Fact]
    public void AcademyConfig_defaults_research_and_silent_screams_on()
    {
        var cfg = new AcademyConfig();
        Assert.True(cfg.IsResearchMode);
        Assert.False(cfg.IsLearningMode);
        Assert.True(cfg.SilentScreams);
    }

    [Fact]
    public void UiPrefsStore_normalizes_presentation_mode()
    {
        Assert.Equal("learning", UiPrefsStore.NormalizePresentationMode("learning"));
        Assert.Equal("research", UiPrefsStore.NormalizePresentationMode("RESEARCH"));
        Assert.Equal("research", UiPrefsStore.NormalizePresentationMode("invalid"));
        Assert.True(UiPrefsStore.IsValidPresentationMode("learning"));
        Assert.False(UiPrefsStore.IsValidPresentationMode("invalid"));
    }

    [Fact]
    public void DifferentialOracleHook_describes_armed_rules()
    {
        var project = new ProjectConfig
        {
            Name = "diff-lab",
            Oracles = new OracleConfig
            {
                Enabled = true,
                Differential =
                [
                    new OracleDifferentialRuleConfig
                    {
                        Id = "ref-parser",
                        ReferenceExecutable = "tools/ref.exe",
                    },
                ],
            },
        };
        Assert.True(DifferentialOracleHook.IsArmed(project));
        Assert.Contains("ref-parser", DifferentialOracleHook.Describe(project));
    }
}
