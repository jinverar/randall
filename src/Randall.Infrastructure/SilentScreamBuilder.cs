using Randall.Contracts;
using Randall.Infrastructure.Oracles;

namespace Randall.Infrastructure;

/// <summary>
/// Wave 5 — promote high oracle invariant violations into scream-like canisters without a memory crash.
/// Bottles the input, writes a sidecar with oracle score, and runs the intelligence pipeline.
/// </summary>
public static class SilentScreamBuilder
{
    public const string TriageTag = "silent-scream";

    private static readonly HashSet<string> HighInvariantClasses = new(StringComparer.OrdinalIgnoreCase)
    {
        "InvariantRule",
        "AuthRule",
        "StateRule",
        "IntegerRule",
        "StructureRule",
        "ResourceRule",
    };

    public static bool IsEnabled(ProjectConfig project) =>
        project.Academy?.SilentScreams != false;

    /// <summary>True when oracle eval qualifies for silent scream promotion.</summary>
    public static bool Qualifies(OracleEvalResult eval) =>
        eval.MaxSeverity >= OracleSeverity.Violation
        && eval.Score.Total >= 40
        && eval.Findings.Any(f =>
            f.Severity.Equals("violation", StringComparison.OrdinalIgnoreCase)
            && HighInvariantClasses.Contains(f.RuleClass));

    public static SavedCrashResult? Promote(
        ProjectConfig project,
        string yamlPath,
        CrashStore crashStore,
        string crashesDir,
        int iteration,
        string mutatorLabel,
        string commandName,
        string mutatorName,
        byte[] payload,
        string payloadHash,
        TargetRunResult result,
        OracleEvalResult oracleEval,
        IReadOnlyList<string> mutatorChain,
        string? parentInputHash,
        string? seedSource,
        IReadOnlyList<string>? seedFiles,
        int newEdges,
        int totalEdges,
        bool coverageGuided,
        bool dryRun,
        string? stalkBackend,
        string? iterTracePath,
        string? runId,
        IFuzzProgressSink? progress = null)
    {
        if (!IsEnabled(project) || !Qualifies(oracleEval))
            return null;

        var expectedInputPath = Path.Combine(crashesDir, $"{project.Name}_{iteration}_{payloadHash}.bin");
        var detail = BuildDetail(oracleEval);
        var topFinding = oracleEval.Findings
            .FirstOrDefault(f => f.Severity.Equals("violation", StringComparison.OrdinalIgnoreCase)
                                 && HighInvariantClasses.Contains(f.RuleClass))
            ?? oracleEval.Findings.FirstOrDefault();

        var savedResult = crashStore.SaveEx(
            project.Name,
            iteration,
            mutatorLabel,
            payload,
            result.ExitCode,
            miniDumpPath: null,
            triageTag: TriageTag,
            runId,
            buildSidecar: id =>
            {
                var traceCopy = CrashSidecarWriter.CopyTrace(crashesDir, id, iterTracePath);
                var triagePreview = CrashTriage.Classify(
                    analysis: null,
                    sidecar: null,
                    summary: new CrashSummaryDto(
                        id, project.Name, iteration, mutatorLabel, payloadHash, expectedInputPath,
                        null, result.ExitCode?.ToString(), TriageTag, null, runId,
                        DateTimeOffset.UtcNow),
                    payload: payload);
                triagePreview = triagePreview with
                {
                    Class = "oracle_only",
                    Severity = oracleEval.Score.Total >= 60 ? "high" : "medium",
                    Summary = detail,
                };

                return new CrashSidecarDto(
                    id,
                    runId ?? "",
                    iteration,
                    project.Name,
                    commandName,
                    mutatorName,
                    mutatorChain,
                    parentInputHash,
                    seedSource ?? "",
                    seedFiles ?? [],
                    payloadHash,
                    expectedInputPath,
                    payload.Length,
                    result.ExitCode,
                    "oracle-only (silent scream)",
                    detail,
                    TriageTag,
                    newEdges,
                    totalEdges,
                    stalkBackend ?? "",
                    iterTracePath,
                    traceCopy,
                    null,
                    CrashSidecarWriter.HexPreview(result.ResponseBytes),
                    new TransportSnapshotDto(
                        project.Kind, project.Transport.Host, project.Transport.Port, project.Transport.Tls),
                    new FuzzSnapshotDto(coverageGuided, dryRun, Path.GetFullPath(yamlPath)),
                    DateTimeOffset.UtcNow,
                    Intel: null,
                    RandallScore: oracleEval.Score,
                    SilentScream: true,
                    OracleFindingId: topFinding?.Id,
                    OracleRuleClass: topFinding?.RuleClass,
                    OracleRuleId: topFinding?.RuleId);
            });

        if (savedResult.IsNew)
        {
            FuzzAnalystLog.Warn(progress,
                $"[silent-scream] oracle {oracleEval.Score.Total} — {Truncate(oracleEval.Summary, 100)}",
                iteration);
            RunIntelligencePipeline(
                crashesDir,
                savedResult.Crash,
                project,
                payload,
                oracleEval.Score,
                progress,
                iteration);
        }

        return savedResult;
    }

    internal static void RunIntelligencePipeline(
        string crashesDir,
        SavedCrash saved,
        ProjectConfig project,
        byte[]? payload,
        OracleScore? oracleScore,
        IFuzzProgressSink? progress,
        int iterations)
    {
        try
        {
            var sidecar = saved.SidecarPath is not null
                ? CrashSidecarWriter.TryRead(saved.SidecarPath)
                : null;
            var summary = new CrashSummaryDto(
                saved.Id, project.Name, saved.Iteration, saved.Mutator, saved.InputHash,
                saved.InputPath, null, saved.TargetExitCode, saved.TriageTag, saved.SidecarPath,
                saved.RunId, saved.At);
            var triage = CrashTriage.Classify(null, sidecar, summary, payload);
            triage = triage with
            {
                Class = "oracle_only",
                Severity = (oracleScore?.Total ?? 0) >= 60 ? "high" : "medium",
            };

            var backwardTrace = BackwardTraceBuilder.Build(
                saved.Id, project.Name, sidecar, null, triage, null, payload);
            BackwardTraceBuilder.Write(crashesDir, backwardTrace);

            var hypotheses = HypothesisEngine.PersistForCrash(
                crashesDir, saved.Id, project.Name, sidecar, triage,
                debugger: null, corruptionChain: null, evolution: null, oracleScore, backwardTrace);

            RootCauseEngine.PersistForCrash(
                crashesDir, saved.Id, project.Name, sidecar, triage,
                debugger: null, corruptionChain: null, backwardTrace, oracleScore);

            var facts = EvidenceFactBuilder.CollectFacts(
                saved.Id, project.Name, sidecar, triage,
                oracleScore: oracleScore, hypotheses: hypotheses, backwardTrace: backwardTrace);
            InfluenceEngine.PersistForCrash(
                crashesDir, saved.Id, project.Name, sidecar, triage,
                debugger: null, corruptionChain: null, backwardTrace, hypotheses, facts, payload);

            EvidenceFactBuilder.PersistForCrash(
                crashesDir, saved.Id, project.Name, sidecar, triage,
                backwardTrace: backwardTrace, oracleScore: oracleScore, hypotheses: hypotheses);

            FuzzAnalystLog.Info(progress,
                $"[silent-scream] intelligence pipeline — root-cause/influence/evidence for {saved.Id:N}",
                iterations);
        }
        catch (Exception ex)
        {
            FuzzAnalystLog.Warn(progress, $"silent-scream pipeline: {ex.Message}", iterations);
        }
    }

    private static string BuildDetail(OracleEvalResult eval)
    {
        var top = eval.Findings
            .FirstOrDefault(f => f.Severity.Equals("violation", StringComparison.OrdinalIgnoreCase))
            ?? eval.Findings.FirstOrDefault();
        if (top is null)
            return $"silent-scream: {eval.Summary}";
        return $"silent-scream: {top.RuleClass}/{top.RuleId} — {top.ActualRelation}";
    }

    private static string Truncate(string? text, int max) =>
        string.IsNullOrEmpty(text) ? "" : text.Length <= max ? text : text[..max] + "…";
}
