using System.Text.Json;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Aggregates sensor outputs into normalized <see cref="EvidenceFact"/> lists and persists crash evidence.
/// </summary>
public static class EvidenceFactBuilder
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
        Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() },
    };

    public static string PathFor(string crashesDir, Guid crashId) =>
        Path.Combine(crashesDir, $"{crashId:N}_evidence.json");

    public static CrashEvidenceDto? TryRead(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            return null;
        try
        {
            return JsonSerializer.Deserialize<CrashEvidenceDto>(File.ReadAllText(path), JsonOpts);
        }
        catch
        {
            return null;
        }
    }

    public static CrashEvidenceDto? TryReadForCrash(string crashesDir, Guid crashId) =>
        TryRead(PathFor(crashesDir, crashId));

    public static CrashEvidenceDto Build(
        Guid crashId,
        string project,
        CrashSidecarDto? sidecar = null,
        CrashTriageDto? triage = null,
        DebuggerObservation? debugger = null,
        CrashCorruptionChainDto? corruptionChain = null,
        CrashBackwardTraceDto? backwardTrace = null,
        ScreamEvolutionDto? evolution = null,
        OracleScore? oracleScore = null,
        HypothesisSetDto? hypotheses = null,
        CrashAnalysisDto? analysis = null,
        CdbTriageDto? cdb = null,
        bool pageHeapEnabled = false,
        string? rppTag = null)
    {
        var at = DateTimeOffset.UtcNow;
        var facts = new List<EvidenceFact>();

        if (debugger?.Provenance is not null)
            facts.AddRange(FromDebuggerProvenance(debugger, at));

        facts.AddRange(FromCorruptionChain(corruptionChain, at));
        facts.AddRange(FromBackwardTrace(backwardTrace, at));
        facts.AddRange(FromEvolution(evolution, at));
        facts.AddRange(FromOracle(oracleScore, sidecar, at));
        facts.AddRange(FromFaultSignals(
            FaultSignalMapper.FromCrash(
                triage, analysis, cdb, sidecar, pageHeapEnabled, rppTag,
                sidecar?.TargetDetail, sidecar?.ExitCode, debugger, corruptionChain),
            at));
        facts.AddRange(FromHypotheses(hypotheses, at));
        facts.AddRange(FromLineage(sidecar, at));
        facts.AddRange(FromTriage(triage, at));

        return new CrashEvidenceDto(
            facts.Count > 0,
            crashId,
            project,
            Dedupe(facts),
            at,
            Engine: RandallBuildInfo.Current);
    }

    /// <summary>Collect facts without persisting — used by RootCauseEngine and InfluenceEngine.</summary>
    public static IReadOnlyList<EvidenceFact> CollectFacts(
        Guid crashId,
        string project,
        CrashSidecarDto? sidecar = null,
        CrashTriageDto? triage = null,
        DebuggerObservation? debugger = null,
        CrashCorruptionChainDto? corruptionChain = null,
        CrashBackwardTraceDto? backwardTrace = null,
        ScreamEvolutionDto? evolution = null,
        OracleScore? oracleScore = null,
        HypothesisSetDto? hypotheses = null,
        CrashAnalysisDto? analysis = null,
        CdbTriageDto? cdb = null,
        bool pageHeapEnabled = false,
        string? rppTag = null) =>
        Build(
            crashId, project, sidecar, triage, debugger, corruptionChain, backwardTrace,
            evolution, oracleScore, hypotheses, analysis, cdb, pageHeapEnabled, rppTag).Facts;

    public static CrashEvidenceDto PersistForCrash(
        string crashesDir,
        Guid crashId,
        string project,
        CrashSidecarDto? sidecar = null,
        CrashTriageDto? triage = null,
        DebuggerObservation? debugger = null,
        CrashCorruptionChainDto? corruptionChain = null,
        CrashBackwardTraceDto? backwardTrace = null,
        ScreamEvolutionDto? evolution = null,
        OracleScore? oracleScore = null,
        HypothesisSetDto? hypotheses = null,
        CrashAnalysisDto? analysis = null,
        CdbTriageDto? cdb = null,
        bool pageHeapEnabled = false,
        string? rppTag = null)
    {
        var dto = Build(
            crashId, project, sidecar, triage, debugger, corruptionChain, backwardTrace,
            evolution, oracleScore, hypotheses, analysis, cdb, pageHeapEnabled, rppTag);
        var path = PathFor(crashesDir, crashId);
        File.WriteAllText(path, JsonSerializer.Serialize(dto, JsonOpts));
        return dto;
    }

    internal static IEnumerable<EvidenceFact> FromDebuggerProvenance(DebuggerObservation obs, DateTimeOffset at)
    {
        if (obs.Provenance is not { } p)
            yield break;

        var artifact = obs.ObservationPath;
        foreach (var fact in MapDebuggerFact("exceptionCode", p.ExceptionCode, artifact, at, related: ["faultAddress"]))
            yield return fact;
        foreach (var fact in MapDebuggerFact("exceptionHint", p.ExceptionHint, artifact, at))
            yield return fact;
        foreach (var fact in MapDebuggerFact("faultAddress", p.FaultAddress, artifact, at, related: ["access", "rip"]))
            yield return fact;
        foreach (var fact in MapDebuggerFact("access", p.Access, artifact, at))
            yield return fact;
        foreach (var fact in MapDebuggerFact("rip", p.Rip, artifact, at))
            yield return fact;
        foreach (var fact in MapDebuggerFact("faultingModule", p.FaultingModule, artifact, at))
            yield return fact;
        foreach (var fact in MapDebuggerFact("faultingFunction", p.FaultingFunction, artifact, at))
            yield return fact;
        foreach (var fact in MapDebuggerFact("faultAddressClass", p.FaultAddressClass, artifact, at))
            yield return fact;
        foreach (var fact in MapDebuggerFact("exploitableClassification", p.ExploitableClassification, artifact, at))
            yield return fact;
        foreach (var fact in MapDebuggerFact("heapSignal", p.HeapSignal, artifact, at))
            yield return fact;

        if (obs.SuspectedInputInfluence is "HIGH" or "MEDIUM")
        {
            yield return Fact(
                "debugger.inputInfluence",
                obs.SuspectedInputInfluence,
                "debugger",
                artifact,
                EvidenceObservationType.Inferred,
                obs.SuspectedInputInfluence == "HIGH" ? 0.85 : 0.65,
                obs.At != default ? obs.At : at);
        }

        foreach (var match in obs.RegisterMatches ?? [])
        {
            yield return Fact(
                $"debugger.register.{match.Register}",
                $"{match.ValueHex} @ input+{match.PayloadOffset} ({match.MatchKind})",
                "debugger",
                artifact,
                EvidenceObservationType.Observed,
                match.MatchKind == "ascii" ? 0.9 : 0.75,
                obs.At != default ? obs.At : at,
                ["faultAddress"]);
        }

        if (obs.Ok && string.IsNullOrWhiteSpace(obs.Provenance.ExceptionCode?.Value?.ToString()))
        {
            if (!string.IsNullOrWhiteSpace(obs.Diagnosis))
            {
                yield return Fact(
                    "debugger.diagnosis",
                    obs.Diagnosis,
                    "debugger",
                    artifact,
                    EvidenceObservationType.Inferred,
                    obs.Confidence,
                    obs.At != default ? obs.At : at);
            }
        }
    }

    internal static IEnumerable<EvidenceFact> FromCorruptionChain(CrashCorruptionChainDto? chain, DateTimeOffset at)
    {
        if (chain is not { Ok: true })
            yield break;

        var ts = chain.At != default ? chain.At : at;
        var artifact = $"{chain.CrashId:N}_corruption_chain.json";

        yield return Fact(
            "corruption.confidence",
            chain.Confidence,
            "corruption_chain",
            artifact,
            EvidenceObservationType.Inferred,
            ConfidenceFromLabel(chain.Confidence),
            ts,
            ["corruption.summary"]);

        if (!string.IsNullOrWhiteSpace(chain.Summary))
        {
            yield return Fact(
                "corruption.summary",
                chain.Summary,
                "corruption_chain",
                artifact,
                EvidenceObservationType.Inferred,
                ConfidenceFromLabel(chain.Confidence),
                ts,
                ["corruption.confidence"]);
        }

        if (chain.PatternDepthBytes is int depth)
        {
            yield return Fact(
                "corruption.patternDepth",
                $"input+0x{depth:X}",
                "corruption_chain",
                artifact,
                EvidenceObservationType.Inferred,
                ConfidenceFromLabel(chain.Confidence),
                ts);
        }

        foreach (var match in chain.RegisterMatches ?? [])
        {
            yield return Fact(
                $"corruption.register.{match.Register}",
                $"{match.ValueHex} @ input+{match.PayloadOffset} ({match.MatchKind})",
                "corruption_chain",
                artifact,
                EvidenceObservationType.Observed,
                ConfidenceFromLabel(chain.Confidence),
                ts,
                ["corruption.patternDepth"]);
        }

        foreach (var step in chain.Steps.Take(8))
        {
            yield return Fact(
                $"corruption.step.{step.Order}",
                $"{step.Kind}: {step.Label}",
                "corruption_chain",
                artifact,
                step.Kind is "register" or "fault-address" or "access"
                    ? EvidenceObservationType.Observed
                    : EvidenceObservationType.Inferred,
                ConfidenceFromLabel(chain.Confidence) * 0.9,
                ts);
        }
    }

    internal static IEnumerable<EvidenceFact> FromBackwardTrace(CrashBackwardTraceDto? trace, DateTimeOffset at)
    {
        if (trace is not { Ok: true })
            yield break;

        var ts = trace.At != default ? trace.At : at;
        var artifact = $"{trace.CrashId:N}_backward_trace.json";

        yield return Fact(
            "backwardTrace.confidence",
            trace.Confidence,
            "backward_trace",
            artifact,
            EvidenceObservationType.Inferred,
            ConfidenceFromLabel(trace.Confidence),
            ts);

        if (!string.IsNullOrWhiteSpace(trace.Story))
        {
            yield return Fact(
                "backwardTrace.story",
                trace.Story,
                "backward_trace",
                artifact,
                EvidenceObservationType.Inferred,
                ConfidenceFromLabel(trace.Confidence),
                ts);
        }

        foreach (var step in trace.Steps.Take(6))
        {
            yield return Fact(
                $"backwardTrace.step.{step.Order}",
                step.Label,
                "backward_trace",
                artifact,
                EvidenceObservationType.Inferred,
                ConfidenceFromLabel(trace.Confidence) * 0.85,
                ts);
        }
    }

    internal static IEnumerable<EvidenceFact> FromEvolution(ScreamEvolutionDto? evolution, DateTimeOffset at)
    {
        if (evolution is not { Ok: true })
            yield break;

        var ts = evolution.At != default ? evolution.At : at;
        var artifact = $"{evolution.CrashId:N}_scream_evolution.json";

        yield return Fact(
            "evolution.momentum",
            $"{evolution.MomentumLabel} ({evolution.MomentumScore})",
            "scream_evolution",
            artifact,
            EvidenceObservationType.Inferred,
            Math.Clamp(evolution.MomentumScore / 100.0, 0.3, 0.9),
            ts);

        yield return Fact(
            "evolution.generation",
            evolution.Generation.ToString(),
            "scream_evolution",
            artifact,
            EvidenceObservationType.Observed,
            0.95,
            ts);
    }

    internal static IEnumerable<EvidenceFact> FromOracle(
        OracleScore? oracleScore,
        CrashSidecarDto? sidecar,
        DateTimeOffset at)
    {
        var score = oracleScore ?? sidecar?.RandallScore;
        if (score is not { Total: > 0 })
            yield break;

        yield return Fact(
            "oracle.score",
            score.Total.ToString(),
            "oracle",
            sidecar?.InputPath,
            EvidenceObservationType.Observed,
            Math.Clamp(score.Total / 100.0, 0.4, 0.95),
            sidecar?.ObservedAt ?? at);

        if (!string.IsNullOrWhiteSpace(score.Summary))
        {
            yield return Fact(
                "oracle.summary",
                score.Summary,
                "oracle",
                null,
                EvidenceObservationType.Observed,
                Math.Clamp(score.Total / 100.0, 0.4, 0.95),
                sidecar?.ObservedAt ?? at,
                ["oracle.score"]);
        }

        foreach (var term in score.Terms.Take(6))
        {
            yield return Fact(
                $"oracle.term.{SanitizeName(term.Label)}",
                $"+{term.Points} {term.Label}",
                "oracle",
                null,
                EvidenceObservationType.Observed,
                Math.Clamp(Math.Abs(term.Points) / 100.0, 0.35, 0.9),
                sidecar?.ObservedAt ?? at,
                ["oracle.score"]);
        }
    }

    internal static IEnumerable<EvidenceFact> FromFaultSignals(IReadOnlyList<FaultSignal> signals, DateTimeOffset at)
    {
        foreach (var signal in signals)
        {
            var name = $"fault.{SanitizeName(signal.Kind.ToString())}";
            yield return Fact(
                name,
                signal.Summary ?? signal.Detail,
                signal.Source.ToString().ToLowerInvariant(),
                null,
                signal.Source is FaultSignalSource.OracleRuntime or FaultSignalSource.CdbAnalyze
                    or FaultSignalSource.MinidumpAnalysis or FaultSignalSource.DebuggerInvestigation
                    ? EvidenceObservationType.Observed
                    : EvidenceObservationType.Inferred,
                signal.Confidence,
                at,
                signal.Detail is not null ? null : null);
        }
    }

    internal static IEnumerable<EvidenceFact> FromHypotheses(HypothesisSetDto? set, DateTimeOffset at)
    {
        if (set is not { Ok: true })
            yield break;

        var artifact = $"_hypotheses/{set.CrashId:N}.json";
        var ts = set.At != default ? set.At : at;

        foreach (var hypo in set.Hypotheses.Take(8))
        {
            var obsType = hypo.Status switch
            {
                HypothesisStatus.Confirmed => EvidenceObservationType.ExperimentallyConfirmed,
                HypothesisStatus.Refuted => EvidenceObservationType.Observed,
                HypothesisStatus.Partial => EvidenceObservationType.Inferred,
                _ => EvidenceObservationType.Hypothesized,
            };

            yield return Fact(
                $"hypothesis.{hypo.Id}",
                hypo.Statement,
                "hypothesis_engine",
                artifact,
                obsType,
                hypo.ConfidencePercent / 100.0,
                ts);

            foreach (var tag in hypo.Evidence ?? [])
            {
                yield return Fact(
                    $"hypothesis.{hypo.Id}.evidence.{SanitizeName(tag)}",
                    tag,
                    "hypothesis_engine",
                    artifact,
                    EvidenceObservationType.Inferred,
                    hypo.ConfidencePercent / 100.0 * 0.85,
                    ts,
                    [$"hypothesis.{hypo.Id}"]);
            }
        }
    }

    internal static IEnumerable<EvidenceFact> FromLineage(CrashSidecarDto? sidecar, DateTimeOffset at)
    {
        if (sidecar?.MutatorChain is not { Count: > 0 } chain)
            yield break;

        yield return Fact(
            "lineage.mutatorChain",
            string.Join(" → ", chain),
            "sidecar",
            sidecar.InputPath,
            EvidenceObservationType.Observed,
            chain.Count >= 2 ? 0.88 : 0.72,
            sidecar.ObservedAt != default ? sidecar.ObservedAt : at);

        if (!string.IsNullOrWhiteSpace(sidecar.ParentInputHash))
        {
            yield return Fact(
                "lineage.parentInputHash",
                sidecar.ParentInputHash,
                "sidecar",
                sidecar.InputPath,
                EvidenceObservationType.Observed,
                0.85,
                sidecar.ObservedAt != default ? sidecar.ObservedAt : at,
                ["lineage.mutatorChain"]);
        }

        if (!string.IsNullOrWhiteSpace(sidecar.Command))
        {
            yield return Fact(
                "lineage.command",
                sidecar.Command,
                "sidecar",
                sidecar.InputPath,
                EvidenceObservationType.Observed,
                0.55,
                sidecar.ObservedAt != default ? sidecar.ObservedAt : at);
        }
    }

    internal static IEnumerable<EvidenceFact> FromTriage(CrashTriageDto? triage, DateTimeOffset at)
    {
        if (triage is null)
            yield break;

        if (triage.StaticFunction is { } sf)
        {
            yield return Fact(
                "static.function",
                $"{sf.FunctionName}{sf.Offset} @ {sf.PcAddress}",
                "ghidra",
                sf.Source,
                EvidenceObservationType.Observed,
                0.7,
                at);

            if (!string.IsNullOrWhiteSpace(sf.InstructionHint))
            {
                yield return Fact(
                    "static.instruction",
                    sf.InstructionHint,
                    "ghidra",
                    sf.Source,
                    EvidenceObservationType.Observed,
                    0.65,
                    at,
                    ["static.function"]);
            }
        }

        if (triage.StackLooksSmashed)
        {
            yield return Fact(
                "triage.stackSmashed",
                "Stack smash signals present",
                "triage",
                null,
                EvidenceObservationType.Observed,
                0.8,
                at);
        }

        if (triage.IpLooksControlled)
        {
            yield return Fact(
                "triage.ipControlled",
                "Instruction pointer looks attacker-influenced",
                "triage",
                null,
                EvidenceObservationType.Observed,
                0.85,
                at);
        }

        if (triage.PatternDepthBytes is int depth)
        {
            yield return Fact(
                "triage.patternDepth",
                depth.ToString(),
                "triage",
                null,
                EvidenceObservationType.Observed,
                0.55,
                at);
        }

        if (!string.IsNullOrWhiteSpace(triage.Summary))
        {
            yield return Fact(
                "triage.summary",
                triage.Summary,
                "triage",
                null,
                EvidenceObservationType.Observed,
                0.6,
                at);
        }
    }

    private static IEnumerable<EvidenceFact> MapDebuggerFact<T>(
        string name,
        DebuggerFactDto<T>? dto,
        string? artifact,
        DateTimeOffset fallbackAt,
        IReadOnlyList<string>? related = null)
    {
        if (dto is null)
            yield break;

        var valueStr = dto.Value switch
        {
            null => null,
            string s => s,
            Enum e => e.ToString(),
            _ => dto.Value?.ToString(),
        };

        if (string.IsNullOrWhiteSpace(valueStr))
            yield break;

        var obsType = dto.Kind switch
        {
            DebuggerFactKind.Observed => EvidenceObservationType.Observed,
            _ => EvidenceObservationType.Inferred,
        };

        yield return Fact(
            name,
            valueStr,
            "debugger",
            dto.Source ?? artifact,
            obsType,
            ConfidenceFromDebugger(dto.Confidence),
            fallbackAt,
            related);
    }

    internal static EvidenceFact Fact(
        string name,
        string? value,
        string source,
        string? sourceArtifact,
        EvidenceObservationType observationType,
        double confidence,
        DateTimeOffset timestamp,
        IReadOnlyList<string>? relatedFacts = null) =>
        new(
            name,
            value,
            source,
            sourceArtifact,
            observationType,
            Math.Clamp(confidence, 0, 1),
            timestamp,
            relatedFacts);

    private static double ConfidenceFromDebugger(DebuggerFactConfidence confidence) =>
        confidence switch
        {
            DebuggerFactConfidence.High => 0.9,
            DebuggerFactConfidence.Medium => 0.72,
            DebuggerFactConfidence.Low => 0.55,
            _ => 0.45,
        };

    private static double ConfidenceFromLabel(string? label) =>
        label?.ToUpperInvariant() switch
        {
            "HIGH" => 0.88,
            "MEDIUM" => 0.72,
            "LOW" => 0.55,
            _ => 0.48,
        };

    private static string SanitizeName(string input)
    {
        var chars = input.Select(c => char.IsLetterOrDigit(c) ? c : '_').ToArray();
        return new string(chars).Trim('_');
    }

    private static List<EvidenceFact> Dedupe(List<EvidenceFact> facts)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var result = new List<EvidenceFact>();
        foreach (var fact in facts)
        {
            var key = $"{fact.Name}|{fact.Value}|{fact.Source}";
            if (seen.Add(key))
                result.Add(fact);
        }

        return result;
    }
}
