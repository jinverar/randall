using System.Text;
using System.Text.Json;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Wave 1 Root Cause Engine — deterministic correlation of Ghidra static (when present),
/// CDB/DebuggerObservation, mutation lineage, corruption chain, oracle, and backward trace.
/// Research-only; no LLM on the hot path.
/// </summary>
public static class RootCauseEngine
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
        Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() },
    };

    public static string PathFor(string crashesDir, Guid crashId) =>
        Path.Combine(crashesDir, $"{crashId:N}_root_cause.json");

    public static RootCauseAnalysisDto? TryRead(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            return null;
        try
        {
            return JsonSerializer.Deserialize<RootCauseAnalysisDto>(File.ReadAllText(path), JsonOpts);
        }
        catch
        {
            return null;
        }
    }

    public static RootCauseAnalysisDto Build(
        Guid crashId,
        string project,
        CrashSidecarDto? sidecar,
        CrashTriageDto? triage,
        DebuggerObservation? debugger,
        CrashCorruptionChainDto? corruptionChain,
        CrashBackwardTraceDto? backwardTrace,
        OracleScore? oracleScore = null)
    {
        var facts = CollectEvidenceFacts(
            sidecar, triage, debugger, corruptionChain, backwardTrace, oracleScore,
            crashId: crashId, project: project);
        if (facts.Count == 0 && debugger is not { Ok: true } && triage is null && corruptionChain is not { Ok: true })
        {
            return new RootCauseAnalysisDto(
                false,
                crashId,
                project,
                EmptyCandidate(),
                "Insufficient evidence to infer a root cause — capture a minidump with cdb triage or enrich the sidecar.",
                At: DateTimeOffset.UtcNow,
                Error: "no correlatable evidence");
        }

        var observed = BuildObservedFacts(facts, debugger, triage, corruptionChain, backwardTrace, sidecar);
        var unknowns = BuildUnknowns(debugger, triage, corruptionChain, backwardTrace, sidecar);
        var (category, alternatives) = ClassifyCategories(debugger, triage, corruptionChain, backwardTrace, sidecar, facts);
        var candidate = BuildCandidate(category, debugger, triage, corruptionChain, backwardTrace, sidecar, facts, observed, unknowns);
        var altCandidates = alternatives
            .Where(a => a != category)
            .Select(a => BuildCandidate(a, debugger, triage, corruptionChain, backwardTrace, sidecar, facts, observed, unknowns))
            .ToList();

        var summary = BuildEducationalSummary(candidate, sidecar, corruptionChain, backwardTrace, debugger);
        return new RootCauseAnalysisDto(
            true,
            crashId,
            project,
            candidate,
            summary,
            altCandidates.Count > 0 ? altCandidates : null,
            DateTimeOffset.UtcNow);
    }

    public static RootCauseAnalysisDto PersistForCrash(
        string crashesDir,
        Guid crashId,
        string project,
        CrashSidecarDto? sidecar,
        CrashTriageDto? triage,
        DebuggerObservation? debugger,
        CrashCorruptionChainDto? corruptionChain,
        CrashBackwardTraceDto? backwardTrace,
        OracleScore? oracleScore = null)
    {
        var analysis = Build(crashId, project, sidecar, triage, debugger, corruptionChain, backwardTrace, oracleScore);
        Write(crashesDir, analysis);
        return analysis;
    }

    public static string Write(string crashesDir, RootCauseAnalysisDto analysis)
    {
        Directory.CreateDirectory(crashesDir);
        var path = PathFor(crashesDir, analysis.CrashId);
        File.WriteAllText(path, JsonSerializer.Serialize(analysis, JsonOpts));
        return path;
    }

    /// <summary>Collect normalized evidence facts from all available sensors.</summary>
    public static IReadOnlyList<EvidenceFact> CollectEvidenceFacts(
        CrashSidecarDto? sidecar,
        CrashTriageDto? triage,
        DebuggerObservation? debugger,
        CrashCorruptionChainDto? corruptionChain,
        CrashBackwardTraceDto? backwardTrace,
        OracleScore? oracleScore = null,
        HypothesisSetDto? hypotheses = null,
        Guid crashId = default,
        string project = "?")
    {
        return EvidenceFactBuilder.CollectFacts(
            crashId,
            project,
            sidecar,
            triage,
            debugger,
            corruptionChain,
            backwardTrace,
            oracleScore: oracleScore,
            hypotheses: hypotheses);
    }

    private static RootCauseCandidate BuildCandidate(
        RootCauseCategory category,
        DebuggerObservation? debugger,
        CrashTriageDto? triage,
        CrashCorruptionChainDto? chain,
        CrashBackwardTraceDto? trace,
        CrashSidecarDto? sidecar,
        IReadOnlyList<EvidenceFact> facts,
        IReadOnlyList<string> observed,
        IReadOnlyList<string> unknowns)
    {
        var faultFn = FormatFaultFunction(debugger, triage);
        var sink = faultFn ?? debugger?.Rip ?? triage?.Rip;
        var source = trace?.BadPointerSource
                       ?? chain?.Narrative
                       ?? InferSourceLabel(debugger, chain);
        var sourceFn = triage?.StaticFunction?.FunctionName
                       ?? InferSourceFunction(debugger, chain, sidecar);
        var inputRegion = FormatInputRegion(chain, trace, debugger);
        var allocSite = InferAllocationSite(debugger, chain);
        var corruptSite = InferCorruptionSite(debugger, chain, trace);
        var confidence = ScoreRootConfidence(category, debugger, chain, trace, facts);
        var inferences = BuildInferences(category, debugger, chain, trace, sidecar);

        return new RootCauseCandidate(
            category,
            faultFn,
            sourceFn,
            sink,
            inputRegion,
            allocSite,
            corruptSite,
            facts,
            confidence,
            observed,
            inferences,
            unknowns);
    }

    private static (RootCauseCategory Primary, IReadOnlyList<RootCauseCategory> Alternatives) ClassifyCategories(
        DebuggerObservation? debugger,
        CrashTriageDto? triage,
        CrashCorruptionChainDto? chain,
        CrashBackwardTraceDto? trace,
        CrashSidecarDto? sidecar,
        IReadOnlyList<EvidenceFact> facts)
    {
        var scores = new Dictionary<RootCauseCategory, int>();

        void Bump(RootCauseCategory c, int pts) =>
            scores[c] = scores.GetValueOrDefault(c) + pts;

        var heapText = $"{debugger?.HeapSignal} {debugger?.Diagnosis} {chain?.Summary}".ToLowerInvariant();
        if (debugger?.FaultAddressClass == DebuggerAddressClass.Freed
            || heapText.Contains("use after free", StringComparison.Ordinal)
            || heapText.Contains("uaf", StringComparison.Ordinal)
            || trace?.HeapTimeline?.Contains("freed", StringComparison.OrdinalIgnoreCase) == true)
            Bump(RootCauseCategory.LifetimeViolation, 40);

        if (triage?.StackLooksSmashed == true
            || debugger?.FaultAddressClass == DebuggerAddressClass.Stackish)
            Bump(RootCauseCategory.BoundsViolation, 35);

        if (debugger?.FaultAddressClass == DebuggerAddressClass.NullPage
            && debugger.Access == DebuggerAccessKind.Read
            && chain?.RegisterMatches is not { Count: > 0 })
            Bump(RootCauseCategory.Uninitialized, 28);

        var nullWriteOnly = IsNullOrNearNullWrite(debugger)
                            && !HasStrongNonZeroControlEvidence(debugger, chain);

        if (!nullWriteOnly
            && (debugger?.FaultAddressClass is DebuggerAddressClass.AsciiPattern
                    or DebuggerAddressClass.NearNull
                    or DebuggerAddressClass.SmallOffset
                || chain?.PatternDepthBytes is not null
                || debugger?.SuspectedInputInfluence == "HIGH"))
        {
            var pts = 25;
            if (debugger?.FaultAddressClass == DebuggerAddressClass.AsciiPattern
                && (debugger.Access == DebuggerAccessKind.Write
                    || chain?.RegisterMatches is { Count: > 0 }
                    || debugger.SuspectedInputInfluence == "HIGH"))
                pts += 10;
            if (debugger?.FaultAddressClass is DebuggerAddressClass.NearNull
                    or DebuggerAddressClass.SmallOffset)
                pts = Math.Min(pts, 12);
            Bump(RootCauseCategory.BoundsViolation, pts);
        }

        if (LooksLikeSizeMismatch(debugger, chain, triage))
            Bump(RootCauseCategory.SizeMismatch, 30);

        if (LooksLikeIntegerConversion(chain, sidecar, facts))
            Bump(RootCauseCategory.IntegerConversion, 22);

        if (!nullWriteOnly && LooksLikeParserState(debugger, triage, sidecar))
            Bump(RootCauseCategory.ParserState, 26);

        if (nullWriteOnly)
            Bump(RootCauseCategory.Uninitialized, 18);

        if (!nullWriteOnly && LooksLikeFormatInterpretation(debugger, chain, sidecar))
            Bump(RootCauseCategory.FormatInterpretation, 24);

        if (debugger?.FaultAddressClass == DebuggerAddressClass.Heapish
            && scores.GetValueOrDefault(RootCauseCategory.LifetimeViolation) < 30)
            Bump(RootCauseCategory.UnexpectedObjectState, 20);

        if (scores.Count == 0)
            return (RootCauseCategory.Unknown, []);

        var ordered = scores.OrderByDescending(kv => kv.Value).ToList();
        var primary = ordered[0].Key;
        var alts = ordered.Skip(1).Where(kv => kv.Value >= ordered[0].Value - 12).Select(kv => kv.Key).ToList();
        return (primary, alts);
    }

    private static bool LooksLikeSizeMismatch(
        DebuggerObservation? debugger,
        CrashCorruptionChainDto? chain,
        CrashTriageDto? triage)
    {
        var fn = $"{debugger?.FaultingFunction} {triage?.StaticFunction?.FunctionName}".ToLowerInvariant();
        if (fn.Contains("memcpy", StringComparison.Ordinal)
            || fn.Contains("memmove", StringComparison.Ordinal)
            || fn.Contains("strcpy", StringComparison.Ordinal)
            || fn.Contains("strncpy", StringComparison.Ordinal)
            || fn.Contains("read", StringComparison.Ordinal))
            return chain?.PatternDepthBytes is not null
                   || chain?.SuspectedField is not null
                   || debugger?.SuspectedInputInfluence is "HIGH" or "MEDIUM";
        return false;
    }

    private static bool LooksLikeIntegerConversion(
        CrashCorruptionChainDto? chain,
        CrashSidecarDto? sidecar,
        IReadOnlyList<EvidenceFact> facts)
    {
        if (chain?.PatternDepthBytes is not null && chain.MutatorLineage.Any(m =>
                m.Contains("interesting", StringComparison.OrdinalIgnoreCase)
                || m.Contains("boundary", StringComparison.OrdinalIgnoreCase)))
            return true;
        if (sidecar?.MutatorChain?.Any(m =>
                m.Contains("interesting", StringComparison.OrdinalIgnoreCase)) == true)
            return true;
        return facts.Any(f =>
            f.Source == "oracle"
            && (f.Value?.Contains("overflow", StringComparison.OrdinalIgnoreCase) == true
                || f.Name.Contains("overflow", StringComparison.OrdinalIgnoreCase)));
    }

    private static bool LooksLikeParserState(
        DebuggerObservation? debugger,
        CrashTriageDto? triage,
        CrashSidecarDto? sidecar)
    {
        var fn = $"{debugger?.FaultingFunction} {triage?.StaticFunction?.FunctionName}".ToLowerInvariant();
        if (fn.Contains("parse", StringComparison.Ordinal)
            || fn.Contains("decode", StringComparison.Ordinal)
            || fn.Contains("lex", StringComparison.Ordinal)
            || fn.Contains("token", StringComparison.Ordinal))
            return true;
        return !string.IsNullOrWhiteSpace(sidecar?.Command)
               && debugger?.FaultAddressClass is DebuggerAddressClass.AsciiPattern
                   or DebuggerAddressClass.Heapish
                   or DebuggerAddressClass.Stackish;
    }

    internal static bool IsNullOrNearNullWrite(DebuggerObservation? debugger) =>
        debugger is { Access: DebuggerAccessKind.Write }
        && debugger.FaultAddressClass is DebuggerAddressClass.NullPage
            or DebuggerAddressClass.NearNull
            or DebuggerAddressClass.SmallOffset;

    internal static bool HasStrongNonZeroControlEvidence(
        DebuggerObservation? debugger,
        CrashCorruptionChainDto? chain)
    {
        if (debugger?.FaultAddressClass == DebuggerAddressClass.AsciiPattern)
            return true;
        if (debugger?.RegisterMatches?.Any(m =>
                m.MatchKind == "ascii"
                || InputAttributionEngine.IsStrongNonZeroPattern(m.ValueHex)) == true)
            return true;
        if (chain?.RegisterMatches?.Any(m =>
                m.MatchKind == "ascii"
                || InputAttributionEngine.IsStrongNonZeroPattern(m.ValueHex)) == true)
            return true;
        if (debugger?.FaultAddress is { } fa
            && InputAttributionEngine.IsStrongNonZeroPattern(fa))
            return true;
        return false;
    }

    private static bool LooksLikeFormatInterpretation(
        DebuggerObservation? debugger,
        CrashCorruptionChainDto? chain,
        CrashSidecarDto? sidecar)
    {
        if (debugger?.FaultAddressClass == DebuggerAddressClass.AsciiPattern)
            return true;
        if (chain?.RegisterMatches?.Any(m => m.MatchKind == "ascii") == true)
            return true;
        return !string.IsNullOrWhiteSpace(sidecar?.Command)
               && chain?.PatternDepthBytes is not null;
    }

    private static List<string> BuildObservedFacts(
        IReadOnlyList<EvidenceFact> facts,
        DebuggerObservation? debugger,
        CrashTriageDto? triage,
        CrashCorruptionChainDto? chain,
        CrashBackwardTraceDto? trace,
        CrashSidecarDto? sidecar)
    {
        var observed = facts
            .Where(f => f.ObservationType is EvidenceObservationType.Observed
                or EvidenceObservationType.ExperimentallyConfirmed
                || f.Source is "sidecar" or "oracle" or "ghidra")
            .Select(FormatFactLine)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(12)
            .ToList();

        if (debugger is { Ok: true, ExceptionHint: not null } && !observed.Any(o => o.Contains(debugger.ExceptionHint, StringComparison.OrdinalIgnoreCase)))
            observed.Add(debugger.ExceptionHint);
        if (triage?.Summary is { } ts && !observed.Contains(ts))
            observed.Add(ts);
        if (sidecar?.Mutator is { } m)
            observed.Add($"Last mutator: {m}");
        if (trace is { Ok: true } && !observed.Any(o => o.Contains(trace.Story, StringComparison.OrdinalIgnoreCase)))
            observed.Add(trace.Story.Length > 160 ? trace.Story[..160] + "…" : trace.Story);

        return observed;
    }

    private static List<string> BuildUnknowns(
        DebuggerObservation? debugger,
        CrashTriageDto? triage,
        CrashCorruptionChainDto? chain,
        CrashBackwardTraceDto? trace,
        CrashSidecarDto? sidecar)
    {
        var unknowns = new List<string>();
        if (debugger is not { Ok: true })
            unknowns.Add("No structured debugger observation — root cause confidence limited");
        if (triage?.StaticFunction is null)
            unknowns.Add("No Ghidra static map at fault PC — source function is heuristic only");
        if (chain is not { Ok: true })
            unknowns.Add("Corruption chain missing — input region attribution uncertain");
        if (trace is not { Ok: true })
            unknowns.Add("Backward trace unavailable — allocation/corruption timeline incomplete");
        if (sidecar?.MutatorChain is not { Count: > 1 })
            unknowns.Add("Thin mutation lineage — introducing mutator step is approximate");
        return unknowns;
    }

    private static List<string> BuildInferences(
        RootCauseCategory category,
        DebuggerObservation? debugger,
        CrashCorruptionChainDto? chain,
        CrashBackwardTraceDto? trace,
        CrashSidecarDto? sidecar)
    {
        var list = new List<string>();
        switch (category)
        {
            case RootCauseCategory.LifetimeViolation:
                list.Add("Fault likely occurs after object lifetime ended (use-after-free or dangling pointer)");
                break;
            case RootCauseCategory.BoundsViolation:
                list.Add("Fault likely driven by out-of-bounds index, length, or pointer derived from fuzz input");
                break;
            case RootCauseCategory.SizeMismatch:
                list.Add("Copied/read size probably disagrees with buffer capacity (length vs allocation)");
                break;
            case RootCauseCategory.IntegerConversion:
                list.Add("Width/sign conversion or boundary integer may wrap/truncate into a dangerous size/index");
                break;
            case RootCauseCategory.ParserState:
                list.Add("Parser/state machine reached an unexpected token or field value from mutated input");
                break;
            case RootCauseCategory.FormatInterpretation:
                list.Add("Structured field bytes were interpreted as pointer/length without validation");
                break;
            case RootCauseCategory.Uninitialized:
                list.Add(debugger?.Access == DebuggerAccessKind.Write
                    ? "NULL/invalid destination reached a write — leading hypothesis only until counterfactual/delta evidence"
                    : "Read through null or small offset suggests missing initialization or unchecked null deref");
                break;
            case RootCauseCategory.UnexpectedObjectState:
                list.Add("Heap/object metadata inconsistent — corruption may precede the visible fault");
                break;
        }

        if (chain?.SuspectedMutator is { } mut)
            list.Add($"Mutation `{mut}` most likely introduced the controlling bytes");
        if (trace?.SuspectedMutator is { } tm && tm != chain?.SuspectedMutator)
            list.Add($"Backward trace attributes `{tm}` as the introducing step");
        if (debugger?.Access is DebuggerAccessKind.Write && !IsNullOrNearNullWrite(debugger))
            list.Add("Write AV implies attacker-controlled store — prioritize length/index hypotheses");
        else if (IsNullOrNearNullWrite(debugger))
            list.Add("Null/invalid destination write — do not assume controlled store from zero-coincidence");
        if (!string.IsNullOrWhiteSpace(sidecar?.Command) && !IsNullOrNearNullWrite(debugger))
            list.Add($"Session node `{sidecar.Command}` may scope which field was mutated");

        return list;
    }

    private static string BuildEducationalSummary(
        RootCauseCandidate candidate,
        CrashSidecarDto? sidecar,
        CrashCorruptionChainDto? chain,
        CrashBackwardTraceDto? trace,
        DebuggerObservation? debugger = null)
    {
        var sb = new StringBuilder();
        var catLabel = CategoryLabel(candidate.Category);
        sb.Append($"**{catLabel}** ({candidate.Confidence} confidence). ");

        if (!string.IsNullOrWhiteSpace(debugger?.FaultAddress))
            sb.Append($"Fault address `{debugger.FaultAddress}` ({ScreamInvestigator.FormatAddressClass(debugger.FaultAddressClass)}). ");

        if (!string.IsNullOrWhiteSpace(candidate.InputRegion))
            sb.Append($"Fuzz input region **{candidate.InputRegion}** appears to influence the fault. ");
        else if (chain?.PatternDepthBytes is int d)
            sb.Append($"Bytes around payload offset **+{d}** correlate with the crash. ");

        if (!string.IsNullOrWhiteSpace(candidate.SuspectedSourceFunction))
            sb.Append($"Likely origin near **`{candidate.SuspectedSourceFunction}`** (source). ");
        else if (!string.IsNullOrWhiteSpace(trace?.BadPointerSource))
            sb.Append($"Bad pointer traced to **{trace.BadPointerSource}**. ");

        if (!string.IsNullOrWhiteSpace(candidate.SuspectedSink))
            sb.Append($"Failure manifests at sink **`{candidate.SuspectedSink}`**. ");

        if (candidate.Category == RootCauseCategory.LifetimeViolation)
            sb.Append("Study allocation/free pairing and whether the mutator reuses freed slots. ");
        else if (candidate.Category == RootCauseCategory.BoundsViolation)
            sb.Append("Sweep the attributed offset and hold neighboring bytes to confirm index/length control. ");
        else if (candidate.Category == RootCauseCategory.SizeMismatch)
            sb.Append("Compare declared length fields against allocation sites in static analysis. ");
        else if (candidate.Category == RootCauseCategory.ParserState)
            sb.Append("Minimize while preserving the protocol node and token that preceded the fault. ");

        if (sidecar?.MutatorChain is { Count: > 0 })
            sb.Append($"Lineage: `{string.Join(" → ", sidecar.MutatorChain)}`. ");

        if (candidate.Unknowns.Count > 0)
            sb.Append($"Open questions: {string.Join("; ", candidate.Unknowns.Take(2))}.");

        return sb.ToString().Trim();
    }

    private static string CategoryLabel(RootCauseCategory category) => category switch
    {
        RootCauseCategory.BoundsViolation => "Bounds violation",
        RootCauseCategory.IntegerConversion => "Integer conversion",
        RootCauseCategory.SizeMismatch => "Size mismatch",
        RootCauseCategory.LifetimeViolation => "Lifetime violation",
        RootCauseCategory.UnexpectedObjectState => "Unexpected object state",
        RootCauseCategory.Uninitialized => "Uninitialized / null deref",
        RootCauseCategory.ParserState => "Parser state error",
        RootCauseCategory.FormatInterpretation => "Format interpretation",
        _ => "Unknown root cause",
    };

    private static string? FormatFaultFunction(DebuggerObservation? debugger, CrashTriageDto? triage)
    {
        if (debugger?.FaultingFunction is not null)
            return $"{debugger.FaultingModule ?? "?"}!{debugger.FaultingFunction}{debugger.FunctionOffset ?? ""}";
        if (triage?.StaticFunction is { } sf)
            return $"{sf.FunctionName}{sf.Offset}";
        return null;
    }

    private static string? InferSourceLabel(DebuggerObservation? debugger, CrashCorruptionChainDto? chain)
    {
        if (chain?.RegisterMatches?.FirstOrDefault() is { } m)
            return $"payload+{m.PayloadOffset} ({m.Register})";
        if (debugger?.FaultAddressClass == DebuggerAddressClass.AsciiPattern)
            return "ASCII pattern in payload";
        return chain?.SuspectedField;
    }

    private static string? InferSourceFunction(
        DebuggerObservation? debugger,
        CrashCorruptionChainDto? chain,
        CrashSidecarDto? sidecar)
    {
        var stack = debugger?.Stack;
        if (stack is { Count: > 1 })
        {
            var caller = stack.FirstOrDefault(f => f.Index == 1 && !string.IsNullOrWhiteSpace(f.Symbol));
            if (caller?.Symbol is not null)
                return $"{caller.Module ?? "?"}!{caller.Symbol}{caller.Offset ?? ""}";
        }
        return chain?.SuspectedMutator ?? sidecar?.Mutator;
    }

    private static string? FormatInputRegion(
        CrashCorruptionChainDto? chain,
        CrashBackwardTraceDto? trace,
        DebuggerObservation? debugger)
    {
        if (trace?.PrimaryPayloadOffset is { } po)
            return $"payload{po}";
        if (chain?.PatternDepthBytes is int d)
            return $"payload+{d} (0x{d:X})";
        var match = chain?.RegisterMatches?.FirstOrDefault()
                    ?? debugger?.RegisterMatches?.FirstOrDefault();
        return match is not null ? $"payload+{match.PayloadOffset}" : chain?.SuspectedField;
    }

    private static string? InferAllocationSite(DebuggerObservation? debugger, CrashCorruptionChainDto? chain)
    {
        if (debugger?.HeapSignal?.Contains("alloc", StringComparison.OrdinalIgnoreCase) == true)
            return debugger.HeapSignal;
        var heapStep = chain?.Steps.LastOrDefault(s => s.Kind == "heap");
        return heapStep?.Label;
    }

    private static string? InferCorruptionSite(
        DebuggerObservation? debugger,
        CrashCorruptionChainDto? chain,
        CrashBackwardTraceDto? trace)
    {
        if (!string.IsNullOrWhiteSpace(trace?.FaultInstruction))
            return trace.FaultInstruction;
        if (debugger?.DisasmNearRip is { Length: > 0 } disasm)
        {
            var line = disasm.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .FirstOrDefault(l => l.Contains("rip", StringComparison.OrdinalIgnoreCase) || l.Contains("=>", StringComparison.Ordinal));
            return line ?? disasm.Split('\n').FirstOrDefault()?.Trim();
        }
        return debugger?.FaultAddress is not null
            ? $"{debugger.FaultAddress} ({debugger.FaultAddressClass})"
            : chain?.Steps.LastOrDefault(s => s.Kind == "fault-address")?.Label;
    }

    private static string ScoreRootConfidence(
        RootCauseCategory category,
        DebuggerObservation? debugger,
        CrashCorruptionChainDto? chain,
        CrashBackwardTraceDto? trace,
        IReadOnlyList<EvidenceFact> facts)
    {
        if (category == RootCauseCategory.Unknown)
            return "UNKNOWN";

        if (IsNullOrNearNullWrite(debugger) && !HasStrongNonZeroControlEvidence(debugger, chain))
        {
            return category is RootCauseCategory.Uninitialized or RootCauseCategory.Unknown
                ? "LOW"
                : "MEDIUM";
        }

        var score = 0;
        if (debugger is { Ok: true }) score += 25;
        if (chain is { Ok: true }) score += ScoreBase(chain.Confidence) / 2;
        if (trace is { Ok: true }) score += ScoreBase(trace.Confidence) / 3;
        if (facts.Count >= 6) score += 10;
        if (chain?.RegisterMatches is { Count: > 0 }
            && chain.RegisterMatches.Any(m =>
                !InputAttributionEngine.IsExcludedFromRawInputAttribution(m.ValueHex)))
            score += 12;
        if (debugger?.SuspectedInputInfluence == "HIGH"
            && HasStrongNonZeroControlEvidence(debugger, chain))
            score += 8;

        return score switch
        {
            >= 72 => "HIGH",
            >= 48 => "MEDIUM",
            _ => "LOW",
        };
    }

    private static int ScoreBase(string? confidenceLabel) =>
        confidenceLabel?.ToUpperInvariant() switch
        {
            "HIGH" => 72,
            "MEDIUM" => 55,
            "LOW" => 38,
            _ => 45,
        };

    private static string FormatFactLine(EvidenceFact fact) =>
        string.IsNullOrWhiteSpace(fact.Value) ? fact.Name : $"{fact.Name}: {fact.Value}";

    private static double ScoreConfidence(string? confidenceLabel) =>
        ScoreBase(confidenceLabel) / 100.0;

    private static RootCauseCandidate EmptyCandidate() =>
        new(
            RootCauseCategory.Unknown,
            null,
            null,
            null,
            null,
            null,
            null,
            [],
            "UNKNOWN",
            [],
            [],
            ["No evidence collected"]);
}
