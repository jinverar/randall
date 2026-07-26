using System.Text;
using System.Text.Json;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Wave 1 Priority 2 — maps which input regions influence which program state
/// (length→alloc/copy, pointer→fault address, register→sink, …).
/// Reuses HypothesisEngine sweep/hold/replay for confirmation; no new experiment framework.
/// Research-only — teaches control of state, not exploit payloads.
/// </summary>
public static class InfluenceEngine
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() },
    };

    public static string PathFor(string crashesDir, Guid crashId) =>
        Path.Combine(crashesDir, $"{crashId:N}_influence.json");

    public static CrashInfluenceMapDto? TryRead(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            return null;
        try
        {
            return JsonSerializer.Deserialize<CrashInfluenceMapDto>(File.ReadAllText(path), JsonOptions);
        }
        catch
        {
            return null;
        }
    }

    public static CrashInfluenceMapDto Build(
        Guid crashId,
        string project,
        CrashSidecarDto? sidecar,
        CrashTriageDto? triage,
        DebuggerObservation? debugger,
        CrashCorruptionChainDto? corruptionChain,
        CrashBackwardTraceDto? backwardTrace = null,
        HypothesisSetDto? hypotheses = null,
        IReadOnlyList<EvidenceFact>? externalFacts = null,
        byte[]? payload = null)
    {
        var lineage = corruptionChain?.MutatorLineage?.ToList()
                      ?? sidecar?.MutatorChain?.ToList()
                      ?? (sidecar?.Mutator is { } m ? new List<string> { m } : []);
        var attribution = InputAttributionEngine.Analyze(payload, debugger, triage, sidecar, lineage);
        var facts = CollectFacts(sidecar, triage, debugger, corruptionChain, backwardTrace, attribution, externalFacts);
        var links = new List<InfluenceLinkDto>();

        AddRegisterLinks(links, attribution, debugger, corruptionChain, sidecar, hypotheses);
        AddPatternDepthLinks(links, attribution, debugger, corruptionChain, sidecar, hypotheses);
        AddLengthCopyLinks(links, attribution, debugger, corruptionChain, sidecar, hypotheses);
        AddBackwardTraceLinks(links, backwardTrace, corruptionChain, sidecar, hypotheses);
        AddHeapLinks(links, debugger, corruptionChain, backwardTrace, sidecar);

        ApplyHypothesisOutcomes(links, hypotheses);

        var confidence = RollupConfidence(links, attribution.Confidence, debugger?.SuspectedInputInfluence);
        var narrative = attribution.Narrative ?? corruptionChain?.Narrative;
        var summary = BuildSummary(links, confidence, attribution);

        return new CrashInfluenceMapDto(
            links.Count > 0,
            crashId,
            project,
            confidence,
            summary,
            links.OrderByDescending(l => StatusRank(l.Status)).ThenBy(l => l.Region.StartOffset).ToList(),
            facts,
            DateTimeOffset.UtcNow,
            narrative);
    }

    public static CrashInfluenceMapDto PersistForCrash(
        string crashesDir,
        Guid crashId,
        string project,
        CrashSidecarDto? sidecar,
        CrashTriageDto? triage,
        DebuggerObservation? debugger,
        CrashCorruptionChainDto? corruptionChain,
        CrashBackwardTraceDto? backwardTrace = null,
        HypothesisSetDto? hypotheses = null,
        IReadOnlyList<EvidenceFact>? externalFacts = null,
        byte[]? payload = null)
    {
        var map = Build(crashId, project, sidecar, triage, debugger, corruptionChain,
            backwardTrace, hypotheses, externalFacts, payload);
        Write(crashesDir, map);
        return map;
    }

    public static string Write(string crashesDir, CrashInfluenceMapDto map)
    {
        Directory.CreateDirectory(crashesDir);
        var path = PathFor(crashesDir, map.CrashId);
        File.WriteAllText(path, JsonSerializer.Serialize(map, JsonOptions));
        return path;
    }

    /// <summary>
    /// Refresh confirmation status on an existing map after HypothesisEngine records an outcome.
    /// </summary>
    public static CrashInfluenceMapDto? RefreshFromHypotheses(
        string crashesDir,
        Guid crashId,
        HypothesisSetDto? hypotheses = null)
    {
        var path = PathFor(crashesDir, crashId);
        var map = TryRead(path);
        if (map is null)
            return null;

        hypotheses ??= HypothesisEngine.TryReadForCrash(crashesDir, crashId);
        if (hypotheses is null)
            return map;

        var links = map.Links.ToList();
        ApplyHypothesisOutcomes(links, hypotheses);
        var confidence = RollupConfidence(links, map.Confidence, null);
        var updated = map with
        {
            Links = links.OrderByDescending(l => StatusRank(l.Status)).ThenBy(l => l.Region.StartOffset).ToList(),
            Confidence = confidence,
            Summary = BuildSummary(links, confidence, null),
            At = DateTimeOffset.UtcNow,
        };
        Write(crashesDir, updated);
        return updated;
    }

    internal static void ApplyHypothesisOutcomes(List<InfluenceLinkDto> links, HypothesisSetDto? hypotheses)
    {
        if (hypotheses?.Hypotheses is not { Count: > 0 })
            return;

        foreach (var hyp in hypotheses.Hypotheses)
        {
            if (hyp.Result is null)
                continue;

            var offset = hyp.Experiment.OffsetBytes;
            foreach (var i in links.Select((link, idx) => (link, idx)).ToList())
            {
                if (offset is int o && (i.link.Region.StartOffset != o && i.link.Region.EndOffset != o + 1))
                {
                    if (i.link.Region.StartOffset > o + 8 || (i.link.Region.EndOffset ?? i.link.Region.StartOffset + 4) < o)
                        continue;
                }

                var matchesHyp = i.link.HypothesisId?.Equals(hyp.Id, StringComparison.OrdinalIgnoreCase) == true
                    || (offset is int off && Math.Abs(i.link.Region.StartOffset - off) <= 4)
                    || hyp.Id.Contains("lineage", StringComparison.OrdinalIgnoreCase)
                        && i.link.Region.Mutator?.Equals(hyp.Experiment.Mutator, StringComparison.OrdinalIgnoreCase) == true;

                if (!matchesHyp)
                    continue;

                var newStatus = hyp.Result.Status switch
                {
                    HypothesisStatus.Confirmed => InfluenceConfirmationStatus.Confirmed,
                    HypothesisStatus.Partial => i.link.Status == InfluenceConfirmationStatus.Unknown
                        ? InfluenceConfirmationStatus.Candidate
                        : i.link.Status,
                    HypothesisStatus.Refuted => i.link.Status == InfluenceConfirmationStatus.Confirmed
                        ? InfluenceConfirmationStatus.Observed
                        : InfluenceConfirmationStatus.Candidate,
                    _ => i.link.Status,
                };

                if (newStatus != i.link.Status)
                {
                    links[i.idx] = i.link with
                    {
                        Status = newStatus,
                        HypothesisId = hyp.Id,
                    };
                }
            }
        }
    }

    private static void AddRegisterLinks(
        List<InfluenceLinkDto> links,
        InputAttributionEngine.AttributionResult attribution,
        DebuggerObservation? debugger,
        CrashCorruptionChainDto? chain,
        CrashSidecarDto? sidecar,
        HypothesisSetDto? hypotheses)
    {
        foreach (var match in attribution.RegisterMatches)
        {
            if (string.Equals(match.Register, "RIP", StringComparison.OrdinalIgnoreCase)
                || string.Equals(match.Register, "FAULT", StringComparison.OrdinalIgnoreCase))
            {
                links.Add(new InfluenceLinkDto(
                    $"inf-ptr-{match.PayloadOffset:X}",
                    new InfluenceRegionDto(
                        match.PayloadOffset,
                        match.PayloadOffset + match.WidthBytes,
                        match.WidthBytes,
                        chain?.SuspectedField ?? $"payload+{match.PayloadOffset}",
                        chain?.SuspectedMutator,
                        chain?.SuspectedMutatorStep),
                    new InfluencedStateDto(
                        InfluencedStateKind.FaultAddress,
                        match.Register,
                        match.ValueHex,
                        debugger?.FaultAddressClass.ToString()),
                    InfluenceConfirmationStatus.Observed,
                    match.MatchKind == "ascii" ? "pointer→fault address (ASCII)" : "pointer→fault address",
                    [$"register:{match.Register}@+{match.PayloadOffset}", $"match:{match.MatchKind}"],
                    SuggestExperiment(hypotheses, match.PayloadOffset, chain, sidecar, HypothesisExperimentKind.MinimizeHold),
                    FindHypothesisId(hypotheses, match.PayloadOffset, "ascii")));
                continue;
            }

            links.Add(new InfluenceLinkDto(
                $"inf-reg-{match.Register.ToLowerInvariant()}-{match.PayloadOffset:X}",
                new InfluenceRegionDto(
                    match.PayloadOffset,
                    match.PayloadOffset + match.WidthBytes,
                    match.WidthBytes,
                    chain?.SuspectedField,
                    chain?.SuspectedMutator,
                    chain?.SuspectedMutatorStep),
                new InfluencedStateDto(
                    InfluencedStateKind.Register,
                    match.Register,
                    match.ValueHex,
                    match.Note),
                InfluenceConfirmationStatus.Observed,
                "input→register value",
                [$"register:{match.Register}@+{match.PayloadOffset}", $"debugger:{debugger?.Access}"],
                SuggestExperiment(hypotheses, match.PayloadOffset, chain, sidecar, HypothesisExperimentKind.SweepOffset),
                FindHypothesisId(hypotheses, match.PayloadOffset, "offset")));
        }
    }

    private static void AddPatternDepthLinks(
        List<InfluenceLinkDto> links,
        InputAttributionEngine.AttributionResult attribution,
        DebuggerObservation? debugger,
        CrashCorruptionChainDto? chain,
        CrashSidecarDto? sidecar,
        HypothesisSetDto? hypotheses)
    {
        if (attribution.PatternDepthBytes is not int offset)
            return;

        if (links.Any(l => l.Region.StartOffset == offset))
            return;

        var width = debugger?.FaultAddressClass == DebuggerAddressClass.AsciiPattern ? 4 : 8;
        var status = attribution.Confidence is "HIGH" or "MEDIUM"
            ? InfluenceConfirmationStatus.Observed
            : InfluenceConfirmationStatus.Candidate;

        links.Add(new InfluenceLinkDto(
            $"inf-depth-{offset:X}",
            new InfluenceRegionDto(
                offset,
                offset + width,
                width,
                chain?.SuspectedField ?? sidecar?.Command ?? $"payload+{offset}",
                chain?.SuspectedMutator ?? attribution.SuspectedMutator,
                attribution.SuspectedMutatorStep),
            new InfluencedStateDto(
                debugger?.FaultAddressClass == DebuggerAddressClass.AsciiPattern
                    ? InfluencedStateKind.Pointer
                    : InfluencedStateKind.FaultAddress,
                debugger?.FaultAddress ?? "fault",
                debugger?.Rip,
                attribution.PatternNote),
            status,
            InferMechanism(debugger, chain),
            [$"patternDepth:{offset}", $"corruption:{chain?.Confidence ?? "UNKNOWN"}"],
            SuggestExperiment(hypotheses, offset, chain, sidecar, HypothesisExperimentKind.SweepOffset),
            FindHypothesisId(hypotheses, offset, "offset")));
    }

    private static void AddLengthCopyLinks(
        List<InfluenceLinkDto> links,
        InputAttributionEngine.AttributionResult attribution,
        DebuggerObservation? debugger,
        CrashCorruptionChainDto? chain,
        CrashSidecarDto? sidecar,
        HypothesisSetDto? hypotheses)
    {
        var fn = (debugger?.FaultingFunction ?? "").ToLowerInvariant();
        var disasm = (debugger?.DisasmNearRip ?? "").ToLowerInvariant();
        var isCopySink = fn.Contains("memcpy") || fn.Contains("memmove") || fn.Contains("strcpy")
                         || fn.Contains("strncpy") || fn.Contains("read") || fn.Contains("recv")
                         || disasm.Contains("memcpy") || disasm.Contains("rep movs");

        if (!isCopySink && debugger?.Access != DebuggerAccessKind.Write)
            return;

        var offset = attribution.PatternDepthBytes ?? 0;
        var mutator = attribution.SuspectedMutator ?? chain?.SuspectedMutator;
        if (mutator is null || !LooksLikeLengthMutator(mutator))
            return;

        if (links.Any(l => l.State.Kind is InfluencedStateKind.Length or InfluencedStateKind.CopyLength))
            return;

        var regionStart = Math.Max(0, offset - 4);
        links.Add(new InfluenceLinkDto(
            $"inf-len-{regionStart:X}",
            new InfluenceRegionDto(
                regionStart,
                regionStart + 4,
                4,
                sidecar?.Command ?? "length field",
                mutator,
                attribution.SuspectedMutatorStep),
            new InfluencedStateDto(
                fn.Contains("read") || fn.Contains("recv") ? InfluencedStateKind.Length : InfluencedStateKind.CopyLength,
                debugger?.FaultingFunction ?? "copy sink",
                debugger?.FaultAddress,
                "length→alloc/copy"),
            InfluenceConfirmationStatus.Candidate,
            "length→alloc/copy",
            [$"mutator:{mutator}", $"sink:{debugger?.FaultingFunction ?? "?"}", $"access:{debugger?.Access}"],
            SuggestExperiment(hypotheses, offset, chain, sidecar, HypothesisExperimentKind.BoundaryProbe),
            FindHypothesisId(hypotheses, offset, "boundary")));
    }

    private static void AddBackwardTraceLinks(
        List<InfluenceLinkDto> links,
        CrashBackwardTraceDto? trace,
        CrashCorruptionChainDto? chain,
        CrashSidecarDto? sidecar,
        HypothesisSetDto? hypotheses)
    {
        if (trace is not { Ok: true } || !TryParsePayloadOffset(trace.PrimaryPayloadOffset, out var off))
            return;

        if (links.Any(l => l.Region.StartOffset == off && l.State.Kind == InfluencedStateKind.Register))
            return;

        links.Add(new InfluenceLinkDto(
            $"inf-btrace-{off:X}",
            new InfluenceRegionDto(
                off,
                off + 4,
                4,
                chain?.SuspectedField,
                trace.SuspectedMutator ?? chain?.SuspectedMutator,
                chain?.SuspectedMutatorStep),
            new InfluencedStateDto(
                InfluencedStateKind.Register,
                trace.FaultRegister ?? "fault register",
                trace.BadPointerSource,
                trace.Story),
            InfluenceConfirmationStatus.Observed,
            "input→register (backward trace)",
            [$"backwardTrace:{trace.Confidence}", $"register:{trace.FaultRegister}"],
            SuggestExperiment(hypotheses, off, chain, sidecar, HypothesisExperimentKind.ReplayLineage),
            FindHypothesisId(hypotheses, off, "btrace")));
    }

    private static void AddHeapLinks(
        List<InfluenceLinkDto> links,
        DebuggerObservation? debugger,
        CrashCorruptionChainDto? chain,
        CrashBackwardTraceDto? trace,
        CrashSidecarDto? sidecar)
    {
        if (debugger?.HeapSignal is null && trace?.HeapTimeline is null)
            return;

        var offset = chain?.PatternDepthBytes ?? 0;
        if (links.Any(l => l.State.Kind == InfluencedStateKind.HeapObject))
            return;

        links.Add(new InfluenceLinkDto(
            "inf-heap",
            new InfluenceRegionDto(
                offset,
                null,
                null,
                sidecar?.Command ?? "heap-touching field",
                chain?.SuspectedMutator,
                chain?.SuspectedMutatorStep),
            new InfluencedStateDto(
                InfluencedStateKind.HeapObject,
                debugger?.HeapSignal ?? trace?.HeapTimeline ?? "heap",
                debugger?.FaultAddress,
                trace?.HeapTimeline),
            debugger?.RegisterMatches?.Count > 0
                ? InfluenceConfirmationStatus.Observed
                : InfluenceConfirmationStatus.Candidate,
            "input→heap object lifetime",
            [$"heap:{debugger?.HeapSignal ?? trace?.HeapTimeline}", $"class:{debugger?.FaultAddressClass}"],
            null,
            null));
    }

    private static List<EvidenceFact> CollectFacts(
        CrashSidecarDto? sidecar,
        CrashTriageDto? triage,
        DebuggerObservation? debugger,
        CrashCorruptionChainDto? chain,
        CrashBackwardTraceDto? trace,
        InputAttributionEngine.AttributionResult attribution,
        IReadOnlyList<EvidenceFact>? externalFacts)
    {
        var facts = externalFacts?.ToList() ?? [];

        if (facts.Count == 0)
        {
            facts.AddRange(EvidenceFactBuilder.CollectFacts(
                Guid.Empty,
                sidecar?.Project ?? "?",
                sidecar,
                triage,
                debugger,
                chain,
                trace));
        }

        var at = DateTimeOffset.UtcNow;
        foreach (var match in attribution.RegisterMatches.Take(6))
        {
            if (facts.Any(f => f.Name == $"influence.register.{match.Register}"))
                continue;

            facts.Add(EvidenceFactBuilder.Fact(
                $"influence.register.{match.Register}",
                $"{match.ValueHex} at input+{match.PayloadOffset} ({match.MatchKind})",
                "input_attribution",
                null,
                EvidenceObservationType.Observed,
                match.MatchKind == "ascii" ? 0.9 : 0.75,
                at));
        }

        if (attribution.PatternDepthBytes is int d
            && !facts.Any(f => f.Name is "corruption.patternDepth" or "triage.patternDepth"))
        {
            facts.Add(EvidenceFactBuilder.Fact(
                "influence.patternDepth",
                d.ToString(),
                "input_attribution",
                null,
                EvidenceObservationType.Observed,
                0.7,
                at));
        }

        return facts;
    }

    private static bool TryParsePayloadOffset(string? text, out int offset)
    {
        offset = 0;
        if (string.IsNullOrWhiteSpace(text))
            return false;

        var t = text.Trim();
        if (t.StartsWith("+", StringComparison.Ordinal))
            t = t[1..];
        if (t.StartsWith("payload+", StringComparison.OrdinalIgnoreCase))
            t = t["payload+".Length..];
        if (t.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            return int.TryParse(t[2..], System.Globalization.NumberStyles.HexNumber, null, out offset);

        return int.TryParse(t, out offset);
    }

    private static string InferMechanism(DebuggerObservation? debugger, CrashCorruptionChainDto? chain)
    {
        var fn = (debugger?.FaultingFunction ?? "").ToLowerInvariant();
        if (debugger?.FaultAddressClass == DebuggerAddressClass.AsciiPattern)
            return "pointer→fault address";
        if (fn.Contains("memcpy") || fn.Contains("memmove"))
            return "length→memcpy-style copy";
        if (debugger?.Access == DebuggerAccessKind.Write)
            return "input→controlled write";
        if (chain?.Steps.Any(s => s.Kind == "register") == true)
            return "input→register→sink";
        return "input→fault state";
    }

    private static bool LooksLikeLengthMutator(string mutator) =>
        mutator.Contains("expand", StringComparison.OrdinalIgnoreCase)
        || mutator.Contains("insert", StringComparison.OrdinalIgnoreCase)
        || mutator.Contains("splice", StringComparison.OrdinalIgnoreCase)
        || mutator.Contains("interesting", StringComparison.OrdinalIgnoreCase)
        || mutator.Contains("boundary", StringComparison.OrdinalIgnoreCase)
        || mutator.Contains("cyclic", StringComparison.OrdinalIgnoreCase);

    private static HypothesisExperimentDto? SuggestExperiment(
        HypothesisSetDto? hypotheses,
        int offset,
        CrashCorruptionChainDto? chain,
        CrashSidecarDto? sidecar,
        HypothesisExperimentKind kind)
    {
        var hyp = hypotheses?.Hypotheses.FirstOrDefault(h =>
            h.Experiment.OffsetBytes == offset && h.Experiment.Kind == kind)
            ?? hypotheses?.Hypotheses.FirstOrDefault(h =>
                h.Experiment.OffsetBytes == offset);

        if (hyp is not null)
            return hyp.Experiment;

        return kind switch
        {
            HypothesisExperimentKind.SweepOffset => new HypothesisExperimentDto(
                kind,
                $"Sweep ±4 bytes around offset {offset}",
                "bitflip",
                offset,
                4,
                chain?.MutatorLineage,
                sidecar?.Command),
            HypothesisExperimentKind.MinimizeHold => new HypothesisExperimentDto(
                kind,
                $"Preserve bytes at offset {offset}; shrink elsewhere",
                chain?.SuspectedMutator ?? "expand",
                offset,
                SweepRange: 4,
                Command: sidecar?.Command),
            HypothesisExperimentKind.BoundaryProbe => new HypothesisExperimentDto(
                kind,
                $"Probe boundary values at offset {offset}",
                "interesting",
                offset,
                Command: sidecar?.Command),
            HypothesisExperimentKind.ReplayLineage => new HypothesisExperimentDto(
                kind,
                "Replay mutator lineage from seed",
                chain?.SuspectedMutator,
                MutatorChain: chain?.MutatorLineage,
                Command: sidecar?.Command),
            _ => null,
        };
    }

    private static string? FindHypothesisId(HypothesisSetDto? hypotheses, int offset, string hint)
    {
        if (hypotheses is null)
            return null;
        return hypotheses.Hypotheses.FirstOrDefault(h =>
                h.Experiment.OffsetBytes == offset
                || h.Id.Contains(hint, StringComparison.OrdinalIgnoreCase))
            ?.Id;
    }

    private static string RollupConfidence(
        IReadOnlyList<InfluenceLinkDto> links,
        string attributionConfidence,
        string? debuggerInfluence)
    {
        if (links.Any(l => l.Status == InfluenceConfirmationStatus.Confirmed))
            return "HIGH";
        if (links.Any(l => l.Status == InfluenceConfirmationStatus.Observed)
            && (attributionConfidence is "HIGH" or "MEDIUM" || debuggerInfluence is "HIGH"))
            return attributionConfidence is "HIGH" or "MEDIUM" ? attributionConfidence : "MEDIUM";
        if (links.Any(l => l.Status == InfluenceConfirmationStatus.Observed))
            return "MEDIUM";
        if (links.Any(l => l.Status == InfluenceConfirmationStatus.Candidate))
            return "LOW";
        return attributionConfidence is "UNKNOWN" ? "UNKNOWN" : "LOW";
    }

    private static string BuildSummary(
        IReadOnlyList<InfluenceLinkDto> links,
        string confidence,
        InputAttributionEngine.AttributionResult? attribution)
    {
        if (links.Count == 0)
            return attribution?.Summary ?? "[UNKNOWN] no influence links inferred";

        var sb = new StringBuilder();
        sb.Append($"[{confidence}] ");
        var top = links.OrderByDescending(l => StatusRank(l.Status)).First();
        sb.Append($"{FormatRegion(top.Region)} → {top.State.Label} ({top.Mechanism})");
        if (links.Count > 1)
            sb.Append($" · +{links.Count - 1} link(s)");
        return sb.ToString();
    }

    private static string FormatRegion(InfluenceRegionDto region)
    {
        if (region.EndOffset is int end && end > region.StartOffset + 1)
            return $"input[{region.StartOffset},{end})";
        if (region.WidthBytes is int w && w > 1)
            return $"input+{region.StartOffset} ({w}B)";
        return $"input+{region.StartOffset}";
    }

    private static int StatusRank(InfluenceConfirmationStatus status) => status switch
    {
        InfluenceConfirmationStatus.Confirmed => 4,
        InfluenceConfirmationStatus.Observed => 3,
        InfluenceConfirmationStatus.Candidate => 2,
        _ => 1,
    };
}
