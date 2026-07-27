using System.Text.Json;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Builds a research-only corruption chain: mutation lineage + pattern depth + debugger evidence.
/// Does not invent exploit payloads — attributes what Randall already observed.
/// </summary>
public static class CorruptionChainBuilder
{
    private static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = true };

    public static string PathFor(string crashesDir, Guid crashId) =>
        Path.Combine(crashesDir, $"{crashId:N}_corruption_chain.json");

    public static CrashCorruptionChainDto? TryRead(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            return null;
        try
        {
            return JsonSerializer.Deserialize<CrashCorruptionChainDto>(File.ReadAllText(path));
        }
        catch
        {
            return null;
        }
    }

    public static CrashCorruptionChainDto Build(
        Guid crashId,
        string project,
        CrashSidecarDto? sidecar,
        DebuggerObservation? debugger,
        CrashTriageDto? triage,
        byte[]? payload = null)
    {
        var lineage = CrashLineageResolver.Resolve(sidecar);
        var chain = lineage?.MutatorChain?.ToList()
                    ?? sidecar?.MutatorChain?.ToList()
                    ?? (sidecar?.Mutator is { } m ? new List<string> { m } : []);

        var attribution = InputAttributionEngine.Analyze(payload, debugger, triage, sidecar, chain);
        var depth = attribution.PatternDepthBytes;
        var depthNote = attribution.PatternNote;

        var steps = new List<CorruptionChainStepDto>();
        var order = 0;

        if (!string.IsNullOrWhiteSpace(sidecar?.SeedSource))
            steps.Add(new CorruptionChainStepDto(++order, "seed", sidecar.SeedSource!, "seed origin"));

        for (var i = 0; i < chain.Count; i++)
        {
            var isAttributed = attribution.SuspectedMutatorStep == i;
            steps.Add(new CorruptionChainStepDto(
                ++order,
                "mutation",
                chain[i],
                isAttributed
                    ? "attributed mutation step"
                    : i == chain.Count - 1 ? "last mutator before crash" : null));
        }

        if (!string.IsNullOrWhiteSpace(sidecar?.Command))
            steps.Add(new CorruptionChainStepDto(++order, "field", sidecar.Command, "session / protocol node"));

        foreach (var match in attribution.RegisterMatches.Take(6))
        {
            steps.Add(new CorruptionChainStepDto(
                ++order,
                "register",
                $"{match.Register}={match.ValueHex}",
                $"input+{match.PayloadOffset} ({match.MatchKind}) · {match.Note}"));
        }

        if (depth is int off && attribution.RegisterMatches.All(m => m.PayloadOffset != off))
            steps.Add(new CorruptionChainStepDto(
                ++order, "input-offset", $"input+0x{off:X}", depthNote ?? "address dword/qword found in payload"));

        if (debugger is { Ok: true })
        {
            if (debugger.Access != DebuggerAccessKind.Unknown)
                steps.Add(new CorruptionChainStepDto(++order, "access", debugger.Access.ToString(),
                    debugger.FaultAddressClass.ToString()));
            if (!string.IsNullOrWhiteSpace(debugger.FaultingFunction))
            {
                var sinkDetail = InferSinkDetail(debugger);
                steps.Add(new CorruptionChainStepDto(++order, "function",
                    $"{debugger.FaultingModule ?? "?"}!{debugger.FaultingFunction}{debugger.FunctionOffset ?? ""}",
                    sinkDetail ?? debugger.Rip));
            }

            if (!string.IsNullOrWhiteSpace(debugger.FaultAddress))
                steps.Add(new CorruptionChainStepDto(++order, "fault-address", debugger.FaultAddress!,
                    debugger.FaultAddressClass.ToString()));
            if (!string.IsNullOrWhiteSpace(debugger.HeapSignal))
                steps.Add(new CorruptionChainStepDto(++order, "heap", debugger.HeapSignal!));
            steps.Add(new CorruptionChainStepDto(++order, "crash",
                debugger.ExceptionHint ?? "ACCESS_VIOLATION", debugger.Diagnosis));
        }
        else if (triage is not null)
        {
            steps.Add(new CorruptionChainStepDto(++order, "crash",
                triage.ExceptionHint ?? triage.Class, triage.Summary));
        }

        var suspectedMutator = attribution.SuspectedMutator ?? (chain.Count > 0 ? chain[^1] : sidecar?.Mutator);
        var suspectedField = InferField(sidecar?.Command, depth, depthNote, debugger, attribution.PrimaryMatch);
        var diagnosis = MergeDiagnosis(debugger?.Diagnosis, attribution.Narrative);

        return new CrashCorruptionChainDto(
            Ok: steps.Count > 0,
            CrashId: crashId,
            Project: project,
            Confidence: attribution.Confidence,
            Summary: attribution.Summary,
            SuspectedField: suspectedField,
            SuspectedMutator: suspectedMutator,
            PatternDepthBytes: depth,
            PatternNote: depthNote,
            MutatorLineage: chain,
            Steps: steps,
            DebuggerDiagnosis: diagnosis,
            StackHash: debugger?.StackHash,
            At: DateTimeOffset.UtcNow,
            SuspectedMutatorStep: attribution.SuspectedMutatorStep,
            RegisterMatches: attribution.RegisterMatches,
            PrimaryRegister: attribution.PrimaryMatch?.Register,
            Narrative: attribution.Narrative,
            AttributionScreamBonus: attribution.AttributionScreamBonus);
    }

    public static CrashCorruptionChainDto PersistForCrash(
        string crashesDir,
        Guid crashId,
        string project,
        CrashSidecarDto? sidecar,
        DebuggerObservation? debugger,
        CrashTriageDto? triage,
        byte[]? payload = null)
    {
        var chain = Build(crashId, project, sidecar, debugger, triage, payload);
        Write(crashesDir, chain);
        return chain;
    }

    public static string Write(string crashesDir, CrashCorruptionChainDto chain)
    {
        Directory.CreateDirectory(crashesDir);
        var path = PathFor(crashesDir, chain.CrashId);
        File.WriteAllText(path, JsonSerializer.Serialize(chain, JsonOpts));
        return path;
    }

    private static string InferField(
        string? command,
        int? depth,
        string? depthNote,
        DebuggerObservation? debugger,
        RegisterPayloadMatchDto? primaryMatch)
    {
        if (primaryMatch is not null)
            return $"payload+{primaryMatch.PayloadOffset}" + (command is null ? "" : $" ({command})");
        if (depth is int d && !string.IsNullOrWhiteSpace(depthNote))
            return $"payload+{d}" + (command is null ? "" : $" ({command})");
        if (debugger?.FaultAddressClass == DebuggerAddressClass.AsciiPattern)
            return command is null ? "length/body (ASCII-controlled address)" : $"{command} body/length";
        if (!string.IsNullOrWhiteSpace(command))
            return command;
        return "unknown field";
    }

    private static string? InferSinkDetail(DebuggerObservation debugger)
    {
        var fn = (debugger.FaultingFunction ?? "").ToLowerInvariant();
        var disasm = (debugger.DisasmNearRip ?? "").ToLowerInvariant();
        if (fn.Contains("memcpy") || fn.Contains("memmove") || disasm.Contains("memcpy"))
            return "length→memcpy-style sink";
        if (debugger.Access == DebuggerAccessKind.Write
            && (debugger.FaultAddressClass is (DebuggerAddressClass.NullPage
                    or DebuggerAddressClass.NearNull
                    or DebuggerAddressClass.SmallOffset)
                || InputAttributionEngine.IsExcludedFromRawInputAttribution(debugger.FaultAddress)))
            return "null/invalid destination write";
        if (debugger.Access == DebuggerAccessKind.Write
            && InputAttributionEngine.IsStrongNonZeroPattern(debugger.FaultAddress))
            return "controlled write sink";
        if (debugger.Access == DebuggerAccessKind.Write)
            return "write sink";
        return null;
    }

    private static string? MergeDiagnosis(string? debuggerDiagnosis, string? narrative)
    {
        if (string.IsNullOrWhiteSpace(narrative))
            return debuggerDiagnosis;
        if (string.IsNullOrWhiteSpace(debuggerDiagnosis))
            return narrative;
        if (debuggerDiagnosis.Contains(narrative, StringComparison.OrdinalIgnoreCase))
            return debuggerDiagnosis;
        return $"{debuggerDiagnosis} Attribution: {narrative}";
    }
}
