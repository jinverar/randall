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

        var (depth, depthNote) = triage?.PatternDepthBytes is int d
            ? (triage.PatternDepthBytes, triage.PatternNote)
            : CrashTriage.FindPatternDepth(
                payload,
                debugger?.Rip ?? triage?.Rip,
                debugger?.FaultAddress ?? triage?.FaultAddress,
                triage?.Rsp);

        var steps = new List<CorruptionChainStepDto>();
        var order = 0;

        if (!string.IsNullOrWhiteSpace(sidecar?.SeedSource))
            steps.Add(new CorruptionChainStepDto(++order, "seed", sidecar.SeedSource!, "seed origin"));

        for (var i = 0; i < chain.Count; i++)
        {
            steps.Add(new CorruptionChainStepDto(
                ++order,
                "mutation",
                chain[i],
                i == chain.Count - 1 ? "last mutator before crash" : null));
        }

        if (!string.IsNullOrWhiteSpace(sidecar?.Command))
            steps.Add(new CorruptionChainStepDto(++order, "command", sidecar.Command, "session / protocol node"));

        if (depth is int off)
            steps.Add(new CorruptionChainStepDto(
                ++order, "input-offset", $"input+0x{off:X}", depthNote ?? "address dword/qword found in payload"));

        if (debugger is { Ok: true })
        {
            if (debugger.Access != DebuggerAccessKind.Unknown)
                steps.Add(new CorruptionChainStepDto(++order, "access", debugger.Access.ToString(),
                    debugger.FaultAddressClass.ToString()));
            if (!string.IsNullOrWhiteSpace(debugger.FaultingFunction))
                steps.Add(new CorruptionChainStepDto(++order, "function",
                    $"{debugger.FaultingModule ?? "?"}!{debugger.FaultingFunction}{debugger.FunctionOffset ?? ""}",
                    debugger.Rip));
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

        var suspectedMutator = chain.Count > 0 ? chain[^1] : sidecar?.Mutator;
        var suspectedField = InferField(sidecar?.Command, depth, depthNote, debugger);
        var confidence = ScoreConfidence(debugger, depth, chain.Count);
        var summary = BuildSummary(suspectedMutator, suspectedField, debugger, depth, confidence);

        return new CrashCorruptionChainDto(
            Ok: steps.Count > 0,
            CrashId: crashId,
            Project: project,
            Confidence: confidence,
            Summary: summary,
            SuspectedField: suspectedField,
            SuspectedMutator: suspectedMutator,
            PatternDepthBytes: depth,
            PatternNote: depthNote,
            MutatorLineage: chain,
            Steps: steps,
            DebuggerDiagnosis: debugger?.Diagnosis,
            StackHash: debugger?.StackHash,
            At: DateTimeOffset.UtcNow);
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
        DebuggerObservation? debugger)
    {
        if (depth is int d && !string.IsNullOrWhiteSpace(depthNote))
            return $"payload+{d}" + (command is null ? "" : $" ({command})");
        if (debugger?.FaultAddressClass == DebuggerAddressClass.AsciiPattern)
            return command is null ? "length/body (ASCII-controlled address)" : $"{command} body/length";
        if (!string.IsNullOrWhiteSpace(command))
            return command;
        return "unknown field";
    }

    private static string ScoreConfidence(DebuggerObservation? dbg, int? depth, int chainLen)
    {
        var score = 0;
        if (dbg is { Ok: true }) score += 2;
        if (dbg?.SuspectedInputInfluence == "HIGH") score += 3;
        else if (dbg?.SuspectedInputInfluence == "MEDIUM") score += 1;
        if (dbg?.FaultAddressClass == DebuggerAddressClass.AsciiPattern) score += 2;
        if (depth is not null) score += 2;
        if (chainLen >= 2) score += 1;
        return score switch
        {
            >= 6 => "HIGH",
            >= 3 => "MEDIUM",
            >= 1 => "LOW",
            _ => "UNKNOWN",
        };
    }

    private static string BuildSummary(
        string? mutator,
        string? field,
        DebuggerObservation? dbg,
        int? depth,
        string confidence)
    {
        var parts = new List<string>();
        if (!string.IsNullOrWhiteSpace(mutator))
            parts.Add($"mutation '{mutator}'");
        if (!string.IsNullOrWhiteSpace(field))
            parts.Add($"field {field}");
        if (depth is int d)
            parts.Add($"pattern @ +{d}");
        if (dbg?.Access is DebuggerAccessKind.Write or DebuggerAccessKind.Execute)
            parts.Add($"{dbg.Access.ToString().ToLowerInvariant()} AV");
        if (dbg?.FaultingFunction is not null)
            parts.Add($"in {dbg.FaultingModule}!{dbg.FaultingFunction}");
        var body = parts.Count == 0 ? "insufficient evidence for attribution" : string.Join(" → ", parts);
        return $"[{confidence}] {body}";
    }
}
