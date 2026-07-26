using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Builds a research-only backward trace from post-mortem CDB/dump evidence — no live TTD.
/// Joins fault instruction, register↔payload matches, stack/heap heuristics, and mutation lineage.
/// </summary>
public static partial class BackwardTraceBuilder
{
    private static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = true };

    public static string PathFor(string crashesDir, Guid crashId) =>
        Path.Combine(crashesDir, $"{crashId:N}_backward_trace.json");

    public static CrashBackwardTraceDto? TryRead(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            return null;
        try
        {
            return JsonSerializer.Deserialize<CrashBackwardTraceDto>(File.ReadAllText(path));
        }
        catch
        {
            return null;
        }
    }

    public static CrashBackwardTraceDto Build(
        Guid crashId,
        string project,
        CrashSidecarDto? sidecar,
        DebuggerObservation? debugger,
        CrashTriageDto? triage,
        CrashCorruptionChainDto? corruptionChain,
        byte[]? payload = null)
    {
        if (debugger is not { Ok: true } && corruptionChain is not { Ok: true } && triage is null)
        {
            return new CrashBackwardTraceDto(
                false, crashId, project, "UNKNOWN", "insufficient debugger evidence for backward trace",
                [], null, null, null, null, null, null, null, null, DateTimeOffset.UtcNow,
                "no debugger observation or corruption chain");
        }

        var lineage = corruptionChain?.MutatorLineage?.ToList()
                      ?? sidecar?.MutatorChain?.ToList()
                      ?? (sidecar?.Mutator is { } m ? new List<string> { m } : []);

        var attribution = InputAttributionEngine.Analyze(payload, debugger, triage, sidecar, lineage);
        var matches = corruptionChain?.RegisterMatches?.ToList()
                      ?? attribution.RegisterMatches.ToList();
        var primary = matches.FirstOrDefault(m =>
                          corruptionChain?.PrimaryRegister is { } pr
                          && m.Register.Equals(pr, StringComparison.OrdinalIgnoreCase))
                      ?? attribution.PrimaryMatch;

        var steps = new List<BackwardTraceStepDto>();
        var order = 0;

        if (!string.IsNullOrWhiteSpace(sidecar?.SeedSource))
            steps.Add(new BackwardTraceStepDto(++order, "seed", sidecar.SeedSource!, "origin seed", "MEDIUM"));

        for (var i = 0; i < lineage.Count; i++)
        {
            var attributed = attribution.SuspectedMutatorStep == i
                             || corruptionChain?.SuspectedMutatorStep == i;
            var conf = attributed ? "HIGH" : i == lineage.Count - 1 ? "MEDIUM" : "LOW";
            steps.Add(new BackwardTraceStepDto(
                ++order, "mutation", lineage[i],
                attributed ? "introduced value seen at fault" : null, conf));
        }

        foreach (var match in matches.Take(4))
        {
            steps.Add(new BackwardTraceStepDto(
                ++order, "register",
                $"{match.Register}={match.ValueHex}",
                $"payload+{match.PayloadOffset} ({match.MatchKind})",
                match.MatchKind == "ascii" ? "HIGH" : "MEDIUM"));
        }

        var badSource = InferBadPointerSource(debugger, triage, primary);
        if (badSource is not null)
            steps.Add(new BackwardTraceStepDto(++order, "source", badSource.Label, badSource.Detail, badSource.Confidence));

        var heapTimeline = BuildHeapTimeline(debugger);
        if (heapTimeline is not null)
            steps.Add(new BackwardTraceStepDto(++order, "heap-timeline", heapTimeline, "post-mortem heap signal", "MEDIUM"));

        var faultInstr = ExtractFaultInstruction(debugger);
        if (faultInstr is not null)
            steps.Add(new BackwardTraceStepDto(++order, "instruction", faultInstr, debugger?.Rip, "HIGH"));

        if (debugger is { Ok: true })
        {
            var sink = debugger.FaultingFunction is not null
                ? $"{debugger.FaultingModule ?? "?"}!{debugger.FaultingFunction}{debugger.FunctionOffset ?? ""}"
                : debugger.Rip ?? "fault site";
            steps.Add(new BackwardTraceStepDto(
                ++order, "sink", sink,
                debugger.Access != DebuggerAccessKind.Unknown ? $"{debugger.Access} at {debugger.FaultAddress}" : debugger.FaultAddress,
                "HIGH"));
        }

        if (debugger?.ExceptionHint is not null || triage?.ExceptionHint is not null)
        {
            steps.Add(new BackwardTraceStepDto(
                ++order, "crash",
                debugger?.ExceptionHint ?? triage?.ExceptionHint ?? "ACCESS_VIOLATION",
                debugger?.Diagnosis ?? triage?.Summary,
                "HIGH"));
        }

        var story = BuildStory(sidecar, debugger, corruptionChain, attribution, primary, badSource?.Label, faultInstr);
        var confidence = ScoreConfidence(debugger, corruptionChain, attribution, steps);
        var suspectedMutator = corruptionChain?.SuspectedMutator ?? attribution.SuspectedMutator;
        var mutStep = corruptionChain?.SuspectedMutatorStep ?? attribution.SuspectedMutatorStep;
        var offsetLabel = primary is not null
            ? $"+{primary.PayloadOffset}"
            : attribution.PatternDepthBytes is int d ? $"+{d}" : null;

        return new CrashBackwardTraceDto(
            Ok: steps.Count > 0,
            CrashId: crashId,
            Project: project,
            Confidence: confidence,
            Story: story,
            Steps: steps,
            FaultInstruction: faultInstr,
            FaultRegister: primary?.Register ?? corruptionChain?.PrimaryRegister ?? debugger?.PrimaryRegisterMatch,
            BadPointerSource: badSource?.Label,
            SuspectedMutator: suspectedMutator,
            SuspectedMutatorStep: mutStep,
            PrimaryPayloadOffset: offsetLabel,
            RegisterMatches: matches.Count > 0 ? matches : null,
            HeapTimeline: heapTimeline,
            At: DateTimeOffset.UtcNow);
    }

    public static CrashBackwardTraceDto PersistForCrash(
        string crashesDir,
        Guid crashId,
        string project,
        CrashSidecarDto? sidecar,
        DebuggerObservation? debugger,
        CrashTriageDto? triage,
        CrashCorruptionChainDto? corruptionChain,
        byte[]? payload = null)
    {
        var trace = Build(crashId, project, sidecar, debugger, triage, corruptionChain, payload);
        Write(crashesDir, trace);
        return trace;
    }

    public static string Write(string crashesDir, CrashBackwardTraceDto trace)
    {
        Directory.CreateDirectory(crashesDir);
        var path = PathFor(crashesDir, trace.CrashId);
        File.WriteAllText(path, JsonSerializer.Serialize(trace, JsonOpts));
        return path;
    }

    private sealed record SourceHint(string Label, string? Detail, string Confidence);

    private static SourceHint? InferBadPointerSource(
        DebuggerObservation? dbg,
        CrashTriageDto? triage,
        RegisterPayloadMatchDto? primary)
    {
        if (primary is not null)
        {
            return new SourceHint(
                $"input bytes at payload+{primary.PayloadOffset}",
                $"{primary.Register} loaded from fuzz input ({primary.MatchKind})",
                primary.MatchKind == "ascii" ? "HIGH" : "MEDIUM");
        }

        if (dbg?.FaultAddressClass == DebuggerAddressClass.AsciiPattern)
            return new SourceHint("ASCII-controlled pointer in payload", dbg.FaultAddress, "HIGH");

        if (dbg?.FaultAddressClass == DebuggerAddressClass.Freed)
            return new SourceHint("freed heap chunk (UAF candidate)", dbg.HeapSignal ?? "USE_AFTER_FREE", "MEDIUM");

        if (dbg?.FaultAddressClass == DebuggerAddressClass.Heapish)
            return new SourceHint("heap corruption / bad heap pointer", dbg.HeapSignal ?? dbg.FaultAddress, "MEDIUM");

        if (dbg?.FaultAddressClass == DebuggerAddressClass.Stackish)
            return new SourceHint("stack slot / return address", InferStackSlot(dbg), "MEDIUM");

        if (triage?.StackLooksSmashed == true)
            return new SourceHint("smashed stack (return address overwrite)", triage.Summary, "MEDIUM");

        if (dbg?.MemoryNearRsp is not null && primary is null)
        {
            var slot = InferStackPointerSource(dbg);
            if (slot is not null)
                return slot;
        }

        if (dbg?.FaultAddress is not null && dbg.FaultAddressClass == DebuggerAddressClass.ModuleRange)
            return new SourceHint("bad pointer into module image", dbg.FaultAddress, "LOW");

        return null;
    }

    private static SourceHint? InferStackPointerSource(DebuggerObservation dbg)
    {
        if (string.IsNullOrWhiteSpace(dbg.MemoryNearRsp) || string.IsNullOrWhiteSpace(dbg.FaultAddress))
            return null;

        if (!TryParseUlong(dbg.FaultAddress, out var fault))
            return null;

        foreach (Match m in StackQwordLine().Matches(dbg.MemoryNearRsp))
        {
            if (!TryParseUlong(NormalizeAddr(m.Groups["val"].Value) ?? "", out var slot))
                continue;
            if (slot == fault)
            {
                return new SourceHint(
                    $"stack slot @ {NormalizeAddr(m.Groups["addr"].Value)}",
                    "fault address appears on stack near RSP",
                    "MEDIUM");
            }
        }

        return null;
    }

    private static string? InferStackSlot(DebuggerObservation dbg)
    {
        if (dbg.Stack.Count > 1)
            return $"frame {dbg.Stack[1].Symbol ?? dbg.Stack[1].Module ?? "caller"} stack";
        return "near-RSP stack window";
    }

    private static string? BuildHeapTimeline(DebuggerObservation? dbg)
    {
        if (dbg is null)
            return null;

        if (dbg.HeapSignal == "USE_AFTER_FREE" || dbg.FaultAddressClass == DebuggerAddressClass.Freed)
            return "freed → reuse → crash (heap signal from !analyze/!address/!heap)";

        if (dbg.HeapSignal == "HEAP_CORRUPTION")
            return "corrupt → bad pointer → crash";

        if (dbg.HeapSignal is not null)
            return $"{dbg.HeapSignal.Replace('_', ' ').ToLowerInvariant()} → fault";

        return null;
    }

    private static string? ExtractFaultInstruction(DebuggerObservation? dbg)
    {
        if (string.IsNullOrWhiteSpace(dbg?.DisasmNearRip))
            return null;

        foreach (var line in dbg.DisasmNearRip.Split('\n'))
        {
            var trimmed = line.Trim();
            if (trimmed.Length == 0)
                continue;

            if (dbg.Rip is not null && trimmed.Contains(dbg.Rip, StringComparison.OrdinalIgnoreCase))
                return trimmed;

            if (FaultInstrLine().IsMatch(trimmed))
                return trimmed;
        }

        return dbg.DisasmNearRip.Split('\n').Select(l => l.Trim()).FirstOrDefault(l => l.Length > 0);
    }

    private static string BuildStory(
        CrashSidecarDto? sidecar,
        DebuggerObservation? dbg,
        CrashCorruptionChainDto? chain,
        InputAttributionEngine.AttributionResult attribution,
        RegisterPayloadMatchDto? primary,
        string? badSource,
        string? faultInstr)
    {
        if (!string.IsNullOrWhiteSpace(chain?.Narrative))
            return chain.Narrative;

        if (!string.IsNullOrWhiteSpace(attribution.Narrative))
            return attribution.Narrative;

        var sb = new StringBuilder();
        var field = sidecar?.Command ?? sidecar?.Mutator ?? "input";

        if (attribution.SuspectedMutator is not null)
            sb.Append($"Mutator '{attribution.SuspectedMutator}'");
        else if (sidecar?.Mutator is not null)
            sb.Append($"Mutator '{sidecar.Mutator}'");
        else
            sb.Append("Fuzz input");

        sb.Append($" on {field}");

        if (primary is not null)
            sb.Append($" placed {primary.ValueHex} in {primary.Register} (payload+{primary.PayloadOffset})");
        else if (attribution.PatternDepthBytes is int off)
            sb.Append($" influenced bytes at +{off}");

        if (badSource is not null)
            sb.Append($" → bad pointer from {badSource}");

        if (dbg?.FaultingFunction is not null)
            sb.Append($" → fault in {dbg.FaultingModule}!{dbg.FaultingFunction}");
        else if (dbg?.Rip is not null)
            sb.Append($" → fault at {dbg.Rip}");

        if (faultInstr is not null)
        {
            var shortInstr = faultInstr.Length > 80 ? faultInstr[..80] + "…" : faultInstr;
            sb.Append($" ({shortInstr})");
        }

        if (dbg?.Access is DebuggerAccessKind.Write or DebuggerAccessKind.Read or DebuggerAccessKind.Execute)
            sb.Append($" → {dbg.Access.ToString().ToLowerInvariant()} AV");

        if (dbg?.HeapSignal is not null)
            sb.Append($" → {dbg.HeapSignal.Replace('_', ' ').ToLowerInvariant()}");

        sb.Append('.');
        sb.Append(" Research-only — from dump/CDB probes, not live TTD.");
        return sb.ToString();
    }

    private static string ScoreConfidence(
        DebuggerObservation? dbg,
        CrashCorruptionChainDto? chain,
        InputAttributionEngine.AttributionResult attribution,
        IReadOnlyList<BackwardTraceStepDto> steps)
    {
        var score = 0;
        if (dbg is { Ok: true }) score += 2;
        if (chain is { Ok: true }) score += 1;
        if (attribution.PrimaryMatch is not null) score += 3;
        if (attribution.RegisterMatches.Count >= 2) score += 1;
        if (dbg?.FaultAddressClass == DebuggerAddressClass.AsciiPattern) score += 2;
        if (dbg?.FaultAddressClass == DebuggerAddressClass.Freed) score += 2;
        if (steps.Any(s => s.Kind == "instruction")) score += 2;
        if (steps.Any(s => s.Confidence == "HIGH")) score += 1;
        if (attribution.SuspectedMutatorStep is not null) score += 2;

        var baseConf = chain?.Confidence ?? attribution.Confidence;
        if (baseConf == "HIGH") score += 2;
        else if (baseConf == "MEDIUM") score += 1;

        return score switch
        {
            >= 8 => "HIGH",
            >= 4 => "MEDIUM",
            >= 1 => "LOW",
            _ => "UNKNOWN",
        };
    }

    private static bool TryParseUlong(string addr, out ulong v)
    {
        v = 0;
        var h = addr.Trim();
        if (h.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            h = h[2..];
        h = h.Replace("`", "", StringComparison.Ordinal);
        return ulong.TryParse(h, System.Globalization.NumberStyles.HexNumber,
            System.Globalization.CultureInfo.InvariantCulture, out v);
    }

    private static string? NormalizeAddr(string addr)
    {
        var a = addr.Trim().Replace("`", "", StringComparison.Ordinal);
        if (a.Length == 0) return null;
        if (!a.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            a = "0x" + a;
        return a;
    }

    [GeneratedRegex(@"^\s*[0-9A-Fa-fx`]+", RegexOptions.IgnoreCase)]
    private static partial Regex FaultInstrLine();

    // 00000000`0012ff00  41414141`41414141
    [GeneratedRegex(@"(?<addr>[0-9A-Fa-fx`]+)\s+(?<val>[0-9A-Fa-fx`]+)", RegexOptions.IgnoreCase)]
    private static partial Regex StackQwordLine();
}
