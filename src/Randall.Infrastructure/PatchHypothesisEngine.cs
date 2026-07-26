using System.Text;
using System.Text.Json;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Automatic Patch Hypothesis — proposes educational remediation <em>text</em> from
/// root-cause, influence, primitives, and triage/debugger evidence.
/// Research/teaching only: never emits exploit patches, payloads, ROP, or shellcode.
/// </summary>
public static class PatchHypothesisEngine
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() },
    };

    public static string PathFor(string crashesDir, Guid crashId) =>
        Path.Combine(crashesDir, $"{crashId:N}_patch_hypothesis.json");

    public static PatchHypothesisDto? TryRead(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            return null;
        try
        {
            return JsonSerializer.Deserialize<PatchHypothesisDto>(File.ReadAllText(path), JsonOpts);
        }
        catch
        {
            return null;
        }
    }

    public static PatchHypothesisDto? TryReadForCrash(string crashesDir, Guid crashId) =>
        TryRead(PathFor(crashesDir, crashId));

    public static PatchHypothesisDto Build(
        Guid crashId,
        string project,
        RootCauseAnalysisDto? rootCause,
        CrashInfluenceMapDto? influence = null,
        CrashPrimitiveReportDto? primitives = null,
        CrashTriageDto? triage = null,
        DebuggerObservation? debugger = null)
    {
        var category = rootCause?.Candidate.Category ?? InferCategory(debugger, triage);
        var related = CollectRelatedFunctions(rootCause, triage, debugger);
        var refs = CollectEvidenceRefs(rootCause, influence, primitives, triage, debugger);
        var confidence = RollupConfidence(rootCause, influence, primitives, debugger);

        if (rootCause is not { Ok: true } && debugger is not { Ok: true } && triage is null
            && influence is not { Ok: true } && primitives is not { Ok: true })
        {
            return new PatchHypothesisDto(
                false,
                crashId,
                project,
                "Insufficient evidence for a remediation hypothesis — capture triage/debugger evidence or a root-cause analysis first.",
                false,
                "No patched-lab verification hook until a root-cause category is available.",
                related,
                refs,
                "UNKNOWN",
                DateTimeOffset.UtcNow,
                category,
                Error: "no correlatable evidence");
        }

        var remediation = BuildRemediationText(category, rootCause, influence, primitives, related);
        var (verify, hook) = BuildPatchedLabHook(project, category, related);

        return new PatchHypothesisDto(
            true,
            crashId,
            project,
            remediation,
            verify,
            hook,
            related,
            refs,
            confidence,
            DateTimeOffset.UtcNow,
            category);
    }

    public static PatchHypothesisDto PersistForCrash(
        string crashesDir,
        Guid crashId,
        string project,
        RootCauseAnalysisDto? rootCause,
        CrashInfluenceMapDto? influence = null,
        CrashPrimitiveReportDto? primitives = null,
        CrashTriageDto? triage = null,
        DebuggerObservation? debugger = null)
    {
        var dto = Build(crashId, project, rootCause, influence, primitives, triage, debugger);
        Write(crashesDir, dto);
        return dto;
    }

    public static string Write(string crashesDir, PatchHypothesisDto dto)
    {
        Directory.CreateDirectory(crashesDir);
        var path = PathFor(crashesDir, dto.CrashId);
        File.WriteAllText(path, JsonSerializer.Serialize(dto, JsonOpts));
        return path;
    }

    private static RootCauseCategory InferCategory(DebuggerObservation? debugger, CrashTriageDto? triage)
    {
        var text = string.Join(' ',
            debugger?.HeapProbeText ?? "",
            debugger?.HeapSignal ?? "",
            debugger?.AddressQueryText ?? "",
            debugger?.Diagnosis ?? "",
            triage?.Summary ?? "",
            triage?.Class ?? "");
        if (text.Contains("use after free", StringComparison.OrdinalIgnoreCase)
            || text.Contains("double free", StringComparison.OrdinalIgnoreCase)
            || text.Contains("Free memory", StringComparison.OrdinalIgnoreCase)
            || debugger?.FaultAddressClass == DebuggerAddressClass.Freed)
            return RootCauseCategory.LifetimeViolation;
        if (debugger?.Access == DebuggerAccessKind.Write
            || text.Contains("overflow", StringComparison.OrdinalIgnoreCase)
            || text.Contains("ACCESS_VIOLATION", StringComparison.OrdinalIgnoreCase))
            return RootCauseCategory.BoundsViolation;
        return RootCauseCategory.Unknown;
    }

    private static IReadOnlyList<string> CollectRelatedFunctions(
        RootCauseAnalysisDto? rootCause,
        CrashTriageDto? triage,
        DebuggerObservation? debugger)
    {
        var list = new List<string>();
        void Add(string? name)
        {
            if (string.IsNullOrWhiteSpace(name))
                return;
            var trimmed = name.Trim();
            if (!list.Contains(trimmed, StringComparer.OrdinalIgnoreCase))
                list.Add(trimmed);
        }

        Add(rootCause?.Candidate.FaultingFunction);
        Add(rootCause?.Candidate.SuspectedSourceFunction);
        Add(rootCause?.Candidate.SuspectedSink);
        Add(triage?.StaticFunction?.FunctionName);
        Add(debugger?.FaultingFunction);
        if (debugger?.Stack is { Count: > 0 })
        {
            foreach (var frame in debugger.Stack.Take(4))
            {
                if (!string.IsNullOrWhiteSpace(frame.Symbol))
                    Add(frame.Symbol);
                else if (!string.IsNullOrWhiteSpace(frame.Module))
                    Add(frame.Module);
            }
        }

        return list;
    }

    private static IReadOnlyList<string> CollectEvidenceRefs(
        RootCauseAnalysisDto? rootCause,
        CrashInfluenceMapDto? influence,
        CrashPrimitiveReportDto? primitives,
        CrashTriageDto? triage,
        DebuggerObservation? debugger)
    {
        var refs = new List<string>();
        void Add(string? r)
        {
            if (!string.IsNullOrWhiteSpace(r) && !refs.Contains(r, StringComparer.OrdinalIgnoreCase))
                refs.Add(r);
        }

        if (rootCause is { Ok: true })
        {
            Add($"root_cause:{rootCause.Candidate.Category}");
            foreach (var f in rootCause.Candidate.Evidence.Take(6))
                Add($"{f.Source}:{f.Name}");
        }

        if (influence is { Ok: true, Links.Count: > 0 })
        {
            foreach (var link in influence.Links.Take(4))
            {
                Add($"influence:{link.Id}");
                foreach (var er in link.EvidenceRefs.Take(2))
                    Add(er);
            }
        }

        if (primitives is { Ok: true, Primitives.Count: > 0 })
        {
            foreach (var p in primitives.Primitives.Take(4))
                Add($"primitive:{p.Kind}:{p.State}");
        }

        if (triage is not null)
            Add($"triage:{triage.Class}");
        if (debugger is { Ok: true })
            Add("debugger:observation");

        return refs;
    }

    private static string RollupConfidence(
        RootCauseAnalysisDto? rootCause,
        CrashInfluenceMapDto? influence,
        CrashPrimitiveReportDto? primitives,
        DebuggerObservation? debugger)
    {
        var scores = new List<int>();
        void Rank(string? c)
        {
            scores.Add(c?.ToUpperInvariant() switch
            {
                "HIGH" => 3,
                "MEDIUM" => 2,
                "LOW" => 1,
                _ => 0,
            });
        }

        Rank(rootCause?.Candidate.Confidence);
        Rank(influence?.Confidence);
        Rank(primitives?.Confidence);
        if (debugger is { Ok: true })
            scores.Add(2);

        if (scores.Count == 0)
            return "UNKNOWN";
        var avg = scores.Average();
        return avg >= 2.5 ? "HIGH" : avg >= 1.5 ? "MEDIUM" : avg > 0 ? "LOW" : "UNKNOWN";
    }

    private static string BuildRemediationText(
        RootCauseCategory category,
        RootCauseAnalysisDto? rootCause,
        CrashInfluenceMapDto? influence,
        CrashPrimitiveReportDto? primitives,
        IReadOnlyList<string> related)
    {
        var sb = new StringBuilder();
        var fnHint = related.Count > 0
            ? $" Focus study on: {string.Join(", ", related.Take(4))}."
            : "";

        switch (category)
        {
            case RootCauseCategory.BoundsViolation:
            case RootCauseCategory.SizeMismatch:
                sb.Append(
                    "Bounds / length study: audit the copy or store path for an explicit bounds-check " +
                    "and length validation before the write. Compare declared buffer capacity against " +
                    "the attacker-influenced length (or field) that reaches the sink.");
                break;
            case RootCauseCategory.LifetimeViolation:
                sb.Append(
                    "Lifetime study: audit free/use pairing around the faulting object — ensure each " +
                    "free clears or invalidates outstanding references, and that no use path runs after " +
                    "the free on the same heap object.");
                break;
            case RootCauseCategory.IntegerConversion:
                sb.Append(
                    "Integer-conversion study: validate width/sign conversions that feed allocation or " +
                    "copy lengths; check for wrap/truncation before the size reaches the sink.");
                break;
            case RootCauseCategory.Uninitialized:
                sb.Append(
                    "Uninitialized-state study: ensure the faulting field/object is fully initialized " +
                    "on every path that reaches the sink; prefer definite-assignment or zero-init patterns.");
                break;
            case RootCauseCategory.ParserState:
            case RootCauseCategory.FormatInterpretation:
                sb.Append(
                    "Parser/format study: harden state-machine transitions and length/type fields so " +
                    "malformed input cannot advance into a sink with inconsistent sizes.");
                break;
            case RootCauseCategory.UnexpectedObjectState:
                sb.Append(
                    "Object-state study: verify invariants for the object at the sink (flags, type tags, " +
                    "refcount) and reject transitions that leave it in an unexpected state.");
                break;
            default:
                sb.Append(
                    "General remediation study: correlate the faulting site with input-influenced state, " +
                    "then add defensive validation at the earliest trusted boundary before the sink.");
                break;
        }

        sb.Append(fnHint);

        if (influence is { Ok: true, Links.Count: > 0 })
        {
            var top = influence.Links[0];
            sb.Append(
                $" Influence map highlights {top.Mechanism} (region {top.Region.StartOffset}" +
                $"{(top.Region.EndOffset is int e ? $"..{e}" : "")}) — use that region when designing the check.");
        }

        if (primitives is { Ok: true, Primitives.Count: > 0 })
        {
            var kinds = string.Join(", ", primitives.Primitives.Take(3).Select(p => p.Kind.ToString()));
            sb.Append($" Capability primitives under study: {kinds}.");
        }

        if (!string.IsNullOrWhiteSpace(rootCause?.EducationalSummary))
            sb.Append($" Root-cause note: {Truncate(rootCause.EducationalSummary, 160)}");

        sb.Append(
            " This is teaching remediation guidance only — Randall does not generate exploit patches or payloads.");

        return sb.ToString();
    }

    private static (bool Verify, string Hook) BuildPatchedLabHook(
        string project,
        RootCauseCategory category,
        IReadOnlyList<string> related)
    {
        var fn = related.Count > 0 ? related[0] : "(faulting function)";
        var tierHint = category switch
        {
            RootCauseCategory.LifetimeViolation =>
                "Prefer a heap-hardened lab tier (or ASAN/PageHeap) so free/use mistakes surface clearly.",
            RootCauseCategory.BoundsViolation or RootCauseCategory.SizeMismatch =>
                "Prefer a bounds-sensitive lab tier (canary/NX variants are fine for teaching crash diffs).",
            _ => "Any mitigation-lab tier that rebuilds with your defensive check is fine for the study.",
        };

        var hook =
            $"Experiment hook (manual): rebuild a patched lab binary for project '{project}' that adds " +
            $"defensive validation around '{fn}', then point the differential oracle / fuzz profile at that " +
            $"patched executable (same seed corpus). Expect the original crashing input to no longer fault " +
            $"when the check is correct — compare crash catalogs (patched vs unpatched). {tierHint} " +
            "This is a verification experiment description only; Randall does not auto-apply patches or weaponize.";

        return (true, hook);
    }

    private static string Truncate(string text, int max) =>
        text.Length <= max ? text : text[..(max - 1)] + "…";
}
