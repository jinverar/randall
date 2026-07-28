using System.Text.Json;
using System.Text.Json.Serialization;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Counterfactual Fuzzing — reuses HypothesisEngine sweep/boundary patterns to find
/// the smallest nearby change that makes a bug disappear, and maps adjacent safe vs corrupt.
/// Research/teaching only; no exploit payloads.
/// </summary>
public static class CounterfactualEngine
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter() },
    };

    public static string PathFor(string crashesDir, Guid crashId) =>
        Path.Combine(crashesDir, $"{crashId:N}_counterfactual.json");

    public static CounterfactualReportDto? TryRead(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            return null;
        try
        {
            return JsonSerializer.Deserialize<CounterfactualReportDto>(File.ReadAllText(path), JsonOpts);
        }
        catch
        {
            return null;
        }
    }

    public static CounterfactualReportDto? TryReadForCrash(string crashesDir, Guid crashId) =>
        TryRead(PathFor(crashesDir, crashId));

    /// <summary>
    /// Build a pending probe plan around the suspected offset (no target execution).
    /// </summary>
    public static CounterfactualReportDto BuildPlan(
        Guid crashId,
        string project,
        byte[] payload,
        int? suspectedOffset = null,
        CrashInfluenceMapDto? influence = null,
        RootCauseAnalysisDto? rootCause = null,
        CrashCorruptionChainDto? corruption = null)
    {
        var offset = ResolveOffset(suspectedOffset, influence, rootCause, corruption, payload.Length);
        if (payload.Length == 0 || offset is null)
        {
            return new CounterfactualReportDto(
                false, crashId, project, null,
                "Insufficient evidence for counterfactual probes — need a payload and suspected offset.",
                null, [], 0, 0, "UNKNOWN", DateTimeOffset.UtcNow,
                Error: "no offset or empty payload");
        }

        var probes = GenerateProbes(payload, offset.Value);
        var summary =
            $"{probes.Count} counterfactual probe(s) around offset {offset} — " +
            "run Evaluate to classify adjacent safe vs corrupt.";

        return new CounterfactualReportDto(
            true, crashId, project, offset, summary, null, probes, 0, 0, "LOW",
            DateTimeOffset.UtcNow);
    }

    /// <summary>
    /// Apply HypothesisEngine sweeps/boundaries and classify with <paramref name="stillCrashes"/>.
    /// Finds the smallest byte-delta change that makes the bug disappear.
    /// </summary>
    /// <param name="maxProbes">
    /// Bounded execution budget (hot-path safe). Null = run all planned probes.
    /// </param>
    public static CounterfactualReportDto Evaluate(
        Guid crashId,
        string project,
        byte[] payload,
        Func<byte[], bool> stillCrashes,
        int? suspectedOffset = null,
        CrashInfluenceMapDto? influence = null,
        RootCauseAnalysisDto? rootCause = null,
        CrashCorruptionChainDto? corruption = null,
        int? maxProbes = null)
    {
        var plan = BuildPlan(crashId, project, payload, suspectedOffset, influence, rootCause, corruption);
        if (!plan.Ok || plan.SuspectedOffset is not int offset)
            return plan;

        var rng = new Random(unchecked((int)(crashId.GetHashCode() ^ offset)));
        var classified = new List<CounterfactualProbeDto>();
        CounterfactualProbeDto? smallestSafe = null;
        var budget = maxProbes is int m && m > 0 ? Math.Min(m, plan.Probes.Count) : plan.Probes.Count;
        var pendingTail = plan.Probes.Skip(budget).Select(p => p with { Outcome = CounterfactualOutcome.Pending }).ToList();

        foreach (var probe in plan.Probes.Take(budget))
        {
            var experiment = new HypothesisExperimentDto(
                probe.Kind,
                probe.Description,
                OffsetBytes: offset,
                SweepRange: probe.Kind == HypothesisExperimentKind.SweepOffset ? 4 : null);

            var variant = HypothesisEngine.ApplyExperiment(payload, experiment, probe.SweepIndex, rng);
            if (variant is null)
            {
                classified.Add(probe with
                {
                    Outcome = CounterfactualOutcome.Inconclusive,
                    Detail = "empty variant",
                });
                continue;
            }

            bool crashes;
            try
            {
                crashes = stillCrashes(variant);
            }
            catch (Exception ex)
            {
                classified.Add(probe with
                {
                    Outcome = CounterfactualOutcome.Inconclusive,
                    Detail = Truncate(ex.Message, 120),
                });
                continue;
            }

            var outcome = crashes
                ? CounterfactualOutcome.StillCorrupt
                : CounterfactualOutcome.SafeAdjacent;
            var byteDelta = HammingByteDelta(payload, variant);
            var row = probe with
            {
                Outcome = outcome,
                ByteDelta = byteDelta,
                Detail = crashes ? "still crashes" : "crash disappeared",
            };
            classified.Add(row);

            if (outcome == CounterfactualOutcome.SafeAdjacent &&
                (smallestSafe is null || byteDelta < smallestSafe.ByteDelta))
            {
                smallestSafe = row;
            }
        }

        classified.AddRange(pendingTail);

        var safeCount = classified.Count(p => p.Outcome == CounterfactualOutcome.SafeAdjacent);
        var corruptCount = classified.Count(p => p.Outcome == CounterfactualOutcome.StillCorrupt);
        var executed = budget;
        var confidence = smallestSafe is not null
            ? (smallestSafe.ByteDelta <= 1 ? "HIGH" : "MEDIUM")
            : safeCount > 0 ? "MEDIUM" : corruptCount > 0 ? "LOW" : "UNKNOWN";

        var summary = smallestSafe is not null
            ? $"Smallest safe change: {smallestSafe.Description} (Δ{smallestSafe.ByteDelta} byte(s)) — " +
              $"{safeCount} safe-adjacent / {corruptCount} still-corrupt " +
              $"(live {executed}/{classified.Count} probe(s))."
            : safeCount == 0 && corruptCount > 0
                ? $"No disappearing boundary in ±sweep — {corruptCount} still-corrupt probe(s) " +
                  $"(live {executed}/{classified.Count}). Bug may be deeper than a local byte flip."
                : $"{executed} live probe(s) evaluated — {safeCount} safe / {corruptCount} corrupt.";

        return new CounterfactualReportDto(
            true, crashId, project, offset, summary, smallestSafe, classified,
            safeCount, corruptCount, confidence, DateTimeOffset.UtcNow,
            LiveExecuted: true,
            ExperimentsExecuted: executed);
    }

    /// <summary>
    /// Persist a plan (or evaluated report). When <paramref name="stillCrashes"/> is null,
    /// writes the pending probe plan only.
    /// </summary>
    public static CounterfactualReportDto PersistForCrash(
        string crashesDir,
        Guid crashId,
        string project,
        byte[]? payload,
        Func<byte[], bool>? stillCrashes = null,
        int? suspectedOffset = null,
        CrashInfluenceMapDto? influence = null,
        RootCauseAnalysisDto? rootCause = null,
        CrashCorruptionChainDto? corruption = null,
        int? maxProbes = null)
    {
        CounterfactualReportDto report;
        if (payload is null || payload.Length == 0)
        {
            report = new CounterfactualReportDto(
                false, crashId, project, null,
                "No crash input bytes available for counterfactual probes.",
                null, [], 0, 0, "UNKNOWN", DateTimeOffset.UtcNow, Error: "no payload");
        }
        else if (stillCrashes is not null)
        {
            report = Evaluate(
                crashId, project, payload, stillCrashes, suspectedOffset,
                influence, rootCause, corruption, maxProbes);
        }
        else
        {
            report = BuildPlan(
                crashId, project, payload, suspectedOffset, influence, rootCause, corruption);
        }

        Write(crashesDir, report);
        return report;
    }

    public static string Write(string crashesDir, CounterfactualReportDto report)
    {
        Directory.CreateDirectory(crashesDir);
        var path = PathFor(crashesDir, report.CrashId);
        File.WriteAllText(path, JsonSerializer.Serialize(report, JsonOpts));
        return path;
    }

    internal static int? ResolveOffset(
        int? suspectedOffset,
        CrashInfluenceMapDto? influence,
        RootCauseAnalysisDto? rootCause,
        CrashCorruptionChainDto? corruption,
        int payloadLength)
    {
        if (suspectedOffset is int o && o >= 0 && o < payloadLength)
            return o;

        if (corruption?.PatternDepthBytes is int depth && depth >= 0 && depth < payloadLength)
            return depth;

        var link = influence?.Links?
            .OrderByDescending(l => l.Status is InfluenceConfirmationStatus.Observed or InfluenceConfirmationStatus.Confirmed)
            .ThenBy(l => l.Region.StartOffset)
            .FirstOrDefault();
        if (link is not null && link.Region.StartOffset >= 0 && link.Region.StartOffset < payloadLength)
            return link.Region.StartOffset;

        if (TryParseOffsetFromRegion(rootCause?.Candidate.InputRegion, payloadLength) is int fromRegion)
            return fromRegion;

        return payloadLength > 0 ? Math.Min(4, payloadLength - 1) : null;
    }

    private static int? TryParseOffsetFromRegion(string? region, int payloadLength)
    {
        if (string.IsNullOrWhiteSpace(region)) return null;
        // Accept "len@4", "offset 28", "@0x1C"
        foreach (var token in region.Split(['@', ' ', '=', ':'], StringSplitOptions.RemoveEmptyEntries))
        {
            if (token.StartsWith("0x", StringComparison.OrdinalIgnoreCase) &&
                int.TryParse(token[2..], System.Globalization.NumberStyles.HexNumber, null, out var hex) &&
                hex >= 0 && hex < payloadLength)
                return hex;
            if (int.TryParse(token, out var dec) && dec >= 0 && dec < payloadLength)
                return dec;
        }
        return null;
    }

    private static List<CounterfactualProbeDto> GenerateProbes(byte[] payload, int offset)
    {
        var probes = new List<CounterfactualProbeDto>();
        // Keep SweepRange aligned with Evaluate() / HypothesisEngine default (±4).
        const int range = 4;
        var maxOff = Math.Max(0, payload.Length - 1);

        // SweepOffset indices cover center ± range. OffsetBytes = actual mutated byte
        // (not the center) so UI Off columns vary; Evaluate still applies via SweepIndex.
        var sweepCount = range * 2 + 1;
        for (var i = 0; i < sweepCount; i++)
        {
            var delta = i - range;
            var actual = Math.Clamp(offset + delta, 0, maxOff);
            probes.Add(new CounterfactualProbeDto(
                $"cf-sweep-{i}",
                HypothesisExperimentKind.SweepOffset,
                i,
                actual,
                ByteDelta: 1,
                $"Bit-flip at +{actual} (center{delta:+#;-#;0}, sweep #{i})",
                CounterfactualOutcome.Pending));
        }

        if (offset + 4 <= payload.Length)
        {
            for (var i = 0; i < 3; i++)
            {
                var label = i switch
                {
                    0 => "zeros (0)",
                    1 => "MAX-1 (0xFFFFFFFE)",
                    _ => "MAX (0xFFFFFFFF)",
                };
                probes.Add(new CounterfactualProbeDto(
                    $"cf-boundary-{i}",
                    HypothesisExperimentKind.BoundaryProbe,
                    i,
                    offset,
                    ByteDelta: 4,
                    $"BoundaryProbe {label} at offset {offset}",
                    CounterfactualOutcome.Pending));
            }
        }

        return probes;
    }

    private static int HammingByteDelta(byte[] a, byte[] b)
    {
        var n = Math.Min(a.Length, b.Length);
        var d = Math.Abs(a.Length - b.Length);
        for (var i = 0; i < n; i++)
        {
            if (a[i] != b[i]) d++;
        }
        return d;
    }

    private static string Truncate(string? text, int max) =>
        string.IsNullOrEmpty(text) ? "" : text.Length <= max ? text : text[..max] + "…";
}
