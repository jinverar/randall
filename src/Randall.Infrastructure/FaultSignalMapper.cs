using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Maps CrashTriage, minidump/cdb analysis, Page Heap context, sanitizer hints, and RPP tags
/// into unified <see cref="FaultSignal"/> rows for scream intelligence and oracle FINDINGS.
/// </summary>
public static class FaultSignalMapper
{
    public static IReadOnlyList<FaultSignal> FromCrash(
        CrashTriageDto? triage,
        CrashAnalysisDto? analysis = null,
        CdbTriageDto? cdb = null,
        CrashSidecarDto? sidecar = null,
        bool pageHeapEnabled = false,
        string? rppTag = null,
        string? targetDetail = null,
        int? exitCode = null,
        DebuggerObservation? debugger = null)
    {
        var signals = new List<FaultSignal>();

        if (triage is not null)
            signals.Add(FromTriage(triage, analysis));

        var detail = sidecar?.TargetDetail
            ?? targetDetail
            ?? sidecar?.ExceptionHint
            ?? triage?.ExceptionHint
            ?? analysis?.ExceptionHint;

        foreach (var san in SanitizerLogParser.ExtractAll(detail))
        {
            signals.Add(new FaultSignal(
                SanitizerLogParser.MapCheckKind(san.CheckType),
                0.95,
                SanitizerLogParser.MapSeverity(san.CheckType, san.Sanitizer),
                FaultSignalSource.SanitizerLog,
                $"{san.Sanitizer}: {san.CheckType}",
                Truncate(san.Location is not null ? $"{san.SummaryLine} ({san.Location})" : san.SummaryLine, 240)));
        }

        if (pageHeapEnabled)
        {
            signals.Add(new FaultSignal(
                FaultSignalKind.PageHeap,
                0.72,
                "medium",
                FaultSignalSource.PageHeap,
                "Page Heap enabled for target image",
                "UAF / heap misuse signals may be amplified (gflags /full)"));
        }

        if (cdb is { Ok: true })
        {
            var wer = FromCdb(cdb);
            if (wer is not null)
                signals.Add(wer);
        }

        if (debugger is { Ok: true })
        {
            var dbg = FromDebugger(debugger);
            if (dbg is not null)
                signals.Add(dbg);
        }

        if (!string.IsNullOrWhiteSpace(rppTag))
        {
            signals.Add(new FaultSignal(
                MapRppKind(rppTag),
                0.65,
                "medium",
                FaultSignalSource.RppPlugin,
                $"RPP post_crash: {rppTag}",
                rppTag));
        }

        if (signals.Count == 0)
        {
            var fallback = TryFallbackFromDetail(
                detail,
                exitCode ?? sidecar?.ExitCode,
                sidecar?.ExceptionHint);
            if (fallback is not null)
                signals.Add(fallback);
        }

        return Deduplicate(signals);
    }

    public static FaultSignal? Primary(IReadOnlyList<FaultSignal> signals)
    {
        if (signals.Count == 0)
            return null;
        return signals
            .OrderByDescending(s => s.Confidence)
            .ThenByDescending(s => SeverityRank(s.Severity))
            .ThenByDescending(s => KindRank(s.Kind))
            .First();
    }

    public static void PublishFaults(
        ObservationBus bus,
        string runId,
        int iteration,
        string inputHash,
        string? project,
        IReadOnlyList<FaultSignal> signals)
    {
        foreach (var fault in signals)
        {
            bus.Publish(ObservationEvents.Fault(
                runId, iteration, inputHash, fault, project));
        }
    }

    public static FaultSignal? FromOracleFinding(string ruleId, string severity, string actualRelation, double confidence)
    {
        if (ruleId.Equals("runtime.crash", StringComparison.OrdinalIgnoreCase))
        {
            return new FaultSignal(
                FaultSignalKind.AccessViolation,
                confidence,
                severity,
                FaultSignalSource.OracleRuntime,
                "Oracle runtime crash rule",
                Truncate(actualRelation, 240));
        }

        if (ruleId.Equals("runtime.sanitizer", StringComparison.OrdinalIgnoreCase))
        {
            var san = SanitizerLogParser.ExtractAll(actualRelation).FirstOrDefault();
            if (san is not null)
            {
                return new FaultSignal(
                    SanitizerLogParser.MapCheckKind(san.CheckType),
                    confidence,
                    SanitizerLogParser.MapSeverity(san.CheckType, san.Sanitizer),
                    FaultSignalSource.OracleRuntime,
                    $"{san.Sanitizer}: {san.CheckType}",
                    Truncate(actualRelation, 240));
            }

            return new FaultSignal(
                FaultSignalKind.Sanitizer,
                confidence,
                "high",
                FaultSignalSource.OracleRuntime,
                "Oracle sanitizer rule",
                Truncate(actualRelation, 240));
        }

        if (ruleId.Equals("runtime.timeout", StringComparison.OrdinalIgnoreCase))
        {
            return new FaultSignal(
                FaultSignalKind.Hang,
                confidence,
                severity,
                FaultSignalSource.OracleRuntime,
                "Oracle timeout rule",
                Truncate(actualRelation, 240));
        }

        return null;
    }

    private static FaultSignal FromTriage(CrashTriageDto triage, CrashAnalysisDto? analysis)
    {
        var kind = triage.Class switch
        {
            "access_violation" => FaultSignalKind.AccessViolation,
            "stack_overflow" => FaultSignalKind.StackOverflow,
            "stack_buffer_overrun" => FaultSignalKind.StackBufferOverrun,
            "illegal_instruction" => FaultSignalKind.IllegalInstruction,
            "hang" => FaultSignalKind.Hang,
            "divide_by_zero" => FaultSignalKind.Other,
            _ => FaultSignalKind.Other,
        };

        if (triage.StackLooksSmashed && kind is FaultSignalKind.AccessViolation or FaultSignalKind.Other)
            kind = FaultSignalKind.StackBufferOverrun;

        var source = analysis?.Ok == true ? FaultSignalSource.MinidumpAnalysis : FaultSignalSource.CrashTriage;
        var confidence = analysis?.Ok == true ? 0.92 : 0.78;
        if (triage.IpLooksControlled)
            confidence = Math.Min(0.99, confidence + 0.06);

        return new FaultSignal(
            kind,
            confidence,
            triage.Severity,
            source,
            triage.Summary,
            triage.ExceptionHint);
    }

    private static FaultSignal? FromCdb(CdbTriageDto cdb)
    {
        var exp = (cdb.ExploitableClassification ?? "").Trim();
        if (string.IsNullOrWhiteSpace(exp))
            return null;

        var sev = exp.ToUpperInvariant() switch
        {
            "EXPLOITABLE" or "PROBABLY_EXPLOITABLE" => "critical",
            "PROBABLY_NOT_EXPLOITABLE" => "medium",
            "NOT_EXPLOITABLE" => "low",
            _ => "medium",
        };

        return new FaultSignal(
            FaultSignalKind.WerClassification,
            0.88,
            sev,
            FaultSignalSource.CdbAnalyze,
            $"!exploitable: {exp}",
            cdb.ExploitableDescription);
    }

    private static FaultSignal? FromDebugger(DebuggerObservation dbg)
    {
        var kind = dbg.HeapSignal switch
        {
            "HEAP_CORRUPTION" or "HEAP_SIGNAL" => FaultSignalKind.HeapCorruption,
            "USE_AFTER_FREE" => FaultSignalKind.UseAfterFree,
            _ => dbg.ExceptionHint?.Contains("ACCESS", StringComparison.OrdinalIgnoreCase) == true
                || dbg.ExceptionCode?.Contains("c0000005", StringComparison.OrdinalIgnoreCase) == true
                ? FaultSignalKind.AccessViolation
                : FaultSignalKind.WerClassification,
        };

        var sev = dbg.ExploitabilityHint.ToUpperInvariant() switch
        {
            "HIGH" => "critical",
            "MEDIUM" => "high",
            "LOW" => "medium",
            _ => "high",
        };

        return new FaultSignal(
            kind,
            dbg.Confidence,
            sev,
            FaultSignalSource.DebuggerInvestigation,
            Truncate(dbg.Diagnosis, 160),
            Truncate(
                $"{dbg.Access} @ {dbg.FaultAddress ?? dbg.Rip} · input={dbg.SuspectedInputInfluence}" +
                (dbg.FaultingFunction is not null ? $" · {dbg.FaultingModule}!{dbg.FaultingFunction}" : ""),
                240));
    }

    private static FaultSignal? TryFallbackFromDetail(string? detail, int? exitCode, string? exceptionHint)
    {
        if (SanitizerLogParser.TryParseFirst(detail, out var san) && san is not null)
        {
            return new FaultSignal(
                SanitizerLogParser.MapCheckKind(san.CheckType),
                0.9,
                SanitizerLogParser.MapSeverity(san.CheckType, san.Sanitizer),
                FaultSignalSource.SanitizerLog,
                $"{san.Sanitizer}: {san.CheckType}",
                Truncate(san.SummaryLine, 240));
        }

        var hint = exceptionHint
            ?? WindowsExceptionHints.Describe(exitCode)
            ?? (exitCode is not null ? $"exit {exitCode}" : null);
        if (string.IsNullOrWhiteSpace(hint))
            return null;

        var kind = hint.Contains("ACCESS_VIOLATION", StringComparison.OrdinalIgnoreCase) ||
                   exitCode is 139 or unchecked((int)0xC0000005)
            ? FaultSignalKind.AccessViolation
            : exitCode is 134
                ? FaultSignalKind.HeapCorruption
                : FaultSignalKind.Other;

        return new FaultSignal(
            kind,
            0.55,
            exitCode is 139 or unchecked((int)0xC0000005) ? "high" : "medium",
            FaultSignalSource.ExitCode,
            hint,
            Truncate(detail, 240));
    }

    private static FaultSignalKind MapRppKind(string tag)
    {
        var t = tag.ToLowerInvariant();
        if (t.Contains("overflow"))
            return FaultSignalKind.StackBufferOverrun;
        if (t.Contains("access") || t.Contains("violation"))
            return FaultSignalKind.AccessViolation;
        if (t.Contains("heap") || t.Contains("uaf"))
            return FaultSignalKind.HeapCorruption;
        if (t.Contains("hang") || t.Contains("timeout"))
            return FaultSignalKind.Hang;
        if (t.Contains("sanitizer") || t.Contains("asan"))
            return FaultSignalKind.Sanitizer;
        return FaultSignalKind.Other;
    }

    private static int SeverityRank(string severity) => severity.ToLowerInvariant() switch
    {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    };

    private static int KindRank(FaultSignalKind kind) => kind switch
    {
        FaultSignalKind.WerClassification => 5,
        FaultSignalKind.Sanitizer => 4,
        FaultSignalKind.StackBufferOverrun => 3,
        FaultSignalKind.UseAfterFree => 3,
        FaultSignalKind.HeapCorruption => 3,
        FaultSignalKind.AccessViolation => 2,
        _ => 1,
    };

    private static List<FaultSignal> Deduplicate(List<FaultSignal> signals)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var list = new List<FaultSignal>();
        foreach (var s in signals)
        {
            var key = $"{s.Kind}|{s.Source}|{s.Summary}";
            if (seen.Add(key))
                list.Add(s);
        }
        return list;
    }

    private static string? Truncate(string? text, int max)
    {
        if (string.IsNullOrWhiteSpace(text) || text.Length <= max)
            return text;
        return text[..max] + "…";
    }
}
