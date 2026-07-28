using System.Text.RegularExpressions;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Machine-enforced R0–R7 evidence gates. Maturity is <em>computed and capped</em> from
/// evidence — callers cannot arbitrarily assign R5+. See docs/SCORING_CONTRACT.md.
/// </summary>
public static class ResearchMaturityGates
{
    /// <summary>
    /// Cap a provisional maturity level to what the available evidence supports.
    /// R2 and R5+ gates are independent (R3/R4 may stand without a full R2 fault site).
    /// </summary>
    public static (ResearchMaturity Level, string? CapReason) Enforce(
        ResearchMaturity provisional,
        RootCauseAnalysisDto? rootCause,
        CrashInfluenceMapDto? influence,
        IReadOnlyList<PrimitiveAssessmentDto> primitives,
        CrashTriageDto? triage,
        DebuggerObservation? debugger,
        IReadOnlyList<EvidenceFact> facts,
        SkepticReportDto? skeptic,
        EvidenceCourtReportDto? court = null)
    {
        _ = influence;
        _ = primitives;
        _ = triage;

        var level = provisional;
        string? reason = null;

        // R5+: Court (Skeptic Survived + EvidenceFact) + counterfactual/delta observation.
        if (level >= ResearchMaturity.R5 && !MeetsR5Plus(skeptic, facts, court))
        {
            var detail = court?.Overall == EvidenceCourtVerdict.Rejected
                ? (court.Detail ?? court.SummaryLine)
                : !EvidenceCourt.PassesPromotionGate(skeptic, facts)
                    ? EvidenceCourt.PromotionGateFailureReason(skeptic, facts)
                    : "R5+ requires counterfactual/delta observation on a Survived Skeptic challenge";
            level = ResearchMaturity.R4;
            reason = $"{detail} — held at R4 (Candidate)";
        }

        // R2 (root-caused label): fault instruction + address/value required.
        // If provisional landed on exactly R2 without fault site → R1.
        // If higher (R3/R4) without fault site, leave level — attribution/candidate can outrank a weak RC.
        if (level == ResearchMaturity.R2 && !HasFaultSiteEvidence(debugger, facts))
        {
            level = ResearchMaturity.R1;
            reason = "R2 requires fault instruction + fault address/value — held at R1 (Triaged)";
        }

        return (level, reason);
    }

    public static bool MeetsR1(
        CrashTriageDto? triage,
        DebuggerObservation? debugger,
        IReadOnlyList<EvidenceFact>? facts) =>
        debugger is { Ok: true } || triage is not null || (facts?.Count ?? 0) > 0;

    /// <summary>
    /// R2 requires a deterministic root-cause category <em>and</em> fault site evidence:
    /// parseable fault instruction plus fault address and/or written value.
    /// </summary>
    public static bool MeetsR2(
        RootCauseAnalysisDto? rootCause,
        DebuggerObservation? debugger,
        IReadOnlyList<EvidenceFact>? facts)
    {
        if (rootCause is not { Ok: true } || rootCause.Candidate.Category == RootCauseCategory.Unknown)
            return false;
        return HasFaultSiteEvidence(debugger, facts);
    }

    public static bool MeetsR3(CrashInfluenceMapDto? influence) =>
        influence is { Links.Count: > 0 };

    public static bool MeetsR4(IReadOnlyList<PrimitiveAssessmentDto> primitives) =>
        primitives.Count > 0;

    /// <summary>
    /// R5+ requires Court promotion gate (Skeptic Survived + ≥1 sensor EvidenceFact)
    /// and counterfactual / delta observation on a Survived challenge.
    /// </summary>
    public static bool MeetsR5Plus(
        SkepticReportDto? skeptic,
        IReadOnlyList<EvidenceFact>? facts,
        EvidenceCourtReportDto? court = null)
    {
        if (court?.Overall == EvidenceCourtVerdict.Rejected)
            return false;
        if (!EvidenceCourt.PassesPromotionGate(skeptic, facts))
            return false;
        return PrimitiveEngine.HasCounterfactualDeltaEvidence(skeptic);
    }

    /// <summary>
    /// Fault instruction + (fault address or written/causing value).
    /// Accepts debugger observation or EvidenceFact names.
    /// </summary>
    public static bool HasFaultSiteEvidence(
        DebuggerObservation? debugger,
        IReadOnlyList<EvidenceFact>? facts)
    {
        var insn = ResolveFaultInstruction(debugger, facts);
        if (string.IsNullOrWhiteSpace(insn) || IsUnknownToken(insn))
            return false;

        var addr = ResolveFaultAddress(debugger, facts);
        var value = ResolveFaultValue(debugger, facts);
        return (!string.IsNullOrWhiteSpace(addr) && !IsUnknownToken(addr))
               || (!string.IsNullOrWhiteSpace(value) && !IsUnknownToken(value));
    }

    internal static string? ResolveFaultInstruction(
        DebuggerObservation? debugger,
        IReadOnlyList<EvidenceFact>? facts)
    {
        if (debugger is { Ok: true })
        {
            var line = ScreamInvestigator.ExtractFaultInstructionLine(debugger.DisasmNearRip, debugger.Rip);
            if (!string.IsNullOrWhiteSpace(line) && !IsUnknownToken(line))
                return line;
        }

        return FindFactValue(facts, "faultInstruction", "fault.instruction", "fault_insn", "disasm.fault");
    }

    internal static string? ResolveFaultAddress(
        DebuggerObservation? debugger,
        IReadOnlyList<EvidenceFact>? facts)
    {
        if (!string.IsNullOrWhiteSpace(debugger?.FaultAddress) && !IsUnknownToken(debugger.FaultAddress))
            return debugger.FaultAddress;
        return FindFactValue(facts, "faultAddress", "fault.address", "causingAddress");
    }

    internal static string? ResolveFaultValue(
        DebuggerObservation? debugger,
        IReadOnlyList<EvidenceFact>? facts)
    {
        var fromFact = FindFactValue(facts, "writtenValue", "causingValue", "fault.value", "write.value");
        if (!string.IsNullOrWhiteSpace(fromFact))
            return fromFact;

        if (debugger?.RegisterMatches is { Count: > 0 })
        {
            var m = debugger.RegisterMatches.FirstOrDefault(r =>
                !string.IsNullOrWhiteSpace(r.ValueHex) && !IsUnknownToken(r.ValueHex));
            if (m is not null)
                return m.ValueHex;
        }

        return null;
    }

    private static string? FindFactValue(IReadOnlyList<EvidenceFact>? facts, params string[] names)
    {
        if (facts is null || facts.Count == 0)
            return null;
        foreach (var name in names)
        {
            var hit = facts.FirstOrDefault(f =>
                f.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
            if (!string.IsNullOrWhiteSpace(hit?.Value))
                return hit!.Value;
        }

        return null;
    }

    private static bool IsUnknownToken(string? s) =>
        string.IsNullOrWhiteSpace(s)
        || s.Equals("UNKNOWN", StringComparison.OrdinalIgnoreCase)
        || s.Equals("?", StringComparison.OrdinalIgnoreCase)
        || Regex.IsMatch(s, @"^\?+$");
}
