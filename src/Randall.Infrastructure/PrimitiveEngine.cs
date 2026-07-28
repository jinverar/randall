using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Wave 2 Primitive Engine — assesses which bug <em>capabilities</em> a crash exposes
/// (input-influenced read/write, write/read-length control, pointer / RIP influence,
/// allocation-size and object-lifetime influence) and rolls the crash up to an
/// educational research-maturity level (R0…R7).
///
/// Derives capabilities from the confirmed evidence produced by earlier waves
/// (<see cref="InfluenceEngine"/> links, <see cref="RootCauseEngine"/> categories,
/// <see cref="DebuggerObservation"/>), reusing the same Observed/Confirmed/Candidate/Unknown
/// states. Research/teaching only — it describes what state you can observe or influence,
/// never exploit payloads, ROP, or weaponization.
/// </summary>
public static class PrimitiveEngine
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() },
    };

    public static string PathFor(string crashesDir, Guid crashId) =>
        Path.Combine(crashesDir, $"{crashId:N}_primitives.json");

    public static CrashPrimitiveReportDto? TryRead(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            return null;
        try
        {
            return JsonSerializer.Deserialize<CrashPrimitiveReportDto>(File.ReadAllText(path), JsonOptions);
        }
        catch
        {
            return null;
        }
    }

    public static CrashPrimitiveReportDto? TryReadForCrash(string crashesDir, Guid crashId) =>
        TryRead(PathFor(crashesDir, crashId));

    public static CrashPrimitiveReportDto Build(
        Guid crashId,
        string project,
        CrashInfluenceMapDto? influence,
        RootCauseAnalysisDto? rootCause = null,
        DebuggerObservation? debugger = null,
        CrashCorruptionChainDto? corruptionChain = null,
        CrashTriageDto? triage = null,
        IReadOnlyList<EvidenceFact>? facts = null,
        HypothesisSetDto? hypotheses = null,
        SkepticReportDto? skeptic = null)
    {
        var primitives = new List<PrimitiveAssessmentDto>();

        if (influence?.Links is { Count: > 0 })
        {
            foreach (var link in influence.Links)
            {
                var mapped = FromInfluenceLink(link, debugger);
                if (mapped is not null)
                    primitives.Add(mapped);
            }
        }

        // Fallback: debugger + root cause can imply a candidate capability even when the
        // influence map is thin (e.g. cdb-only crash with no corpus lineage).
        AddDebuggerFallback(primitives, debugger, rootCause, corruptionChain);

        var merged = MergeByKind(primitives);
        var gateOk = SkepticEngine.PassesPromotionGate(skeptic);
        if (!gateOk)
            merged = DemoteConfirmedWithoutSkeptic(merged);

        var (nullWriteCapped, mergedAfterNullGate) = ApplyNullWriteHonestyGate(
            merged, debugger, skeptic, influence, corruptionChain);
        merged = mergedAfterNullGate;

        var collectedFacts = CollectFacts(facts, influence, rootCause, merged);
        // Court lite: sensor EvidenceFacts only (not synthetic primitive.*); demote INVALID / no-cite.
        var court = EvidenceCourt.Evaluate(merged, collectedFacts, skeptic);
        merged = EvidenceCourt.ApplyDemotions(merged, court);
        if (court.Rulings.Any(r => r.Verdict == EvidenceCourtVerdict.Rejected))
            court = EvidenceCourt.Evaluate(merged, collectedFacts, skeptic);

        var confidence = RollupConfidence(merged);
        var (maturity, rationale) = ComputeMaturity(
            merged, rootCause, influence, triage, debugger, collectedFacts, skeptic, nullWriteCapped,
            corruptionChain, court);
        var summary = BuildSummary(maturity, merged, confidence, court);

        return new CrashPrimitiveReportDto(
            merged.Count > 0 || maturity > ResearchMaturity.R0,
            crashId,
            project,
            maturity,
            MaturityLabel(maturity),
            rationale,
            confidence,
            summary,
            merged
                .OrderByDescending(p => StateRank(p.State))
                .ThenByDescending(p => p.Confidence)
                .ToList(),
            collectedFacts,
            DateTimeOffset.UtcNow,
            Engine: RandallBuildInfo.Current,
            Court: court);
    }

    public static CrashPrimitiveReportDto PersistForCrash(
        string crashesDir,
        Guid crashId,
        string project,
        CrashInfluenceMapDto? influence,
        RootCauseAnalysisDto? rootCause = null,
        DebuggerObservation? debugger = null,
        CrashCorruptionChainDto? corruptionChain = null,
        CrashTriageDto? triage = null,
        IReadOnlyList<EvidenceFact>? facts = null,
        HypothesisSetDto? hypotheses = null,
        SkepticReportDto? skeptic = null)
    {
        var report = Build(
            crashId, project, influence, rootCause, debugger, corruptionChain, triage, facts,
            hypotheses, skeptic);
        Write(crashesDir, report);
        return report;
    }

    public static string Write(string crashesDir, CrashPrimitiveReportDto report)
    {
        Directory.CreateDirectory(crashesDir);
        var path = PathFor(crashesDir, report.CrashId);
        File.WriteAllText(path, JsonSerializer.Serialize(report, JsonOptions));
        return path;
    }

    private static PrimitiveAssessmentDto? FromInfluenceLink(InfluenceLinkDto link, DebuggerObservation? debugger)
    {
        var state = MapState(link.Status);
        var access = debugger?.Access;

        var (kind, mechanism) = link.State.Kind switch
        {
            InfluencedStateKind.FaultAddress => access switch
            {
                DebuggerAccessKind.Write => (PrimitiveKind.InputInfluencedWrite, "input controls the faulting store address"),
                DebuggerAccessKind.Read => (PrimitiveKind.InputInfluencedRead, "input controls the faulting load address"),
                _ => (PrimitiveKind.PointerControl, "input controls the faulting address"),
            },
            InfluencedStateKind.Pointer => (PrimitiveKind.PointerControl, "input bytes flow into a pointer value"),
            InfluencedStateKind.Register => IsInstructionPointer(link.State.Label)
                ? (PrimitiveKind.InstructionPointerInfluence, "input bytes reach the instruction pointer")
                : (PrimitiveKind.RegisterControl, $"input bytes reach register {link.State.Label}"),
            InfluencedStateKind.Length => (PrimitiveKind.LengthControl, "input controls a read/receive length"),
            InfluencedStateKind.CopyLength => (PrimitiveKind.WriteLengthControl, "input controls a copy/store length"),
            InfluencedStateKind.AllocationSize => (PrimitiveKind.AllocationSizeControl, "input controls an allocation size"),
            InfluencedStateKind.HeapObject => (PrimitiveKind.ObjectLifetimeInfluence, "input influences heap object lifetime"),
            InfluencedStateKind.ParserState => (PrimitiveKind.ParserStateInfluence, "input drives a parser/state transition"),
            _ => (PrimitiveKind.Unknown, link.Mechanism),
        };

        if (kind == PrimitiveKind.Unknown)
            return null;

        var refs = new List<string> { $"influence:{link.Id}" };
        refs.AddRange(link.EvidenceRefs.Take(3));

        return new PrimitiveAssessmentDto(
            $"prim-{KindSlug(kind)}-{link.Region.StartOffset:X}",
            kind,
            state,
            ConfidenceForState(state),
            mechanism,
            link.Region,
            refs,
            link.Id,
            link.HypothesisId);
    }

    private static void AddDebuggerFallback(
        List<PrimitiveAssessmentDto> primitives,
        DebuggerObservation? debugger,
        RootCauseAnalysisDto? rootCause,
        CrashCorruptionChainDto? chain)
    {
        if (debugger is not { Ok: true })
            return;

        var influenced = debugger.SuspectedInputInfluence is "HIGH" or "MEDIUM"
                         || chain is { PatternDepthBytes: not null }
                         || rootCause?.Candidate.Category is RootCauseCategory.BoundsViolation
                             or RootCauseCategory.SizeMismatch;
        if (!influenced)
            return;

        var kind = debugger.Access switch
        {
            DebuggerAccessKind.Write => PrimitiveKind.InputInfluencedWrite,
            DebuggerAccessKind.Read => PrimitiveKind.InputInfluencedRead,
            DebuggerAccessKind.Execute => PrimitiveKind.InstructionPointerInfluence,
            _ => PrimitiveKind.Unknown,
        };
        if (kind == PrimitiveKind.Unknown || primitives.Any(p => p.Kind == kind))
            return;

        var nullWriteWeak = RootCauseEngine.IsNullOrNearNullWrite(debugger)
                            && !RootCauseEngine.HasStrongNonZeroControlEvidence(debugger, chain);

        var offset = chain?.PatternDepthBytes ?? 0;
        primitives.Add(new PrimitiveAssessmentDto(
            $"prim-{KindSlug(kind)}-dbg",
            kind,
            PrimitiveState.Candidate,
            nullWriteWeak ? 0.35 : debugger.SuspectedInputInfluence == "HIGH" ? 0.6 : 0.45,
            debugger.Access switch
            {
                DebuggerAccessKind.Write when nullWriteWeak =>
                    "null/invalid destination write — candidate only until counterfactual/strong pattern",
                DebuggerAccessKind.Write => "write fault under input influence (no attributed offset yet)",
                DebuggerAccessKind.Read => "read fault under input influence (no attributed offset yet)",
                _ => "execute fault under input influence",
            },
            new InfluenceRegionDto(offset, null, null, chain?.SuspectedField, chain?.SuspectedMutator, chain?.SuspectedMutatorStep),
            [$"debugger:{debugger.Access}", $"influence:{debugger.SuspectedInputInfluence}"]));
    }

    private static List<PrimitiveAssessmentDto> MergeByKind(List<PrimitiveAssessmentDto> primitives)
    {
        var best = new Dictionary<PrimitiveKind, PrimitiveAssessmentDto>();
        foreach (var p in primitives)
        {
            if (!best.TryGetValue(p.Kind, out var existing))
            {
                best[p.Kind] = p;
                continue;
            }

            var keep = StateRank(p.State) > StateRank(existing.State)
                       || (StateRank(p.State) == StateRank(existing.State) && p.Confidence > existing.Confidence)
                ? p
                : existing;
            var other = ReferenceEquals(keep, p) ? existing : p;
            best[p.Kind] = keep with
            {
                EvidenceRefs = keep.EvidenceRefs.Concat(other.EvidenceRefs).Distinct().Take(6).ToList(),
                HypothesisId = keep.HypothesisId ?? other.HypothesisId,
            };
        }

        return best.Values.ToList();
    }

    private static (ResearchMaturity Level, string Rationale) ComputeMaturity(
        IReadOnlyList<PrimitiveAssessmentDto> primitives,
        RootCauseAnalysisDto? rootCause,
        CrashInfluenceMapDto? influence,
        CrashTriageDto? triage,
        DebuggerObservation? debugger,
        IReadOnlyList<EvidenceFact> facts,
        SkepticReportDto? skeptic = null,
        bool nullWriteCapped = false,
        CrashCorruptionChainDto? corruptionChain = null,
        EvidenceCourtReportDto? court = null)
    {
        var confirmed = primitives.Count(p => p.State == PrimitiveState.Confirmed);
        var observed = primitives.Count(p => p.State == PrimitiveState.Observed);
        var candidate = primitives.Count(p => p.State == PrimitiveState.Candidate);
        var rootHigh = rootCause is { Ok: true } && string.Equals(rootCause.Candidate.Confidence, "HIGH", StringComparison.OrdinalIgnoreCase);

        ResearchMaturity level;
        string rationale;
        if (confirmed >= 2 && rootHigh)
        {
            level = ResearchMaturity.R7;
            rationale = $"{confirmed} confirmed capabilities with HIGH-confidence root cause";
        }
        else if (confirmed >= 1)
        {
            level = ResearchMaturity.R6;
            rationale = "capability experimentally confirmed";
        }
        else if (observed >= 1)
        {
            level = ResearchMaturity.R5;
            rationale = "capability directly observed in debugger/influence evidence";
        }
        else if (candidate >= 1 || primitives.Count > 0)
        {
            level = ResearchMaturity.R4;
            rationale = "at least one capability inferred as a candidate";
        }
        else if (influence is { Links.Count: > 0 })
        {
            level = ResearchMaturity.R3;
            rationale = "input region attributed to influenced program state";
        }
        else if (rootCause is { Ok: true } && rootCause.Candidate.Category != RootCauseCategory.Unknown)
        {
            level = ResearchMaturity.R2;
            rationale = $"deterministic root cause: {rootCause.Candidate.Category}";
        }
        else if (debugger is { Ok: true } || triage is not null || facts.Count > 0)
        {
            level = ResearchMaturity.R1;
            rationale = "fault triaged (signal/severity classified)";
        }
        else
        {
            level = ResearchMaturity.R0;
            rationale = "crash discovered; no analysis yet";
        }

        // Machine-enforced R0–R7 evidence caps (fault site, Court/Skeptic, counterfactual).
        var (gated, gateReason) = ResearchMaturityGates.Enforce(
            level, rootCause, influence, primitives, triage, debugger, facts, skeptic, court);
        if (gateReason is not null)
        {
            level = gated;
            rationale = $"{rationale} — {gateReason}";
        }

        if (nullWriteCapped)
        {
            var hasControl = HasWriteControlEvidence(primitives, debugger, influence, skeptic);
            var repeatedBoundary = InfluenceEngine.HasRepeatedBoundaryCausality(corruptionChain, null);

            if (hasControl)
            {
                // R4 only with destination / written-value / copy-length / index control evidence.
                if (level > ResearchMaturity.R4)
                {
                    return (
                        ResearchMaturity.R4,
                        "Null/near-null write with control evidence — held at R4 pending Skeptic / counterfactual confirmation");
                }
            }
            else if (repeatedBoundary && level > ResearchMaturity.R3)
            {
                return (
                    ResearchMaturity.R3,
                    "Null/near-null write with repeated boundary causality — held at R3 (not write-length / R4 without control evidence)");
            }
            else if (level > ResearchMaturity.R2)
            {
                // Cap at R1–R2 (triaged / root-cause) without EA/instruction/counterfactual control.
                var cap = ResearchMaturityGates.MeetsR2(rootCause, debugger, facts)
                    ? ResearchMaturity.R2
                    : ResearchMaturity.R1;
                if (level > cap)
                {
                    return (
                        cap,
                        "Null/near-null write without destination/value/length/index control evidence — held at "
                        + $"{cap} (boundary mutator alone ≠ write-length control)");
                }
            }
        }

        return (level, rationale);
    }

    /// <summary>
    /// Destination / written-value / copy-length / index control from experiment, instruction, or EA —
    /// not mutator label alone.
    /// </summary>
    internal static bool HasWriteControlEvidence(
        IReadOnlyList<PrimitiveAssessmentDto> primitives,
        DebuggerObservation? debugger,
        CrashInfluenceMapDto? influence,
        SkepticReportDto? skeptic)
    {
        if (HasCounterfactualDeltaEvidence(skeptic))
            return true;
        if (RootCauseEngine.HasStrongNonZeroControlEvidence(debugger, null))
            return true;

        if (primitives.Any(p =>
                p.Kind is PrimitiveKind.WriteLengthControl
                    or PrimitiveKind.LengthControl
                    or PrimitiveKind.AllocationSizeControl
                && p.State is PrimitiveState.Observed or PrimitiveState.Confirmed
                && !p.Mechanism.Contains("boundary alone", StringComparison.OrdinalIgnoreCase)))
            return true;

        if (influence?.Links.Any(l =>
                l.Honesty == InfluenceHonestyLabel.Observed
                && l.State.Kind is InfluencedStateKind.CopyLength
                    or InfluencedStateKind.Length
                    or InfluencedStateKind.AllocationSize
                && !l.Mechanism.Contains("correlation", StringComparison.OrdinalIgnoreCase)) == true)
            return true;

        var insn = debugger?.DisasmNearRip ?? "";
        if (ScreamInvestigator.ExtractFaultInstructionLine(insn, debugger?.Rip) is { } good
            && (good.Contains('[', StringComparison.Ordinal)
                || Regex.IsMatch(good, @"\b(rep\s+movs|movs)\b", RegexOptions.IgnoreCase)))
        {
            // Real faulting store/copy at RIP counts as instruction evidence for control hypotheses.
            if (debugger?.Access == DebuggerAccessKind.Write
                && debugger.FaultAddressClass == DebuggerAddressClass.AsciiPattern)
                return true;
        }

        return false;
    }

    internal static (bool Capped, List<PrimitiveAssessmentDto> Primitives) ApplyNullWriteHonestyGate(
        IReadOnlyList<PrimitiveAssessmentDto> primitives,
        DebuggerObservation? debugger,
        SkepticReportDto? skeptic,
        CrashInfluenceMapDto? influence = null,
        CrashCorruptionChainDto? chain = null)
    {
        if (!RootCauseEngine.IsNullOrNearNullWrite(debugger))
            return (false, primitives.ToList());

        if (RootCauseEngine.HasStrongNonZeroControlEvidence(debugger, chain))
            return (false, primitives.ToList());

        if (HasCounterfactualDeltaEvidence(skeptic))
            return (false, primitives.ToList());

        var list = new List<PrimitiveAssessmentDto>();
        foreach (var p in primitives)
        {
            // Drop length/alloc primitives inferred only from weak null-write + mutator name.
            if (p.Kind is PrimitiveKind.WriteLengthControl
                    or PrimitiveKind.LengthControl
                    or PrimitiveKind.AllocationSizeControl
                && p.State is (PrimitiveState.Candidate or PrimitiveState.Unknown))
                continue;

            if (p.Kind is (PrimitiveKind.InputInfluencedWrite or PrimitiveKind.PointerControl)
                && p.State is (PrimitiveState.Observed or PrimitiveState.Confirmed))
            {
                list.Add(p with
                {
                    State = PrimitiveState.Candidate,
                    Confidence = ConfidenceForState(PrimitiveState.Candidate),
                    Mechanism = p.Mechanism + " (demoted: null-write needs counterfactual/strong pattern)",
                    EvidenceRefs = p.EvidenceRefs.Append("honesty:null-write-gate").Distinct().Take(8).ToList(),
                });
                continue;
            }

            list.Add(p);
        }

        _ = influence;
        return (true, list);
    }

    internal static bool HasCounterfactualDeltaEvidence(SkepticReportDto? skeptic)
    {
        if (skeptic is not { Ok: true, Challenges.Count: > 0 })
            return false;

        return skeptic.Challenges.Any(c =>
            c.Status == SkepticChallengeStatus.Survived
            && !string.IsNullOrWhiteSpace(c.Observation)
            && (c.Observation!.Contains("fault", StringComparison.OrdinalIgnoreCase)
                || c.Observation.Contains("delta", StringComparison.OrdinalIgnoreCase)
                || c.Observation.Contains("marker", StringComparison.OrdinalIgnoreCase)
                || c.Observation.Contains("tracks", StringComparison.OrdinalIgnoreCase)
                || c.Observation.Contains("unchanged", StringComparison.OrdinalIgnoreCase)));
    }

    /// <summary>
    /// Without Skeptic gate pass, Confirmed capabilities demote to Observed (cannot promote
    /// Candidate→Confirmed). Observed stays Observed but maturity still caps at R4 above.
    /// </summary>
    internal static List<PrimitiveAssessmentDto> DemoteConfirmedWithoutSkeptic(
        IReadOnlyList<PrimitiveAssessmentDto> primitives) =>
        primitives.Select(p => p.State == PrimitiveState.Confirmed
            ? p with
            {
                State = PrimitiveState.Observed,
                Confidence = ConfidenceForState(PrimitiveState.Observed),
                EvidenceRefs = p.EvidenceRefs.Append("skeptic:gate-blocked-confirmed").Distinct().Take(8).ToList(),
            }
            : p).ToList();

    private static IReadOnlyList<EvidenceFact> CollectFacts(
        IReadOnlyList<EvidenceFact>? external,
        CrashInfluenceMapDto? influence,
        RootCauseAnalysisDto? rootCause,
        IReadOnlyList<PrimitiveAssessmentDto> primitives)
    {
        var facts = external?.ToList() ?? influence?.Facts?.ToList() ?? [];
        if (facts.Count == 0 && rootCause is { Ok: true })
            facts = rootCause.Candidate.Evidence.ToList();

        var at = DateTimeOffset.UtcNow;
        foreach (var p in primitives)
        {
            var name = $"primitive.{KindSlug(p.Kind)}";
            if (facts.Any(f => f.Name == name))
                continue;
            facts.Add(EvidenceFactBuilder.Fact(
                name,
                $"{p.State}: {p.Mechanism}",
                "primitive_engine",
                null,
                p.State switch
                {
                    PrimitiveState.Confirmed => EvidenceObservationType.ExperimentallyConfirmed,
                    PrimitiveState.Observed => EvidenceObservationType.Observed,
                    _ => EvidenceObservationType.Inferred,
                },
                p.Confidence,
                at,
                p.InfluenceLinkId is { } l ? [$"influence:{l}"] : null));
        }

        return facts;
    }

    private static string RollupConfidence(IReadOnlyList<PrimitiveAssessmentDto> primitives)
    {
        if (primitives.Count == 0)
            return "UNKNOWN";
        if (primitives.Any(p => p.State == PrimitiveState.Confirmed))
            return "HIGH";
        if (primitives.Any(p => p.State == PrimitiveState.Observed))
            return "MEDIUM";
        if (primitives.Any(p => p.State == PrimitiveState.Candidate))
            return "LOW";
        return "UNKNOWN";
    }

    private static string BuildSummary(
        ResearchMaturity maturity,
        IReadOnlyList<PrimitiveAssessmentDto> primitives,
        string confidence,
        EvidenceCourtReportDto? court = null)
    {
        var sb = new StringBuilder();
        sb.Append($"[{maturity} · {MaturityLabel(maturity)}] ");
        if (primitives.Count == 0)
        {
            sb.Append("no capability primitives assessed");
            if (court is not null)
                sb.Append($" · {court.SummaryLine}");
            return sb.ToString();
        }

        var top = primitives
            .OrderByDescending(p => StateRank(p.State))
            .ThenByDescending(p => p.Confidence)
            .First();
        sb.Append($"{KindLabel(top.Kind)} ({top.State}) [{confidence}]");
        if (primitives.Count > 1)
            sb.Append($" · +{primitives.Count - 1} more");
        if (court is not null)
            sb.Append($" · {court.SummaryLine}");
        return sb.ToString();
    }

    private static bool IsInstructionPointer(string? register) =>
        register is not null
        && (register.Equals("RIP", StringComparison.OrdinalIgnoreCase)
            || register.Equals("EIP", StringComparison.OrdinalIgnoreCase)
            || register.Equals("PC", StringComparison.OrdinalIgnoreCase));

    private static PrimitiveState MapState(InfluenceConfirmationStatus status) => status switch
    {
        InfluenceConfirmationStatus.Confirmed => PrimitiveState.Confirmed,
        InfluenceConfirmationStatus.Observed => PrimitiveState.Observed,
        InfluenceConfirmationStatus.Candidate => PrimitiveState.Candidate,
        _ => PrimitiveState.Unknown,
    };

    private static double ConfidenceForState(PrimitiveState state) => state switch
    {
        PrimitiveState.Confirmed => 0.92,
        PrimitiveState.Observed => 0.75,
        PrimitiveState.Candidate => 0.5,
        _ => 0.3,
    };

    private static int StateRank(PrimitiveState state) => state switch
    {
        PrimitiveState.Confirmed => 4,
        PrimitiveState.Observed => 3,
        PrimitiveState.Candidate => 2,
        _ => 1,
    };

    internal static string MaturityLabel(ResearchMaturity maturity) => maturity switch
    {
        ResearchMaturity.R0 => "Discovered",
        ResearchMaturity.R1 => "Triaged",
        ResearchMaturity.R2 => "Root-caused",
        ResearchMaturity.R3 => "Input-attributed",
        ResearchMaturity.R4 => "Primitive candidate",
        ResearchMaturity.R5 => "Primitive observed",
        ResearchMaturity.R6 => "Primitive confirmed",
        ResearchMaturity.R7 => "Research-mature",
        _ => "Discovered",
    };

    /// <summary>Compact Investigation/Crashes chip text (R0 Crash … R7 Research package).</summary>
    internal static string MaturityChipLabel(ResearchMaturity maturity) => maturity switch
    {
        ResearchMaturity.R0 => "Crash",
        ResearchMaturity.R1 => "Triaged",
        ResearchMaturity.R2 => "Root cause",
        ResearchMaturity.R3 => "Attributed",
        ResearchMaturity.R4 => "Candidate",
        ResearchMaturity.R5 => "Observed",
        ResearchMaturity.R6 => "Confirmed",
        ResearchMaturity.R7 => "Research package",
        _ => "Crash",
    };

    /// <summary>Learning-mode explanation of what each study-depth level means.</summary>
    internal static string MaturityTeachingBlurb(ResearchMaturity maturity) => maturity switch
    {
        ResearchMaturity.R0 => "Crash discovered — reproduced or observed, but no analysis yet.",
        ResearchMaturity.R1 => "Triaged — fault classified (signal, severity, or faulting site).",
        ResearchMaturity.R2 => "Root-caused — a deterministic root-cause category is assigned.",
        ResearchMaturity.R3 => "Input-attributed — an input region is linked to influenced program state.",
        ResearchMaturity.R4 => "Primitive candidate — at least one capability primitive is inferred.",
        ResearchMaturity.R5 => "Primitive observed — a capability is directly seen in evidence.",
        ResearchMaturity.R6 => "Primitive confirmed — a capability is experimentally confirmed.",
        ResearchMaturity.R7 => "Research package — multiple confirmed capabilities with high-confidence root cause.",
        _ => "Crash discovered — reproduced or observed, but no analysis yet.",
    };

    private static string KindLabel(PrimitiveKind kind) => kind switch
    {
        PrimitiveKind.InputInfluencedRead => "input-influenced read",
        PrimitiveKind.InputInfluencedWrite => "input-influenced write",
        PrimitiveKind.PointerControl => "pointer control",
        PrimitiveKind.InstructionPointerInfluence => "instruction-pointer influence",
        PrimitiveKind.RegisterControl => "register control",
        PrimitiveKind.LengthControl => "read-length control",
        PrimitiveKind.WriteLengthControl => "write-length control",
        PrimitiveKind.AllocationSizeControl => "allocation-size control",
        PrimitiveKind.ObjectLifetimeInfluence => "object-lifetime influence",
        PrimitiveKind.ParserStateInfluence => "parser-state influence",
        _ => "unknown",
    };

    private static string KindSlug(PrimitiveKind kind) => kind switch
    {
        PrimitiveKind.InputInfluencedRead => "read",
        PrimitiveKind.InputInfluencedWrite => "write",
        PrimitiveKind.PointerControl => "ptr",
        PrimitiveKind.InstructionPointerInfluence => "rip",
        PrimitiveKind.RegisterControl => "reg",
        PrimitiveKind.LengthControl => "len",
        PrimitiveKind.WriteLengthControl => "wlen",
        PrimitiveKind.AllocationSizeControl => "alloc",
        PrimitiveKind.ObjectLifetimeInfluence => "lifetime",
        PrimitiveKind.ParserStateInfluence => "parser",
        _ => "unknown",
    };
}
