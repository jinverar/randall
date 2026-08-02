using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Allow-list of (hypothesis kind / type, experiment kind) pairs that may update support.
/// Unregistered pairs are ignored — prevents evidence leakage (e.g. safe-adjacent → MutatorCorrelation).
/// Part of the in-place HypothesisEngine upgrade (not a parallel engine).
/// </summary>
public static class HypothesisExperimentRegistry
{
    private static readonly HashSet<(HypothesisKind Kind, HypothesisExperimentKind Experiment)> Allowed = new()
    {
        (HypothesisKind.TriggerSensitivity, HypothesisExperimentKind.SweepOffset),
        (HypothesisKind.TriggerSensitivity, HypothesisExperimentKind.BoundaryProbe),
        (HypothesisKind.TriggerSensitivity, HypothesisExperimentKind.MinimizeHold),
        (HypothesisKind.TriggerSensitivity, HypothesisExperimentKind.CounterfactualSafeAdjacent),

        (HypothesisKind.InputRegionInfluence, HypothesisExperimentKind.SweepOffset),
        (HypothesisKind.InputRegionInfluence, HypothesisExperimentKind.BoundaryProbe),
        (HypothesisKind.InputRegionInfluence, HypothesisExperimentKind.MinimizeHold),
        (HypothesisKind.InputRegionInfluence, HypothesisExperimentKind.HoldMutator),

        (HypothesisKind.ReplaySamePrimaryFault, HypothesisExperimentKind.ReplayLineage),
        (HypothesisKind.ReplaySamePrimaryFault, HypothesisExperimentKind.HoldMutator),
        (HypothesisKind.ReplaySamePrimaryFault, HypothesisExperimentKind.MinimizeHold),

        (HypothesisKind.MutatorCorrelation, HypothesisExperimentKind.ReplayLineage),
        (HypothesisKind.MutatorCorrelation, HypothesisExperimentKind.HoldMutator),

        (HypothesisKind.DestinationControl, HypothesisExperimentKind.SweepOffset),
        (HypothesisKind.DestinationControl, HypothesisExperimentKind.MinimizeHold),
        (HypothesisKind.DestinationControl, HypothesisExperimentKind.HoldMutator),
        (HypothesisKind.DestinationControl, HypothesisExperimentKind.ReplayLineage),

        (HypothesisKind.WrittenValueControl, HypothesisExperimentKind.SweepOffset),
        (HypothesisKind.WrittenValueControl, HypothesisExperimentKind.BoundaryProbe),
        (HypothesisKind.WrittenValueControl, HypothesisExperimentKind.MinimizeHold),

        (HypothesisKind.RootCause, HypothesisExperimentKind.ReplayLineage),
        (HypothesisKind.RootCause, HypothesisExperimentKind.HoldMutator),
        (HypothesisKind.RootCause, HypothesisExperimentKind.MinimizeHold),

        (HypothesisKind.FamilyProgression, HypothesisExperimentKind.HoldMutator),
        (HypothesisKind.FamilyProgression, HypothesisExperimentKind.ReplayLineage),
        (HypothesisKind.FamilyProgression, HypothesisExperimentKind.SweepOffset),

        (HypothesisKind.SharedCodeTwin, HypothesisExperimentKind.ReplayLineage),
    };

    /// <summary>Type-id prefixes that map to typed kinds when Kind is Unknown (legacy rows).</summary>
    public static HypothesisKind InferKind(string? typeId, HypothesisExperimentKind experiment)
    {
        var id = typeId ?? "";
        if (id.StartsWith("hyp-offset", StringComparison.OrdinalIgnoreCase)
            || id.StartsWith("hyp-boundary", StringComparison.OrdinalIgnoreCase)
            || id.StartsWith("hyp-ascii", StringComparison.OrdinalIgnoreCase)
            || id.StartsWith("hyp-cf-trigger", StringComparison.OrdinalIgnoreCase)
            || id.Equals("h-cf-live", StringComparison.OrdinalIgnoreCase)
            || id.StartsWith("hyp-btrace-reg", StringComparison.OrdinalIgnoreCase))
            return HypothesisKind.TriggerSensitivity;

        if (id.StartsWith("hyp-lineage", StringComparison.OrdinalIgnoreCase)
            || id.StartsWith("hyp-oracle", StringComparison.OrdinalIgnoreCase)
            || id.StartsWith("hyp-hold", StringComparison.OrdinalIgnoreCase))
            return HypothesisKind.MutatorCorrelation;

        if (id.StartsWith("hyp-write-progression", StringComparison.OrdinalIgnoreCase)
            || id.StartsWith("hyp-stall", StringComparison.OrdinalIgnoreCase))
            return HypothesisKind.FamilyProgression;

        if (id.StartsWith("hyp-btrace-heap", StringComparison.OrdinalIgnoreCase)
            || id.StartsWith("hyp-btrace-source", StringComparison.OrdinalIgnoreCase))
            return HypothesisKind.RootCause;

        if (id.StartsWith("twin-", StringComparison.OrdinalIgnoreCase)
            || id.Contains("twin", StringComparison.OrdinalIgnoreCase))
            return HypothesisKind.SharedCodeTwin;

        // Fall back from experiment kind for ad-hoc rows.
        return experiment switch
        {
            HypothesisExperimentKind.CounterfactualSafeAdjacent => HypothesisKind.TriggerSensitivity,
            HypothesisExperimentKind.SweepOffset or HypothesisExperimentKind.BoundaryProbe
                => HypothesisKind.TriggerSensitivity,
            HypothesisExperimentKind.ReplayLineage => HypothesisKind.ReplaySamePrimaryFault,
            _ => HypothesisKind.Unknown,
        };
    }

    public static bool IsAllowed(HypothesisKind kind, HypothesisExperimentKind experiment)
    {
        if (kind == HypothesisKind.Unknown)
            return false;
        return Allowed.Contains((kind, experiment));
    }

    public static bool IsAllowed(HypothesisDto hyp, HypothesisExperimentKind experiment)
    {
        var kind = hyp.Kind != HypothesisKind.Unknown
            ? hyp.Kind
            : InferKind(hyp.HypothesisTypeId, hyp.Experiment.Kind);
        return IsAllowed(kind, experiment);
    }

    /// <summary>
    /// Counterfactual safe-adjacent may only update TriggerSensitivity (or inferred trigger hyps).
    /// </summary>
    public static bool AllowsCounterfactualSafeAdjacent(HypothesisDto hyp)
    {
        var kind = hyp.Kind != HypothesisKind.Unknown
            ? hyp.Kind
            : InferKind(hyp.HypothesisTypeId, hyp.Experiment.Kind);
        return kind == HypothesisKind.TriggerSensitivity
               && IsAllowed(kind, HypothesisExperimentKind.CounterfactualSafeAdjacent);
    }
}
