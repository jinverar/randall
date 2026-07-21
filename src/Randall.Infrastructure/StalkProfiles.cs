using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Named stalking intensity presets — <c>basic</c> → <c>fuzz</c> → <c>fuzzier</c> — that ramp how
/// aggressively the engine explores: iteration budget, havoc depth, power schedule (favor corpus
/// entries that found new coverage), session-graph branching bias, coverage-guided feedback, and the
/// mutator set. Applying a profile rewrites the loaded project's fuzz settings in-memory so the same
/// target can be compared across intensities.
/// </summary>
public static class StalkProfiles
{
    public static readonly IReadOnlyList<string> Names = ["basic", "fuzz", "fuzzier"];

    public sealed record Profile(
        string Name,
        int Iterations,
        int HavocDepth,
        bool PowerSchedule,
        double SessionFlowBias,
        double SessionGraphBias,
        bool CoverageGuided,
        IReadOnlyList<string> Mutators,
        string Blurb);

    public static bool IsKnown(string? name) =>
        !string.IsNullOrWhiteSpace(name) && Names.Contains(name.Trim().ToLowerInvariant());

    /// <summary>Resolve a preset. <paramref name="coverageAvailable"/> gates coverage-guided feedback.</summary>
    public static Profile Get(string name, bool coverageAvailable = false)
    {
        return name.Trim().ToLowerInvariant() switch
        {
            "basic" => new Profile("basic", 100, 2, false, 0.10, 0.10, false,
                ["bitflip", "insert"],
                "gentle: shallow havoc, no power schedule, minimal mutators — smoke test"),
            "fuzzier" => new Profile("fuzzier", 2000, 16, true, 0.40, 0.40, coverageAvailable,
                ["bitflip", "havoc", "interesting", "dictionary", "arith", "expand", "boundary", "insert", "splice"],
                "aggressive: deep havoc, high graph bias, full mutators + splice, coverage-guided"),
            _ => new Profile("fuzz", 500, 8, true, 0.30, 0.25, coverageAvailable,
                ["bitflip", "havoc", "interesting", "dictionary", "arith", "insert"],
                "standard: balanced havoc + power schedule + core mutators"),
        };
    }

    /// <summary>Rewrites <paramref name="project"/>'s fuzz settings to the profile (in place).</summary>
    public static Profile Apply(ProjectConfig project, string name, bool coverageAvailable = false, int? iterationsOverride = null)
    {
        var p = Get(name, coverageAvailable);
        project.Fuzz.MaxIterations = iterationsOverride ?? p.Iterations;
        project.Fuzz.HavocDepth = p.HavocDepth;
        project.Fuzz.PowerSchedule = p.PowerSchedule;
        project.Fuzz.SessionFlowBias = p.SessionFlowBias;
        project.Fuzz.SessionGraphBias = p.SessionGraphBias;
        project.Fuzz.CoverageGuided = p.CoverageGuided;
        project.Mutators = [.. p.Mutators];
        return p;
    }
}
