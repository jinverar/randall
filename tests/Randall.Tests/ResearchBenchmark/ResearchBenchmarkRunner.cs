using Randall.Contracts;
using Randall.Infrastructure;

namespace Randall.Tests.ResearchBenchmark;

/// <summary>
/// Runs investigation engines against fixture observations and fills a scorecard.
/// Fixture-only — does not start lab TCP listeners.
/// </summary>
public static class ResearchBenchmarkRunner
{
    public static ResearchBenchmarkScorecard Evaluate(ResearchBenchmarkEnvelope env)
    {
        if (env.Stub)
        {
            return new ResearchBenchmarkScorecard(
                env.FixtureId, env.Family, Stub: true,
                CrashDetected: false, ClassificationOk: false, PcOk: false,
                RootCauseFamilyOk: false, AttributionHonest: true,
                ObservedMaturity: ResearchMaturity.R0,
                PrimitiveLevelOk: true, UnsupportedR5Plus: false, FalseConfidentClaims: false,
                Summary: "STUB — not wired",
                Notes: [env.Notes ?? "TODO"]);
        }

        var id = Guid.NewGuid();
        var obs = ResearchBenchmarkFixtures.BuildObservation(env);
        var root = RootCauseEngine.Build(id, "benchmark", null, null, obs, null, null);
        var influence = InfluenceEngine.Build(id, "benchmark", null, null, obs, null, null, null, null, null);
        var facts = EvidenceFactBuilder.CollectFacts(
            id, "benchmark", debugger: obs);
        var primitives = PrimitiveEngine.Build(id, "benchmark", influence, root, obs, facts: facts);

        var crashDetected = obs.Ok || !string.IsNullOrWhiteSpace(obs.ExceptionCode);
        var classificationOk =
            (env.ExpectedAccess is null || obs.Access == env.ExpectedAccess)
            && (env.ExpectedAddressClass is null || obs.FaultAddressClass == env.ExpectedAddressClass);

        var pcOk = env.ExpectedPcContains is null
                   || (!string.IsNullOrWhiteSpace(obs.Rip)
                       && obs.Rip.Contains(env.ExpectedPcContains, StringComparison.OrdinalIgnoreCase));

        var rootOk = env.AllowedRootFamilies is null || env.AllowedRootFamilies.Count == 0
                     || (root.Ok && env.AllowedRootFamilies.Contains(root.Candidate.Category));

        // Attribution honesty: do not claim HIGH influence without pattern/ASCII evidence.
        var attributionHonest = influence is not { Confidence: "HIGH" }
                                || obs.FaultAddressClass == DebuggerAddressClass.AsciiPattern
                                || obs.SuspectedInputInfluence is "HIGH" or "MEDIUM";

        var maturity = primitives.Maturity;
        var unsupportedR5 = maturity >= ResearchMaturity.R5 && !env.AllowR5Plus
                            && !ResearchMaturityGates.MeetsR5Plus(null, facts, primitives.Court);
        // Without promotion inputs, maturity must stay ≤ MaxMaturityWithoutPromotion.
        var primitiveLevelOk = maturity <= env.MaxMaturityWithoutPromotion && !unsupportedR5;

        var falseConfident = primitives.Court?.Overall == EvidenceCourtVerdict.Rejected
                             && primitives.Primitives.Any(p => p.Confidence >= 0.7
                                 && !p.EvidenceRefs.Any(r => r.StartsWith("court:", StringComparison.Ordinal)));
        // Also: HIGH confidence Observed/Confirmed with zero non-primitive facts.
        var sensorFacts = facts.Count(f => !f.Name.StartsWith("primitive.", StringComparison.OrdinalIgnoreCase));
        if (sensorFacts == 0
            && primitives.Primitives.Any(p => p.Confidence >= 0.7 && p.State is PrimitiveState.Observed or PrimitiveState.Confirmed))
            falseConfident = true;

        var notes = new List<string>();
        if (env.Notes is not null) notes.Add(env.Notes);
        notes.Add($"maturity={maturity} root={root.Candidate.Category} access={obs.Access} addrClass={obs.FaultAddressClass}");
        if (primitives.Court is not null) notes.Add(primitives.Court.SummaryLine);

        var summary = crashDetected && classificationOk && pcOk && rootOk && primitiveLevelOk && !falseConfident
            ? "PASS"
            : "FAIL";

        return new ResearchBenchmarkScorecard(
            env.FixtureId, env.Family, Stub: false,
            crashDetected, classificationOk, pcOk, rootOk, attributionHonest,
            maturity, primitiveLevelOk, unsupportedR5, falseConfident,
            summary, notes);
    }

    public static ResearchBenchmarkReport RunAll()
    {
        var cards = ResearchBenchmarkFixtures.All.Select(Evaluate).ToList();
        var live = cards.Where(c => !c.Stub).ToList();
        return new ResearchBenchmarkReport(
            live.Count,
            cards.Count(c => c.Stub),
            live.Count(c => c.Summary == "PASS"),
            cards);
    }
}
