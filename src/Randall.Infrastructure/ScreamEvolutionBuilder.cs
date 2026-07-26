using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Groups related crashes into scream families (phenotype), tracks generation / ancestors,
/// and scores momentum (READ→WRITE→controlled WRITE progression).
/// </summary>
public static class ScreamEvolutionBuilder
{
    private static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = true };

    public static string PathFor(string crashesDir, Guid crashId) =>
        Path.Combine(crashesDir, $"{crashId:N}_scream_evolution.json");

    public static ScreamEvolutionDto? TryRead(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            return null;
        try
        {
            return JsonSerializer.Deserialize<ScreamEvolutionDto>(File.ReadAllText(path), JsonOpts);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>Build evolution for one crash using sibling crashes in the same project.</summary>
    public static ScreamEvolutionDto Build(
        Guid crashId,
        string project,
        CrashSidecarDto? sidecar,
        CrashTriageDto? triage,
        DebuggerObservation? debugger,
        CrashCorruptionChainDto? corruptionChain,
        IReadOnlyList<CrashContext> projectCrashes)
    {
        try
        {
            var self = projectCrashes.FirstOrDefault(c => c.Id == crashId)
                       ?? new CrashContext(crashId, project, sidecar, triage, debugger, corruptionChain, null, 0, DateTimeOffset.UtcNow);

            var familyKey = ComputeFamilyKey(self);
            var familyLabel = BuildFamilyLabel(self);
            var progression = ClassifyProgression(triage, debugger, corruptionChain);
            var seedRoot = ResolveSeedRootHash(self, projectCrashes);

            var familyMembers = projectCrashes
                .Where(c => ComputeFamilyKey(c) == familyKey)
                .OrderBy(c => c.ObservedAt)
                .ToList();

            var ancestor = ResolveAncestor(self, projectCrashes);
            var generation = ancestor is null ? 1 : Math.Max(1, ancestor.Generation + 1);
            var ancestorStep = ancestor?.Progression ?? ScreamProgressionStep.Unknown;
            var progressionDelta = (int)progression - (int)ancestorStep;

            var bestPriorStep = familyMembers
                .Where(c => c.Id != crashId && c.ObservedAt < self.ObservedAt)
                .Select(c => ClassifyProgression(c.Triage, c.Debugger, c.CorruptionChain))
                .DefaultIfEmpty(ancestorStep)
                .Max();

            var momentumScore = ComputeMomentum(
                progression, bestPriorStep, ancestorStep, progressionDelta,
                self.ScreamScore, ancestor?.ScreamScore ?? 0, debugger, triage);
            var momentumLabel = LabelMomentum(momentumScore, progressionDelta);

            var memberIds = familyMembers.Select(c => c.Id).ToList();
            if (!memberIds.Contains(crashId))
                memberIds.Add(crashId);

            var summary = BuildSummary(
                familyLabel, generation, momentumLabel, momentumScore,
                progression, ancestorStep, progressionDelta, memberIds.Count, seedRoot);

            return new ScreamEvolutionDto(
                Ok: true,
                CrashId: crashId,
                Project: project,
                FamilyId: familyKey,
                FamilyLabel: familyLabel,
                Generation: generation,
                AncestorCrashId: ancestor?.CrashId,
                AncestorInputHash: sidecar?.ParentInputHash ?? ancestor?.InputHash,
                MomentumScore: momentumScore,
                MomentumLabel: momentumLabel,
                ProgressionStep: progression,
                AncestorProgressionStep: ancestorStep == ScreamProgressionStep.Unknown ? null : ancestorStep,
                ProgressionDelta: progressionDelta,
                FamilyMemberIds: memberIds,
                FamilySize: memberIds.Count,
                Summary: summary,
                At: DateTimeOffset.UtcNow);
        }
        catch (Exception ex)
        {
            return new ScreamEvolutionDto(
                false, crashId, project, "", null, 0, null, null,
                0, "stable", ScreamProgressionStep.Unknown, null, 0, [], 0,
                null, DateTimeOffset.UtcNow, ex.Message);
        }
    }

    public static ScreamEvolutionDto PersistForCrash(
        string crashesDir,
        Guid crashId,
        string project,
        CrashSidecarDto? sidecar,
        CrashTriageDto? triage,
        DebuggerObservation? debugger,
        CrashCorruptionChainDto? corruptionChain,
        IReadOnlyList<CrashContext> projectCrashes)
    {
        var evolution = Build(crashId, project, sidecar, triage, debugger, corruptionChain, projectCrashes);
        Write(crashesDir, evolution);
        return evolution;
    }

    public static string Write(string crashesDir, ScreamEvolutionDto evolution)
    {
        Directory.CreateDirectory(crashesDir);
        var path = PathFor(crashesDir, evolution.CrashId);
        File.WriteAllText(path, JsonSerializer.Serialize(evolution, JsonOpts));
        return path;
    }

    /// <summary>Load project crash contexts from disk for family recomputation.</summary>
    public static IReadOnlyList<CrashContext> LoadProjectContexts(string crashesDir, string project)
    {
        if (!Directory.Exists(crashesDir))
            return [];

        var store = new CrashStore(crashesDir);
        var contexts = new List<CrashContext>();
        foreach (var c in store.List())
        {
            if (!c.Project.Equals(project, StringComparison.OrdinalIgnoreCase))
                continue;

            var sidecar = CrashSidecarWriter.TryRead(c.SidecarPath);
            var debugger = ScreamInvestigator.TryRead(ScreamInvestigator.ObservationPathFor(crashesDir, c.Id));
            var corruption = CorruptionChainBuilder.TryRead(CorruptionChainBuilder.PathFor(crashesDir, c.Id));
            var evolution = TryRead(PathFor(crashesDir, c.Id));

            var summary = new CrashSummaryDto(
                c.Id, c.Project, c.Iteration, c.Mutator, c.InputHash, c.InputPath,
                c.MiniDumpPath, c.TargetExitCode, c.TriageTag, c.SidecarPath, c.RunId, c.At);

            byte[]? payload = null;
            if (File.Exists(c.InputPath))
            {
                try { payload = File.ReadAllBytes(c.InputPath); }
                catch { /* ignore */ }
            }

            var triage = CrashTriage.Classify(null, sidecar, summary, payload, debugger: debugger);

            contexts.Add(new CrashContext(
                c.Id,
                project,
                sidecar,
                triage,
                debugger,
                corruption,
                sidecar?.InputHash,
                evolution?.Generation ?? 0,
                c.At,
                0));
        }

        // Second pass: fill generation from persisted evolution or recompute ancestor depth
        var byHash = contexts
            .Where(c => !string.IsNullOrWhiteSpace(c.InputHash))
            .GroupBy(c => c.InputHash!, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);

        return contexts.Select(ctx =>
        {
            if (ctx.Generation > 0)
                return ctx;
            var gen = ComputeGenerationDepth(ctx, byHash, contexts);
            return ctx with { Generation = gen };
        }).ToList();
    }

    public static ScreamProgressionStep ClassifyProgression(
        CrashTriageDto? triage,
        DebuggerObservation? debugger,
        CrashCorruptionChainDto? corruptionChain)
    {
        if (corruptionChain?.PatternDepthBytes is not null)
            return ScreamProgressionStep.PatternDepth;

        if (debugger?.FaultAddressClass == DebuggerAddressClass.AsciiPattern
            || debugger?.SuspectedInputInfluence == "HIGH"
            || triage?.IpLooksControlled == true)
            return ScreamProgressionStep.ControlledAddress;

        return debugger?.Access switch
        {
            DebuggerAccessKind.Execute => ScreamProgressionStep.ExecuteViolation,
            DebuggerAccessKind.Write => ScreamProgressionStep.WriteViolation,
            DebuggerAccessKind.Read => ScreamProgressionStep.ReadViolation,
            _ => ScreamProgressionStep.Unknown,
        };
    }

    public static int ComputeMomentum(
        ScreamProgressionStep current,
        ScreamProgressionStep bestPrior,
        ScreamProgressionStep ancestor,
        int progressionDelta,
        int screamScore,
        int ancestorScreamScore,
        DebuggerObservation? debugger,
        CrashTriageDto? triage)
    {
        var score = 0;

        if (progressionDelta > 0)
            score += Math.Min(40, progressionDelta * 15);
        else if (progressionDelta < 0)
            score -= Math.Min(20, -progressionDelta * 8);

        var vsBest = (int)current - (int)bestPrior;
        if (vsBest > 0)
            score += Math.Min(25, vsBest * 12);

        var screamDelta = screamScore - ancestorScreamScore;
        if (screamDelta > 0)
            score += Math.Min(15, screamDelta / 3);

        if (debugger?.SuspectedInputInfluence == "HIGH")
            score += 10;
        else if (debugger?.SuspectedInputInfluence == "MEDIUM")
            score += 5;

        if (triage?.IpLooksControlled == true && current >= ScreamProgressionStep.ControlledAddress)
            score += 8;

        if (current == ScreamProgressionStep.Unknown && bestPrior == ScreamProgressionStep.Unknown)
            score = Math.Max(0, score);

        return Math.Clamp(score, 0, 100);
    }

    public static string LabelMomentum(int momentumScore, int progressionDelta) =>
        momentumScore switch
        {
            >= 65 when progressionDelta > 0 => "hot",
            >= 40 when progressionDelta > 0 => "warming",
            >= 40 => "warming",
            <= 15 when progressionDelta < 0 => "cooling",
            _ => "stable",
        };

    internal static string ComputeFamilyKey(CrashContext ctx)
    {
        var fn = ctx.Debugger?.FaultingFunction is not null
            ? $"{ctx.Debugger.FaultingModule ?? "?"}!{ctx.Debugger.FaultingFunction}"
            : ctx.Triage?.StaticFunction?.FunctionName is not null
                ? ctx.Triage.StaticFunction.FunctionName
                : null;

        var stack = ctx.Debugger?.StackHash;
        var field = ctx.CorruptionChain?.SuspectedField;
        var seedRoot = ctx.Sidecar?.SeedSource ?? "unknown";
        var lineageHead = ctx.Sidecar?.MutatorChain?.FirstOrDefault()
                          ?? ctx.Sidecar?.Mutator
                          ?? ctx.Triage?.ClusterKey
                          ?? "unknown";

        // Phenotype key: function + stack + field + seed lineage — deliberately not IP/RIP cluster alone.
        var raw = string.Join('|',
            ctx.Project.ToLowerInvariant(),
            fn ?? "fn:?",
            stack ?? "stack:?",
            field ?? "field:?",
            seedRoot.ToLowerInvariant(),
            lineageHead.ToLowerInvariant());

        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(raw)))[..16];
        return $"{ctx.Project}|fam|{hash}";
    }

    private static string BuildFamilyLabel(CrashContext ctx)
    {
        var fn = ctx.Debugger?.FaultingFunction is not null
            ? $"{ctx.Debugger.FaultingModule}!{ctx.Debugger.FaultingFunction}"
            : ctx.Triage?.StaticFunction?.FunctionName;
        var parts = new List<string>();
        if (!string.IsNullOrWhiteSpace(fn))
            parts.Add(fn);
        if (ctx.CorruptionChain?.SuspectedField is { } field)
            parts.Add(field);
        if (ctx.Debugger?.Access is { } acc && acc != DebuggerAccessKind.Unknown)
            parts.Add($"{acc.ToString().ToLowerInvariant()} AV");
        if (ctx.Sidecar?.SeedSource is { } seed)
            parts.Add($"seed:{seed}");
        return parts.Count == 0 ? "unknown phenotype" : string.Join(" · ", parts);
    }

    private static string? ResolveSeedRootHash(CrashContext self, IReadOnlyList<CrashContext> projectCrashes)
    {
        var byHash = projectCrashes
            .Where(c => !string.IsNullOrWhiteSpace(c.InputHash))
            .GroupBy(c => c.InputHash!, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);

        var current = self;
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        while (!string.IsNullOrWhiteSpace(current.Sidecar?.ParentInputHash)
               && visited.Add(current.Sidecar.ParentInputHash))
        {
            if (!byHash.TryGetValue(current.Sidecar.ParentInputHash, out var parent))
                break;
            current = parent;
        }

        return current.InputHash ?? self.InputHash;
    }

    private static AncestorInfo? ResolveAncestor(CrashContext self, IReadOnlyList<CrashContext> projectCrashes)
    {
        var parentHash = self.Sidecar?.ParentInputHash;
        if (string.IsNullOrWhiteSpace(parentHash))
            return null;

        var parent = projectCrashes
            .Where(c => parentHash.Equals(c.InputHash, StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(c => c.ObservedAt)
            .FirstOrDefault();

        if (parent is null)
            return null;

        return new AncestorInfo(
            parent.Id,
            parent.InputHash,
            parent.Generation > 0 ? parent.Generation : ComputeGenerationDepth(parent,
                projectCrashes.Where(c => !string.IsNullOrWhiteSpace(c.InputHash))
                    .GroupBy(c => c.InputHash!, StringComparer.OrdinalIgnoreCase)
                    .ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase),
                projectCrashes),
            ClassifyProgression(parent.Triage, parent.Debugger, parent.CorruptionChain),
            parent.ScreamScore);
    }

    private static int ComputeGenerationDepth(
        CrashContext ctx,
        IReadOnlyDictionary<string, CrashContext> byHash,
        IReadOnlyList<CrashContext> all)
    {
        var depth = 1;
        var current = ctx;
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        while (!string.IsNullOrWhiteSpace(current.Sidecar?.ParentInputHash)
               && visited.Add(current.Sidecar.ParentInputHash))
        {
            if (!byHash.TryGetValue(current.Sidecar.ParentInputHash, out var parent))
                break;
            depth++;
            current = parent;
        }

        return depth;
    }

    private static string BuildSummary(
        string? familyLabel,
        int generation,
        string momentumLabel,
        int momentumScore,
        ScreamProgressionStep step,
        ScreamProgressionStep ancestorStep,
        int delta,
        int familySize,
        string? seedRoot)
    {
        var stepName = step.ToString();
        var trend = delta switch
        {
            > 0 => $"↑{delta} vs ancestor ({ancestorStep}→{step})",
            < 0 => $"↓{-delta} vs ancestor",
            _ => "same step as ancestor",
        };
        var root = seedRoot is null ? "" : $" · root {seedRoot[..Math.Min(12, seedRoot.Length)]}";
        return $"[{momentumLabel} {momentumScore}] gen {generation} · {stepName} · {trend} · family×{familySize} · {familyLabel}{root}";
    }

    internal sealed record AncestorInfo(
        Guid CrashId,
        string? InputHash,
        int Generation,
        ScreamProgressionStep Progression,
        int ScreamScore);

    /// <summary>Minimal crash slice for scream-family recomputation.</summary>
    public sealed record CrashContext(
        Guid Id,
        string Project,
        CrashSidecarDto? Sidecar,
        CrashTriageDto? Triage,
        DebuggerObservation? Debugger,
        CrashCorruptionChainDto? CorruptionChain,
        string? InputHash,
        int Generation,
        DateTimeOffset ObservedAt,
        int ScreamScore = 0)
    {
        public ScreamProgressionStep Progression =>
            ClassifyProgression(Triage, Debugger, CorruptionChain);
    }
}
