using System.Text.Json;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Project-level scream family index — cross-run persistence, momentum decay, lineage hints.
/// </summary>
public static class ScreamFamilyIndex
{
    public const string FileName = "scream_family_index.json";
    public const int MomentumWarmThreshold = 40;
    public const int MomentumHotThreshold = 65;
    public const int StagnantRunThreshold = 3;
    public const int DecayPerStagnantRun = 5;

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
    };

    public static string PathFor(string project, string? repoRoot = null) =>
        Path.Combine(StalkCampaignStore.ProjectDir(project, repoRoot), FileName);

    public static ScreamFamilyIndexDto? TryLoad(string project, string? repoRoot = null)
    {
        var path = PathFor(project, repoRoot);
        if (!File.Exists(path))
            return null;
        try
        {
            return JsonSerializer.Deserialize<ScreamFamilyIndexDto>(File.ReadAllText(path), JsonOpts);
        }
        catch
        {
            return null;
        }
    }

    public static ScreamFamilyEntryDto? TryGetEntry(string project, string familyId, string? repoRoot = null)
    {
        var index = TryLoad(project, repoRoot);
        return index?.Families.FirstOrDefault(f =>
            f.FamilyId.Equals(familyId, StringComparison.OrdinalIgnoreCase));
    }

    public static (ScreamFamilyIndexDto Index, ScreamEvolutionTelemetryDto Telemetry, int DecayApplied)
        Update(
            string project,
            ScreamEvolutionDto evolution,
            CrashSidecarDto? sidecar,
            string? seedRootHash,
            string? repoRoot = null,
            int lineageBreedsQueued = 0)
    {
        if (evolution is not { Ok: true } || string.IsNullOrWhiteSpace(evolution.FamilyId))
        {
            var empty = TryLoad(project, repoRoot)
                        ?? new ScreamFamilyIndexDto(project, DateTimeOffset.UtcNow, []);
            return (empty, ComputeTelemetry(empty, lineageBreedsQueued, 0), 0);
        }

        var now = DateTimeOffset.UtcNow;
        var families = TryLoad(project, repoRoot)?.Families.ToList() ?? [];
        var idx = families.FindIndex(f =>
            f.FamilyId.Equals(evolution.FamilyId, StringComparison.OrdinalIgnoreCase));

        var lineage = sidecar?.MutatorChain?.ToList()
                      ?? (sidecar?.Mutator is { } m ? new List<string> { m } : null);
        var progressed = idx < 0
                         || evolution.ProgressionStep > families[idx].BestProgressionStep
                         || evolution.ProgressionDelta > 0;

        ScreamFamilyEntryDto entry;
        var decayApplied = 0;

        if (idx < 0)
        {
            entry = new ScreamFamilyEntryDto(
                evolution.FamilyId,
                evolution.FamilyLabel,
                evolution.MomentumScore,
                evolution.MomentumScore,
                evolution.MomentumLabel,
                evolution.ProgressionStep,
                evolution.Generation,
                evolution.FamilySize,
                0,
                now,
                now,
                evolution.CrashId,
                lineage,
                evolution.AncestorInputHash,
                seedRootHash);
            families.Add(entry);
        }
        else
        {
            var prev = families[idx];
            var stagnantRuns = progressed ? 0 : prev.StagnantRuns + 1;
            var peak = Math.Max(prev.PeakMomentumScore, evolution.MomentumScore);
            var effective = ApplyDecay(peak, stagnantRuns);
            decayApplied = Math.Max(0, peak - effective);
            var label = Relabel(effective, evolution.ProgressionDelta, stagnantRuns, prev.MemberCount + 1);

            var bestLineage = lineage is { Count: >= 2 }
                ? lineage
                : prev.BestLineageChain;

            entry = prev with
            {
                FamilyLabel = evolution.FamilyLabel ?? prev.FamilyLabel,
                PeakMomentumScore = peak,
                EffectiveMomentumScore = effective,
                MomentumLabel = label,
                BestProgressionStep = progressed
                    ? (ScreamProgressionStep)Math.Max((int)prev.BestProgressionStep, (int)evolution.ProgressionStep)
                    : prev.BestProgressionStep,
                MaxGeneration = Math.Max(prev.MaxGeneration, evolution.Generation),
                MemberCount = Math.Max(prev.MemberCount, evolution.FamilySize),
                StagnantRuns = stagnantRuns,
                LastProgressAt = progressed ? now : prev.LastProgressAt,
                LastSeenAt = now,
                LeadCrashId = evolution.MomentumScore >= prev.PeakMomentumScore
                    ? evolution.CrashId
                    : prev.LeadCrashId,
                BestLineageChain = bestLineage,
                AncestorInputHash = evolution.AncestorInputHash ?? prev.AncestorInputHash,
                SeedRootHash = seedRootHash ?? prev.SeedRootHash,
            };
            families[idx] = entry;
        }

        var index = new ScreamFamilyIndexDto(project, now, families);
        Persist(index, repoRoot);
        return (index, ComputeTelemetry(index, lineageBreedsQueued, decayApplied), decayApplied);
    }

    public static void Persist(ScreamFamilyIndexDto index, string? repoRoot = null)
    {
        if (string.IsNullOrWhiteSpace(index.Project))
            return;

        var path = PathFor(index.Project, repoRoot);
        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir))
            Directory.CreateDirectory(dir);
        File.WriteAllText(path, JsonSerializer.Serialize(index, JsonOpts));
    }

    public static int ApplyDecay(int peakMomentum, int stagnantRuns) =>
        Math.Max(0, peakMomentum - Math.Min(peakMomentum, stagnantRuns * DecayPerStagnantRun));

    public static string Relabel(int effectiveMomentum, int progressionDelta, int stagnantRuns, int memberCount = 0)
    {
        if (stagnantRuns >= StagnantRunThreshold && progressionDelta <= 0 && effectiveMomentum >= 20)
            return "stagnant";
        if (memberCount >= 6 && effectiveMomentum < MomentumWarmThreshold && progressionDelta <= 0 && stagnantRuns >= 2)
            return "stagnant";

        return effectiveMomentum switch
        {
            >= MomentumHotThreshold when progressionDelta > 0 => "hot",
            >= MomentumHotThreshold => "hot",
            >= MomentumWarmThreshold when progressionDelta > 0 => "warming",
            >= MomentumWarmThreshold => "warming",
            <= 15 when progressionDelta < 0 => "cooling",
            _ => "stable",
        };
    }

    public static ScreamEvolutionTelemetryDto ComputeTelemetry(
        ScreamFamilyIndexDto? index,
        int lineageBreedsQueued = 0,
        int decayApplied = 0)
    {
        if (index is null || index.Families.Count == 0)
            return new ScreamEvolutionTelemetryDto(0, 0, 0, 0, 0, lineageBreedsQueued, decayApplied);

        var families = index.Families;
        return new ScreamEvolutionTelemetryDto(
            families.Count,
            families.Count(f => f.MomentumLabel is "warming"),
            families.Count(f => f.MomentumLabel is "hot"),
            families.Count(f => f.MomentumLabel is "stagnant"),
            families.Count(f => f.MomentumLabel is "cooling"),
            lineageBreedsQueued,
            decayApplied);
    }

    public static IReadOnlyList<string>? BestLineageChain(string project, string? repoRoot = null)
    {
        var index = TryLoad(project, repoRoot);
        if (index is null)
            return null;

        return index.Families
            .Where(f => f.EffectiveMomentumScore >= MomentumWarmThreshold
                        && f.MomentumLabel is not "stagnant")
            .OrderByDescending(f => f.EffectiveMomentumScore)
            .Select(f => f.BestLineageChain)
            .FirstOrDefault(c => c is { Count: >= 2 });
    }
}
