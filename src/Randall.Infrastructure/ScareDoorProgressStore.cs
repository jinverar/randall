using System.Text.Json;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Tracks hunt pressure on pinned Scare Doors — attempts, closest edge distance, best seed/mutator.
/// </summary>
public static class ScareDoorProgressStore
{
    public const string FileName = "scare_door_progress.json";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
    };

    public static string ProgressPath(string project, string? repoRoot = null) =>
        Path.Combine(StalkCampaignStore.ProjectDir(project, repoRoot), FileName);

    public static ScareDoorProgressReportDto? TryLoad(string project, string? repoRoot = null)
    {
        var path = ProgressPath(project, repoRoot);
        if (!File.Exists(path))
            return null;

        try
        {
            return JsonSerializer.Deserialize<ScareDoorProgressReportDto>(File.ReadAllText(path), JsonOptions);
        }
        catch
        {
            return null;
        }
    }

    public static void Save(ScareDoorProgressReportDto report, string? repoRoot = null)
    {
        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var path = ProgressPath(report.Project, repoRoot);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, JsonSerializer.Serialize(report, JsonOptions));
    }

    public static string? ResolveEdgeKey(BrainFocusDto focus, FrontierReportDto? frontier)
    {
        if (!focus.FocusKind.Equals("frontier", StringComparison.OrdinalIgnoreCase))
            return null;

        return ResolveBranch(focus, frontier)?.EdgeKey;
    }

    public static FrontierBranchDto? ResolveBranch(BrainFocusDto focus, FrontierReportDto? frontier)
    {
        if (frontier?.Frontiers is not { Count: > 0 })
            return null;

        if (!string.IsNullOrWhiteSpace(focus.Address))
        {
            var byAddr = frontier.Frontiers.FirstOrDefault(f =>
                f.ToAddress.Equals(focus.Address, StringComparison.OrdinalIgnoreCase));
            if (byAddr is not null)
                return byAddr;
        }

        return frontier.Frontiers.FirstOrDefault(f =>
            LabelFrontier(f).Equals(focus.FocusLabel, StringComparison.OrdinalIgnoreCase));
    }

    public static void EnsurePinnedDoor(
        string project,
        BrainFocusDto focus,
        FrontierReportDto? frontier,
        string? repoRoot = null)
    {
        if (!focus.FocusKind.Equals("frontier", StringComparison.OrdinalIgnoreCase))
            return;

        var edgeKey = ResolveEdgeKey(focus, frontier);
        if (string.IsNullOrWhiteSpace(edgeKey))
            return;

        var branch = ResolveBranch(focus, frontier);
        var report = TryLoad(project, repoRoot) ?? new ScareDoorProgressReportDto(
            project,
            DateTimeOffset.UtcNow,
            edgeKey,
            new Dictionary<string, ScareDoorBranchProgressDto>(StringComparer.OrdinalIgnoreCase));

        var doors = new Dictionary<string, ScareDoorBranchProgressDto>(
            report.Doors, StringComparer.OrdinalIgnoreCase);

        if (!doors.ContainsKey(edgeKey))
        {
            var initialDist = Math.Max(1, (int)Math.Round(branch?.CfgDistance ?? 1));
            doors[edgeKey] = new ScareDoorBranchProgressDto(
                edgeKey,
                InitialCfgDistance: initialDist,
                ClosestDistance: initialDist,
                StaticScore: branch?.Score ?? 0,
                UpdatedAt: DateTimeOffset.UtcNow);
        }

        Save(report with
        {
            PinnedEdgeKey = edgeKey,
            UpdatedAt = DateTimeOffset.UtcNow,
            Doors = doors,
        }, repoRoot);
    }

    public static void RecordPinnedIteration(
        string project,
        BrainFocusDto focus,
        FrontierReportDto? frontier,
        int iteration,
        string mutator,
        string? seedId,
        int newEdges,
        bool newCoverage,
        int coverageEdgeTotal,
        string? repoRoot = null)
    {
        _ = coverageEdgeTotal;
        if (!focus.FocusKind.Equals("frontier", StringComparison.OrdinalIgnoreCase))
            return;

        var edgeKey = ResolveEdgeKey(focus, frontier);
        if (string.IsNullOrWhiteSpace(edgeKey))
            return;

        var branch = ResolveBranch(focus, frontier);
        var report = TryLoad(project, repoRoot) ?? new ScareDoorProgressReportDto(
            project,
            DateTimeOffset.UtcNow,
            edgeKey,
            new Dictionary<string, ScareDoorBranchProgressDto>(StringComparer.OrdinalIgnoreCase));

        var doors = new Dictionary<string, ScareDoorBranchProgressDto>(
            report.Doors, StringComparer.OrdinalIgnoreCase);

        if (!doors.TryGetValue(edgeKey, out var door))
        {
            var initialDist = Math.Max(1, (int)Math.Round(branch?.CfgDistance ?? 1));
            door = new ScareDoorBranchProgressDto(
                edgeKey,
                InitialCfgDistance: initialDist,
                ClosestDistance: initialDist,
                StaticScore: branch?.Score ?? 0);
        }

        var attempts = door.Attempts + 1;
        var closest = door.ClosestDistance;
        string? lastProgress = door.LastProgress;
        var bestEdgeGain = door.BestEdgeGain;
        var bestMutation = door.BestMutation;
        var bestSeed = door.BestSeedId;

        if (newEdges > 0 || newCoverage)
        {
            if (newEdges > 0)
            {
                closest = Math.Max(0, closest - newEdges);
                lastProgress = $"+{newEdges} edge{(newEdges == 1 ? "" : "s")}";
            }
            else
            {
                lastProgress = "new coverage";
            }

            if (newEdges > bestEdgeGain || (newEdges == bestEdgeGain && newCoverage && bestMutation is null))
            {
                bestEdgeGain = Math.Max(bestEdgeGain, newEdges);
                bestMutation = mutator;
                bestSeed = seedId;
            }
        }

        var fraction = ComputeProgressFraction(closest, door.InitialCfgDistance, branch);
        doors[edgeKey] = door with
        {
            Attempts = attempts,
            ClosestDistance = closest,
            LastProgress = lastProgress,
            BestSeedId = bestSeed,
            BestMutation = bestMutation,
            BestEdgeGain = bestEdgeGain,
            StaticScore = door.StaticScore > 0 ? door.StaticScore : branch?.Score ?? 0,
            ProgressFraction = fraction,
            LastIteration = iteration,
            UpdatedAt = DateTimeOffset.UtcNow,
        };

        Save(report with
        {
            PinnedEdgeKey = edgeKey,
            UpdatedAt = DateTimeOffset.UtcNow,
            Doors = doors,
        }, repoRoot);
    }

    public static FrontierBranchDto EnrichBranch(
        FrontierBranchDto branch,
        ScareDoorBranchProgressDto? progress)
    {
        if (progress is null || (progress.Attempts <= 0 && progress.ProgressFraction <= 0))
            return branch;

        return branch with
        {
            Attempts = progress.Attempts,
            ClosestDistance = progress.ClosestDistance,
            LastProgress = progress.LastProgress,
            BestSeedId = progress.BestSeedId,
            BestMutation = progress.BestMutation,
            StaticScore = progress.StaticScore > 0 ? progress.StaticScore : branch.Score,
            ProgressFraction = progress.ProgressFraction,
        };
    }

    public static FrontierReportDto EnrichReport(FrontierReportDto report, string? repoRoot = null)
    {
        var progress = TryLoad(report.Project, repoRoot);
        if (progress?.Doors is not { Count: > 0 })
            return report;

        var enriched = report.Frontiers
            .Select(f => EnrichBranch(f, progress.Doors.GetValueOrDefault(f.EdgeKey)))
            .ToList();

        return report with { Frontiers = enriched };
    }

    public static StalkIntelligenceTargetDto EnrichTarget(
        StalkIntelligenceTargetDto target,
        ScareDoorBranchProgressDto? progress)
    {
        if (progress is null || (progress.Attempts <= 0 && progress.ProgressFraction <= 0))
            return target;

        return target with
        {
            Attempts = progress.Attempts,
            ClosestDistance = progress.ClosestDistance,
            LastProgress = progress.LastProgress,
            BestSeedId = progress.BestSeedId,
            BestMutation = progress.BestMutation,
            StaticScore = progress.StaticScore > 0 ? progress.StaticScore : target.Score,
            ProgressFraction = progress.ProgressFraction,
        };
    }

    internal static double ComputeProgressFraction(
        double closestDistance,
        int initialCfgDistance,
        FrontierBranchDto? branch)
    {
        var initial = initialCfgDistance > 0
            ? initialCfgDistance
            : Math.Max(1, (int)Math.Round(branch?.CfgDistance ?? 1));
        if (initial <= 0)
            return 0;

        var remaining = Math.Clamp(closestDistance, 0, initial);
        return Math.Clamp(1.0 - remaining / initial, 0, 1);
    }

    private static string LabelFrontier(FrontierBranchDto f)
    {
        if (!string.IsNullOrWhiteSpace(f.FunctionName))
            return $"{f.FunctionName} → {f.ToAddress}";
        return $"Unopened door → {f.ToAddress}";
    }
}
