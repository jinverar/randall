using System.Text.Json;
using Randall.Contracts;
using Randall.Infrastructure.Oracles;

namespace Randall.Infrastructure;

/// <summary>
/// Aggregates static/dynamic/frontier/crash/oracle stats into a persisted target profile.
/// Consumes on-disk artifacts only — does not re-run Ghidra or fuzz.
/// </summary>
public static class TargetIntelligenceBuilder
{
    public const string FileName = "target_intelligence.json";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
    };

    public static string ProfilePath(string project, string? repoRoot = null) =>
        Path.Combine(StalkCampaignStore.ProjectDir(project, repoRoot), FileName);

    public static TargetIntelligenceDto? TryLoad(string project, string? repoRoot = null)
    {
        var path = ProfilePath(project, repoRoot);
        if (!File.Exists(path))
            return null;
        try
        {
            return JsonSerializer.Deserialize<TargetIntelligenceDto>(File.ReadAllText(path), JsonOptions);
        }
        catch
        {
            return null;
        }
    }

    public static TargetIntelligenceDto Build(string project, string? repoRoot = null, bool persist = true)
    {
        if (string.IsNullOrWhiteSpace(project))
            throw new ArgumentException("project required");

        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();

        var analysis = GhidraAnalysisBridge.TryLoad(project, repoRoot);
        var frontier = FrontierEngine.TryLoad(project, repoRoot);
        var yaml = FindProjectYaml(repoRoot, project);
        ProjectConfig? cfg = null;
        if (yaml is not null)
        {
            try { cfg = ProjectLoader.Load(yaml); }
            catch { /* ignore */ }
        }

        var oracleFindings = LoadOracleFindings(project, repoRoot);
        var crashes = CrashCatalog.ListAll(repoRoot, project);
        var clusters = CrashCluster.Build(crashes, repoRoot);
        var campaigns = LoadRecentCampaigns(project, yaml, repoRoot, 5);

        var staticDto = BuildStatic(analysis);
        var dynamicDto = BuildDynamic(campaigns, crashes, oracleFindings);
        var frontierDto = BuildFrontier(frontier);
        var crashDto = BuildCrashStats(crashes, clusters);
        var oracleDto = BuildOracleStats(cfg, yaml, oracleFindings);

        var summary = BuildSummary(staticDto, frontierDto, crashDto, oracleDto, dynamicDto);
        var dto = new TargetIntelligenceDto(
            project,
            DateTime.UtcNow.ToString("o"),
            summary,
            staticDto,
            dynamicDto,
            frontierDto,
            crashDto,
            oracleDto,
            campaigns);

        if (persist)
        {
            var path = ProfilePath(project, repoRoot);
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, JsonSerializer.Serialize(dto, JsonOptions));
        }

        return dto;
    }

    public static StalkCommandStripDto BuildCommandStrip(string project, string? repoRoot = null)
    {
        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var analysis = GhidraAnalysisBridge.TryLoad(project, repoRoot);
        var frontier = FrontierEngine.TryLoad(project, repoRoot);
        var crashes = CrashCatalog.ListAll(repoRoot, project);

        double? coveragePct = analysis?.CoverageSummary?.CoverageFraction is { } frac
            ? Math.Round(frac * 100, 1)
            : null;
        var covered = analysis?.CoverageSummary?.CoveredBlocks;
        var total = analysis?.CoverageSummary?.TotalBlocks;
        var frontierCount = frontier?.FrontierCount ?? 0;

        var clusterKeys = crashes
            .Select(c => c.ClusterKey)
            .Where(k => !string.IsNullOrWhiteSpace(k))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var unique = clusterKeys.Count;
        var critical = crashes.Count(c =>
            string.Equals(c.Severity, "critical", StringComparison.OrdinalIgnoreCase));
        var ipCount = crashes.Count(c => c.IpLooksControlled);
        var moods = CanisterMoodScorer.CountMoods([(unique, critical, ipCount)]);

        var yaml = FindProjectYaml(repoRoot, project);
        var differential = false;
        if (yaml is not null)
        {
            try
            {
                var cfg = ProjectLoader.Load(yaml);
                differential = cfg.Oracles.Enabled && cfg.Oracles.Differential.Count > 0;
            }
            catch { /* ignore */ }
        }

        return new StalkCommandStripDto(
            coveragePct,
            covered,
            total,
            frontierCount,
            moods,
            differential);
    }

    private static TargetIntelligenceStaticDto? BuildStatic(RandallAnalysisDocument? analysis)
    {
        if (analysis is null)
            return null;

        var changed = analysis.ChangedFunctions ?? [];
        return new TargetIntelligenceStaticDto(
            analysis.Binary,
            analysis.CoverageSummary?.CoverageFraction is { } f ? Math.Round(f * 100, 1) : null,
            analysis.Functions.Count,
            changed.Count,
            changed
                .OrderByDescending(c => c.ChangeScore)
                .Take(6)
                .Select(c => new TargetIntelligenceChangedFunctionDto(
                    c.Name, c.Address, c.ChangeKind, c.ChangeScore))
                .ToList());
    }

    private static TargetIntelligenceDynamicDto? BuildDynamic(
        IReadOnlyList<TargetIntelligenceCampaignDto> campaigns,
        IReadOnlyList<CrashSummaryDto> crashes,
        IReadOnlyList<OracleFindingDto> findings)
    {
        if (campaigns.Count == 0 && findings.Count == 0 && crashes.Count == 0)
            return null;

        var last = campaigns.FirstOrDefault();
        var uniqueClusters = crashes
            .Select(c => c.ClusterKey)
            .Where(k => !string.IsNullOrWhiteSpace(k))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Count();

        return new TargetIntelligenceDynamicDto(
            campaigns.Sum(c => c.Iterations),
            campaigns.Sum(c => c.CrashesFound),
            uniqueClusters,
            findings.Count,
            last?.RunId,
            last?.StartedAt);
    }

    private static TargetIntelligenceFrontierDto? BuildFrontier(FrontierReportDto? frontier)
    {
        if (frontier is null || frontier.FrontierCount == 0)
            return null;

        var top = frontier.Frontiers.FirstOrDefault();
        var topLabel = top is null
            ? null
            : string.IsNullOrWhiteSpace(top.FunctionName)
                ? top.ToAddress
                : $"{top.FunctionName} → {top.ToAddress}";

        return new TargetIntelligenceFrontierDto(frontier.FrontierCount, frontier.Mode, topLabel);
    }

    private static TargetIntelligenceCrashDto? BuildCrashStats(
        IReadOnlyList<CrashSummaryDto> crashes,
        IReadOnlyList<CrashClusterSummary> clusters)
    {
        if (crashes.Count == 0)
            return null;

        var clusterKeys = crashes
            .Select(c => c.ClusterKey)
            .Where(k => !string.IsNullOrWhiteSpace(k))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var unique = clusterKeys.Count;
        var critical = crashes.Count(c =>
            string.Equals(c.Severity, "critical", StringComparison.OrdinalIgnoreCase));
        var ipCount = crashes.Count(c => c.IpLooksControlled);
        var moods = CanisterMoodScorer.CountMoods([(unique, critical, ipCount)]);
        var maxScream = crashes.Count == 0 ? 0 : crashes.Max(c => c.ScreamScore);

        return new TargetIntelligenceCrashDto(
            crashes.Count,
            clusters.Count,
            moods,
            maxScream);
    }

    private static TargetIntelligenceOracleDto? BuildOracleStats(
        ProjectConfig? cfg,
        string? yamlPath,
        IReadOnlyList<OracleFindingDto> findings)
    {
        var diffRules = new List<TargetIntelligenceDifferentialRuleDto>();
        var differentialEnabled = false;
        if (cfg?.Oracles.Enabled == true && cfg.Oracles.Differential.Count > 0)
        {
            differentialEnabled = true;
            foreach (var rule in cfg.Oracles.Differential)
            {
                var refPath = yamlPath is null
                    ? rule.ReferenceExecutable
                    : ProjectLoader.ResolvePath(yamlPath, rule.ReferenceExecutable);
                diffRules.Add(new TargetIntelligenceDifferentialRuleDto(
                    string.IsNullOrWhiteSpace(rule.Id) ? "differential.ref" : rule.Id,
                    rule.Type,
                    refPath,
                    File.Exists(refPath)));
            }
        }

        if (findings.Count == 0 && !differentialEnabled)
            return null;

        var violations = findings.Count(f =>
            f.Severity.Equals("violation", StringComparison.OrdinalIgnoreCase));

        return new TargetIntelligenceOracleDto(
            findings.Count,
            violations,
            differentialEnabled,
            diffRules);
    }

    private static string BuildSummary(
        TargetIntelligenceStaticDto? stat,
        TargetIntelligenceFrontierDto? frontier,
        TargetIntelligenceCrashDto? crashes,
        TargetIntelligenceOracleDto? oracles,
        TargetIntelligenceDynamicDto? dynamic)
    {
        var parts = new List<string>();
        if (stat?.CoveragePercent is { } pct)
            parts.Add($"{pct:0.#}% BB coverage");
        if (frontier?.Count > 0)
            parts.Add($"{frontier.Count} gray door(s)");
        if (stat?.ChangedFunctionCount > 0)
            parts.Add($"{stat.ChangedFunctionCount} changed fn(s)");
        if (crashes?.Total > 0)
            parts.Add($"{crashes.Total} crash(es) · {crashes.UniqueClusters} cluster(s)");
        if (oracles?.DifferentialEnabled == true)
            parts.Add("differential oracle armed");
        if (dynamic?.TotalIterations > 0)
            parts.Add($"{dynamic.TotalIterations} campaign iters");

        return parts.Count == 0
            ? "Target profile empty — export Ghidra map, run fuzz, then refresh."
            : string.Join(" · ", parts);
    }

    private static IReadOnlyList<TargetIntelligenceCampaignDto> LoadRecentCampaigns(
        string project,
        string? yamlPath,
        string repoRoot,
        int limit)
    {
        if (yamlPath is null)
            return [];

        try
        {
            var cfg = ProjectLoader.Load(yamlPath);
            var runsRoot = ProjectLoader.ResolvePath(yamlPath, cfg.Fuzz.RunsDir);
            if (!Directory.Exists(runsRoot))
                return [];

            var rows = new List<TargetIntelligenceCampaignDto>();
            foreach (var dir in Directory.EnumerateDirectories(runsRoot)
                         .Where(d => Path.GetFileName(d).StartsWith(project + "_", StringComparison.OrdinalIgnoreCase)))
            {
                var manifestPath = Path.Combine(dir, "run.json");
                if (!File.Exists(manifestPath))
                    continue;
                var manifest = JsonSerializer.Deserialize<FuzzRunManifestDto>(
                    File.ReadAllText(manifestPath), JsonOptions);
                if (manifest is null)
                    continue;
                rows.Add(new TargetIntelligenceCampaignDto(
                    manifest.RunId,
                    manifest.StartedAt,
                    manifest.Iterations,
                    manifest.CrashesFound,
                    manifest.StalkBackend));
            }

            return rows
                .OrderByDescending(r => r.StartedAt)
                .Take(limit)
                .ToList();
        }
        catch
        {
            return [];
        }
    }

    private static IReadOnlyList<OracleFindingDto> LoadOracleFindings(string project, string repoRoot)
    {
        var root = Path.Combine(repoRoot, "data", "crashes", project, "_oracles");
        if (!Directory.Exists(root))
            return [];
        return new OracleFindingStore(root).List(project);
    }

    private static string? FindProjectYaml(string repoRoot, string project)
    {
        var name = project.Trim();
        foreach (var candidate in new[]
                 {
                     Path.Combine(repoRoot, "projects", name + ".yaml"),
                     Path.Combine(repoRoot, "projects", name + ".yml"),
                     Path.Combine(repoRoot, "projects", "local", name + ".yaml"),
                 })
        {
            if (File.Exists(candidate))
                return candidate;
        }

        foreach (var path in ProjectLoader.DiscoverAll(repoRoot))
        {
            try
            {
                var p = ProjectLoader.Load(path);
                if (string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase))
                    return path;
            }
            catch
            {
                /* ignore */
            }
        }

        return null;
    }
}
