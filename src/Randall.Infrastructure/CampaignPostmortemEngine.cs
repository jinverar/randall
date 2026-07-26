using System.Text.Json;
using System.Text.Json.Serialization;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Campaign / run postmortem — teaching narrative from iterations, crashes, corpus growth,
/// top mutators, barriers, scream families, and stop goals. Research only.
/// </summary>
public static class CampaignPostmortemEngine
{
    public const string LastFileName = "campaign_postmortem_last.json";

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter() },
    };

    public static string LastPath(string project, string? repoRoot = null) =>
        Path.Combine(StalkCampaignStore.ProjectDir(project, repoRoot), LastFileName);

    public static string RunPath(string project, string runId, string? repoRoot = null)
    {
        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        return Path.Combine(repoRoot, "data", "runs", Sanitize(project), $"{Sanitize(runId)}_postmortem.json");
    }

    public static CampaignPostmortemDto? TryRead(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            return null;
        try
        {
            return JsonSerializer.Deserialize<CampaignPostmortemDto>(File.ReadAllText(path), JsonOpts);
        }
        catch
        {
            return null;
        }
    }

    public static CampaignPostmortemDto? TryLoadLast(string project, string? repoRoot = null) =>
        TryRead(LastPath(project, repoRoot));

    public static CampaignPostmortemDto Build(CampaignPostmortemInput input, string? repoRoot = null)
    {
        if (string.IsNullOrWhiteSpace(input.Project))
            throw new ArgumentException("project required");

        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();

        var barriers = input.Barriers?.ToList()
                       ?? BarrierDiagnosisEngine.Diagnose(input.Project, repoRoot, persist: false).Barriers.ToList();

        var topMutators = (input.MutatorRows ?? [])
            .OrderByDescending(r => r.Score)
            .ThenByDescending(r => r.NewEdges)
            .Take(5)
            .Select(r => $"{r.Name} (score={r.Score:0}, edges={r.NewEdges}, uniq={r.UniqueCrashes})")
            .ToList();

        if (topMutators.Count == 0)
            topMutators = TryLoadTopMutatorsFromDisk(input.Project, repoRoot);

        var families = input.ScreamFamilies?.ToList() ?? TryLoadScreamFamilies(input.Project, repoRoot);
        var stopSummary = FormatStopGoals(input.StopGoals, input.StopReason);

        var whatWorked = new List<string>();
        var whatStalled = new List<string>();
        var packages = new List<string>();

        if (input.UniqueCrashes > 0)
        {
            whatWorked.Add($"{input.UniqueCrashes} unique crash(es) collected — triage/root-cause study material exists.");
            packages.Add(TeachingPackages.RootCauseStudy);
        }

        if (input.CorpusGrowth > 0)
        {
            whatWorked.Add($"Corpus grew by {input.CorpusGrowth} interesting input(s) — novelty feedback engaged.");
        }

        if (topMutators.Count > 0 && input.MutatorRows?.Any(r => r.NewEdges > 0 || r.UniqueCrashes > 0) == true)
        {
            whatWorked.Add($"Top mutator signal: {topMutators[0]}.");
        }

        if (families.Count > 0)
        {
            whatWorked.Add($"{families.Count} scream family key(s) observed — phenotype clustering available for teaching.");
            packages.Add(TeachingPackages.HypothesisFalsification);
        }

        if (input.StopGoals?.Met == true)
        {
            whatWorked.Add($"Stop goal met: {input.StopGoals.Reason ?? stopSummary ?? "goal satisfied"}.");
        }

        foreach (var b in barriers)
        {
            whatStalled.Add($"{b.Kind}: {b.Diagnosis}");
            packages.AddRange(MapBarrierToPackages(b.Kind));
        }

        if (input.UniqueCrashes == 0 && input.Iterations > 0)
            whatStalled.Add("No unique crashes this run — coverage/oracle barriers may dominate.");

        if (input.CorpusGrowth <= 0 && input.Iterations >= 50)
            whatStalled.Add("Corpus did not grow — novelty/frontier pressure was insufficient.");

        if (whatWorked.Count == 0)
            whatWorked.Add("Baseline session completed; capture more stalk/oracle artifacts for richer postmortems.");

        if (whatStalled.Count == 0)
            whatStalled.Add("No strong stall signals from barriers — continue research packages on existing crashes.");

        packages.Add(TeachingPackages.MitigationReview);
        packages.Add(TeachingPackages.NoWeaponization);
        var distinctPackages = packages.Distinct(StringComparer.OrdinalIgnoreCase).ToList();

        var narrative =
            $"Campaign postmortem for '{input.Project}'" +
            (string.IsNullOrWhiteSpace(input.RunId) ? "" : $" run '{input.RunId}'") +
            $": {input.Iterations} iteration(s), {input.UniqueCrashes} unique crash(es), " +
            $"corpus+{input.CorpusGrowth}, {barriers.Count} barrier(s), {families.Count} scream family key(s). " +
            (string.IsNullOrWhiteSpace(stopSummary) ? "" : stopSummary + " ") +
            "Teaching only — next steps are research packages, not weaponization.";

        return new CampaignPostmortemDto(
            true,
            input.Project,
            input.RunId,
            DateTimeOffset.UtcNow,
            input.Iterations,
            input.UniqueCrashes,
            input.CorpusGrowth,
            topMutators,
            barriers,
            families,
            stopSummary,
            narrative,
            whatWorked,
            whatStalled,
            distinctPackages);
    }

    /// <summary>Build + persist last + optional run-scoped JSON.</summary>
    public static CampaignPostmortemDto Persist(
        CampaignPostmortemInput input,
        string? repoRoot = null)
    {
        var report = Build(input, repoRoot);
        Write(report, repoRoot);
        return report;
    }

    public static string Write(CampaignPostmortemDto report, string? repoRoot = null)
    {
        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var last = LastPath(report.Project, repoRoot);
        var lastDir = Path.GetDirectoryName(last);
        if (!string.IsNullOrEmpty(lastDir))
            Directory.CreateDirectory(lastDir);
        File.WriteAllText(last, JsonSerializer.Serialize(report, JsonOpts));

        if (!string.IsNullOrWhiteSpace(report.RunId))
        {
            var runPath = RunPath(report.Project, report.RunId, repoRoot);
            var runDir = Path.GetDirectoryName(runPath);
            if (!string.IsNullOrEmpty(runDir))
                Directory.CreateDirectory(runDir);
            File.WriteAllText(runPath, JsonSerializer.Serialize(report, JsonOpts));
            return runPath;
        }

        return last;
    }

    private static IReadOnlyList<string> MapBarrierToPackages(BarrierKind kind) =>
        kind switch
        {
            BarrierKind.EmptyFrontier => [TeachingPackages.RootCauseStudy],
            BarrierKind.FlatMutatorCredit => [TeachingPackages.HypothesisFalsification],
            BarrierKind.StagnantCoverage => [TeachingPackages.InfluenceAttribution],
            BarrierKind.QuietOracle => [TeachingPackages.HypothesisFalsification],
            BarrierKind.ThinDictionary => [TeachingPackages.BoundsStudy],
            BarrierKind.QuietBrain => [TeachingPackages.RootCauseStudy],
            _ => [],
        };

    private static string? FormatStopGoals(IntelligenceStopGoalProgressDto? progress, string? stopReason)
    {
        if (!string.IsNullOrWhiteSpace(stopReason))
            return $"Stop: {stopReason}";
        if (progress is null)
            return null;
        if (progress.Met)
            return $"Stop goals met: {progress.Reason ?? "threshold reached"}";
        if (progress.Items.Count == 0)
            return "Stop goals: none configured / not evaluated";
        var parts = progress.Items.Select(i => $"{i.Label} {i.Current}/{i.Needed}");
        return "Stop goals progress: " + string.Join(", ", parts);
    }

    private static List<string> TryLoadTopMutatorsFromDisk(string project, string repoRoot)
    {
        try
        {
            var path = Path.Combine(repoRoot, "data", "corpus", Sanitize(project), "mutator_credit.txt");
            if (!File.Exists(path))
                return [];
            var rows = new MutatorCreditTracker(path, biasEnabled: false).SnapshotRows();
            return rows.OrderByDescending(r => r.Score).Take(5)
                .Select(r => $"{r.Name} (score={r.Score:0})")
                .ToList();
        }
        catch
        {
            return [];
        }
    }

    private static List<string> TryLoadScreamFamilies(string project, string repoRoot)
    {
        try
        {
            var crashesDir = Path.Combine(repoRoot, "data", "crashes", Sanitize(project));
            var registryPath = Path.Combine(crashesDir, "_deep_scream_families.json");
            if (File.Exists(registryPath))
            {
                var raw = JsonSerializer.Deserialize<Dictionary<string, DeepScreamFamilyEntryDto>>(
                    File.ReadAllText(registryPath), JsonOpts);
                if (raw is { Count: > 0 })
                    return raw.Keys.OrderBy(k => k, StringComparer.OrdinalIgnoreCase).Take(20).ToList();
            }

            // Soft fallback: evolution sidecars with FamilyId.
            if (!Directory.Exists(crashesDir))
                return [];

            var families = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var file in Directory.EnumerateFiles(crashesDir, "*_scream_evolution.json").Take(40))
            {
                try
                {
                    using var doc = JsonDocument.Parse(File.ReadAllText(file));
                    if (doc.RootElement.TryGetProperty("familyId", out var fid)
                        || doc.RootElement.TryGetProperty("FamilyId", out fid))
                    {
                        var s = fid.GetString();
                        if (!string.IsNullOrWhiteSpace(s))
                            families.Add(s);
                    }
                }
                catch
                {
                    /* skip */
                }
            }

            return families.OrderBy(f => f, StringComparer.OrdinalIgnoreCase).Take(20).ToList();
        }
        catch
        {
            return [];
        }
    }

    private static string Sanitize(string value)
    {
        var invalid = Path.GetInvalidFileNameChars();
        var chars = value.Trim().Select(c => invalid.Contains(c) ? '_' : c).ToArray();
        return new string(chars);
    }
}
