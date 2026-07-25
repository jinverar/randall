using System.Collections.Concurrent;
using System.Text.Json;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Event-driven write-back for target intelligence — refreshes profiles and appends hunt journal
/// after fuzz runs, frontier saves, oracle findings, and RPP observe hooks.
/// RandallBrain and future planners subscribe via <see cref="ProfileRefreshed"/> without owning the file.
/// </summary>
public static class TargetIntelligenceWriteBack
{
    public const string HuntJournalFileName = "hunt_journal.jsonl";
    public const string CountersFileName = "intel_counters.json";
    public const int DefaultJournalLimit = 200;

    private static readonly ConcurrentDictionary<string, long> LastOracleRefreshTicks = new();

    private const int OracleRefreshThrottleMs = 30_000;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
    };

    private static readonly JsonSerializerOptions JournalOptions = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    /// <summary>Raised after <c>target_intelligence.json</c> is rebuilt and persisted.</summary>
    public static event Action<TargetIntelligenceDto>? ProfileRefreshed;

    public static string HuntJournalPath(string project, string? repoRoot = null) =>
        Path.Combine(StalkCampaignStore.ProjectDir(project, repoRoot), HuntJournalFileName);

    public static string CountersPath(string project, string? repoRoot = null) =>
        Path.Combine(StalkCampaignStore.ProjectDir(project, repoRoot), CountersFileName);

    public static TargetIntelligenceCountersDto LoadCounters(string project, string? repoRoot = null)
    {
        var path = CountersPath(project, repoRoot);
        if (!File.Exists(path))
            return new TargetIntelligenceCountersDto(0, 0, null, null, null, CountJournalEntries(project, repoRoot));

        try
        {
            var dto = JsonSerializer.Deserialize<TargetIntelligenceCountersDto>(File.ReadAllText(path), JsonOptions);
            return dto ?? EmptyCounters(project, repoRoot);
        }
        catch
        {
            return EmptyCounters(project, repoRoot);
        }
    }

    public static void SaveCounters(string project, TargetIntelligenceCountersDto counters, string? repoRoot = null)
    {
        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var path = CountersPath(project, repoRoot);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, JsonSerializer.Serialize(counters, JsonOptions));
    }

    /// <summary>Full profile rebuild + journal line. Safe to call from finally blocks.</summary>
    public static TargetIntelligenceDto Refresh(
        string project,
        string source,
        string summary,
        string? runId = null,
        IReadOnlyDictionary<string, object?>? data = null,
        string? repoRoot = null)
    {
        if (string.IsNullOrWhiteSpace(project))
            throw new ArgumentException("project required");

        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();

        var counters = LoadCounters(project, repoRoot) with
        {
            LastRefreshSource = source,
            HuntJournalEntries = CountJournalEntries(project, repoRoot),
        };
        SaveCounters(project, counters, repoRoot);

        AppendJournal(project, new HuntJournalEntry(
            DateTime.UtcNow.ToString("o"),
            source,
            summary,
            runId,
            data), repoRoot);

        var profile = TargetIntelligenceBuilder.Build(project, repoRoot, persist: true);
        try { ProfileRefreshed?.Invoke(profile); }
        catch { /* subscriber fault must not break write-back */ }

        return profile;
    }

    /// <summary>Record a planner/brain decision without forcing a full profile rebuild.</summary>
    public static void RecordBrainDecision(
        string project,
        string decision,
        string summary,
        IReadOnlyDictionary<string, object?>? data = null,
        string? repoRoot = null)
    {
        if (string.IsNullOrWhiteSpace(project))
            return;

        var payload = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
        {
            ["decision"] = decision,
        };
        if (data is not null)
        {
            foreach (var kv in data)
                payload[kv.Key] = kv.Value;
        }

        AppendJournal(project, new HuntJournalEntry(
            DateTime.UtcNow.ToString("o"),
            "brain",
            summary,
            null,
            payload), repoRoot);
    }

    /// <summary>After fuzz completes — merge bus snapshot counts and refresh profile.</summary>
    public static void OnFuzzComplete(
        string project,
        string runId,
        int iterations,
        int crashes,
        int corpusAdded,
        IReadOnlyList<Observation> busSnapshot,
        string? repoRoot = null)
    {
        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var counters = LoadCounters(project, repoRoot);
        counters = counters with
        {
            BusObservationCount = counters.BusObservationCount + busSnapshot.Count,
            HuntJournalEntries = CountJournalEntries(project, repoRoot),
        };
        SaveCounters(project, counters, repoRoot);

        var byKind = busSnapshot
            .GroupBy(o => o.Type)
            .ToDictionary(g => g.Key.ToString(), g => (object?)g.Count(), StringComparer.OrdinalIgnoreCase);

        Refresh(
            project,
            "fuzz-complete",
            $"{iterations} iters · {crashes} crash(es) · corpus+{corpusAdded} · bus={busSnapshot.Count}",
            runId,
            byKind,
            repoRoot);
    }

    /// <summary>After frontier.json is saved.</summary>
    public static void OnFrontierSaved(FrontierReportDto report, string? repoRoot = null)
    {
        Refresh(
            report.Project,
            "frontier-refresh",
            $"{report.FrontierCount} gray door(s) [{report.Mode}]",
            null,
            new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
            {
                ["frontierCount"] = report.FrontierCount,
                ["mode"] = report.Mode,
                ["coverageBlocks"] = report.CoverageBlockCount,
            },
            repoRoot);
    }

    /// <summary>After oracle findings are persisted to disk.</summary>
    public static void OnOracleFindings(
        string project,
        int newFindingCount,
        string? topRuleId = null,
        string? repoRoot = null)
    {
        if (newFindingCount <= 0)
            return;

        var summary = $"+{newFindingCount} oracle finding(s)" +
                      (string.IsNullOrWhiteSpace(topRuleId) ? "" : $" · top={topRuleId}");
        var data = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
        {
            ["newFindings"] = newFindingCount,
            ["topRule"] = topRuleId,
        };

        var now = Environment.TickCount64;
        if (LastOracleRefreshTicks.TryGetValue(project, out var last) && now - last < OracleRefreshThrottleMs)
        {
            AppendJournal(project, new HuntJournalEntry(
                DateTime.UtcNow.ToString("o"),
                "oracle-finding",
                summary,
                null,
                data), repoRoot);
            return;
        }

        LastOracleRefreshTicks[project] = now;
        Refresh(project, "oracle-finding", summary, null, data, repoRoot);
    }

    /// <summary>RPP observe hook — always publishes to bus; bumps counters and journals significant signals.</summary>
    public static void OnRppObservation(
        string project,
        string pluginName,
        Observation observation,
        string? repoRoot = null)
    {
        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var counters = LoadCounters(project, repoRoot);
        counters = counters with
        {
            RppObservationCount = counters.RppObservationCount + 1,
            LastRppAt = DateTime.UtcNow.ToString("o"),
            LastRppPlugin = pluginName,
        };
        SaveCounters(project, counters, repoRoot);

        if (!ShouldJournalObservation(observation))
            return;

        AppendJournal(project, new HuntJournalEntry(
            DateTime.UtcNow.ToString("o"),
            "rpp-observe",
            $"{pluginName}: {observation.Severity} · {SummarizeObservation(observation)}",
            observation.RunId,
            new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
            {
                ["plugin"] = pluginName,
                ["kind"] = observation.Type.ToString(),
                ["severity"] = observation.Severity,
                ["confidence"] = observation.Confidence,
                ["iteration"] = observation.Iteration,
            }), repoRoot);
    }

    public static IReadOnlyList<HuntJournalEntry> ReadJournalTail(string project, int limit = 10, string? repoRoot = null)
    {
        var path = HuntJournalPath(project, repoRoot);
        if (!File.Exists(path) || limit <= 0)
            return [];

        try
        {
            var lines = File.ReadAllLines(path);
            var entries = new List<HuntJournalEntry>();
            foreach (var line in lines.Reverse().Take(limit))
            {
                if (string.IsNullOrWhiteSpace(line))
                    continue;
                try
                {
                    var entry = JsonSerializer.Deserialize<HuntJournalEntry>(line, JournalOptions);
                    if (entry is not null)
                        entries.Add(entry);
                }
                catch
                {
                    /* skip malformed line */
                }
            }

            entries.Reverse();
            return entries;
        }
        catch
        {
            return [];
        }
    }

    public static void AppendJournal(
        string project,
        HuntJournalEntry entry,
        string? repoRoot = null,
        int maxEntries = DefaultJournalLimit)
    {
        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var path = HuntJournalPath(project, repoRoot);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);

        var line = JsonSerializer.Serialize(entry, JournalOptions);
        File.AppendAllText(path, line + Environment.NewLine);

        TrimJournal(path, maxEntries);

        var counters = LoadCounters(project, repoRoot) with
        {
            HuntJournalEntries = CountJournalEntries(project, repoRoot),
        };
        SaveCounters(project, counters, repoRoot);
    }

    private static void TrimJournal(string path, int maxEntries)
    {
        if (maxEntries <= 0 || !File.Exists(path))
            return;

        try
        {
            var lines = File.ReadAllLines(path)
                .Where(l => !string.IsNullOrWhiteSpace(l))
                .ToList();
            if (lines.Count <= maxEntries)
                return;

            File.WriteAllText(path, string.Join(Environment.NewLine, lines.Skip(lines.Count - maxEntries)) + Environment.NewLine);
        }
        catch
        {
            /* best-effort trim */
        }
    }

    private static int CountJournalEntries(string project, string? repoRoot)
    {
        var path = HuntJournalPath(project, repoRoot);
        if (!File.Exists(path))
            return 0;
        try
        {
            return File.ReadLines(path).Count(l => !string.IsNullOrWhiteSpace(l));
        }
        catch
        {
            return 0;
        }
    }

    private static TargetIntelligenceCountersDto EmptyCounters(string project, string? repoRoot) =>
        new(0, 0, null, null, null, CountJournalEntries(project, repoRoot));

    private static bool ShouldJournalObservation(Observation observation) =>
        observation.Confidence >= 0.55
        || observation.Novelty >= 0.7
        || observation.Severity is "critical" or "high" or "runtime" or "violation";

    private static string SummarizeObservation(Observation observation)
    {
        if (observation.Data.TryGetValue("summary", out var s) && s is string text && !string.IsNullOrWhiteSpace(text))
            return text.Length <= 80 ? text : text[..77] + "…";
        return $"iter #{observation.Iteration}";
    }
}
