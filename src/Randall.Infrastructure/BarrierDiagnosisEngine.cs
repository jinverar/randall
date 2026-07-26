using System.Text.Json;
using System.Text.Json.Serialization;
using Randall.Contracts;
using Randall.Infrastructure.Oracles;

namespace Randall.Infrastructure;

/// <summary>
/// "Why haven't I found it?" barrier diagnosis — reads frontier, mutator credit, brain,
/// corpus/coverage heuristics, oracle findings, and dictionary thickness.
/// Teaching/research only; soft-fails when artifacts are missing.
/// </summary>
public static class BarrierDiagnosisEngine
{
    public const string FileName = "barrier_diagnosis.json";

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter() },
    };

    public static string StalkPath(string project, string? repoRoot = null) =>
        Path.Combine(StalkCampaignStore.ProjectDir(project, repoRoot), FileName);

    public static string CrashesPath(string project, string? repoRoot = null)
    {
        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        return Path.Combine(repoRoot, "data", "crashes", Sanitize(project), FileName);
    }

    public static BarrierReportDto? TryRead(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            return null;
        try
        {
            return JsonSerializer.Deserialize<BarrierReportDto>(File.ReadAllText(path), JsonOpts);
        }
        catch
        {
            return null;
        }
    }

    public static BarrierReportDto? TryLoad(string project, string? repoRoot = null)
    {
        var stalk = TryRead(StalkPath(project, repoRoot));
        if (stalk is not null)
            return stalk;
        return TryRead(CrashesPath(project, repoRoot));
    }

    /// <summary>
    /// Diagnose barriers from on-disk campaign signals. Prefer stalk persist path.
    /// </summary>
    public static BarrierReportDto Diagnose(
        string project,
        string? repoRoot = null,
        bool persist = true,
        int minIterationsHint = 50)
    {
        if (string.IsNullOrWhiteSpace(project))
            throw new ArgumentException("project required");

        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var signals = new List<string>();
        var barriers = new List<BarrierItemDto>();

        DiagnoseFrontier(project, repoRoot, barriers, signals);
        DiagnoseMutatorCredit(project, repoRoot, barriers, signals, minIterationsHint);
        DiagnoseCoverage(project, repoRoot, barriers, signals);
        DiagnoseOracle(project, repoRoot, barriers, signals, minIterationsHint);
        DiagnoseDictionary(project, repoRoot, barriers, signals);
        DiagnoseBrain(project, repoRoot, barriers, signals);

        var summary = barriers.Count == 0
            ? "No strong barriers detected from available signals — keep stalking; soft-fail artifacts may still be missing."
            : $"{barriers.Count} barrier(s): " +
              string.Join("; ", barriers.Select(b => $"{b.Kind}[{b.Severity}]"));

        var report = new BarrierReportDto(
            true,
            project,
            DateTimeOffset.UtcNow,
            summary,
            barriers,
            signals.Distinct(StringComparer.OrdinalIgnoreCase).ToList());

        if (persist)
            Write(report, repoRoot);

        return report;
    }

    /// <summary>
    /// Build from explicit in-memory signals (unit tests / FuzzEngine hook later). Soft-fail friendly.
    /// </summary>
    public static BarrierReportDto BuildFromSignals(
        string project,
        FrontierReportDto? frontier = null,
        IReadOnlyList<MutatorCreditRowDto>? mutatorRows = null,
        NextHuntDecision? brain = null,
        int corpusFileCount = -1,
        int coverageEdgeCount = -1,
        int oracleFindingCount = -1,
        int dictionaryTokenCount = -1,
        int iterations = 0)
    {
        var barriers = new List<BarrierItemDto>();
        var signals = new List<string>();

        if (frontier is not null)
        {
            signals.Add("frontier:in-memory");
            if (IsEmptyFrontier(frontier))
                barriers.Add(EmptyFrontierBarrier(frontier));
        }
        else
            signals.Add("frontier:missing");

        if (mutatorRows is not null)
        {
            signals.Add($"mutator-credit:rows={mutatorRows.Count}");
            if (IsFlatCredit(mutatorRows, iterations))
                barriers.Add(FlatCreditBarrier(mutatorRows));
        }
        else
            signals.Add("mutator-credit:missing");

        if (coverageEdgeCount >= 0 || corpusFileCount >= 0)
        {
            signals.Add($"coverage:edges={coverageEdgeCount};corpusFiles={corpusFileCount}");
            if (IsStagnant(coverageEdgeCount, corpusFileCount, iterations))
                barriers.Add(StagnantBarrier(coverageEdgeCount, corpusFileCount));
        }
        else
            signals.Add("coverage:missing");

        if (oracleFindingCount >= 0)
        {
            signals.Add($"oracle:findings={oracleFindingCount}");
            if (oracleFindingCount == 0 && iterations >= 50)
                barriers.Add(QuietOracleBarrier(oracleFindingCount, iterations));
        }
        else
            signals.Add("oracle:missing");

        if (dictionaryTokenCount >= 0)
        {
            signals.Add($"dictionary:tokens={dictionaryTokenCount}");
            if (dictionaryTokenCount < 8)
                barriers.Add(ThinDictionaryBarrier(dictionaryTokenCount));
        }
        else
            signals.Add("dictionary:missing");

        if (brain is not null)
        {
            signals.Add($"brain:active={brain.Active};focus={brain.FocusKind}");
            if (!brain.Active)
                barriers.Add(QuietBrainBarrier());
        }
        else
            signals.Add("brain:missing");

        var summary = barriers.Count == 0
            ? "No strong barriers detected from provided signals."
            : $"{barriers.Count} barrier(s): " +
              string.Join("; ", barriers.Select(b => $"{b.Kind}[{b.Severity}]"));

        return new BarrierReportDto(
            true,
            project,
            DateTimeOffset.UtcNow,
            summary,
            barriers,
            signals);
    }

    public static string Write(BarrierReportDto report, string? repoRoot = null)
    {
        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var path = StalkPath(report.Project, repoRoot);
        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir))
            Directory.CreateDirectory(dir);
        File.WriteAllText(path, JsonSerializer.Serialize(report, JsonOpts));

        // Mirror under crashes for operators who only browse crash dirs.
        try
        {
            var crashPath = CrashesPath(report.Project, repoRoot);
            var crashDir = Path.GetDirectoryName(crashPath);
            if (!string.IsNullOrEmpty(crashDir))
                Directory.CreateDirectory(crashDir);
            File.WriteAllText(crashPath, JsonSerializer.Serialize(report, JsonOpts));
        }
        catch
        {
            /* soft-fail mirror */
        }

        return path;
    }

    private static void DiagnoseFrontier(
        string project, string repoRoot, List<BarrierItemDto> barriers, List<string> signals)
    {
        try
        {
            var frontier = FrontierEngine.TryLoad(project, repoRoot);
            if (frontier is null)
            {
                signals.Add("frontier:missing");
                return;
            }

            signals.Add($"frontier:mode={frontier.Mode};count={frontier.FrontierCount}");
            if (IsEmptyFrontier(frontier))
                barriers.Add(EmptyFrontierBarrier(frontier));
        }
        catch
        {
            signals.Add("frontier:error");
        }
    }

    private static void DiagnoseMutatorCredit(
        string project, string repoRoot, List<BarrierItemDto> barriers, List<string> signals, int minIterationsHint)
    {
        try
        {
            var path = Path.Combine(repoRoot, "data", "corpus", Sanitize(project), "mutator_credit.txt");
            if (!File.Exists(path))
            {
                // Also peek run-scoped mutator_stats.json under data/runs/<project>/
                var runRows = TryLoadLatestRunMutatorRows(project, repoRoot);
                if (runRows is null)
                {
                    signals.Add("mutator-credit:missing");
                    return;
                }

                signals.Add($"mutator-credit:run-json;rows={runRows.Count}");
                if (IsFlatCredit(runRows, minIterationsHint))
                    barriers.Add(FlatCreditBarrier(runRows));
                return;
            }

            var tracker = new MutatorCreditTracker(path, biasEnabled: false);
            var rows = tracker.SnapshotRows();
            signals.Add($"mutator-credit:file;rows={rows.Count}");
            var totalRuns = rows.Sum(r => r.Runs);
            if (IsFlatCredit(rows, totalRuns))
                barriers.Add(FlatCreditBarrier(rows));
        }
        catch
        {
            signals.Add("mutator-credit:error");
        }
    }

    private static void DiagnoseCoverage(
        string project, string repoRoot, List<BarrierItemDto> barriers, List<string> signals)
    {
        try
        {
            var corpusDir = Path.Combine(repoRoot, "data", "corpus", Sanitize(project));
            var stalkDir = StalkCampaignStore.ProjectDir(project, repoRoot);
            var edgeCount = 0;
            var edgesPath = Path.Combine(corpusDir, "edges.txt");
            if (File.Exists(edgesPath))
                edgeCount = CountNonEmptyLines(edgesPath);

            var stalkEdges = Path.Combine(stalkDir, "coverage_edges.txt");
            if (edgeCount == 0 && File.Exists(stalkEdges))
                edgeCount = CountNonEmptyLines(stalkEdges);

            var corpusFiles = Directory.Exists(corpusDir)
                ? Directory.EnumerateFiles(corpusDir, "priority_*.bin").Count()
                : 0;
            var layers = StalkCampaignStore.ListLayers(project, repoRoot);
            signals.Add($"coverage:edges={edgeCount};corpusFiles={corpusFiles};layers={layers.Count}");

            // Stagnant when we have layers but no edge growth, or corpus empty after activity.
            if (layers.Count >= 2 && edgeCount <= 1)
                barriers.Add(StagnantBarrier(edgeCount, corpusFiles));
            else if (corpusFiles == 0 && edgeCount == 0 && layers.Count == 0)
            {
                // Not enough signal to call stagnant — leave quiet; brain/frontier cover cold start.
            }
            else if (corpusFiles == 0 && edgeCount <= 1 && layers.Count >= 1)
                barriers.Add(StagnantBarrier(edgeCount, corpusFiles));
        }
        catch
        {
            signals.Add("coverage:error");
        }
    }

    private static void DiagnoseOracle(
        string project, string repoRoot, List<BarrierItemDto> barriers, List<string> signals, int minIterationsHint)
    {
        try
        {
            var root = Path.Combine(repoRoot, "data", "crashes", Sanitize(project), "_oracles");
            if (!Directory.Exists(root))
            {
                signals.Add("oracle:missing");
                return;
            }

            var findings = new OracleFindingStore(root).List(project);
            signals.Add($"oracle:findings={findings.Count}");
            if (findings.Count == 0)
                barriers.Add(QuietOracleBarrier(0, minIterationsHint));
        }
        catch
        {
            signals.Add("oracle:error");
        }
    }

    private static void DiagnoseDictionary(
        string project, string repoRoot, List<BarrierItemDto> barriers, List<string> signals)
    {
        try
        {
            var candidates = new[]
            {
                Path.Combine(repoRoot, "data", "corpus", Sanitize(project), "dictionary.txt"),
                Path.Combine(repoRoot, "dictionaries", Sanitize(project) + ".txt"),
                Path.Combine(repoRoot, "projects", "dictionaries", Sanitize(project) + ".txt"),
            };

            string? found = null;
            foreach (var c in candidates)
            {
                if (File.Exists(c))
                {
                    found = c;
                    break;
                }
            }

            // Soft scan projects/*.yaml sibling dictionaries is out of scope — count tokens if found.
            if (found is null)
            {
                signals.Add("dictionary:missing");
                barriers.Add(ThinDictionaryBarrier(0));
                return;
            }

            var tokens = CountNonEmptyLines(found);
            signals.Add($"dictionary:path={Path.GetFileName(found)};tokens={tokens}");
            if (tokens < 8)
                barriers.Add(ThinDictionaryBarrier(tokens));
        }
        catch
        {
            signals.Add("dictionary:error");
        }
    }

    private static void DiagnoseBrain(
        string project, string repoRoot, List<BarrierItemDto> barriers, List<string> signals)
    {
        try
        {
            var path = RandallBrain.LastDecisionPath(project, repoRoot);
            if (!File.Exists(path))
            {
                signals.Add("brain:missing");
                return;
            }

            var json = File.ReadAllText(path);
            signals.Add("brain:brain_last.json");
            // Soft parse: look for "active": false without hard dependency on snapshot shape.
            if (json.Contains("\"active\":false", StringComparison.OrdinalIgnoreCase)
                || json.Contains("\"active\": false", StringComparison.OrdinalIgnoreCase))
            {
                barriers.Add(QuietBrainBarrier());
            }
        }
        catch
        {
            signals.Add("brain:error");
        }
    }

    internal static bool IsEmptyFrontier(FrontierReportDto frontier) =>
        frontier.FrontierCount <= 0
        || string.Equals(frontier.Mode, "empty", StringComparison.OrdinalIgnoreCase)
        || frontier.Frontiers.Count == 0;

    internal static bool IsFlatCredit(IReadOnlyList<MutatorCreditRowDto> rows, int iterationsHint)
    {
        if (rows.Count == 0)
            return iterationsHint >= 20;
        var totalRuns = rows.Sum(r => r.Runs);
        if (totalRuns < 20)
            return false;
        var scores = rows.Select(r => r.Score).ToList();
        var max = scores.Max();
        var min = scores.Min();
        // Flat when every mutator sits near the floor and max score is tiny relative to runs.
        if (max <= 0)
            return true;
        if (max < 10 && rows.All(r => r.NewEdges == 0 && r.UniqueCrashes == 0))
            return true;
        // Low variance: top and bottom nearly identical after many runs.
        return max > 0 && (max - min) / Math.Max(1.0, max) < 0.05 && rows.All(r => r.NewEdges == 0);
    }

    internal static bool IsStagnant(int coverageEdgeCount, int corpusFileCount, int iterations) =>
        iterations >= 50 && coverageEdgeCount <= 1 && corpusFileCount <= 0
        || coverageEdgeCount <= 1 && corpusFileCount == 0 && iterations >= 20;

    private static BarrierItemDto EmptyFrontierBarrier(FrontierReportDto frontier) =>
        new(
            "barrier-empty-frontier",
            BarrierKind.EmptyFrontier,
            "high",
            $"Frontier is empty (mode={frontier.Mode}, count={frontier.FrontierCount}). No scored gray doors to bias seeds toward.",
            [
                "Run stalk frontier after importing Ghidra analysis or coverage layers.",
                "Import a baseline coverage layer (drcov / edges) so CFG gray doors can score.",
                "Review Scare Floor missed-blocks guidance for teaching targets to open next.",
            ]);

    private static BarrierItemDto FlatCreditBarrier(IReadOnlyList<MutatorCreditRowDto> rows) =>
        new(
            "barrier-flat-mutator-credit",
            BarrierKind.FlatMutatorCredit,
            "medium",
            rows.Count == 0
                ? "Mutator credit has no productive differentiation yet (no rows / zero scores)."
                : $"Mutator credit is flat across {rows.Count} mutator(s) — no edges or unique crashes credited.",
            [
                "Enable mutator credit bias and re-check the leaderboard after a short stalk bench.",
                "Widen the mutator army (havoc / interesting / dictionary / splice) for teaching contrast.",
                "Study Hunt Policy lineage-breed vs havoc-explore modes when credit stays flat.",
            ]);

    private static BarrierItemDto StagnantBarrier(int edges, int corpusFiles) =>
        new(
            "barrier-stagnant-coverage",
            BarrierKind.StagnantCoverage,
            "high",
            $"Coverage/corpus novelty looks stagnant (edges={edges}, priority corpus files={corpusFiles}).",
            [
                "Compare stalk layers (baseline → fuzzed → fuzzier) for teaching novelty deltas.",
                "Seed the corpus with recipe-catalog starters for the target class.",
                "Install DynamoRIO (or use corpus-novelty feedback) and re-run stalk bench --scale 1.",
            ]);

    private static BarrierItemDto QuietOracleBarrier(int findings, int iterations) =>
        new(
            "barrier-quiet-oracle",
            BarrierKind.QuietOracle,
            "medium",
            $"Oracle is quiet ({findings} finding(s); iterations hint={iterations}). Logic/auth/state bugs may be invisible to coverage alone.",
            [
                "Arm oracle packs (auth / state / invariant) for memory-safe teaching targets.",
                "Compile ASSERT-style security invariants into OracleNeed descriptors.",
                "Review docs/ORACLES.md and add expect/forbid substring rules for the protocol under study.",
            ]);

    private static BarrierItemDto ThinDictionaryBarrier(int tokens) =>
        new(
            "barrier-thin-dictionary",
            BarrierKind.ThinDictionary,
            tokens == 0 ? "high" : "medium",
            $"Dictionary is thin ({tokens} token(s)). Protocol/format tokens are under-supplied for teaching mutations.",
            [
                "Instantiate a Case Builder recipe to mint a class dictionary + starter seed.",
                "Pull hot strings from Stalk Map / Ghidra surface analysis into the dictionary.",
                "Enable the dictionary mutator and Magician dictionary needs when Oracle asks.",
            ]);

    private static BarrierItemDto QuietBrainBarrier() =>
        new(
            "barrier-quiet-brain",
            BarrierKind.QuietBrain,
            "low",
            "RandallBrain last decision is inactive — closed-loop hunt steering has no stalk/oracle/scream signals yet.",
            [
                "Run stalk frontier + import static analysis so brain focus kinds can activate.",
                "Keep fuzz.brain enabled (default) and re-check data/stalk/<project>/brain_last.json.",
                "Study NextHuntDecision WhyTerms after a short coverage-guided session.",
            ]);

    private static IReadOnlyList<MutatorCreditRowDto>? TryLoadLatestRunMutatorRows(string project, string repoRoot)
    {
        var runsDir = Path.Combine(repoRoot, "data", "runs", Sanitize(project));
        if (!Directory.Exists(runsDir))
            return null;

        var stats = Directory.EnumerateFiles(runsDir, "mutator_stats.json", SearchOption.AllDirectories)
            .OrderByDescending(File.GetLastWriteTimeUtc)
            .FirstOrDefault();
        if (stats is null)
            return null;

        try
        {
            var dto = JsonSerializer.Deserialize<MutatorCreditRunDto>(File.ReadAllText(stats), JsonOpts);
            return dto?.Mutators;
        }
        catch
        {
            return null;
        }
    }

    private static int CountNonEmptyLines(string path)
    {
        var n = 0;
        foreach (var line in File.ReadLines(path))
        {
            if (!string.IsNullOrWhiteSpace(line) && !line.TrimStart().StartsWith('#'))
                n++;
        }
        return n;
    }

    private static string Sanitize(string project)
    {
        var invalid = Path.GetInvalidFileNameChars();
        var chars = project.Trim().Select(c => invalid.Contains(c) ? '_' : c).ToArray();
        return new string(chars);
    }
}
