using System.Text.Json;
using System.Text.Json.Serialization;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Bug Genealogy — groups crashes and silent findings that share root cause category,
/// faulting function, and/or pattern family into N probable vulns / M failures.
/// Research/teaching only; no exploit payloads.
/// </summary>
public static class BugGenealogyEngine
{
    public const string FileName = "bug_genealogy.json";

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter() },
    };

    public static string PathFor(string crashesDir) =>
        Path.Combine(crashesDir, FileName);

    public static string PathForProject(string project, string? repoRoot = null)
    {
        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        return PathFor(Path.Combine(repoRoot, "data", "crashes", project));
    }

    public static BugGenealogyReportDto? TryRead(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            return null;
        try
        {
            return JsonSerializer.Deserialize<BugGenealogyReportDto>(File.ReadAllText(path), JsonOpts);
        }
        catch
        {
            return null;
        }
    }

    public static BugGenealogyReportDto? TryLoad(string project, string? repoRoot = null) =>
        TryRead(PathForProject(project, repoRoot));

    /// <summary>
    /// Build genealogy from on-disk crash artifacts for a project.
    /// </summary>
    public static BugGenealogyReportDto BuildForProject(string project, string? repoRoot = null)
    {
        if (string.IsNullOrWhiteSpace(project))
        {
            return new BugGenealogyReportDto(
                false, "?", 0, 0, "project required", [], "UNKNOWN",
                DateTimeOffset.UtcNow, Error: "project required");
        }

        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var crashesDir = Path.Combine(repoRoot, "data", "crashes", project);
        if (!Directory.Exists(crashesDir))
        {
            return new BugGenealogyReportDto(
                false, project, 0, 0,
                $"No crash directory for project '{project}'.",
                [], "UNKNOWN", DateTimeOffset.UtcNow, Error: "no crashes dir");
        }

        var members = CollectMembers(crashesDir, project);
        return BuildFromMembers(project, members);
    }

    /// <summary>Build from an explicit member list (tests / offline).</summary>
    public static BugGenealogyReportDto BuildFromMembers(
        string project,
        IReadOnlyList<GenealogyMemberDto> members)
    {
        if (members.Count == 0)
        {
            return new BugGenealogyReportDto(
                true, project, 0, 0,
                "0 probable vulns / 0 failures — no crashes or silent findings yet.",
                [], "LOW", DateTimeOffset.UtcNow);
        }

        var groups = members
            .GroupBy(LineageKey, StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(g => g.Count())
            .ThenBy(g => g.Key, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var lineages = new List<GenealogyLineageDto>();
        var lineageIndex = 0;
        foreach (var g in groups)
        {
            lineageIndex++;
            var list = g.ToList();
            var category = MajorityCategory(list);
            var fn = MajorityString(list.Select(m => m.FaultingFunction));
            var pattern = MajorityString(list.Select(m => m.PatternHint))
                          ?? MajorityString(list.Select(m => m.FamilyId))
                          ?? MajorityString(list.Select(m => m.ClusterKey));
            var confidence = RollupConfidence(list, category, fn);
            var label = BuildLabel(category, fn, pattern, lineageIndex);
            lineages.Add(new GenealogyLineageDto(
                $"lineage-{lineageIndex:D2}",
                label,
                category,
                fn,
                pattern,
                list.Count,
                list,
                confidence,
                BuildEducationalNote(category, fn, list.Count)));
        }

        // Probable vulns = lineages with a usable category or shared function/pattern
        // (not a singleton Unknown with no function).
        var probable = lineages.Count(IsProbableVuln);
        var failures = members.Count;
        var summary =
            $"{probable} probable vuln(s) / {failures} failure(s) — " +
            "grouped by root cause, faulting function, and pattern family.";

        var conf = lineages.Count == 0
            ? "LOW"
            : lineages.Any(l => l.Confidence == "HIGH")
                ? "HIGH"
                : lineages.Any(l => l.Confidence == "MEDIUM")
                    ? "MEDIUM"
                    : "LOW";

        return new BugGenealogyReportDto(
            true, project, probable, failures, summary, lineages, conf, DateTimeOffset.UtcNow);
    }

    public static BugGenealogyReportDto PersistForProject(string project, string? repoRoot = null)
    {
        var report = BuildForProject(project, repoRoot);
        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var crashesDir = Path.Combine(repoRoot, "data", "crashes", project);
        Directory.CreateDirectory(crashesDir);
        File.WriteAllText(PathFor(crashesDir), JsonSerializer.Serialize(report, JsonOpts));
        return report;
    }

    public static string Write(string crashesDir, BugGenealogyReportDto report)
    {
        Directory.CreateDirectory(crashesDir);
        var path = PathFor(crashesDir);
        File.WriteAllText(path, JsonSerializer.Serialize(report, JsonOpts));
        return path;
    }

    private static List<GenealogyMemberDto> CollectMembers(string crashesDir, string project)
    {
        var store = new CrashStore(crashesDir);
        var members = new List<GenealogyMemberDto>();
        foreach (var c in store.List())
        {
            var sidecar = CrashSidecarWriter.TryRead(c.SidecarPath);
            var analysis = CrashAnalysisWriter.TryRead(CrashAnalysisWriter.AnalysisPathFor(crashesDir, c.Id));
            var debugger = ScreamInvestigator.TryRead(ScreamInvestigator.ObservationPathFor(crashesDir, c.Id));
            var summary = new CrashSummaryDto(
                c.Id, c.Project, c.Iteration, c.Mutator, c.InputHash, c.InputPath,
                c.MiniDumpPath, c.TargetExitCode, c.TriageTag, c.SidecarPath, c.RunId, c.At);
            var triage = CrashTriage.Classify(analysis, sidecar, summary, null, debugger: debugger);
            var root = RootCauseEngine.TryRead(RootCauseEngine.PathFor(crashesDir, c.Id));
            var evolution = ScreamEvolutionBuilder.TryRead(ScreamEvolutionBuilder.PathFor(crashesDir, c.Id));

            var kind = IsSilentFinding(c.TriageTag, sidecar, triage)
                ? GenealogyFailureKind.SilentFinding
                : GenealogyFailureKind.Crash;

            var category = root?.Candidate.Category;
            var fn = root?.Candidate.FaultingFunction
                     ?? triage?.StaticFunction?.FunctionName
                     ?? triage?.FaultModule;
            var pattern = evolution?.FamilyId
                          ?? FormatPatternHint(triage?.PatternDepthBytes, root?.Candidate.InputRegion)
                          ?? triage?.SemanticFingerprint
                          ?? triage?.ClusterKey;

            members.Add(new GenealogyMemberDto(
                c.Id,
                kind,
                triage?.ClusterKey ?? summary.ClusterKey,
                evolution?.FamilyId,
                fn,
                category,
                pattern,
                c.TriageTag ?? sidecar?.TriageTag));
        }

        return members;
    }

    private static bool IsSilentFinding(string? triageTag, CrashSidecarDto? sidecar, CrashTriageDto? triage)
    {
        if (sidecar?.SilentScream == true)
            return true;
        if (!string.IsNullOrWhiteSpace(triageTag) &&
            triageTag.Contains("silent", StringComparison.OrdinalIgnoreCase))
            return true;
        if (string.Equals(triage?.Class, "oracle_only", StringComparison.OrdinalIgnoreCase))
            return true;
        return sidecar?.RandallScore is { Total: >= 70 } &&
               string.IsNullOrWhiteSpace(sidecar.ExceptionHint);
    }

    private static string? FormatPatternHint(int? depth, string? region)
    {
        if (depth is int d)
            return $"pattern@{d}";
        if (!string.IsNullOrWhiteSpace(region))
            return region.Trim();
        return null;
    }

    private static string LineageKey(GenealogyMemberDto m)
    {
        var cat = m.Category is null or RootCauseCategory.Unknown
            ? "unknown"
            : m.Category.Value.ToString();
        var fn = NormalizeFn(m.FaultingFunction) ?? "nofn";
        var pattern = NormalizePattern(m.PatternHint)
                      ?? NormalizePattern(m.FamilyId)
                      ?? NormalizePattern(m.ClusterKey)
                      ?? "nopattern";

        // Prefer function+category when both known; else fall back to cluster/family.
        if (m.Category is not null and not RootCauseCategory.Unknown &&
            NormalizeFn(m.FaultingFunction) is not null)
            return $"rc:{cat}|fn:{fn}";
        if (NormalizeFn(m.FaultingFunction) is not null)
            return $"fn:{fn}|pat:{pattern}";
        if (m.Category is not null and not RootCauseCategory.Unknown)
            return $"rc:{cat}|pat:{pattern}";
        return $"pat:{pattern}";
    }

    private static string? NormalizeFn(string? fn)
    {
        if (string.IsNullOrWhiteSpace(fn)) return null;
        var s = fn.Trim();
        var bang = s.LastIndexOf('!');
        if (bang >= 0 && bang + 1 < s.Length)
            s = s[(bang + 1)..];
        var plus = s.IndexOf('+');
        if (plus > 0)
            s = s[..plus];
        return s.ToLowerInvariant();
    }

    private static string? NormalizePattern(string? p)
    {
        if (string.IsNullOrWhiteSpace(p)) return null;
        var s = p.Trim().ToLowerInvariant();
        return s.Length > 48 ? s[..48] : s;
    }

    private static RootCauseCategory MajorityCategory(IReadOnlyList<GenealogyMemberDto> list)
    {
        return list
            .Select(m => m.Category ?? RootCauseCategory.Unknown)
            .GroupBy(c => c)
            .OrderByDescending(g => g.Key != RootCauseCategory.Unknown)
            .ThenByDescending(g => g.Count())
            .Select(g => g.Key)
            .FirstOrDefault();
    }

    private static string? MajorityString(IEnumerable<string?> values)
    {
        return values
            .Where(v => !string.IsNullOrWhiteSpace(v))
            .GroupBy(v => v!, StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(g => g.Count())
            .Select(g => g.Key)
            .FirstOrDefault();
    }

    private static string RollupConfidence(
        IReadOnlyList<GenealogyMemberDto> list,
        RootCauseCategory category,
        string? fn)
    {
        if (list.Count >= 3 && category != RootCauseCategory.Unknown && fn is not null)
            return "HIGH";
        if (list.Count >= 2 && (category != RootCauseCategory.Unknown || fn is not null))
            return "MEDIUM";
        if (category != RootCauseCategory.Unknown || fn is not null)
            return "MEDIUM";
        return "LOW";
    }

    private static string BuildLabel(
        RootCauseCategory category,
        string? fn,
        string? pattern,
        int index)
    {
        var parts = new List<string>();
        if (category != RootCauseCategory.Unknown)
            parts.Add(category.ToString());
        if (!string.IsNullOrWhiteSpace(fn))
            parts.Add(fn!);
        else if (!string.IsNullOrWhiteSpace(pattern))
            parts.Add(pattern!);
        if (parts.Count == 0)
            parts.Add($"ungrouped-{index:D2}");
        return string.Join(" · ", parts);
    }

    private static string BuildEducationalNote(RootCauseCategory category, string? fn, int count)
    {
        var where = string.IsNullOrWhiteSpace(fn) ? "an unresolved site" : fn;
        var cat = category == RootCauseCategory.Unknown ? "unclassified" : category.ToString();
        return $"{count} failure(s) share {cat} at {where}. " +
               "Study as one vulnerability lineage — not one exploit per crash.";
    }

    private static bool IsProbableVuln(GenealogyLineageDto lineage)
    {
        if (lineage.Category != RootCauseCategory.Unknown)
            return true;
        if (!string.IsNullOrWhiteSpace(lineage.FaultingFunction) && lineage.FailureCount >= 1)
            return true;
        if (!string.IsNullOrWhiteSpace(lineage.PatternFamily) && lineage.FailureCount >= 2)
            return true;
        return false;
    }
}
