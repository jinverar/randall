using System.Text;
using System.Text.Json;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Phase D — marks Deep Scream candidates and gates expensive rewind/TTD operator work.
/// Research-only: no TTD capture; external WinDbg Preview steps only.
/// </summary>
public static class DeepScreamBuilder
{
    /// <summary>Minimum unified scream rank for Deep Scream (matches brain hot threshold).</summary>
    public const int MinScreamScore = 55;

    private static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = true };

    public static string PathFor(string crashesDir, Guid crashId) =>
        Path.Combine(crashesDir, $"{crashId:N}_deep_scream.json");

    public static string TtdHintPathFor(string crashesDir, Guid crashId) =>
        Path.Combine(crashesDir, $"{crashId:N}_deep_scream_ttd.md");

    public static DeepScreamDto? TryRead(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            return null;
        try
        {
            return JsonSerializer.Deserialize<DeepScreamDto>(File.ReadAllText(path), JsonOpts);
        }
        catch
        {
            return null;
        }
    }

    public static bool IsCandidate(int screamScore, int seenCount, bool reproducible) =>
        screamScore >= MinScreamScore && seenCount <= 1 && reproducible;

    public static DeepScreamDto Evaluate(
        Guid crashId,
        string project,
        int screamScore,
        int seenCount,
        bool reproducible,
        bool minimized,
        string? dumpPath = null,
        string? crashesDir = null,
        string? ttdHintPath = null)
    {
        var reasons = new List<string>();
        var missing = new List<string>();

        if (screamScore >= MinScreamScore)
            reasons.Add($"screamScore≥{MinScreamScore} (actual {screamScore})");
        else
            missing.Add($"screamScore {screamScore} < {MinScreamScore}");

        if (seenCount <= 1)
            reasons.Add(seenCount <= 0 ? "unique (first in cluster)" : $"unique (seenCount={seenCount})");
        else
            missing.Add($"cluster seenCount={seenCount} (need unique)");

        if (reproducible)
            reasons.Add("reproducible (sidecar + input ready)");
        else
            missing.Add("not reproducible — needs sidecar/input");

        if (minimized)
            reasons.Add("minimized (shortest in cluster — bonus)");

        var candidate = missing.Count == 0;
        var evolutionPath = string.IsNullOrWhiteSpace(crashesDir)
            ? null
            : ScreamEvolutionBuilder.PathFor(crashesDir, crashId);
        var corruptionPath = string.IsNullOrWhiteSpace(crashesDir)
            ? null
            : CorruptionChainBuilder.PathFor(crashesDir, crashId);

        return new DeepScreamDto(
            Ok: true,
            IsCandidate: candidate,
            CrashId: crashId,
            Project: project,
            ScreamScore: screamScore,
            SeenCount: seenCount,
            Reproducible: reproducible,
            Minimized: minimized,
            EligibilityReasons: reasons,
            MissingReasons: missing,
            DumpPath: dumpPath,
            EvolutionPath: evolutionPath,
            CorruptionChainPath: corruptionPath,
            TtdHintPath: ttdHintPath,
            At: DateTimeOffset.UtcNow);
    }

    public static DeepScreamDto PersistForCrash(
        string crashesDir,
        Guid crashId,
        string project,
        int screamScore,
        int seenCount,
        bool reproducible,
        bool minimized,
        string? dumpPath = null,
        string? ttdHintPath = null)
    {
        var dto = Evaluate(
            crashId, project, screamScore, seenCount, reproducible, minimized,
            dumpPath, crashesDir, ttdHintPath);
        Write(crashesDir, dto);
        return dto;
    }

    public static string Write(string crashesDir, DeepScreamDto dto)
    {
        Directory.CreateDirectory(crashesDir);
        var path = PathFor(crashesDir, dto.CrashId);
        File.WriteAllText(path, JsonSerializer.Serialize(dto, JsonOpts));
        return path;
    }

    public static DeepScreamDto WithTtdHint(string crashesDir, DeepScreamDto dto, string ttdHintPath)
    {
        var updated = dto with { TtdHintPath = ttdHintPath, At = DateTimeOffset.UtcNow };
        Write(crashesDir, updated);
        return updated;
    }

    public static string FormatSummary(DeepScreamDto dto)
    {
        if (!dto.IsCandidate)
            return $"not Deep Scream — {string.Join("; ", dto.MissingReasons)}";

        var bits = dto.EligibilityReasons.Take(3);
        return $"Deep Scream candidate — {string.Join(" · ", bits)}";
    }

    public static string WriteTtdOperatorHint(
        string crashesDir,
        Guid crashId,
        string project,
        DeepScreamDto deepScream,
        string? dumpPath)
    {
        Directory.CreateDirectory(crashesDir);
        var path = TtdHintPathFor(crashesDir, crashId);
        var sb = new StringBuilder();
        sb.AppendLine("# Deep Scream — TTD operator path (Phase D)");
        sb.AppendLine();
        sb.AppendLine("Randfuzz does **not** capture Time Travel Debugging traces. This crash passed the Deep Scream gate — use WinDbg Preview TTD externally:");
        sb.AppendLine();
        sb.AppendLine($"Crash: `{crashId:N}` · project `{project}` · screamScore **{deepScream.ScreamScore}**");
        if (!string.IsNullOrWhiteSpace(dumpPath))
            sb.AppendLine($"Dump: `{dumpPath}`");
        if (!string.IsNullOrWhiteSpace(deepScream.EvolutionPath))
            sb.AppendLine($"Evolution: `{deepScream.EvolutionPath}`");
        if (!string.IsNullOrWhiteSpace(deepScream.CorruptionChainPath))
            sb.AppendLine($"Corruption chain: `{deepScream.CorruptionChainPath}`");
        sb.AppendLine($"Deep Scream artifact: `{PathFor(crashesDir, crashId)}`");
        sb.AppendLine();
        sb.AppendLine("**Eligibility**");
        foreach (var r in deepScream.EligibilityReasons)
            sb.AppendLine($"- {r}");
        sb.AppendLine();
        sb.AppendLine("```powershell");
        sb.AppendLine("# 1) Reproduce with the saved input, then record (WinDbg Preview):");
        sb.AppendLine("#    .attach <pid>  then  !tt.record  … reproduce …  !tt.stop");
        sb.AppendLine($"randall debug open -i {crashId:N} --kind windbg-preview");
        sb.AppendLine("# 2) In the trace:  !tt  then  g-  to rewind toward the fault");
        sb.AppendLine("```");
        sb.AppendLine();
        sb.AppendLine("See docs/RECORDING.md#windbg-ttd--rewind-scream-stub · ROADMAP_INTELLIGENCE.md Phase D.");
        File.WriteAllText(path, sb.ToString());
        return path;
    }
}
