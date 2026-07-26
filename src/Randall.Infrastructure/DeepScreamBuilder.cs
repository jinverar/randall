using System.Text;
using System.Text.Json;
using Randall.Contracts;

namespace Randall.Infrastructure;

public static class DeepScreamBuilder
{
    public const int MinScreamScore = 55;
    public const int MomentumJumpThreshold = 15;
    public const int ScreamJumpThreshold = 10;

    private static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = true };

    public static string PathFor(string crashesDir, Guid crashId) =>
        Path.Combine(crashesDir, $"{crashId:N}_deep_scream.json");

    public static string TtdHintPathFor(string crashesDir, Guid crashId) =>
        Path.Combine(crashesDir, $"{crashId:N}_deep_scream_ttd.md");

    public static string FamilyRegistryPathFor(string crashesDir) =>
        Path.Combine(crashesDir, "_deep_scream_families.json");

    public static string DeepScreamIndexPathFor(string crashesDir) =>
        Path.Combine(crashesDir, "_magician", "deep_scream_index.md");

    public static DeepScreamDto? TryRead(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path)) return null;
        try { return JsonSerializer.Deserialize<DeepScreamDto>(File.ReadAllText(path), JsonOpts); }
        catch { return null; }
    }

    public static bool PassesBaseGate(int screamScore, int seenCount, bool reproducible) =>
        screamScore >= MinScreamScore && seenCount <= 1 && reproducible;

    public static bool IsCandidate(int screamScore, int seenCount, bool reproducible) =>
        PassesBaseGate(screamScore, seenCount, reproducible);

    public static DeepScreamDto Evaluate(
        Guid crashId, string project, int screamScore, int seenCount, bool reproducible, bool minimized,
        string? dumpPath = null, string? crashesDir = null, string? ttdHintPath = null,
        string? semanticFingerprint = null, string? familyId = null, bool isMarked = false,
        bool familySuppressed = false, Guid? priorFamilyCrashId = null,
        bool autoMinimizeAttempted = false, bool autoMinimizeSucceeded = false, string? minimizedInputPath = null,
        bool? ttdToolsPresent = null, string? ttdToolsSummary = null)
    {
        var reasons = new List<string>();
        var missing = new List<string>();
        if (screamScore >= MinScreamScore) reasons.Add($"screamScore≥{MinScreamScore} (actual {screamScore})");
        else missing.Add($"screamScore {screamScore} < {MinScreamScore}");
        if (seenCount <= 1) reasons.Add(seenCount <= 0 ? "unique (first in cluster)" : $"unique (seenCount={seenCount})");
        else missing.Add($"cluster seenCount={seenCount} (need unique)");
        if (reproducible) reasons.Add("reproducible (sidecar + input ready)");
        else missing.Add("not reproducible — needs sidecar/input");
        if (minimized) reasons.Add("minimized (shortest in cluster — bonus)");
        if (autoMinimizeAttempted)
            reasons.Add(autoMinimizeSucceeded ? "auto-minimize succeeded before mark" : "auto-minimize attempted (no further shrink)");
        if (familySuppressed && priorFamilyCrashId is { } prior)
            missing.Add($"family dedup — prior deep dive `{prior:N}` (momentum jump required)");
        else if (isMarked && !string.IsNullOrWhiteSpace(familyId))
            reasons.Add($"marked for family `{familyId}`");

        var candidate = PassesBaseGate(screamScore, seenCount, reproducible) && !familySuppressed;
        var ttdProbe = ttdToolsPresent.HasValue
            ? new TtdToolsProbe(ttdToolsPresent.Value, ttdToolsSummary ?? "unknown")
            : DebuggerTools.ProbeTtd();

        return new DeepScreamDto(
            Ok: true, IsCandidate: candidate, CrashId: crashId, Project: project,
            ScreamScore: screamScore, SeenCount: seenCount, Reproducible: reproducible,
            Minimized: minimized || autoMinimizeSucceeded, EligibilityReasons: reasons, MissingReasons: missing,
            DumpPath: dumpPath,
            EvolutionPath: string.IsNullOrWhiteSpace(crashesDir) ? null : ScreamEvolutionBuilder.PathFor(crashesDir, crashId),
            CorruptionChainPath: string.IsNullOrWhiteSpace(crashesDir) ? null : CorruptionChainBuilder.PathFor(crashesDir, crashId),
            HypothesisPath: string.IsNullOrWhiteSpace(crashesDir) ? null : HypothesisEngine.PathFor(crashesDir, crashId),
            SemanticFingerprint: semanticFingerprint, FamilyId: familyId,
            IsMarked: isMarked && candidate, FamilySuppressed: familySuppressed,
            PriorFamilyCrashId: priorFamilyCrashId, AutoMinimizeAttempted: autoMinimizeAttempted,
            AutoMinimizeSucceeded: autoMinimizeSucceeded, MinimizedInputPath: minimizedInputPath,
            TtdToolsPresent: ttdProbe.Present, TtdToolsSummary: ttdProbe.Summary,
            TtdHintPath: ttdHintPath, At: DateTimeOffset.UtcNow);
    }

    public static async Task<DeepScreamDto> ProcessAndPersistAsync(
        string crashesDir, Guid crashId, string project, int screamScore, int seenCount,
        bool reproducible, bool minimized, string? dumpPath, string? semanticFingerprint,
        ScreamEvolutionDto? evolution, bool autoMinimize, ProjectConfig? projectConfig,
        string? yamlPath, byte[]? payload, CancellationToken cancellationToken = default)
    {
        var familyId = evolution?.FamilyId;
        var autoMinimizeAttempted = false;
        var autoMinimizeSucceeded = false;
        string? minimizedInputPath = null;

        if (autoMinimize && PassesBaseGate(screamScore, seenCount, reproducible) && !minimized
            && payload is { Length: > 0 } && projectConfig is not null && !string.IsNullOrWhiteSpace(yamlPath))
        {
            autoMinimizeAttempted = true;
            try
            {
                var minResult = await CrashInputMinimizer.TryMinimizeAsync(
                    projectConfig, yamlPath, payload, crashesDir, crashId, cancellationToken: cancellationToken);
                autoMinimizeSucceeded = minResult.Succeeded;
                minimizedInputPath = minResult.OutputPath;
                if (minResult.Succeeded) minimized = true;
            }
            catch { /* soft-skip */ }
        }

        var (isMarked, familySuppressed, priorFamilyCrashId, familyReason) =
            ResolveFamilyMark(crashesDir, crashId, screamScore, seenCount, reproducible, familyId, evolution);

        var dto = Evaluate(crashId, project, screamScore, seenCount, reproducible, minimized, dumpPath, crashesDir,
            semanticFingerprint: semanticFingerprint, familyId: familyId, isMarked: isMarked,
            familySuppressed: familySuppressed, priorFamilyCrashId: priorFamilyCrashId,
            autoMinimizeAttempted: autoMinimizeAttempted, autoMinimizeSucceeded: autoMinimizeSucceeded,
            minimizedInputPath: minimizedInputPath);

        if (!string.IsNullOrWhiteSpace(familyReason) && familySuppressed)
            dto = dto with { MissingReasons = dto.MissingReasons.Concat([familyReason]).ToList() };

        Write(crashesDir, dto);
        return dto;
    }

    public static DeepScreamDto PersistForCrash(
        string crashesDir, Guid crashId, string project, int screamScore, int seenCount,
        bool reproducible, bool minimized, string? dumpPath = null, string? ttdHintPath = null,
        string? semanticFingerprint = null, string? familyId = null, ScreamEvolutionDto? evolution = null)
    {
        var (isMarked, familySuppressed, priorFamilyCrashId, familyReason) =
            ResolveFamilyMark(crashesDir, crashId, screamScore, seenCount, reproducible, familyId, evolution);
        var dto = Evaluate(crashId, project, screamScore, seenCount, reproducible, minimized,
            dumpPath, crashesDir, ttdHintPath, semanticFingerprint, familyId, isMarked, familySuppressed, priorFamilyCrashId);
        if (!string.IsNullOrWhiteSpace(familyReason) && familySuppressed)
            dto = dto with { MissingReasons = dto.MissingReasons.Concat([familyReason]).ToList() };
        Write(crashesDir, dto);
        return dto;
    }

    public static (bool IsMarked, bool FamilySuppressed, Guid? PriorCrashId, string? Reason) ResolveFamilyMark(
        string crashesDir, Guid crashId, int screamScore, int seenCount, bool reproducible,
        string? familyId, ScreamEvolutionDto? evolution)
    {
        if (!PassesBaseGate(screamScore, seenCount, reproducible)) return (false, false, null, null);
        if (string.IsNullOrWhiteSpace(familyId)) return (true, false, null, null);

        var registry = LoadFamilyRegistry(crashesDir);
        if (!registry.TryGetValue(familyId, out var prior))
        {
            RegisterFamily(crashesDir, registry, familyId, crashId, screamScore, evolution);
            return (true, false, null, null);
        }
        if (prior.CrashId == crashId) return (true, false, null, null);

        var momentumJump = evolution is { MomentumScore: var m } && m >= prior.MomentumScore + MomentumJumpThreshold;
        var scoreJump = screamScore >= prior.ScreamScore + ScreamJumpThreshold;
        var stepJump = evolution is { ProgressionStep: var step } && step > prior.ProgressionStep;
        if (momentumJump || scoreJump || stepJump)
        {
            RegisterFamily(crashesDir, registry, familyId, crashId, screamScore, evolution);
            var jump = momentumJump ? "momentum jump" : scoreJump ? "scream jump" : "progression jump";
            return (true, false, prior.CrashId, $"{jump} — new family deep dive");
        }
        return (false, true, prior.CrashId,
            $"family `{familyId}` dedup — prior deep dive `{prior.CrashId:N}` (momentum={prior.MomentumScore})");
    }

    private static void RegisterFamily(string crashesDir, Dictionary<string, DeepScreamFamilyEntryDto> registry,
        string familyId, Guid crashId, int screamScore, ScreamEvolutionDto? evolution)
    {
        registry[familyId] = new DeepScreamFamilyEntryDto(crashId, screamScore, evolution?.MomentumScore ?? 0,
            evolution?.MomentumLabel, evolution?.ProgressionStep ?? ScreamProgressionStep.Unknown, DateTimeOffset.UtcNow);
        SaveFamilyRegistry(crashesDir, registry);
    }

    public static Dictionary<string, DeepScreamFamilyEntryDto> LoadFamilyRegistry(string crashesDir)
    {
        var path = FamilyRegistryPathFor(crashesDir);
        if (!File.Exists(path)) return new Dictionary<string, DeepScreamFamilyEntryDto>(StringComparer.OrdinalIgnoreCase);
        try
        {
            var raw = JsonSerializer.Deserialize<Dictionary<string, DeepScreamFamilyEntryDto>>(File.ReadAllText(path), JsonOpts);
            return raw is null ? new Dictionary<string, DeepScreamFamilyEntryDto>(StringComparer.OrdinalIgnoreCase)
                : new Dictionary<string, DeepScreamFamilyEntryDto>(raw, StringComparer.OrdinalIgnoreCase);
        }
        catch { return new Dictionary<string, DeepScreamFamilyEntryDto>(StringComparer.OrdinalIgnoreCase); }
    }

    private static void SaveFamilyRegistry(string crashesDir, Dictionary<string, DeepScreamFamilyEntryDto> registry)
    {
        Directory.CreateDirectory(crashesDir);
        File.WriteAllText(FamilyRegistryPathFor(crashesDir), JsonSerializer.Serialize(registry, JsonOpts));
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
        if (dto.FamilySuppressed) return $"Deep Scream suppressed (family) — prior `{dto.PriorFamilyCrashId:N}`";
        if (!dto.IsCandidate) return $"not Deep Scream — {string.Join("; ", dto.MissingReasons)}";
        if (dto.IsMarked) return $"Deep Scream marked — {string.Join(" · ", dto.EligibilityReasons.Take(3))}";
        return $"Deep Scream candidate — {string.Join(" · ", dto.EligibilityReasons.Take(3))}";
    }

    public static string WriteTtdOperatorHint(string crashesDir, Guid crashId, string project,
        DeepScreamDto deepScream, string? dumpPath, string? inputPath = null)
    {
        Directory.CreateDirectory(crashesDir);
        var path = TtdHintPathFor(crashesDir, crashId);
        var ttd = DebuggerTools.ProbeTtd();
        var sb = new StringBuilder();
        sb.AppendLine("# Deep Scream — TTD operator playbook (Phase D)");
        sb.AppendLine();
        sb.AppendLine("Randfuzz does **not** capture TTD traces. This crash is **marked** — use WinDbg Preview externally.");
        sb.AppendLine($"Crash: `{crashId:N}` · project `{project}` · screamScore **{deepScream.ScreamScore}**");
        if (!string.IsNullOrWhiteSpace(deepScream.FamilyId)) sb.AppendLine($"Family: `{deepScream.FamilyId}`");
        if (!string.IsNullOrWhiteSpace(deepScream.SemanticFingerprint)) sb.AppendLine($"Semantic fingerprint: `{deepScream.SemanticFingerprint}`");
        if (!string.IsNullOrWhiteSpace(dumpPath)) sb.AppendLine($"Dump: `{dumpPath}`");
        if (!string.IsNullOrWhiteSpace(inputPath)) sb.AppendLine($"Input: `{inputPath}`");
        if (!string.IsNullOrWhiteSpace(deepScream.MinimizedInputPath)) sb.AppendLine($"Minimized input: `{deepScream.MinimizedInputPath}`");
        if (!string.IsNullOrWhiteSpace(deepScream.EvolutionPath)) sb.AppendLine($"Evolution: `{deepScream.EvolutionPath}`");
        if (!string.IsNullOrWhiteSpace(deepScream.CorruptionChainPath)) sb.AppendLine($"Corruption chain: `{deepScream.CorruptionChainPath}`");
        if (!string.IsNullOrWhiteSpace(deepScream.HypothesisPath)) sb.AppendLine($"Hypotheses: `{deepScream.HypothesisPath}`");
        sb.AppendLine($"Deep Scream artifact: `{PathFor(crashesDir, crashId)}`");
        sb.AppendLine();
        sb.AppendLine("## TTD toolchain");
        sb.AppendLine($"- Status: {(ttd.Present ? "tools detected" : "not detected")}");
        sb.AppendLine($"- Summary: {ttd.Summary}");
        if (ttd.WinDbgPreviewPath is not null) sb.AppendLine($"- WinDbg Preview: `{ttd.WinDbgPreviewPath}`");
        if (ttd.TtdTracerPath is not null) sb.AppendLine($"- tttracer: `{ttd.TtdTracerPath}`");
        sb.AppendLine();
        sb.AppendLine("## Steps");
        sb.AppendLine($"1. `randall replay -i {crashId:N}`");
        sb.AppendLine("2. WinDbg Preview: `.attach <pid>` → `!tt.record` … reproduce … `!tt.stop`");
        if (ttd.TtdTracerPath is not null)
            sb.AppendLine($"   Or: `\"{ttd.TtdTracerPath}\" -out deep_scream_{crashId:N}.run <target.exe> <args>`");
        sb.AppendLine($"3. `randall debug open -i {crashId:N} --kind windbg-preview`");
        sb.AppendLine("4. In trace: `!tt` · `g-` · `!analyze -v`");
        File.WriteAllText(path, sb.ToString());
        return path;
    }

    public static void AppendDeepScreamIndex(string crashesDir, Guid crashId, DeepScreamDto deepScream, string ttdPath)
    {
        var dir = Path.Combine(crashesDir, "_magician");
        Directory.CreateDirectory(dir);
        var indexPath = DeepScreamIndexPathFor(crashesDir);
        var line = $"- `{crashId:N}` scream={deepScream.ScreamScore} family={deepScream.FamilyId ?? "—"} → `{ttdPath}`{Environment.NewLine}";
        if (File.Exists(indexPath)) { File.AppendAllText(indexPath, line); return; }
        var header = new StringBuilder();
        header.AppendLine("# Deep Scream — marked crashes (Phase D)");
        header.AppendLine();
        header.AppendLine("One deep dive per scream family unless momentum jumps.");
        header.AppendLine();
        header.Append(line);
        File.WriteAllText(indexPath, header.ToString());
    }
}

public sealed record TtdToolsProbe(bool Present, string Summary, string? WinDbgPreviewPath = null, string? TtdTracerPath = null);
