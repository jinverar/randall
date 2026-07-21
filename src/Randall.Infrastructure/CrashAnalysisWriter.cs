using System.Text.Json;
using Randall.Contracts;

namespace Randall.Infrastructure;

public static class CrashAnalysisWriter
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    public static string Write(string crashesDir, Guid crashId, CrashAnalysisDto analysis)
    {
        var path = Path.Combine(crashesDir, $"{crashId:N}_analysis.json");
        File.WriteAllText(path, JsonSerializer.Serialize(analysis, JsonOptions));
        return path;
    }

    public static CrashAnalysisDto? TryRead(string? analysisPath)
    {
        if (string.IsNullOrWhiteSpace(analysisPath) || !File.Exists(analysisPath))
            return null;
        try
        {
            return JsonSerializer.Deserialize<CrashAnalysisDto>(File.ReadAllText(analysisPath));
        }
        catch
        {
            return null;
        }
    }

    public static string? AnalysisPathFor(string crashesDir, Guid crashId) =>
        Path.Combine(crashesDir, $"{crashId:N}_analysis.json");

    public static CrashAnalysisDto AnalyzeDump(string? dumpPath)
    {
        if (LinuxCrashAnalysisWriter.LooksLikeLinuxCore(dumpPath))
        {
            // Catalog / cluster reload: prefer existing *_analysis.json written at crash time.
            // Fall back to a lightweight signal-only DTO (full gdb re-triage needs the exe path).
            return new CrashAnalysisDto(
                true,
                dumpPath,
                null,
                "linux-core",
                null,
                null,
                null,
                [],
                null);
        }

        return MiniDumpAnalyzer.Analyze(dumpPath);
    }
}
