using System.Diagnostics;
using System.Text;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// File-target helpers: crash-shaped exit classification, temp lifecycle, multi-file bundles.
/// </summary>
public static class FileFuzzExecution
{
    /// <summary>
    /// True only for memory-corruption / fatal-signal shaped exits — NOT ordinary parser reject (exit 1).
    /// </summary>
    public static bool IsCrashShapedExit(int code) => TargetRunner.IsCrashExitCode(code);

    public static bool LooksLikeSanitizerCrash(string? stderrOrDetail) =>
        SanitizerLogParser.TryParseFirst(stderrOrDetail, out _);

    /// <summary>Classify file OOP result: exit + optional stderr.</summary>
    public static (bool Crashed, string Detail) ClassifyFileExit(int exitCode, string? stderr)
    {
        if (LooksLikeSanitizerCrash(stderr))
        {
            SanitizerLogParser.TryParseFirst(stderr, out var parsed);
            var summary = parsed?.SummaryLine ?? "sanitizer fault";
            return (true, $"sanitizer: {Truncate(summary, 200)}");
        }

        if (IsCrashShapedExit(exitCode))
            return (true, $"crash-shaped exit {exitCode:X8}");

        // Ordinary non-zero (parser reject, usage error) is NOT a memory crash.
        if (exitCode != 0)
            return (false, $"tool-reject exit {exitCode}");

        return (false, "ok");
    }

    public static async Task WriteTempFileAsync(string path, byte[] payload, CancellationToken ct)
    {
        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrWhiteSpace(dir))
            Directory.CreateDirectory(dir);

        // Unique path expected by caller; flush+close before target launch (no reuse race).
        await using var fs = new FileStream(
            path,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.Read,
            bufferSize: 4096,
            options: FileOptions.Asynchronous | FileOptions.SequentialScan);
        await fs.WriteAsync(payload, ct);
        await fs.FlushAsync(ct);
    }

    public static string PickExtension(TransportConfig transport, Random? rng = null)
    {
        rng ??= Random.Shared;
        var primary = NormalizeExt(transport.Extension);
        if (transport.Extensions.Count == 0 || transport.MismatchChance <= 0)
            return primary;

        if (rng.NextDouble() >= transport.MismatchChance)
            return primary;

        var alts = transport.Extensions
            .Select(NormalizeExt)
            .Where(e => !e.Equals(primary, StringComparison.OrdinalIgnoreCase))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (alts.Count == 0)
            return primary;
        return alts[rng.Next(alts.Count)];
    }

    public static string NormalizeExt(string? ext)
    {
        if (string.IsNullOrWhiteSpace(ext))
            return ".bin";
        return ext.StartsWith('.') ? ext : "." + ext;
    }

    private static string Truncate(string s, int max) =>
        s.Length <= max ? s : s[..max] + "…";
}
