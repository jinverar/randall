using System.Text.RegularExpressions;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Extracts structured sanitizer fault lines from target stderr / log text (ASan, UBSan, MSan, TSan).
/// </summary>
public static partial class SanitizerLogParser
{
    public sealed record ParsedSanitizer(
        string Sanitizer,
        string CheckType,
        string? Location,
        string SummaryLine);

    public static bool TryParseFirst(string? text, out ParsedSanitizer? parsed)
    {
        parsed = null;
        if (string.IsNullOrWhiteSpace(text))
            return false;

        foreach (var line in text.Split('\n'))
        {
            if (TryParseLine(line, out parsed))
                return true;
        }

        return false;
    }

    public static IReadOnlyList<ParsedSanitizer> ExtractAll(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
            return [];

        var list = new List<ParsedSanitizer>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in text.Split('\n'))
        {
            if (!TryParseLine(line, out var parsed) || parsed is null)
                continue;
            var key = $"{parsed.Sanitizer}|{parsed.CheckType}|{parsed.Location}";
            if (seen.Add(key))
                list.Add(parsed);
        }

        return list;
    }

    public static FaultSignalKind MapCheckKind(string checkType)
    {
        var c = checkType.ToLowerInvariant();
        if (c.Contains("stack-buffer-overflow") || c.Contains("stack buffer overflow"))
            return FaultSignalKind.StackBufferOverrun;
        if (c.Contains("use-after-free") || c.Contains("heap-use-after-free"))
            return FaultSignalKind.UseAfterFree;
        if (c.Contains("double-free") || c.Contains("heap-buffer-overflow") ||
            c.Contains("heap overflow") || c.Contains("alloc-dealloc-mismatch"))
            return FaultSignalKind.HeapCorruption;
        if (c.Contains("global-buffer-overflow"))
            return FaultSignalKind.AccessViolation;
        return FaultSignalKind.Sanitizer;
    }

    public static string MapSeverity(string checkType, string sanitizer)
    {
        var c = checkType.ToLowerInvariant();
        if (c.Contains("overflow") || c.Contains("use-after-free") || c.Contains("double-free"))
            return "critical";
        if (sanitizer.Contains("UndefinedBehavior", StringComparison.OrdinalIgnoreCase))
            return "high";
        return "high";
    }

    private static bool TryParseLine(string line, out ParsedSanitizer? parsed)
    {
        parsed = null;
        if (string.IsNullOrWhiteSpace(line))
            return false;

        var trimmed = line.Trim();

        var error = AsanError().Match(trimmed);
        if (error.Success)
        {
            var sanitizer = error.Groups[1].Value;
            var check = error.Groups[2].Value.Trim().TrimEnd('.');
            parsed = new ParsedSanitizer(
                sanitizer,
                check,
                ExtractLocation(trimmed),
                trimmed);
            return true;
        }

        var summary = AsanSummary().Match(trimmed);
        if (summary.Success)
        {
            parsed = new ParsedSanitizer(
                summary.Groups[1].Value,
                summary.Groups[2].Value.Trim(),
                ExtractLocation(trimmed),
                trimmed);
            return true;
        }

        var ubsan = UbsanDirect().Match(trimmed);
        if (ubsan.Success)
        {
            parsed = new ParsedSanitizer(
                "UndefinedBehaviorSanitizer",
                ubsan.Groups[1].Value.Trim(),
                ExtractLocation(trimmed),
                trimmed);
            return true;
        }

        var runtime = UbsanRuntime().Match(trimmed);
        if (runtime.Success)
        {
            parsed = new ParsedSanitizer(
                "UndefinedBehaviorSanitizer",
                runtime.Groups[1].Value.Trim(),
                ExtractLocation(trimmed),
                trimmed);
            return true;
        }

        if (LooksLikeSanitizerToken(trimmed))
        {
            parsed = new ParsedSanitizer(
                InferSanitizerName(trimmed),
                InferCheckType(trimmed),
                ExtractLocation(trimmed),
                trimmed);
            return true;
        }

        return false;
    }

    private static string InferSanitizerName(string line)
    {
        if (line.Contains("UndefinedBehaviorSanitizer", StringComparison.OrdinalIgnoreCase) ||
            line.Contains("runtime error:", StringComparison.OrdinalIgnoreCase))
            return "UndefinedBehaviorSanitizer";
        if (line.Contains("ThreadSanitizer", StringComparison.OrdinalIgnoreCase))
            return "ThreadSanitizer";
        if (line.Contains("MemorySanitizer", StringComparison.OrdinalIgnoreCase))
            return "MemorySanitizer";
        return "AddressSanitizer";
    }

    private static string InferCheckType(string line)
    {
        foreach (var token in new[]
                 {
                     "heap-buffer-overflow", "stack-buffer-overflow", "use-after-free",
                     "heap-use-after-free", "double-free", "global-buffer-overflow",
                     "memory leak", "data race",
                 })
        {
            if (line.Contains(token, StringComparison.OrdinalIgnoreCase))
                return token;
        }

        return "sanitizer report";
    }

    private static bool LooksLikeSanitizerToken(string line) =>
        line.Contains("AddressSanitizer", StringComparison.OrdinalIgnoreCase) ||
        line.Contains("UndefinedBehaviorSanitizer", StringComparison.OrdinalIgnoreCase) ||
        line.Contains("MemorySanitizer", StringComparison.OrdinalIgnoreCase) ||
        line.Contains("ThreadSanitizer", StringComparison.OrdinalIgnoreCase) ||
        line.Contains("heap-buffer-overflow", StringComparison.OrdinalIgnoreCase) ||
        line.Contains("stack-buffer-overflow", StringComparison.OrdinalIgnoreCase) ||
        line.Contains("use-after-free", StringComparison.OrdinalIgnoreCase) ||
        line.Contains("runtime error:", StringComparison.OrdinalIgnoreCase);

    private static string? ExtractLocation(string line)
    {
        var loc = SourceLocation().Match(line);
        return loc.Success ? loc.Groups[1].Value.Trim() : null;
    }

    [GeneratedRegex(@"ERROR:\s*(AddressSanitizer|LeakSanitizer|ThreadSanitizer|MemorySanitizer):\s*(.+?)(?:\s+on address|\s*$)", RegexOptions.IgnoreCase)]
    private static partial Regex AsanError();

    [GeneratedRegex(@"SUMMARY:\s*((?:Address|Leak|Thread|Memory|UndefinedBehavior)Sanitizer[^:]*):\s*(.+)$", RegexOptions.IgnoreCase)]
    private static partial Regex AsanSummary();

    [GeneratedRegex(@"(UndefinedBehaviorSanitizer):\s*(.+)$", RegexOptions.IgnoreCase)]
    private static partial Regex UbsanDirect();

    [GeneratedRegex(@":\d+:\d+:\s*runtime error:\s*(.+)$", RegexOptions.IgnoreCase)]
    private static partial Regex UbsanRuntime();

    [GeneratedRegex(@"#\d+\s+0x[0-9a-fA-F]+\s+in\s+(\S+\s\S+|\S+)")]
    private static partial Regex SourceLocation();
}
