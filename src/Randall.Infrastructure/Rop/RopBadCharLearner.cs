using System.Text.Json;
using Randall.Contracts;

namespace Randall.Infrastructure.Rop;

/// <summary>
/// Suggest ROP badchars from a crashing input (lab heuristic — not a live badchar campaign).
/// Writes <c>*_badchars.json</c> beside the scream canister for sketch filters.
/// </summary>
public static class RopBadCharLearner
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    /// <summary>Classic C-string / line-oriented delivery breakers.</summary>
    private static readonly byte[] ClassicBreakers = [0x00, 0x0a, 0x0d, 0x20, 0x09, 0x1a, 0xff];

    public static RopBadCharReportDto LearnFromCrash(Guid crashId, string? repoRoot = null)
    {
        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var detail = CrashCatalog.GetDetail(crashId, repoRoot);
        if (detail is null)
            return new RopBadCharReportDto(crashId, null, [], "",
                "crash not found", Error: "crash not found");

        byte[] input;
        try
        {
            if (string.IsNullOrWhiteSpace(detail.Summary.InputPath) || !File.Exists(detail.Summary.InputPath))
                return new RopBadCharReportDto(crashId, detail.Summary.Project, [], "",
                    "no crash input on disk", Error: "no input");
            input = File.ReadAllBytes(detail.Summary.InputPath);
        }
        catch (Exception ex)
        {
            return new RopBadCharReportDto(crashId, detail.Summary.Project, [], "",
                "read failed: " + ex.Message, Error: ex.Message);
        }

        var offset = detail.Triage?.PatternDepthBytes;
        var report = LearnFromBytes(input, offset, crashId, detail.Summary.Project);

        var crashesDir = Path.Combine(repoRoot, "data", "crashes", detail.Summary.Project);
        Directory.CreateDirectory(crashesDir);
        var outPath = Path.Combine(crashesDir, $"{crashId:N}_badchars.json");
        try
        {
            File.WriteAllText(outPath, JsonSerializer.Serialize(report with
            {
                OutputPath = outPath.Replace('\\', '/'),
            }, JsonOpts));
            return report with { OutputPath = outPath.Replace('\\', '/') };
        }
        catch
        {
            return report;
        }
    }

    public static RopBadCharReportDto LearnFromBytes(
        byte[] input,
        int? controlOffset = null,
        Guid? crashId = null,
        string? project = null)
    {
        var reasons = new List<string>();
        var suggested = new SortedSet<byte>();

        if (input.Length == 0)
        {
            return new RopBadCharReportDto(crashId, project, [], "",
                "empty input — no badchars learned",
                Reasons: ["empty input"]);
        }

        var prefixLen = controlOffset is > 0 and var o
            ? Math.Min(o, input.Length)
            : Math.Min(input.Length, 512);
        var prefix = input.AsSpan(0, prefixLen);
        var asciiHeavy = CountPrintable(prefix) >= prefixLen * 0.7;

        foreach (var b in ClassicBreakers)
        {
            var inPrefix = Contains(prefix, b);
            var inInput = Contains(input, b);
            // Null / CR / LF matter anywhere in the crashing blob; whitespace only in ASCII prefixes.
            var relevant = b switch
            {
                0x00 or 0x0a or 0x0d or 0x1a or 0xff => inInput,
                0x20 or 0x09 => inPrefix && asciiHeavy,
                _ => inPrefix,
            };
            if (!relevant) continue;

            suggested.Add(b);
            reasons.Add(b switch
            {
                0x00 => "\\x00 present — C-string truncation risk",
                0x0a => "\\x0a present — line-oriented parsers may stop",
                0x0d => "\\x0d present — CRLF / line parsers",
                0x20 => "\\x20 present in ASCII-heavy prefix — strtok/scanf-style risk",
                0x09 => "\\x09 present — whitespace tokenization risk",
                0x1a => "\\x1a present — Ctrl-Z / text EOF on some Windows paths",
                0xff => "\\xff present — signed-char / sentinel risk",
                _ => $"\\x{b:x2} observed",
            });
        }

        // Null after non-null later in the buffer → strong truncation signal.
        var firstNull = IndexOf(input, 0x00);
        if (firstNull >= 0 && firstNull < input.Length - 1)
        {
            for (var i = firstNull + 1; i < input.Length; i++)
            {
                if (input[i] == 0) continue;
                suggested.Add(0x00);
                if (!reasons.Any(r => r.Contains("truncation", StringComparison.OrdinalIgnoreCase)))
                    reasons.Add("\\x00 mid-buffer with trailing data — truncation likely");
                break;
            }
        }

        if (suggested.Count == 0)
        {
            // Soft default for sketch filters when input is binary-clean.
            suggested.Add(0x00);
            reasons.Add("no classic breakers in prefix — defaulting \\x00 as conservative filter");
        }

        var hex = FormatHex(suggested);
        var summary = $"badchars: {suggested.Count} suggested · {hex}" +
                      (controlOffset is { } c ? $" · CONTROL@ {c}" : "");

        return new RopBadCharReportDto(
            crashId,
            project,
            suggested.ToList(),
            hex,
            summary,
            Reasons: reasons,
            ControlOffset: controlOffset,
            InputLength: input.Length);
    }

    /// <summary>Format for <c>--badchars</c> / API: <c>\x00\x0a\x0d</c>.</summary>
    public static string FormatHex(IEnumerable<byte> bytes) =>
        string.Concat(bytes.Select(b => $"\\x{b:x2}"));

    private static bool Contains(ReadOnlySpan<byte> data, byte b)
    {
        foreach (var x in data)
            if (x == b) return true;
        return false;
    }

    private static int IndexOf(byte[] data, byte b)
    {
        for (var i = 0; i < data.Length; i++)
            if (data[i] == b) return i;
        return -1;
    }

    private static int CountPrintable(ReadOnlySpan<byte> data)
    {
        var n = 0;
        foreach (var b in data)
            if (b is >= 0x20 and <= 0x7e or 0x09 or 0x0a or 0x0d) n++;
        return n;
    }
}
