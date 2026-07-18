using System.Text;
using System.Text.Json;
using Randall.Contracts;

namespace Randall.Infrastructure;

public static class MemoryLensWriter
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    public static string JsonPathFor(string crashesDir, Guid crashId) =>
        Path.Combine(crashesDir, $"{crashId:N}_memory_lens.json");

    public static string TextPathFor(string crashesDir, Guid crashId) =>
        Path.Combine(crashesDir, $"{crashId:N}_memory_lens.txt");

    public static (string JsonPath, string TextPath) Write(string crashesDir, Guid crashId, MemoryLensReportDto report)
    {
        Directory.CreateDirectory(crashesDir);
        var jsonPath = JsonPathFor(crashesDir, crashId);
        var txtPath = TextPathFor(crashesDir, crashId);
        File.WriteAllText(jsonPath, JsonSerializer.Serialize(report, JsonOptions));
        File.WriteAllText(txtPath, FormatText(report), Encoding.UTF8);
        return (jsonPath, txtPath);
    }

    public static MemoryLensReportDto? TryRead(string crashesDir, Guid crashId)
    {
        var path = JsonPathFor(crashesDir, crashId);
        if (!File.Exists(path))
            return null;
        try
        {
            return JsonSerializer.Deserialize<MemoryLensReportDto>(File.ReadAllText(path), JsonOptions);
        }
        catch
        {
            return null;
        }
    }

    public static string FormatText(MemoryLensReportDto report)
    {
        var sb = new StringBuilder();
        sb.AppendLine("Randfuzz Memory Lens");
        sb.AppendLine($"Confidence: {report.Confidence}");
        if (report.DumpPath is not null)
            sb.AppendLine($"Dump: {report.DumpPath}");
        if (report.Pid is not null)
            sb.AppendLine($"PID: {report.Pid}");
        sb.AppendLine();
        foreach (var line in report.SummaryLines)
            sb.AppendLine(line);
        if (report.Fault is { } f)
        {
            sb.AppendLine();
            sb.AppendLine($"Fault: {f.ExceptionHint} ({f.ExceptionCode}) {f.AccessType} @ {f.FaultAddress}");
            if (f.FaultModule is not null)
                sb.AppendLine($"Module: {f.FaultModule}");
        }

        if (report.PatternHits.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("Pattern hits:");
            foreach (var p in report.PatternHits)
                sb.AppendLine($"  [{p.Confidence}] {p.Where}: {p.PatternName} ({p.Value}) — {p.Hint}");
        }

        if (report.LinkHints.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("Link/unlink hints:");
            foreach (var l in report.LinkHints)
                sb.AppendLine($"  [{l.Confidence}] {l.Where}: Flink={l.Flink} Blink={l.Blink} — {l.Note}");
        }

        if (report.Neighborhood is { } n)
        {
            sb.AppendLine();
            sb.AppendLine($"Neighborhood @ {n.BaseAddress} ({n.Length} bytes):");
            sb.AppendLine(n.HexPreview);
            foreach (var a in n.Annotations)
                sb.AppendLine($"  · {a}");
        }

        if (report.HeapSummaryLines is { Count: > 0 })
        {
            sb.AppendLine();
            sb.AppendLine($"Heap ({report.HeapBackend ?? "unknown"})" +
                          (report.PageHeapLikely ? " — Page Heap likely" : "") + ":");
            foreach (var h in report.HeapSummaryLines.Take(20))
                sb.AppendLine($"  {h}");
        }

        if (!string.IsNullOrWhiteSpace(report.Error))
        {
            sb.AppendLine();
            sb.AppendLine($"Error: {report.Error}");
        }

        return sb.ToString();
    }
}
