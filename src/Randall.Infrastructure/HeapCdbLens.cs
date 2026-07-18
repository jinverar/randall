using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Next-gen heap enrichment via headless cdb (<c>!heap -s</c>, page-heap clues).
/// Falls back gracefully when Debugging Tools are absent.
/// </summary>
public static class HeapCdbLens
{
    public static MemoryLensReportDto Enrich(MemoryLensReportDto report, string? dumpPath)
    {
        if (string.IsNullOrWhiteSpace(dumpPath) || !File.Exists(dumpPath))
            return report;

        var cdb = DebuggerTools.FindCdb();
        if (cdb is null)
        {
            return report with
            {
                HeapBackend = report.HeapBackend ?? "patterns",
                HeapSummaryLines = report.HeapSummaryLines ??
                [
                    "cdb not found — heap summary limited to fill-pattern lens.",
                    "Install Debugging Tools for Windows for !heap enrichment.",
                ],
            };
        }

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = cdb,
                Arguments = $"-z \"{dumpPath}\" -c \".echo RANDFUZZ_HEAP_BEGIN; !heap -s; .echo RANDFUZZ_HEAP_END; .echo RANDFUZZ_PAGEHEAP_BEGIN; !heap -p; .echo RANDFUZZ_PAGEHEAP_END; qd\"",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };

            using var proc = Process.Start(psi);
            if (proc is null)
                return report with { HeapBackend = "patterns", HeapSummaryLines = ["Failed to start cdb"] };

            var stdoutTask = proc.StandardOutput.ReadToEndAsync();
            var stderrTask = proc.StandardError.ReadToEndAsync();
            if (!proc.WaitForExit(25_000))
            {
                try { proc.Kill(entireProcessTree: true); } catch { /* ignore */ }
                return report with
                {
                    HeapBackend = "patterns",
                    HeapSummaryLines = ["cdb !heap timed out — using pattern lens only"],
                };
            }

            var text = stdoutTask.GetAwaiter().GetResult() + "\n" + stderrTask.GetAwaiter().GetResult();
            var heapLines = ExtractBlock(text, "RANDFUZZ_HEAP_BEGIN", "RANDFUZZ_HEAP_END");
            var pageLines = ExtractBlock(text, "RANDFUZZ_PAGEHEAP_BEGIN", "RANDFUZZ_PAGEHEAP_END");
            var summary = new List<string>();
            summary.AddRange(SummarizeHeap(heapLines));
            var pageHeap = DetectPageHeap(pageLines, text);
            if (pageHeap)
                summary.Insert(0, "Page Heap fingerprints detected in debugger output.");
            if (summary.Count == 0)
                summary.Add("cdb ran but produced no parseable !heap summary.");

            var lines = report.SummaryLines.ToList();
            if (pageHeap)
                lines.Insert(Math.Min(2, lines.Count),
                    "Hint: Page Heap active or page-heap clutter in dump — strong UAF signal path.");
            foreach (var s in summary.Take(3))
            {
                if (!lines.Contains(s))
                    lines.Add(s);
            }

            return report with
            {
                SummaryLines = lines,
                HeapSummaryLines = summary.Concat(heapLines.Take(12)).Distinct().ToList(),
                PageHeapLikely = pageHeap || report.PageHeapLikely,
                HeapBackend = "cdb",
                Confidence = pageHeap || report.Confidence == "high" ? "high" : report.Confidence,
            };
        }
        catch (Exception ex)
        {
            return report with
            {
                HeapBackend = "patterns",
                HeapSummaryLines = [$"cdb heap enrich failed: {ex.Message}"],
            };
        }
    }

    private static List<string> ExtractBlock(string text, string begin, string end)
    {
        var lines = new List<string>();
        var started = false;
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            if (line.Contains(begin, StringComparison.Ordinal))
            {
                started = true;
                continue;
            }

            if (line.Contains(end, StringComparison.Ordinal))
                break;
            if (started && !string.IsNullOrWhiteSpace(line))
                lines.Add(line.Trim());
        }

        return lines;
    }

    private static List<string> SummarizeHeap(IReadOnlyList<string> heapLines)
    {
        var summary = new List<string>();
        foreach (var line in heapLines)
        {
            if (Regex.IsMatch(line, @"Heap|Segments|Virtual|Busy|Free", RegexOptions.IgnoreCase) &&
                line.Length < 160)
                summary.Add(line);
            if (summary.Count >= 6)
                break;
        }

        return summary;
    }

    private static bool DetectPageHeap(IReadOnlyList<string> pageLines, string fullText)
    {
        var blob = string.Join('\n', pageLines) + "\n" + fullText;
        return Regex.IsMatch(blob, @"page\s*heap|PAGEHEAP|hpa\s+enabled", RegexOptions.IgnoreCase);
    }
}
