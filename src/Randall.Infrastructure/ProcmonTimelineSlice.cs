using System.Diagnostics;
using System.Globalization;
using System.Text;

namespace Randall.Infrastructure;

/// <summary>
/// Convert a run's Procmon <c>fuzz.pml</c> to CSV and filter rows into the mini-timeline window.
/// Soft-fails when Procmon is missing or the PML is locked/incomplete.
/// </summary>
public static class ProcmonTimelineSlice
{
    public static string? FindPmlForRun(string? repoRoot, string? runId, string? projectName = null)
    {
        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        if (!string.IsNullOrWhiteSpace(runId))
        {
            var direct = Path.Combine(repoRoot, "data", "runs", runId, "fuzz.pml");
            if (File.Exists(direct))
                return direct;
            // RunId may already be an absolute directory name under data/runs
            var alt = Path.Combine(repoRoot, "data", "runs", runId.Replace('/', Path.DirectorySeparatorChar), "fuzz.pml");
            if (File.Exists(alt))
                return alt;
        }

        var runsRoot = Path.Combine(repoRoot, "data", "runs");
        if (!Directory.Exists(runsRoot))
            return null;

        IEnumerable<string> dirs = Directory.EnumerateDirectories(runsRoot);
        if (!string.IsNullOrWhiteSpace(projectName))
        {
            dirs = dirs.Where(d =>
                Path.GetFileName(d).StartsWith(projectName + "_", StringComparison.OrdinalIgnoreCase));
        }

        return dirs
            .Select(d => Path.Combine(d, "fuzz.pml"))
            .Where(File.Exists)
            .OrderByDescending(f => File.GetLastWriteTimeUtc(f))
            .FirstOrDefault();
    }

    /// <summary>
    /// Returns path to filtered CSV and row count, or null on soft-fail.
    /// </summary>
    public static (string? FilteredCsv, int Rows, string? Note) TrySlice(
        string? pmlPath,
        string outDir,
        DateTimeOffset windowStart,
        DateTimeOffset windowEnd,
        string? targetExe = null,
        string? repoRoot = null)
    {
        if (string.IsNullOrWhiteSpace(pmlPath) || !File.Exists(pmlPath))
            return (null, 0, "Procmon PML not found (enable fuzz.procmonCapture for run bookends)");

        var exe = ProcmonCapture.DiscoverExecutable(repoRoot);
        if (exe is null)
            return (null, 0, "Procmon.exe not found — cannot convert .pml to CSV");

        Directory.CreateDirectory(outDir);
        var rawDir = Path.Combine(outDir, "raw");
        Directory.CreateDirectory(rawDir);
        var rawCsv = Path.Combine(rawDir, "procmon_raw.csv");
        if (File.Exists(rawCsv))
        {
            try { File.Delete(rawCsv); } catch { /* */ }
        }

        // Headless convert. May fail if PML is still locked by a live capture — soft-fail.
        var args = $"/AcceptEula /Quiet /OpenLog \"{pmlPath}\" /SaveAs \"{rawCsv}\"";
        var (code, err) = Run(exe, args, 300_000);
        if (!File.Exists(rawCsv) || new FileInfo(rawCsv).Length < 8)
        {
            // Retry SaveAs with .CSV extension hint some builds prefer
            var rawCsv2 = Path.Combine(rawDir, "procmon_raw_save.csv");
            args = $"/AcceptEula /OpenLog \"{pmlPath}\" /SaveAs \"{rawCsv2}\" /SaveApplyFilter";
            (code, err) = Run(exe, args, 300_000);
            if (File.Exists(rawCsv2) && new FileInfo(rawCsv2).Length >= 8)
                rawCsv = rawCsv2;
            else
                return (null, 0, $"Procmon CSV convert failed (exit={code}): {Trim(err)} — stop capture first if PML is locked");
        }

        var filtered = Path.Combine(outDir, "procmon.csv");
        var rows = FilterCsv(rawCsv, filtered, windowStart, windowEnd, targetExe);
        return (filtered, rows, rows > 0 ? null : "Procmon CSV converted but 0 rows in window");
    }

    private static int FilterCsv(
        string rawCsv,
        string filteredCsv,
        DateTimeOffset start,
        DateTimeOffset end,
        string? targetExe)
    {
        var lines = File.ReadAllLines(rawCsv);
        if (lines.Length == 0)
        {
            File.WriteAllText(filteredCsv, "");
            return 0;
        }

        var header = lines[0];
        var cols = SplitCsv(header);
        var timeIdx = FindCol(cols, "Time of Day", "TimeOfDay", "Date & Time", "Timestamp", "Time");
        var processIdx = FindCol(cols, "Process Name", "ProcessName", "Image Path", "Path");
        var exeLeaf = string.IsNullOrWhiteSpace(targetExe)
            ? null
            : Path.GetFileNameWithoutExtension(targetExe);
        var exeFile = string.IsNullOrWhiteSpace(targetExe) ? null : Path.GetFileName(targetExe);

        var kept = new List<string> { header };
        for (var i = 1; i < lines.Length; i++)
        {
            var line = lines[i];
            if (string.IsNullOrWhiteSpace(line)) continue;
            var fields = SplitCsv(line);

            if (timeIdx >= 0 && timeIdx < fields.Count)
            {
                if (!TryParseProcmonTime(fields[timeIdx], start.Date, out var ts))
                    continue;
                // Procmon "Time of Day" is often local clock without date — pin to anchor day.
                var utc = ts.ToUniversalTime();
                // Allow same local-day ambiguity: compare time-of-day against window in local and UTC.
                if (!InWindow(utc, start, end) && !InWindow(ts, start.ToLocalTime(), end.ToLocalTime()))
                    continue;
            }

            if (exeLeaf is not null && processIdx >= 0 && processIdx < fields.Count)
            {
                var proc = fields[processIdx];
                if (proc.IndexOf(exeLeaf, StringComparison.OrdinalIgnoreCase) < 0 &&
                    (exeFile is null || proc.IndexOf(exeFile, StringComparison.OrdinalIgnoreCase) < 0))
                {
                    // Keep CreateProcess / load-image of the target even if Process Name differs
                    if (line.IndexOf(exeLeaf, StringComparison.OrdinalIgnoreCase) < 0)
                        continue;
                }
            }

            kept.Add(line);
            if (kept.Count > 50_001) // header + 50k
                break;
        }

        File.WriteAllLines(filteredCsv, kept, Encoding.UTF8);
        return Math.Max(0, kept.Count - 1);
    }

    private static bool InWindow(DateTimeOffset ts, DateTimeOffset start, DateTimeOffset end) =>
        ts >= start && ts <= end;

    private static bool TryParseProcmonTime(string raw, DateTime anchorDate, out DateTimeOffset ts)
    {
        raw = raw.Trim().Trim('"');
        if (DateTimeOffset.TryParse(raw, CultureInfo.InvariantCulture,
                DateTimeStyles.AllowWhiteSpaces, out ts))
            return true;
        if (DateTime.TryParse(raw, CultureInfo.CurrentCulture, DateTimeStyles.AllowWhiteSpaces, out var local))
        {
            // Time-of-day only → combine with crash day
            if (raw.Length <= 16 && !raw.Contains('-') && !raw.Contains('/'))
            {
                var combined = anchorDate.Date + local.TimeOfDay;
                ts = new DateTimeOffset(DateTime.SpecifyKind(combined, DateTimeKind.Local));
                return true;
            }

            ts = new DateTimeOffset(local);
            return true;
        }

        ts = default;
        return false;
    }

    private static int FindCol(IReadOnlyList<string> cols, params string[] names)
    {
        for (var i = 0; i < cols.Count; i++)
        {
            var c = cols[i].Trim().Trim('"');
            foreach (var n in names)
            {
                if (c.Equals(n, StringComparison.OrdinalIgnoreCase))
                    return i;
            }
        }

        for (var i = 0; i < cols.Count; i++)
        {
            var c = cols[i].Trim().Trim('"');
            if (c.Contains("time", StringComparison.OrdinalIgnoreCase))
                return i;
        }

        return -1;
    }

    private static List<string> SplitCsv(string line)
    {
        var result = new List<string>();
        var sb = new StringBuilder();
        var inQuotes = false;
        for (var i = 0; i < line.Length; i++)
        {
            var ch = line[i];
            if (ch == '"')
            {
                if (inQuotes && i + 1 < line.Length && line[i + 1] == '"')
                {
                    sb.Append('"');
                    i++;
                }
                else inQuotes = !inQuotes;
            }
            else if (ch == ',' && !inQuotes)
            {
                result.Add(sb.ToString());
                sb.Clear();
            }
            else sb.Append(ch);
        }

        result.Add(sb.ToString());
        return result;
    }

    private static (int Code, string Err) Run(string exe, string args, int timeoutMs)
    {
        var psi = new ProcessStartInfo
        {
            FileName = exe,
            Arguments = args,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        using var proc = Process.Start(psi);
        if (proc is null) return (-1, "failed to start");
        var stdout = proc.StandardOutput.ReadToEnd();
        var stderr = proc.StandardError.ReadToEnd();
        if (!proc.WaitForExit(timeoutMs))
        {
            try { proc.Kill(entireProcessTree: true); } catch { /* */ }
            return (-1, "timeout");
        }

        return (proc.ExitCode, string.IsNullOrWhiteSpace(stderr) ? stdout : stderr);
    }

    private static string Trim(string? s)
    {
        if (string.IsNullOrWhiteSpace(s)) return "";
        s = s.Replace('\r', ' ').Replace('\n', ' ').Trim();
        return s.Length <= 200 ? s : s[..200] + "…";
    }
}
