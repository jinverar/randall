using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Text.Json;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Crash-scoped Windows mini-timeline using Eric Zimmerman CLIs (EvtxECmd, MFTECmd, …).
/// Soft-fails when tools are missing. Intended for <b>unique</b> screams only — see docs/MINI_TIMELINE.md.
/// </summary>
public static class MiniTimelineCapture
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    public static string TimelineDir(string crashesDir, Guid crashId) =>
        Path.Combine(crashesDir, "timeline", crashId.ToString("N"));

    public static string SummaryPath(string crashesDir, Guid crashId) =>
        Path.Combine(TimelineDir(crashesDir, crashId), "summary.json");

    public static MiniTimelineSummaryDto? TryRead(string crashesDir, Guid crashId)
    {
        var path = SummaryPath(crashesDir, crashId);
        if (!File.Exists(path))
            return null;
        try
        {
            return JsonSerializer.Deserialize<MiniTimelineSummaryDto>(File.ReadAllText(path), JsonOpts);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Capture a mini-timeline around <paramref name="anchorUtc"/>. Returns a summary even on soft-fail
    /// (Ok=false) so callers can log a single line.
    /// </summary>
    public static MiniTimelineSummaryDto TryCapture(
        string crashesDir,
        Guid crashId,
        DateTimeOffset anchorUtc,
        int windowSeconds = 60,
        string? targetExe = null,
        string? repoRoot = null,
        string? projectName = null)
    {
        windowSeconds = Math.Clamp(windowSeconds <= 0 ? 60 : windowSeconds, 5, 3600);
        var windowStart = anchorUtc - TimeSpan.FromSeconds(windowSeconds);
        var windowEnd = anchorUtc + TimeSpan.FromSeconds(windowSeconds);
        var tools = ZimmermanToolPaths.Probe(repoRoot);
        var used = new List<string>();
        var artifacts = new List<string>();
        var notes = new List<string>();

        if (!OperatingSystem.IsWindows())
        {
            var skip = Fail(crashId, windowStart, windowEnd, windowSeconds, projectName, targetExe, anchorUtc,
                "mini-timeline is Windows-only for now (journalctl twin later)");
            WriteSummary(crashesDir, crashId, skip);
            return skip;
        }

        if (!tools.HasCore)
        {
            var skip = Fail(crashId, windowStart, windowEnd, windowSeconds, projectName, targetExe, anchorUtc,
                "EvtxECmd/MFTECmd not found — install EZ tools under tools/ez/ (docs/MINI_TIMELINE.md)");
            WriteSummary(crashesDir, crashId, skip);
            return skip;
        }

        var outDir = TimelineDir(crashesDir, crashId);
        var rawDir = Path.Combine(outDir, "raw");
        Directory.CreateDirectory(rawDir);
        Directory.CreateDirectory(Path.Combine(outDir, "wer"));

        var evtxRows = 0;
        var mftRows = 0;
        var prefetchRows = 0;
        var amcacheRows = 0;
        var werCopied = 0;

        if (tools.EvtxECmd is not null)
        {
            used.Add(tools.EvtxECmd);
            try
            {
                var rawCsv = RunEvtxECmd(tools.EvtxECmd, rawDir, windowStart, windowEnd, notes);
                if (rawCsv is not null && File.Exists(rawCsv))
                {
                    var filtered = Path.Combine(outDir, "evtx.csv");
                    evtxRows = FilterCsvByTime(rawCsv, filtered, windowStart, windowEnd, targetExe);
                    if (evtxRows > 0 || File.Exists(filtered))
                        artifacts.Add(filtered);
                    artifacts.Add(rawCsv);
                }
            }
            catch (Exception ex)
            {
                notes.Add($"EvtxECmd: {ex.Message}");
            }
        }

        if (tools.MFTECmd is not null)
        {
            used.Add(tools.MFTECmd);
            try
            {
                var rawCsv = RunMFTECmd(tools.MFTECmd, rawDir, notes);
                if (rawCsv is not null && File.Exists(rawCsv))
                {
                    var filtered = Path.Combine(outDir, "mft.csv");
                    mftRows = FilterCsvByTime(rawCsv, filtered, windowStart, windowEnd, targetExe);
                    if (File.Exists(filtered))
                        artifacts.Add(filtered);
                    artifacts.Add(rawCsv);
                }
            }
            catch (Exception ex)
            {
                notes.Add($"MFTECmd: {ex.Message}");
            }
        }

        if (tools.PECmd is not null)
        {
            used.Add(tools.PECmd);
            try
            {
                var rawCsv = RunPECmd(tools.PECmd, rawDir, notes);
                if (rawCsv is not null && File.Exists(rawCsv))
                {
                    var filtered = Path.Combine(outDir, "prefetch.csv");
                    prefetchRows = FilterCsvByTime(rawCsv, filtered, windowStart, windowEnd, targetExe);
                    if (File.Exists(filtered))
                        artifacts.Add(filtered);
                    artifacts.Add(rawCsv);
                }
            }
            catch (Exception ex)
            {
                notes.Add($"PECmd: {ex.Message}");
            }
        }

        if (tools.AmcacheParser is not null)
        {
            used.Add(tools.AmcacheParser);
            try
            {
                var rawCsv = RunAmcache(tools.AmcacheParser, rawDir, notes);
                if (rawCsv is not null && File.Exists(rawCsv))
                {
                    var filtered = Path.Combine(outDir, "amcache.csv");
                    amcacheRows = FilterCsvByTime(rawCsv, filtered, windowStart, windowEnd, targetExe);
                    if (File.Exists(filtered))
                        artifacts.Add(filtered);
                    artifacts.Add(rawCsv);
                }
            }
            catch (Exception ex)
            {
                notes.Add($"AmcacheParser: {ex.Message}");
            }
        }

        try
        {
            werCopied = CopyWerReports(Path.Combine(outDir, "wer"), windowStart, windowEnd, targetExe, artifacts);
        }
        catch (Exception ex)
        {
            notes.Add($"WER: {ex.Message}");
        }

        var ok = evtxRows > 0 || mftRows > 0 || prefetchRows > 0 || amcacheRows > 0 || werCopied > 0
                 || artifacts.Count > 0;
        var summaryLine = ok
            ? $"mini-timeline ±{windowSeconds}s: evtx={evtxRows} mft={mftRows} pf={prefetchRows} amcache={amcacheRows} wer={werCopied}"
            : $"mini-timeline soft: no rows in window (±{windowSeconds}s)" +
              (notes.Count > 0 ? $" — {notes[0]}" : "");

        var dto = new MiniTimelineSummaryDto(
            Ok: ok || used.Count > 0,
            Error: ok ? null : (notes.Count > 0 ? string.Join("; ", notes.Take(3)) : "no matching rows"),
            CrashId: crashId,
            Project: projectName,
            TargetExe: targetExe,
            AnchorUtc: anchorUtc,
            WindowStartUtc: windowStart,
            WindowEndUtc: windowEnd,
            WindowSeconds: windowSeconds,
            ToolsUsed: used,
            Artifacts: artifacts.Select(a => a.Replace('\\', '/')).Distinct().ToList(),
            EvtxRows: evtxRows,
            MftRows: mftRows,
            PrefetchRows: prefetchRows,
            AmcacheRows: amcacheRows,
            WerCopied: werCopied,
            Notes: notes,
            SummaryLine: summaryLine,
            CapturedAtUtc: DateTimeOffset.UtcNow);

        var summaryPath = SummaryPath(crashesDir, crashId);
        WriteSummary(crashesDir, crashId, dto);
        return dto;
    }

    private static void WriteSummary(string crashesDir, Guid crashId, MiniTimelineSummaryDto dto)
    {
        var dir = TimelineDir(crashesDir, crashId);
        Directory.CreateDirectory(dir);
        File.WriteAllText(SummaryPath(crashesDir, crashId), JsonSerializer.Serialize(dto, JsonOpts));
    }

    private static MiniTimelineSummaryDto Fail(
        Guid crashId,
        DateTimeOffset windowStart,
        DateTimeOffset windowEnd,
        int windowSeconds,
        string? projectName,
        string? targetExe,
        DateTimeOffset anchorUtc,
        string error) =>
        new(
            Ok: false,
            Error: error,
            CrashId: crashId,
            Project: projectName,
            TargetExe: targetExe,
            AnchorUtc: anchorUtc,
            WindowStartUtc: windowStart,
            WindowEndUtc: windowEnd,
            WindowSeconds: windowSeconds,
            ToolsUsed: [],
            Artifacts: [],
            EvtxRows: 0,
            MftRows: 0,
            PrefetchRows: 0,
            AmcacheRows: 0,
            WerCopied: 0,
            Notes: [error],
            SummaryLine: $"mini-timeline skipped: {error}",
            CapturedAtUtc: DateTimeOffset.UtcNow);

    private static string? RunEvtxECmd(
        string exe, string rawDir, DateTimeOffset start, DateTimeOffset end, List<string> notes)
    {
        var logsDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "System32", "winevt", "Logs");
        if (!Directory.Exists(logsDir))
        {
            notes.Add($"EVTX dir missing: {logsDir}");
            return null;
        }

        // Prefer a few high-signal channels; fall back to whole Logs dir.
        var channels = new[] { "Application.evtx", "System.evtx", "Security.evtx" };
        var existing = channels
            .Select(c => Path.Combine(logsDir, c))
            .Where(File.Exists)
            .ToList();

        var outCsv = Path.Combine(rawDir, "evtx_raw.csv");
        if (File.Exists(outCsv))
            File.Delete(outCsv);

        var sd = start.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
        var ed = end.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);

        if (existing.Count > 0)
        {
            // Concatenate per-channel CSVs into one raw file.
            var parts = new List<string>();
            foreach (var evtx in existing)
            {
                var part = Path.Combine(rawDir, Path.GetFileNameWithoutExtension(evtx) + "_raw.csv");
                if (File.Exists(part)) File.Delete(part);
                var args =
                    $"-f \"{evtx}\" --csv \"{rawDir}\" --csvf \"{Path.GetFileName(part)}\" " +
                    $"--sd \"{sd}\" --ed \"{ed}\"";
                var (code, err) = RunTool(exe, args, 180_000);
                if (code != 0 && !File.Exists(part))
                {
                    // Older builds may lack --sd/--ed — retry without date filter.
                    args = $"-f \"{evtx}\" --csv \"{rawDir}\" --csvf \"{Path.GetFileName(part)}\"";
                    (code, err) = RunTool(exe, args, 180_000);
                }

                if (File.Exists(part))
                    parts.Add(part);
                else if (!string.IsNullOrWhiteSpace(err))
                    notes.Add($"EvtxECmd {Path.GetFileName(evtx)}: {TrimNote(err)}");
            }

            if (parts.Count == 0)
                return null;
            MergeCsvFiles(parts, outCsv);
            return outCsv;
        }

        var argsDir =
            $"-d \"{logsDir}\" --csv \"{rawDir}\" --csvf \"{Path.GetFileName(outCsv)}\" " +
            $"--sd \"{sd}\" --ed \"{ed}\"";
        var (exit, stderr) = RunTool(exe, argsDir, 300_000);
        if (!File.Exists(outCsv))
        {
            argsDir = $"-d \"{logsDir}\" --csv \"{rawDir}\" --csvf \"{Path.GetFileName(outCsv)}\"";
            (exit, stderr) = RunTool(exe, argsDir, 300_000);
        }

        if (!File.Exists(outCsv))
        {
            notes.Add($"EvtxECmd exit={exit}: {TrimNote(stderr)}");
            return null;
        }

        return outCsv;
    }

    private static string? RunMFTECmd(string exe, string rawDir, List<string> notes)
    {
        var candidates = new[]
        {
            @"C:\$MFT",
            Path.Combine(Path.GetPathRoot(Environment.SystemDirectory) ?? "C:\\", "$MFT"),
        };
        string? mft = candidates.FirstOrDefault(File.Exists);
        // Live $MFT often invisible to File.Exists — still try common path.
        mft ??= @"C:\$MFT";

        var outName = "mft_raw.csv";
        var outCsv = Path.Combine(rawDir, outName);
        if (File.Exists(outCsv)) File.Delete(outCsv);
        var args = $"-f \"{mft}\" --csv \"{rawDir}\" --csvf \"{outName}\"";
        var (code, err) = RunTool(exe, args, 300_000);
        if (!File.Exists(outCsv))
        {
            notes.Add($"MFTECmd exit={code}: {TrimNote(err)} (live $MFT often needs elevation)");
            return null;
        }

        return outCsv;
    }

    private static string? RunPECmd(string exe, string rawDir, List<string> notes)
    {
        var prefetch = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");
        if (!Directory.Exists(prefetch))
        {
            notes.Add("Prefetch dir missing");
            return null;
        }

        var outName = "prefetch_raw.csv";
        var outCsv = Path.Combine(rawDir, outName);
        if (File.Exists(outCsv)) File.Delete(outCsv);
        var args = $"-d \"{prefetch}\" --csv \"{rawDir}\" --csvf \"{outName}\"";
        var (code, err) = RunTool(exe, args, 180_000);
        if (!File.Exists(outCsv))
        {
            notes.Add($"PECmd exit={code}: {TrimNote(err)}");
            return null;
        }

        return outCsv;
    }

    private static string? RunAmcache(string exe, string rawDir, List<string> notes)
    {
        var hive = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "appcompat", "Programs", "Amcache.hve");
        if (!File.Exists(hive))
        {
            notes.Add("Amcache.hve missing");
            return null;
        }

        var outName = "amcache_raw.csv";
        var outCsv = Path.Combine(rawDir, outName);
        if (File.Exists(outCsv)) File.Delete(outCsv);
        var args = $"-f \"{hive}\" --csv \"{rawDir}\" --csvf \"{outName}\"";
        var (code, err) = RunTool(exe, args, 180_000);
        // AmcacheParser may emit multiple CSVs; pick the largest csv in rawDir matching *Amcache*
        if (!File.Exists(outCsv))
        {
            var alt = Directory.GetFiles(rawDir, "*Amcache*.csv")
                .OrderByDescending(f => new FileInfo(f).Length)
                .FirstOrDefault();
            if (alt is not null)
            {
                File.Copy(alt, outCsv, overwrite: true);
                return outCsv;
            }

            notes.Add($"AmcacheParser exit={code}: {TrimNote(err)}");
            return null;
        }

        return outCsv;
    }

    private static int CopyWerReports(
        string werOutDir,
        DateTimeOffset start,
        DateTimeOffset end,
        string? targetExe,
        List<string> artifacts)
    {
        var roots = new List<string>();
        var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        if (!string.IsNullOrWhiteSpace(programData))
        {
            roots.Add(Path.Combine(programData, "Microsoft", "Windows", "WER", "ReportArchive"));
            roots.Add(Path.Combine(programData, "Microsoft", "Windows", "WER", "ReportQueue"));
        }

        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (!string.IsNullOrWhiteSpace(local))
        {
            roots.Add(Path.Combine(local, "Microsoft", "Windows", "WER", "ReportArchive"));
            roots.Add(Path.Combine(local, "Microsoft", "Windows", "WER", "ReportQueue"));
        }

        var exeLeaf = string.IsNullOrWhiteSpace(targetExe)
            ? null
            : Path.GetFileNameWithoutExtension(targetExe);
        var copied = 0;
        foreach (var root in roots.Where(Directory.Exists))
        {
            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(root, "Report.wer", SearchOption.AllDirectories);
            }
            catch
            {
                continue;
            }

            foreach (var file in files)
            {
                DateTimeOffset stamp;
                try
                {
                    stamp = new DateTimeOffset(File.GetLastWriteTimeUtc(file), TimeSpan.Zero);
                }
                catch
                {
                    continue;
                }

                if (stamp < start || stamp > end)
                    continue;

                if (exeLeaf is not null)
                {
                    try
                    {
                        var text = File.ReadAllText(file);
                        if (text.IndexOf(exeLeaf, StringComparison.OrdinalIgnoreCase) < 0 &&
                            text.IndexOf(Path.GetFileName(targetExe!), StringComparison.OrdinalIgnoreCase) < 0)
                            continue;
                    }
                    catch
                    {
                        // still copy if unreadable check fails? skip
                        continue;
                    }
                }

                var destName = $"{stamp:yyyyMMdd_HHmmss}_{copied}_{Path.GetFileName(Path.GetDirectoryName(file))}.wer";
                foreach (var c in Path.GetInvalidFileNameChars())
                    destName = destName.Replace(c, '_');
                var dest = Path.Combine(werOutDir, destName);
                try
                {
                    File.Copy(file, dest, overwrite: true);
                    artifacts.Add(dest);
                    copied++;
                    if (copied >= 20)
                        return copied;
                }
                catch
                {
                    // ignore single copy failures
                }
            }
        }

        return copied;
    }

    private static int FilterCsvByTime(
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
        var cols = SplitCsvLine(header);
        var timeIdx = FindTimeColumn(cols);
        var exeLeaf = string.IsNullOrWhiteSpace(targetExe)
            ? null
            : Path.GetFileNameWithoutExtension(targetExe);

        var kept = new List<string> { header };
        for (var i = 1; i < lines.Length; i++)
        {
            var line = lines[i];
            if (string.IsNullOrWhiteSpace(line))
                continue;
            var fields = SplitCsvLine(line);
            if (timeIdx >= 0 && timeIdx < fields.Count)
            {
                if (!TryParseTimestamp(fields[timeIdx], out var ts))
                    continue;
                if (ts < start || ts > end)
                    continue;
            }
            else if (timeIdx < 0)
            {
                // No time column — keep rows that mention the target, else drop to avoid dumping whole MFT.
                if (exeLeaf is null)
                    continue;
                if (line.IndexOf(exeLeaf, StringComparison.OrdinalIgnoreCase) < 0)
                    continue;
            }

            if (exeLeaf is not null &&
                timeIdx >= 0 &&
                line.IndexOf(exeLeaf, StringComparison.OrdinalIgnoreCase) < 0 &&
                // Keep EVTX crash-ish rows even without exe name when in window
                line.IndexOf("1000", StringComparison.Ordinal) < 0 &&
                line.IndexOf("1001", StringComparison.Ordinal) < 0 &&
                line.IndexOf("1002", StringComparison.Ordinal) < 0)
            {
                // Still keep in-window rows; exe filter is a preference not a hard gate for EVTX.
            }

            kept.Add(line);
        }

        File.WriteAllLines(filteredCsv, kept, Encoding.UTF8);
        return Math.Max(0, kept.Count - 1);
    }

    private static int FindTimeColumn(IReadOnlyList<string> cols)
    {
        string[] prefer =
        [
            "TimeCreated", "Timestamp", "TimeStamp", "LastWriteTimestamp",
            "Created0x10", "Created0x30", "LastModified0x10", "LastModified0x30",
            "LastAccess0x10", "LastAccess0x30", "RecordTime", "RunTime", "LastRun",
            "FileKeyLastWriteTimestamp", "LinkDate", "SourceCreatedOn",
        ];
        for (var i = 0; i < cols.Count; i++)
        {
            var c = cols[i].Trim().Trim('"');
            foreach (var p in prefer)
            {
                if (c.Equals(p, StringComparison.OrdinalIgnoreCase))
                    return i;
            }
        }

        for (var i = 0; i < cols.Count; i++)
        {
            var c = cols[i].Trim().Trim('"');
            if (c.Contains("time", StringComparison.OrdinalIgnoreCase) ||
                c.Contains("date", StringComparison.OrdinalIgnoreCase))
                return i;
        }

        return -1;
    }

    private static bool TryParseTimestamp(string raw, out DateTimeOffset ts)
    {
        raw = raw.Trim().Trim('"');
        if (DateTimeOffset.TryParse(raw, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out ts))
            return true;
        if (DateTime.TryParse(raw, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var dt))
        {
            ts = new DateTimeOffset(DateTime.SpecifyKind(dt, DateTimeKind.Utc));
            return true;
        }

        ts = default;
        return false;
    }

    private static List<string> SplitCsvLine(string line)
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
                else
                {
                    inQuotes = !inQuotes;
                }
            }
            else if (ch == ',' && !inQuotes)
            {
                result.Add(sb.ToString());
                sb.Clear();
            }
            else
            {
                sb.Append(ch);
            }
        }

        result.Add(sb.ToString());
        return result;
    }

    private static void MergeCsvFiles(IReadOnlyList<string> parts, string dest)
    {
        using var writer = new StreamWriter(dest, false, Encoding.UTF8);
        var headerWritten = false;
        foreach (var part in parts)
        {
            var lines = File.ReadAllLines(part);
            if (lines.Length == 0) continue;
            if (!headerWritten)
            {
                writer.WriteLine(lines[0]);
                headerWritten = true;
            }

            for (var i = 1; i < lines.Length; i++)
                writer.WriteLine(lines[i]);
        }
    }

    private static (int ExitCode, string Stderr) RunTool(string exe, string args, int timeoutMs)
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
        if (proc is null)
            return (-1, "failed to start");
        var stdout = proc.StandardOutput.ReadToEnd();
        var stderr = proc.StandardError.ReadToEnd();
        if (!proc.WaitForExit(timeoutMs))
        {
            try { proc.Kill(entireProcessTree: true); } catch { /* */ }
            return (-1, "timeout");
        }

        if (string.IsNullOrWhiteSpace(stderr))
            stderr = stdout;
        return (proc.ExitCode, stderr ?? "");
    }

    private static string TrimNote(string? s)
    {
        if (string.IsNullOrWhiteSpace(s))
            return "";
        s = s.Replace('\r', ' ').Replace('\n', ' ').Trim();
        return s.Length <= 240 ? s : s[..240] + "…";
    }
}
