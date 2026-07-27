using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using Randall.Contracts;
using Randall.Infrastructure.Mutators;

namespace Randall.Infrastructure;

public sealed record SavedCrash(
    Guid Id,
    string Project,
    int Iteration,
    string Mutator,
    string InputHash,
    string InputPath,
    string? TargetExitCode,
    string? MiniDumpPath,
    string? TriageTag,
    string? SidecarPath,
    string? RunId,
    DateTimeOffset At);

public sealed record SavedCrashResult(SavedCrash Crash, bool IsNew);

public sealed class CrashStore(string crashesDir)
{
    private static readonly ConcurrentDictionary<string, object> IndexLocks = new(StringComparer.OrdinalIgnoreCase);

    private readonly string _indexPath = Path.Combine(crashesDir, "index.jsonl");
    private readonly string _corruptPath = Path.Combine(crashesDir, "index.jsonl.corrupt");
    private readonly object _gate = IndexLocks.GetOrAdd(
        Path.GetFullPath(crashesDir),
        static _ => new object());

    public void Ensure()
    {
        Directory.CreateDirectory(crashesDir);
    }

    public SavedCrash? FindByHash(string hash, string project)
    {
        lock (_gate)
        {
            return FindByHashUnlocked(hash, project);
        }
    }

    public SavedCrash Save(
        string project,
        int iteration,
        string mutator,
        byte[] input,
        int? exitCode,
        string? miniDumpPath = null,
        string? triageTag = null,
        string? runId = null,
        Func<Guid, CrashSidecarDto>? buildSidecar = null) =>
        SaveEx(project, iteration, mutator, input, exitCode, miniDumpPath, triageTag, runId, buildSidecar).Crash;

    /// <summary>Save crash; <see cref="SavedCrashResult.IsNew"/> is false when input hash already exists.</summary>
    public SavedCrashResult SaveEx(
        string project,
        int iteration,
        string mutator,
        byte[] input,
        int? exitCode,
        string? miniDumpPath = null,
        string? triageTag = null,
        string? runId = null,
        Func<Guid, CrashSidecarDto>? buildSidecar = null)
    {
        Ensure();
        var hash = InputHash.StackHash(input);

        lock (_gate)
        {
            var existing = FindByHashUnlocked(hash, project);
            if (existing is not null)
                return new SavedCrashResult(existing, false);

            var id = Guid.NewGuid();
            var fileName = $"{project}_{iteration}_{hash}.bin";
            var inputPath = Path.Combine(crashesDir, fileName);
            AtomicFile.WriteAllBytes(inputPath, input);

            string? sidecarPath = null;
            if (buildSidecar is not null)
                sidecarPath = CrashSidecarWriter.Write(crashesDir, buildSidecar(id));

            var record = new SavedCrash(
                id,
                project,
                iteration,
                mutator,
                hash,
                inputPath,
                exitCode?.ToString(),
                miniDumpPath,
                triageTag,
                sidecarPath,
                runId,
                DateTimeOffset.UtcNow);
            AppendIndexLine(JsonSerializer.Serialize(record));
            return new SavedCrashResult(record, true);
        }
    }

    /// <summary>
    /// List crash index entries. Corrupt / null-byte / non-JSON lines are skipped,
    /// appended to <c>index.jsonl.corrupt</c>, and never throw.
    /// </summary>
    public IReadOnlyList<SavedCrash> List(string? project = null)
    {
        lock (_gate)
        {
            return ListUnlocked(project);
        }
    }

    private SavedCrash? FindByHashUnlocked(string hash, string project) =>
        ListUnlocked(project).FirstOrDefault(c =>
            c.InputHash.Equals(hash, StringComparison.OrdinalIgnoreCase));

    private IReadOnlyList<SavedCrash> ListUnlocked(string? project)
    {
        if (!File.Exists(_indexPath))
            return [];

        string[] lines;
        try
        {
            lines = File.ReadAllLines(_indexPath);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[CrashStore] warn: cannot read {_indexPath}: {ex.Message}");
            return [];
        }

        var list = new List<SavedCrash>();
        var bad = new List<string>();
        foreach (var line in lines)
        {
            if (string.IsNullOrWhiteSpace(line))
                continue;
            if (IsCorruptJsonLine(line))
            {
                bad.Add(line);
                continue;
            }

            try
            {
                var c = JsonSerializer.Deserialize<SavedCrash>(line);
                if (c is null)
                {
                    bad.Add(line);
                    continue;
                }

                if (project is null || c.Project.Equals(project, StringComparison.OrdinalIgnoreCase))
                    list.Add(c);
            }
            catch (Exception ex)
            {
                bad.Add(line);
                Console.Error.WriteLine(
                    $"[CrashStore] warn: skipping corrupt index line in {crashesDir}: {ex.Message}");
            }
        }

        if (bad.Count > 0)
            QuarantineBadLines(bad);

        return list;
    }

    private void AppendIndexLine(string jsonLine)
    {
        var payload = Encoding.UTF8.GetBytes(jsonLine + Environment.NewLine);
        // Exclusive append so concurrent readers never see a torn mid-line write from us.
        using var fs = new FileStream(
            _indexPath,
            FileMode.Append,
            FileAccess.Write,
            FileShare.Read,
            bufferSize: 4096,
            FileOptions.WriteThrough);
        fs.Write(payload, 0, payload.Length);
        fs.Flush(flushToDisk: true);
    }

    private void QuarantineBadLines(IReadOnlyList<string> badLines)
    {
        try
        {
            Ensure();
            var stamp = DateTimeOffset.UtcNow.ToString("o");
            var block = new StringBuilder();
            foreach (var line in badLines)
            {
                block.Append("# quarantined ").Append(stamp).AppendLine();
                // Preserve raw bytes as base64 when the line is mostly NUL / non-text.
                if (line.Any(ch => ch == '\0' || char.IsControl(ch) && ch is not '\t' and not '\r' and not '\n'))
                    block.Append("base64:").AppendLine(Convert.ToBase64String(Encoding.UTF8.GetBytes(line)));
                else
                    block.AppendLine(line);
            }

            File.AppendAllText(_corruptPath, block.ToString());

            // Rewrite index without the bad lines (research-safe: originals live in .corrupt).
            var kept = new List<string>();
            foreach (var line in File.ReadAllLines(_indexPath))
            {
                if (string.IsNullOrWhiteSpace(line))
                    continue;
                if (IsCorruptJsonLine(line))
                    continue;
                try
                {
                    _ = JsonSerializer.Deserialize<SavedCrash>(line);
                    kept.Add(line);
                }
                catch
                {
                    /* already quarantined */
                }
            }

            AtomicFile.WriteAllText(_indexPath, kept.Count == 0
                ? string.Empty
                : string.Join(Environment.NewLine, kept) + Environment.NewLine);

            Console.Error.WriteLine(
                $"[CrashStore] warn: quarantined {badLines.Count} corrupt index line(s) → {_corruptPath}");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[CrashStore] warn: quarantine failed: {ex.Message}");
        }
    }

    internal static bool IsCorruptJsonLine(string line)
    {
        if (string.IsNullOrWhiteSpace(line))
            return true;
        // NUL / BOM-only / garbage that cannot be a JSON object/array/value start.
        if (line[0] == '\0' || line.Contains('\0'))
            return true;
        var trimmed = line.TrimStart();
        if (trimmed.Length == 0)
            return true;
        var c = trimmed[0];
        return c is not ('{' or '[' or '"' or '-' or 't' or 'f' or 'n')
               && !char.IsDigit(c);
    }
}

/// <summary>Temp-file + replace writes so readers never see a half-written JSON/binary.</summary>
public static class AtomicFile
{
    public static void WriteAllText(string path, string contents)
    {
        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrWhiteSpace(dir))
            Directory.CreateDirectory(dir);
        var tmp = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            File.WriteAllText(tmp, contents);
            File.Move(tmp, path, overwrite: true);
        }
        finally
        {
            try { if (File.Exists(tmp)) File.Delete(tmp); } catch { /* ignore */ }
        }
    }

    public static void WriteAllBytes(string path, byte[] bytes)
    {
        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrWhiteSpace(dir))
            Directory.CreateDirectory(dir);
        var tmp = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            File.WriteAllBytes(tmp, bytes);
            File.Move(tmp, path, overwrite: true);
        }
        finally
        {
            try { if (File.Exists(tmp)) File.Delete(tmp); } catch { /* ignore */ }
        }
    }
}
