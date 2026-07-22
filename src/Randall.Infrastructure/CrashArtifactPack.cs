using System.IO.Compression;
using System.Text;
using System.Text.Json;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Zip a project's crash tree (inputs, dumps, analysis, memory lens, optional runs)
/// for offline backup and import into another Randfuzz console.
/// </summary>
public static class CrashArtifactPack
{
    public const string Kind = "crash-artifact-pack";
    public const int Version = 1;
    private const string ManifestName = "pack.json";

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
    };

    public static CrashArtifactPackResultDto Export(
        string project,
        string? outputPath = null,
        bool includeRuns = true,
        string? repoRoot = null)
    {
        if (string.IsNullOrWhiteSpace(project))
            throw new ArgumentException("project required", nameof(project));

        repoRoot ??= CrashCatalog.FindRepoRoot()
                     ?? throw new InvalidOperationException("Could not locate repo root (Randall.sln).");

        var crashesDir = Path.GetFullPath(Path.Combine(repoRoot, "data", "crashes", project));
        if (!Directory.Exists(crashesDir))
            throw new DirectoryNotFoundException($"No crash data for project '{project}' at {crashesDir}");

        var store = new CrashStore(crashesDir);
        var crashes = store.List(project);
        var runIds = crashes
            .Select(c => c.RunId)
            .Where(id => !string.IsNullOrWhiteSpace(id))
            .Select(id => id!)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        outputPath ??= Path.Combine(
            repoRoot,
            "data",
            "exports",
            $"{project}_artifacts_{DateTimeOffset.UtcNow:yyyyMMdd_HHmmss}.zip");
        outputPath = Path.GetFullPath(outputPath);
        Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);
        if (File.Exists(outputPath))
            File.Delete(outputPath);

        var runsRoot = Path.Combine(repoRoot, "data", "runs");
        var staging = Path.Combine(Path.GetTempPath(), $"randall_crashpack_{Guid.NewGuid():N}");
        var runCount = 0;
        try
        {
            Directory.CreateDirectory(staging);
            var crashesDest = Path.Combine(staging, "crashes");
            CopyDirectory(crashesDir, crashesDest);

            if (includeRuns && runIds.Count > 0 && Directory.Exists(runsRoot))
            {
                var runsDest = Path.Combine(staging, "runs");
                Directory.CreateDirectory(runsDest);
                foreach (var runId in runIds)
                {
                    var src = Path.Combine(runsRoot, runId);
                    if (!Directory.Exists(src))
                        continue;
                    CopyDirectory(src, Path.Combine(runsDest, runId));
                    runCount++;
                }
            }

            var manifest = new CrashArtifactPackManifest(
                Version,
                Kind,
                project,
                DateTimeOffset.UtcNow,
                Environment.MachineName,
                crashesDir,
                Directory.Exists(runsRoot) ? Path.GetFullPath(runsRoot) : null,
                includeRuns,
                crashes.Count,
                runCount);
            File.WriteAllText(
                Path.Combine(staging, ManifestName),
                JsonSerializer.Serialize(manifest, JsonOpts));

            ZipFile.CreateFromDirectory(staging, outputPath, CompressionLevel.Optimal, includeBaseDirectory: false);
            var size = new FileInfo(outputPath).Length;
            return new CrashArtifactPackResultDto(outputPath, project, size, crashes.Count, runCount, "export");
        }
        finally
        {
            try { Directory.Delete(staging, recursive: true); } catch { /* ignore */ }
        }
    }

    public static CrashArtifactPackImportResultDto Import(
        string zipPath,
        string? repoRoot = null,
        bool overwriteFiles = true)
    {
        zipPath = Path.GetFullPath(zipPath);
        if (!File.Exists(zipPath))
            throw new FileNotFoundException($"Pack not found: {zipPath}");

        repoRoot ??= CrashCatalog.FindRepoRoot()
                     ?? throw new InvalidOperationException("Could not locate repo root (Randall.sln).");

        var staging = Path.Combine(Path.GetTempPath(), $"randall_crashpack_in_{Guid.NewGuid():N}");
        try
        {
            Directory.CreateDirectory(staging);
            ZipFile.ExtractToDirectory(zipPath, staging, overwriteFiles: true);

            var manifestPath = Path.Combine(staging, ManifestName);
            if (!File.Exists(manifestPath))
                throw new InvalidDataException("Not a crash artifact pack (missing pack.json).");

            var manifest = JsonSerializer.Deserialize<CrashArtifactPackManifest>(
                               File.ReadAllText(manifestPath), JsonOpts)
                           ?? throw new InvalidDataException("Invalid pack.json");

            if (!string.Equals(manifest.Kind, Kind, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException($"Unexpected pack kind: {manifest.Kind}");

            var project = manifest.Project;
            if (string.IsNullOrWhiteSpace(project))
                throw new InvalidDataException("pack.json missing project");

            var srcCrashes = Path.Combine(staging, "crashes");
            if (!Directory.Exists(srcCrashes))
                throw new InvalidDataException("Pack has no crashes/ directory");

            var destCrashes = Path.GetFullPath(Path.Combine(repoRoot, "data", "crashes", project));
            Directory.CreateDirectory(destCrashes);

            var existing = new CrashStore(destCrashes).List(project);
            var existingIds = existing.Select(c => c.Id).ToHashSet();
            var existingHashes = existing
                .Select(c => c.InputHash)
                .Where(h => !string.IsNullOrWhiteSpace(h))
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            // Keep local index.jsonl — merge packed entries after copy.
            CopyDirectory(srcCrashes, destCrashes, overwriteFiles, excludeFileNames: ["index.jsonl"]);

            RewritePathsUnder(destCrashes, manifest.SourceCrashesDir, destCrashes);

            var packedIndex = Path.Combine(srcCrashes, "index.jsonl");
            var (imported, skipped) = MergePackedIndex(
                destCrashes, packedIndex, manifest.SourceCrashesDir, destCrashes,
                existingIds, existingHashes);

            var importedRuns = 0;
            var srcRuns = Path.Combine(staging, "runs");
            if (Directory.Exists(srcRuns))
            {
                var destRuns = Path.GetFullPath(Path.Combine(repoRoot, "data", "runs"));
                Directory.CreateDirectory(destRuns);
                foreach (var runDir in Directory.EnumerateDirectories(srcRuns))
                {
                    var runId = Path.GetFileName(runDir);
                    var dest = Path.Combine(destRuns, runId);
                    CopyDirectory(runDir, dest, overwriteFiles);
                    if (!string.IsNullOrWhiteSpace(manifest.SourceRunsDir))
                        RewritePathsUnder(dest, manifest.SourceRunsDir, destRuns);
                    if (!string.IsNullOrWhiteSpace(manifest.SourceCrashesDir))
                        RewritePathsUnder(dest, manifest.SourceCrashesDir, destCrashes);
                    importedRuns++;
                }
            }

            var msg = skipped > 0
                ? $"Merged {imported} new crash(es), skipped {skipped} duplicate(s), {importedRuns} run folder(s)."
                : $"Imported {imported} crash(es), {importedRuns} run folder(s).";

            return new CrashArtifactPackImportResultDto(
                project, destCrashes, imported, skipped, importedRuns, msg);
        }
        finally
        {
            try { Directory.Delete(staging, recursive: true); } catch { /* ignore */ }
        }
    }

    /// <summary>Download a pack from a remote agent and optionally import it.</summary>
    public static async Task<CrashArtifactPackResultDto> PullFromAgentAsync(
        string agentUrl,
        string project,
        string? outputPath = null,
        bool includeRuns = true,
        string? token = null,
        CancellationToken ct = default)
    {
        if (!LabAgentClient.TryNormalizeAgentUrl(agentUrl, out var baseUrl, out var err))
            throw new ArgumentException(err ?? "Invalid agent URL");

        var repoRoot = CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        outputPath ??= Path.Combine(
            repoRoot,
            "data",
            "exports",
            $"{project}_from_{SanitizeHost(baseUrl)}_{DateTimeOffset.UtcNow:yyyyMMdd_HHmmss}.zip");
        outputPath = Path.GetFullPath(outputPath);
        Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);

        var q = $"project={Uri.EscapeDataString(project)}&includeRuns={(includeRuns ? "true" : "false")}";
        using var http = new HttpClient { Timeout = TimeSpan.FromMinutes(10) };
        using var req = new HttpRequestMessage(HttpMethod.Get, $"{baseUrl}/api/crashes/pack/download?{q}");
        LabAccess.Apply(req, token);
        using var resp = await http.SendAsync(req, ct);
        if (!resp.IsSuccessStatusCode)
        {
            var body = await resp.Content.ReadAsStringAsync(ct);
            throw new InvalidOperationException(
                resp.StatusCode == System.Net.HttpStatusCode.Unauthorized
                    ? "Agent requires RANDALL_AGENT_TOKEN (set env, --token, or --agent-token)."
                    : $"Agent pack download failed ({(int)resp.StatusCode}): {body}");
        }

        await using (var fs = File.Create(outputPath))
            await resp.Content.CopyToAsync(fs, ct);

        var size = new FileInfo(outputPath).Length;
        // Peek crash count from manifest without full import.
        var (crashCount, runCount) = PeekCounts(outputPath);
        return new CrashArtifactPackResultDto(outputPath, project, size, crashCount, runCount, "pull");
    }

    private static (int crashes, int runs) PeekCounts(string zipPath)
    {
        try
        {
            using var zip = ZipFile.OpenRead(zipPath);
            var entry = zip.GetEntry(ManifestName);
            if (entry is null)
                return (0, 0);
            using var stream = entry.Open();
            using var reader = new StreamReader(stream);
            var manifest = JsonSerializer.Deserialize<CrashArtifactPackManifest>(reader.ReadToEnd(), JsonOpts);
            return manifest is null ? (0, 0) : (manifest.CrashCount, manifest.RunCount);
        }
        catch
        {
            return (0, 0);
        }
    }

    private static string SanitizeHost(string baseUrl)
    {
        try
        {
            var u = new Uri(baseUrl);
            return string.Join('_', u.Host.Split(Path.GetInvalidFileNameChars(), StringSplitOptions.RemoveEmptyEntries));
        }
        catch
        {
            return "agent";
        }
    }

    private static (int imported, int skipped) MergePackedIndex(
        string destCrashes,
        string packedIndexPath,
        string sourceCrashesDir,
        string localCrashesDir,
        HashSet<Guid> existingIds,
        HashSet<string> existingHashes)
    {
        if (!File.Exists(packedIndexPath))
            return (0, 0);

        var destIndex = Path.Combine(destCrashes, "index.jsonl");
        var imported = 0;
        var skipped = 0;
        var append = new List<string>();

        foreach (var line in File.ReadLines(packedIndexPath))
        {
            if (string.IsNullOrWhiteSpace(line))
                continue;

            SavedCrash? c;
            try
            {
                c = JsonSerializer.Deserialize<SavedCrash>(line);
            }
            catch
            {
                continue;
            }

            if (c is null)
                continue;

            if (existingIds.Contains(c.Id) ||
                (!string.IsNullOrWhiteSpace(c.InputHash) && existingHashes.Contains(c.InputHash)))
            {
                skipped++;
                continue;
            }

            var rewritten = ReplacePathPrefix(line, Path.GetFullPath(sourceCrashesDir).TrimEnd('\\', '/'),
                Path.GetFullPath(localCrashesDir).TrimEnd('\\', '/'));
            // Also handle slash-variant prefixes inside the JSON line.
            rewritten = ReplacePathPrefix(
                rewritten,
                Path.GetFullPath(sourceCrashesDir).TrimEnd('\\', '/').Replace('\\', '/'),
                Path.GetFullPath(localCrashesDir).TrimEnd('\\', '/').Replace('\\', '/'));

            append.Add(rewritten.TrimEnd('\r', '\n'));
            existingIds.Add(c.Id);
            if (!string.IsNullOrWhiteSpace(c.InputHash))
                existingHashes.Add(c.InputHash);
            imported++;
        }

        if (append.Count > 0)
            File.AppendAllLines(destIndex, append);

        return (imported, skipped);
    }

    private static void RewritePathsUnder(string rootDir, string oldPrefix, string newPrefix)
    {
        if (string.IsNullOrWhiteSpace(oldPrefix) || string.IsNullOrWhiteSpace(newPrefix))
            return;

        var oldNorm = Path.GetFullPath(oldPrefix).TrimEnd('\\', '/');
        var newNorm = Path.GetFullPath(newPrefix).TrimEnd('\\', '/');
        if (oldNorm.Equals(newNorm, StringComparison.OrdinalIgnoreCase))
            return;

        foreach (var file in Directory.EnumerateFiles(rootDir, "*", SearchOption.AllDirectories))
        {
            var ext = Path.GetExtension(file);
            if (ext is not (".json" or ".jsonl" or ".txt"))
                continue;

            string text;
            try
            {
                text = File.ReadAllText(file);
            }
            catch
            {
                continue;
            }

            var rewritten = ReplacePathPrefix(text, oldNorm, newNorm);
            if (!ReferenceEquals(rewritten, text) && rewritten != text)
                File.WriteAllText(file, rewritten, Encoding.UTF8);
        }
    }

    /// <summary>Replace absolute path prefixes, tolerating / vs \ in JSON strings.</summary>
    internal static string ReplacePathPrefix(string text, string oldPrefix, string newPrefix)
    {
        var variants = new[]
        {
            oldPrefix,
            oldPrefix.Replace('\\', '/'),
            oldPrefix.Replace('/', '\\'),
        }.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();

        var result = text;
        foreach (var old in variants)
        {
            if (string.IsNullOrEmpty(old))
                continue;
            // Case-insensitive replace for Windows paths embedded in JSON.
            var sb = new StringBuilder(result.Length);
            var i = 0;
            while (i < result.Length)
            {
                var idx = result.IndexOf(old, i, StringComparison.OrdinalIgnoreCase);
                if (idx < 0)
                {
                    sb.Append(result, i, result.Length - i);
                    break;
                }

                sb.Append(result, i, idx - i);
                var slashStyle = old.Contains('/') ? '/' : '\\';
                var replacement = slashStyle == '/'
                    ? newPrefix.Replace('\\', '/')
                    : newPrefix.Replace('/', '\\');
                sb.Append(replacement);
                i = idx + old.Length;
            }

            result = sb.ToString();
        }

        return result;
    }

    private static void CopyDirectory(
        string sourceDir,
        string destDir,
        bool overwrite = true,
        IEnumerable<string>? excludeFileNames = null)
    {
        var exclude = excludeFileNames is null
            ? null
            : new HashSet<string>(excludeFileNames, StringComparer.OrdinalIgnoreCase);

        Directory.CreateDirectory(destDir);
        foreach (var file in Directory.EnumerateFiles(sourceDir, "*", SearchOption.AllDirectories))
        {
            if (exclude is not null && exclude.Contains(Path.GetFileName(file)))
                continue;
            var rel = Path.GetRelativePath(sourceDir, file);
            var dest = Path.Combine(destDir, rel);
            Directory.CreateDirectory(Path.GetDirectoryName(dest)!);
            File.Copy(file, dest, overwrite);
        }
    }
}
