using System.IO.Compression;
using System.Text;
using System.Text.Json;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Analyst-facing fuzz session browser: list/open/close/save/export/import completed
/// run journals under data/runs/ (flat JSON/JSONL). Recursive folder import walks for run.json.
/// </summary>
public static class FuzzSessionArchive
{
    public const string PackKind = "fuzz-session-pack";
    public const int PackVersion = 1;
    private const string PackManifestName = "session-pack.json";
    private const string OpenStateFile = "open.json";
    private const string SessionMetaFile = "session.json";

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
    };

    private static readonly object Gate = new();

    public static string SessionsRoot(string? repoRoot = null)
    {
        repoRoot ??= CrashCatalog.FindRepoRoot()
                     ?? throw new InvalidOperationException("Could not locate repo root (Randall.sln).");
        return Path.GetFullPath(Path.Combine(repoRoot, "data", "sessions"));
    }

    public static string RunsRoot(string? repoRoot = null)
    {
        repoRoot ??= CrashCatalog.FindRepoRoot()
                     ?? throw new InvalidOperationException("Could not locate repo root (Randall.sln).");
        return Path.GetFullPath(Path.Combine(repoRoot, "data", "runs"));
    }

    public static FuzzSessionOpenStateDto GetOpenState(string? repoRoot = null)
    {
        try
        {
            var path = Path.Combine(SessionsRoot(repoRoot), OpenStateFile);
            if (!File.Exists(path))
                return new FuzzSessionOpenStateDto(null, null, null);
            var state = JsonSerializer.Deserialize<FuzzSessionOpenStateDto>(File.ReadAllText(path), JsonOpts);
            return state ?? new FuzzSessionOpenStateDto(null, null, null);
        }
        catch
        {
            return new FuzzSessionOpenStateDto(null, null, null);
        }
    }

    public static FuzzSessionOpenStateDto Open(string runId, string? repoRoot = null)
    {
        if (string.IsNullOrWhiteSpace(runId))
            throw new ArgumentException("runId required", nameof(runId));

        repoRoot ??= CrashCatalog.FindRepoRoot()
                     ?? throw new InvalidOperationException("Could not locate repo root (Randall.sln).");

        var manifest = LoadManifest(runId, repoRoot)
                       ?? throw new FileNotFoundException($"No run.json for session '{runId}'");
        var label = TryReadLabel(FindRunDirectory(runId, repoRoot));
        var state = new FuzzSessionOpenStateDto(manifest.RunId, manifest.Project, DateTimeOffset.UtcNow, label);
        PersistOpenState(state, repoRoot);
        return state;
    }

    public static FuzzSessionOpenStateDto Close(string? repoRoot = null)
    {
        var empty = new FuzzSessionOpenStateDto(null, null, null);
        PersistOpenState(empty, repoRoot);
        return empty;
    }

    public static FuzzSessionListResultDto List(string? project = null, string? repoRoot = null, int limit = 64)
    {
        repoRoot ??= CrashCatalog.FindRepoRoot()
                     ?? throw new InvalidOperationException("Could not locate repo root (Randall.sln).");
        var opened = GetOpenState(repoRoot);
        // Build saved-dir index once — per-row EnumerateDirectories was freezing the UI when
        // /api/sessions was polled from every dashboard paint.
        var savedIndex = BuildSavedIndex(repoRoot);
        var sessions = EnumerateManifests(repoRoot)
            .Where(m => string.IsNullOrWhiteSpace(project)
                        || m.Project.Equals(project, StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(m => m.CompletedAt ?? m.StartedAt)
            .Take(Math.Clamp(limit, 1, 200))
            .Select(m =>
            {
                // Prefer O(1) path under data/runs/<runId> — avoid AllDirectories scan on list.
                var runsDirect = Path.Combine(RunsRoot(repoRoot), m.RunId);
                var dir = Directory.Exists(runsDirect) && File.Exists(Path.Combine(runsDirect, "run.json"))
                    ? runsDirect
                    : FindRunDirectory(m.RunId, repoRoot) ?? "";
                var label = TryReadLabel(dir);
                var saved = savedIndex.Contains(m.RunId)
                            || (!string.IsNullOrWhiteSpace(label) && savedIndex.Contains("label:" + label));
                return new FuzzSessionSummaryDto(
                    m.RunId,
                    m.Project,
                    m.Kind,
                    m.StartedAt,
                    m.CompletedAt,
                    m.Iterations,
                    m.CrashesFound,
                    m.CoverageGuided,
                    label,
                    dir,
                    saved);
            })
            .ToList();

        return new FuzzSessionListResultDto(sessions, opened.RunId, opened.Project);
    }

    private static HashSet<string> BuildSavedIndex(string repoRoot)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var savedRoot = Path.Combine(SessionsRoot(repoRoot), "saved");
        if (!Directory.Exists(savedRoot))
            return set;
        foreach (var dir in Directory.EnumerateDirectories(savedRoot))
        {
            var name = Path.GetFileName(dir);
            set.Add(name);
            var label = TryReadLabel(dir);
            if (!string.IsNullOrWhiteSpace(label))
                set.Add("label:" + label);
            // Also index by embedded runId suffix when present in folder name.
            var underscore = name.LastIndexOf('_');
            if (underscore > 0 && underscore < name.Length - 1)
                set.Add(name[(underscore + 1)..]);
        }

        return set;
    }

    public static FuzzRunManifestDto? LoadManifest(string runId, string? repoRoot = null)
    {
        var dir = FindRunDirectory(runId, repoRoot);
        if (dir is null)
            return null;
        var path = Path.Combine(dir, "run.json");
        if (!File.Exists(path))
            return null;
        try
        {
            return JsonSerializer.Deserialize<FuzzRunManifestDto>(File.ReadAllText(path), JsonOpts);
        }
        catch
        {
            return null;
        }
    }

    public static FuzzSessionSaveResultDto Save(FuzzSessionSaveRequest request, string? repoRoot = null)
    {
        repoRoot ??= CrashCatalog.FindRepoRoot()
                     ?? throw new InvalidOperationException("Could not locate repo root (Randall.sln).");

        var runId = request.RunId;
        if (string.IsNullOrWhiteSpace(runId))
        {
            var opened = GetOpenState(repoRoot);
            runId = opened.RunId;
            if (string.IsNullOrWhiteSpace(runId) && !string.IsNullOrWhiteSpace(request.Project))
            {
                runId = List(request.Project, repoRoot, 1).Sessions.FirstOrDefault()?.RunId;
            }
        }

        if (string.IsNullOrWhiteSpace(runId))
            throw new InvalidOperationException("No runId — Open a session or pass runId/project.");

        var manifest = LoadManifest(runId, repoRoot)
                       ?? throw new FileNotFoundException($"No run.json for session '{runId}'");
        var src = FindRunDirectory(runId, repoRoot)
                  ?? throw new DirectoryNotFoundException($"Run folder missing for '{runId}'");

        var label = string.IsNullOrWhiteSpace(request.Label)
            ? $"{manifest.Project}_{manifest.StartedAt:yyyyMMdd_HHmmss}"
            : SanitizeLabel(request.Label!);

        WriteSessionMeta(src, label, manifest);

        var savedRoot = Path.Combine(SessionsRoot(repoRoot), "saved");
        Directory.CreateDirectory(savedRoot);
        var destName = $"{SanitizeLabel(label)}_{manifest.RunId}";
        var dest = Path.Combine(savedRoot, destName);
        CopyDirectory(src, dest, overwrite: true);
        WriteSessionMeta(dest, label, manifest);

        return new FuzzSessionSaveResultDto(
            manifest.RunId,
            manifest.Project,
            label,
            dest,
            $"Saved session '{label}' → {dest}");
    }

    public static FuzzSessionExportResultDto Export(FuzzSessionExportRequest request, string? repoRoot = null)
    {
        if (string.IsNullOrWhiteSpace(request.RunId))
            throw new ArgumentException("runId required");

        repoRoot ??= CrashCatalog.FindRepoRoot()
                     ?? throw new InvalidOperationException("Could not locate repo root (Randall.sln).");

        var manifest = LoadManifest(request.RunId, repoRoot)
                       ?? throw new FileNotFoundException($"No run.json for session '{request.RunId}'");
        var src = FindRunDirectory(request.RunId, repoRoot)
                  ?? throw new DirectoryNotFoundException($"Run folder missing for '{request.RunId}'");

        var outputPath = request.OutputPath;
        if (string.IsNullOrWhiteSpace(outputPath))
        {
            outputPath = Path.Combine(
                repoRoot,
                "data",
                "exports",
                $"{manifest.Project}_session_{DateTimeOffset.UtcNow:yyyyMMdd_HHmmss}.zip");
        }

        outputPath = Path.GetFullPath(outputPath);
        Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);
        if (File.Exists(outputPath))
            File.Delete(outputPath);

        var staging = Path.Combine(Path.GetTempPath(), $"randall_session_{Guid.NewGuid():N}");
        var crashCount = 0;
        try
        {
            Directory.CreateDirectory(staging);
            CopyDirectory(src, Path.Combine(staging, "run"));

            if (request.IncludeLinkedCrashes)
            {
                var crashesDir = Path.Combine(repoRoot, "data", "crashes", manifest.Project);
                if (Directory.Exists(crashesDir))
                {
                    var store = new CrashStore(crashesDir);
                    var linked = store.List(manifest.Project)
                        .Where(c => string.Equals(c.RunId, manifest.RunId, StringComparison.OrdinalIgnoreCase))
                        .ToList();
                    if (linked.Count > 0)
                    {
                        var crashDest = Path.Combine(staging, "crashes", manifest.Project);
                        Directory.CreateDirectory(crashDest);
                        // Copy whole project crash tree so index/sidecars stay coherent; filter is by run on import.
                        CopyDirectory(crashesDir, crashDest);
                        crashCount = linked.Count;
                        File.WriteAllText(
                            Path.Combine(staging, "linked-crash-ids.json"),
                            JsonSerializer.Serialize(linked.Select(c => c.Id).ToList(), JsonOpts));
                    }
                }
            }

            var pack = new
            {
                version = PackVersion,
                kind = PackKind,
                runId = manifest.RunId,
                project = manifest.Project,
                exportedAt = DateTimeOffset.UtcNow,
                sourceHost = Environment.MachineName,
                sourceRunDir = src,
                includeLinkedCrashes = request.IncludeLinkedCrashes,
                crashCount,
            };
            File.WriteAllText(
                Path.Combine(staging, PackManifestName),
                JsonSerializer.Serialize(pack, JsonOpts));

            ZipFile.CreateFromDirectory(staging, outputPath, CompressionLevel.Optimal, includeBaseDirectory: false);
            return new FuzzSessionExportResultDto(
                outputPath,
                manifest.RunId,
                manifest.Project,
                new FileInfo(outputPath).Length,
                crashCount,
                "export");
        }
        finally
        {
            try { Directory.Delete(staging, recursive: true); } catch { /* ignore */ }
        }
    }

    /// <summary>
    /// Import a zip session pack, a single run folder (with run.json), or recursively scan a tree
    /// of completed fuzz test folders for run.json / crash trees.
    /// </summary>
    public static FuzzSessionImportResultDto Import(FuzzSessionImportRequest request, string? repoRoot = null)
    {
        if (string.IsNullOrWhiteSpace(request.Path))
            throw new ArgumentException("path required");

        var path = Path.GetFullPath(request.Path);
        if (!File.Exists(path) && !Directory.Exists(path))
            throw new FileNotFoundException($"Import path not found: {path}");

        repoRoot ??= CrashCatalog.FindRepoRoot()
                     ?? throw new InvalidOperationException("Could not locate repo root (Randall.sln).");

        if (File.Exists(path) && path.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
            return ImportZip(path, repoRoot, request.OverwriteFiles);

        return ImportFolderTree(path, repoRoot, request.Recursive, request.OverwriteFiles);
    }

    public static string? FindRunDirectory(string runId, string? repoRoot = null)
    {
        if (string.IsNullOrWhiteSpace(runId))
            return null;
        repoRoot ??= CrashCatalog.FindRepoRoot();
        if (repoRoot is null)
            return null;

        var runsRoot = RunsRoot(repoRoot);
        var direct = Path.Combine(runsRoot, runId);
        if (Directory.Exists(direct) && File.Exists(Path.Combine(direct, "run.json")))
            return direct;

        // Saved snapshots
        var saved = Path.Combine(SessionsRoot(repoRoot), "saved");
        if (Directory.Exists(saved))
        {
            foreach (var dir in Directory.EnumerateDirectories(saved))
            {
                if (!Path.GetFileName(dir).Contains(runId, StringComparison.OrdinalIgnoreCase))
                    continue;
                if (File.Exists(Path.Combine(dir, "run.json")))
                    return dir;
            }
        }

        // Slow scan of runs root (custom nested layouts)
        if (Directory.Exists(runsRoot))
        {
            foreach (var dir in Directory.EnumerateDirectories(runsRoot, "*", SearchOption.AllDirectories))
            {
                if (!string.Equals(Path.GetFileName(dir), runId, StringComparison.OrdinalIgnoreCase))
                    continue;
                if (File.Exists(Path.Combine(dir, "run.json")))
                    return dir;
            }
        }

        return null;
    }

    private static FuzzSessionImportResultDto ImportZip(string zipPath, string repoRoot, bool overwrite)
    {
        var staging = Path.Combine(Path.GetTempPath(), $"randall_session_in_{Guid.NewGuid():N}");
        try
        {
            Directory.CreateDirectory(staging);
            ZipFile.ExtractToDirectory(zipPath, staging, overwriteFiles: true);

            var packPath = Path.Combine(staging, PackManifestName);
            if (File.Exists(packPath))
            {
                using var doc = JsonDocument.Parse(File.ReadAllText(packPath));
                var kind = doc.RootElement.TryGetProperty("kind", out var k) ? k.GetString() : null;
                if (!string.Equals(kind, PackKind, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException($"Unexpected session pack kind: {kind}");
            }

            var runSrc = Path.Combine(staging, "run");
            if (!Directory.Exists(runSrc) || !File.Exists(Path.Combine(runSrc, "run.json")))
            {
                // Allow zip that is just a run folder
                if (File.Exists(Path.Combine(staging, "run.json")))
                    runSrc = staging;
                else
                    return ImportFolderTree(staging, repoRoot, recursive: true, overwrite);
            }

            var imported = ImportRunDirectory(runSrc, repoRoot, overwrite, out var runId);
            var crashTrees = 0;
            var crashesSrc = Path.Combine(staging, "crashes");
            if (Directory.Exists(crashesSrc))
            {
                foreach (var projDir in Directory.EnumerateDirectories(crashesSrc))
                {
                    var project = Path.GetFileName(projDir);
                    var dest = Path.Combine(repoRoot, "data", "crashes", project);
                    Directory.CreateDirectory(dest);
                    CopyDirectory(projDir, dest, overwrite, excludeFileNames: ["index.jsonl"]);
                    MergeCrashIndex(projDir, dest);
                    crashTrees++;
                }
            }

            var ids = imported && runId is not null ? new List<string> { runId } : new List<string>();
            return new FuzzSessionImportResultDto(
                imported ? 1 : 0,
                imported ? 0 : 1,
                crashTrees,
                imported
                    ? $"Imported session '{runId}' (+ {crashTrees} crash tree(s))."
                    : "Session already present (skipped).",
                ids);
        }
        finally
        {
            try { Directory.Delete(staging, recursive: true); } catch { /* ignore */ }
        }
    }

    private static FuzzSessionImportResultDto ImportFolderTree(
        string rootPath,
        string repoRoot,
        bool recursive,
        bool overwrite)
    {
        var option = recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly;
        var runDirs = new List<string>();
        if (File.Exists(Path.Combine(rootPath, "run.json")))
            runDirs.Add(rootPath);

        if (Directory.Exists(rootPath))
        {
            foreach (var file in Directory.EnumerateFiles(rootPath, "run.json", option))
            {
                var dir = Path.GetDirectoryName(file)!;
                if (!runDirs.Contains(dir, StringComparer.OrdinalIgnoreCase))
                    runDirs.Add(dir);
            }
        }

        var importedRuns = 0;
        var skipped = 0;
        var runIds = new List<string>();
        foreach (var dir in runDirs)
        {
            if (ImportRunDirectory(dir, repoRoot, overwrite, out var runId))
            {
                importedRuns++;
                if (runId is not null)
                    runIds.Add(runId);
            }
            else
            {
                skipped++;
            }
        }

        // Also pick up data/crashes/<project> trees (or bare crash folders with index.jsonl).
        var crashTrees = 0;
        if (Directory.Exists(rootPath))
        {
            foreach (var index in Directory.EnumerateFiles(rootPath, "index.jsonl", option))
            {
                var crashDir = Path.GetDirectoryName(index)!;
                // Heuristic: parent of index.jsonl is project crash folder
                var project = Path.GetFileName(crashDir);
                if (string.IsNullOrWhiteSpace(project) || project.Equals("crashes", StringComparison.OrdinalIgnoreCase))
                    continue;
                // Prefer folder that looks like a crash store (has *_crash.json or inputs)
                var hasCrashArtifacts = Directory.EnumerateFiles(crashDir, "*_crash.json").Any()
                                        || Directory.EnumerateFiles(crashDir, "*.bin").Any()
                                        || Directory.EnumerateFiles(crashDir, "input_*").Any();
                if (!hasCrashArtifacts && !File.Exists(Path.Combine(crashDir, "index.jsonl")))
                    continue;

                var dest = Path.Combine(repoRoot, "data", "crashes", project);
                Directory.CreateDirectory(dest);
                CopyDirectory(crashDir, dest, overwrite, excludeFileNames: ["index.jsonl"]);
                MergeCrashIndex(crashDir, dest);
                crashTrees++;
            }
        }

        var msg = $"Imported {importedRuns} run(s), skipped {skipped}, merged {crashTrees} crash tree(s) from {rootPath}.";
        return new FuzzSessionImportResultDto(importedRuns, skipped, crashTrees, msg, runIds);
    }

    private static bool ImportRunDirectory(string srcDir, string repoRoot, bool overwrite, out string? runId)
    {
        runId = null;
        var manifestPath = Path.Combine(srcDir, "run.json");
        if (!File.Exists(manifestPath))
            return false;

        FuzzRunManifestDto? manifest;
        try
        {
            manifest = JsonSerializer.Deserialize<FuzzRunManifestDto>(File.ReadAllText(manifestPath), JsonOpts);
        }
        catch
        {
            return false;
        }

        if (manifest is null || string.IsNullOrWhiteSpace(manifest.RunId))
            return false;

        runId = manifest.RunId;
        var dest = Path.Combine(RunsRoot(repoRoot), manifest.RunId);
        if (Directory.Exists(dest) && !overwrite)
        {
            // Still consider present
            return false;
        }

        CopyDirectory(srcDir, dest, overwrite: true);
        return true;
    }

    private static void MergeCrashIndex(string srcCrashDir, string destCrashDir)
    {
        var packedIndex = Path.Combine(srcCrashDir, "index.jsonl");
        var destIndex = Path.Combine(destCrashDir, "index.jsonl");
        if (!File.Exists(packedIndex))
            return;

        var existingIds = new HashSet<Guid>();
        if (File.Exists(destIndex))
        {
            foreach (var line in File.ReadLines(destIndex))
            {
                if (string.IsNullOrWhiteSpace(line))
                    continue;
                try
                {
                    using var doc = JsonDocument.Parse(line);
                    if (doc.RootElement.TryGetProperty("id", out var idEl)
                        && Guid.TryParse(idEl.GetString(), out var id))
                        existingIds.Add(id);
                    else if (doc.RootElement.TryGetProperty("Id", out var idEl2)
                             && Guid.TryParse(idEl2.GetString(), out var id2))
                        existingIds.Add(id2);
                }
                catch
                {
                    /* skip */
                }
            }
        }

        var append = new List<string>();
        foreach (var line in File.ReadLines(packedIndex))
        {
            if (string.IsNullOrWhiteSpace(line))
                continue;
            try
            {
                using var doc = JsonDocument.Parse(line);
                Guid id = default;
                if (doc.RootElement.TryGetProperty("id", out var idEl))
                    Guid.TryParse(idEl.GetString(), out id);
                else if (doc.RootElement.TryGetProperty("Id", out var idEl2))
                    Guid.TryParse(idEl2.GetString(), out id);
                if (id != default && existingIds.Contains(id))
                    continue;
                if (id != default)
                    existingIds.Add(id);
                append.Add(line.TrimEnd('\r', '\n'));
            }
            catch
            {
                /* skip */
            }
        }

        if (append.Count > 0)
            File.AppendAllLines(destIndex, append, Encoding.UTF8);
    }

    private static IEnumerable<FuzzRunManifestDto> EnumerateManifests(string repoRoot)
    {
        var runsRoot = RunsRoot(repoRoot);
        if (!Directory.Exists(runsRoot))
            yield break;

        foreach (var dir in Directory.EnumerateDirectories(runsRoot))
        {
            var path = Path.Combine(dir, "run.json");
            if (!File.Exists(path))
                continue;
            FuzzRunManifestDto? m = null;
            try
            {
                m = JsonSerializer.Deserialize<FuzzRunManifestDto>(File.ReadAllText(path), JsonOpts);
            }
            catch
            {
                /* skip */
            }

            if (m is not null)
                yield return m;
        }
    }

    private static void PersistOpenState(FuzzSessionOpenStateDto state, string? repoRoot)
    {
        lock (Gate)
        {
            var root = SessionsRoot(repoRoot);
            Directory.CreateDirectory(root);
            File.WriteAllText(Path.Combine(root, OpenStateFile), JsonSerializer.Serialize(state, JsonOpts));
        }
    }

    private static void WriteSessionMeta(string runDir, string label, FuzzRunManifestDto manifest)
    {
        var meta = new
        {
            label,
            runId = manifest.RunId,
            project = manifest.Project,
            savedAt = DateTimeOffset.UtcNow,
            iterations = manifest.Iterations,
            crashesFound = manifest.CrashesFound,
        };
        File.WriteAllText(Path.Combine(runDir, SessionMetaFile), JsonSerializer.Serialize(meta, JsonOpts));
    }

    private static string? TryReadLabel(string? runDir)
    {
        if (string.IsNullOrWhiteSpace(runDir))
            return null;
        var path = Path.Combine(runDir, SessionMetaFile);
        if (!File.Exists(path))
            return null;
        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(path));
            return doc.RootElement.TryGetProperty("label", out var l) ? l.GetString() : null;
        }
        catch
        {
            return null;
        }
    }

    private static string SanitizeLabel(string label)
    {
        var chars = label.Trim().Select(c =>
            char.IsLetterOrDigit(c) || c is '-' or '_' ? c : '_').ToArray();
        var s = new string(chars);
        return string.IsNullOrWhiteSpace(s) ? "session" : s[..Math.Min(s.Length, 64)];
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
