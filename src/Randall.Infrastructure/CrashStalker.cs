using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>Leg 5 — Scream: path dedup and first-diverge from drcov traces (Phase 4).</summary>
public static class CrashStalker
{
    /// <summary>
    /// Sequential diverge index when both traces preserve BB-table order.
    /// Prefer <see cref="FindNovelFocus"/> for set-based crash-vs-baseline focus.
    /// </summary>
    public static int? FindFirstDiverge(string? traceA, string? traceB)
    {
        if (string.IsNullOrWhiteSpace(traceA) || string.IsNullOrWhiteSpace(traceB))
            return null;

        var a = DrcovParser.ParseEdges(traceA);
        var b = DrcovParser.ParseEdges(traceB);
        var min = Math.Min(a.Count, b.Count);
        for (var i = 0; i < min; i++)
        {
            if (!a[i].Equals(b[i], StringComparison.OrdinalIgnoreCase))
                return i;
        }
        if (a.Count != b.Count)
            return min;
        return null;
    }

    /// <summary>First crash edge (by address) not present in baseline — Ghidra focus target.</summary>
    public static (string? Edge, long? Rva, int? Index) FindNovelFocus(
        IReadOnlyList<string> crashEdges,
        IReadOnlyList<string> baselineEdges)
    {
        var baseSet = baselineEdges.ToHashSet(StringComparer.OrdinalIgnoreCase);
        for (var i = 0; i < crashEdges.Count; i++)
        {
            var edge = crashEdges[i];
            if (baseSet.Contains(edge))
                continue;
            var parts = edge.Split(':');
            if (parts.Length < 2)
                continue;
            var s = parts[1].Trim();
            if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                s = s[2..];
            if (!long.TryParse(s, System.Globalization.NumberStyles.HexNumber,
                    System.Globalization.CultureInfo.InvariantCulture, out var rva))
                continue;
            return (edge, rva, i);
        }

        return (null, null, null);
    }

    public static TriageBundleDto? ExportBundle(Guid crashId, string? repoRoot = null)
    {
        repoRoot ??= CrashCatalog.FindRepoRoot();
        if (repoRoot is null)
            return null;

        var detail = CrashCatalog.GetDetail(crashId, repoRoot);
        if (detail is null)
            return null;

        var exportDir = Path.Combine(repoRoot, "data", "exports", crashId.ToString("N"));
        Directory.CreateDirectory(exportDir);

        var inputCopy = Path.Combine(exportDir, "crash_input.bin");
        File.Copy(detail.Summary.InputPath, inputCopy, overwrite: true);

        string? drcovPath = null;
        var sidecar = CrashSidecarWriter.TryRead(detail.Summary.SidecarPath);
        if (sidecar?.TraceCopyPath is not null && File.Exists(sidecar.TraceCopyPath))
            drcovPath = sidecar.TraceCopyPath;
        else if (sidecar?.TracePath is not null && File.Exists(sidecar.TracePath))
            drcovPath = sidecar.TracePath;
        else
        {
            var corpusTraces = Path.Combine(repoRoot, "data", "corpus", detail.Summary.Project, "traces");
            if (Directory.Exists(corpusTraces))
            {
                drcovPath = Directory.EnumerateFiles(corpusTraces, "*.log")
                    .OrderByDescending(File.GetLastWriteTimeUtc)
                    .FirstOrDefault();
            }
        }

        if (drcovPath is not null && File.Exists(drcovPath))
            File.Copy(drcovPath, Path.Combine(exportDir, "sample.drcov.log"), overwrite: true);

        string? dumpCopy = null;
        if (detail.Summary.MiniDumpPath is not null && File.Exists(detail.Summary.MiniDumpPath))
        {
            dumpCopy = Path.Combine(exportDir, Path.GetFileName(detail.Summary.MiniDumpPath));
            File.Copy(detail.Summary.MiniDumpPath, dumpCopy, overwrite: true);
        }

        IReadOnlyList<string> edges = [];
        var drcovCopy = Path.Combine(exportDir, "sample.drcov.log");
        if (File.Exists(drcovCopy))
            edges = DrcovParser.ParseEdges(drcovCopy);

        var baselineEdges = LoadBaselineEdges(detail.Summary.Project, repoRoot);
        var (divergeEdge, goToRva, divergeIndex) = FindNovelFocus(edges, baselineEdges);

        var manifest = $"""
            Randfuzz triage bundle
            Crash: {crashId}
            Project: {detail.Summary.Project}
            Iteration: {detail.Summary.Iteration}
            Mutator: {detail.Summary.Mutator}
            InputHash: {detail.Summary.InputHash}
            Input: crash_input.bin
            Minidump: {(dumpCopy is null ? "(none)" : Path.GetFileName(dumpCopy))}
            Drcov sample: {(drcovPath is null ? "(none)" : "sample.drcov.log")}
            Coverage edges: {edges.Count}
            Baseline edges: {baselineEdges.Count}
            Focus diverge: {divergeEdge ?? "(none)"}
            Ghidra: run ghidra_import.py in Script Manager (see GHIDRA_README.txt)
            """;
        File.WriteAllText(Path.Combine(exportDir, "README.txt"), manifest);

        var bundle = new TriageBundleDto(
            crashId,
            detail.Summary.Project,
            inputCopy,
            dumpCopy,
            File.Exists(drcovCopy) ? drcovCopy : null,
            divergeIndex,
            exportDir);

        GhidraExporter.WriteArtifacts(exportDir, bundle, edges, baselineEdges, goToRva, divergeEdge);
        return bundle with { FirstDivergeIndex = divergeIndex };
    }

    private static IReadOnlyList<string> LoadBaselineEdges(string project, string repoRoot)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var layer in StalkCampaignStore.ListLayers(project, repoRoot))
        {
            if (!layer.Tag.Contains("base", StringComparison.OrdinalIgnoreCase))
                continue;
            foreach (var e in StalkCampaignStore.LoadEdges(project, layer.Id, repoRoot))
                set.Add(e);
        }

        if (set.Count == 0)
        {
            var corpus = Path.Combine(repoRoot, "data", "corpus", project, "edges.txt");
            if (File.Exists(corpus))
            {
                foreach (var line in File.ReadLines(corpus))
                {
                    if (!string.IsNullOrWhiteSpace(line))
                        set.Add(line.Trim());
                }
            }
        }

        return set.ToList();
    }
}
