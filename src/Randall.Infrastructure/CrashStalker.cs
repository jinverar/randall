using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>Leg 5 — Scream: path dedup and first-diverge from drcov traces (Phase 4).</summary>
public static class CrashStalker
{
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

        var manifest = $"""
            Randall triage bundle
            Crash: {crashId}
            Project: {detail.Summary.Project}
            Iteration: {detail.Summary.Iteration}
            Mutator: {detail.Summary.Mutator}
            InputHash: {detail.Summary.InputHash}
            Input: crash_input.bin
            Minidump: {(dumpCopy is null ? "(none)" : Path.GetFileName(dumpCopy))}
            Drcov sample: {(drcovPath is null ? "(none)" : "sample.drcov.log")}
            """;
        File.WriteAllText(Path.Combine(exportDir, "README.txt"), manifest);

        IReadOnlyList<string>? edges = null;
        var drcovCopy = Path.Combine(exportDir, "sample.drcov.log");
        if (File.Exists(drcovCopy))
            edges = DrcovParser.ParseEdges(drcovCopy);

        var bundle = new TriageBundleDto(
            crashId,
            detail.Summary.Project,
            inputCopy,
            dumpCopy,
            drcovPath is null ? null : drcovCopy,
            null,
            exportDir);

        GhidraExporter.WriteArtifacts(exportDir, bundle, edges);
        return bundle with { FirstDivergeIndex = null };
    }
}
