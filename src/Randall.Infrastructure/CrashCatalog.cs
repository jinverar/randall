using System.Diagnostics;
using Randall.Contracts;

namespace Randall.Infrastructure;

public static class CrashCatalog
{
    public static string? FindRepoRoot()
    {
        var starts = new[]
        {
            Directory.GetCurrentDirectory(),
            AppContext.BaseDirectory,
        };

        foreach (var start in starts)
        {
            if (string.IsNullOrWhiteSpace(start))
                continue;

            var dir = new DirectoryInfo(Path.GetFullPath(start));
            while (dir is not null)
            {
                if (File.Exists(Path.Combine(dir.FullName, "Randall.sln")))
                    return dir.FullName;
                dir = dir.Parent;
            }
        }

        return null;
    }

    public static IReadOnlyList<CrashSummaryDto> ListAll(string? repoRoot = null, string? projectFilter = null)
    {
        repoRoot ??= FindRepoRoot();
        if (repoRoot is null)
            return [];

        var crashesRoot = Path.Combine(repoRoot, "data", "crashes");
        if (!Directory.Exists(crashesRoot))
            return [];

        var results = new List<CrashSummaryDto>();
        foreach (var dir in Directory.EnumerateDirectories(crashesRoot))
        {
            var projectName = Path.GetFileName(dir);
            if (projectFilter is not null &&
                !projectName.Equals(projectFilter, StringComparison.OrdinalIgnoreCase))
                continue;

            var store = new CrashStore(dir);
            foreach (var c in store.List())
            {
                var analysisPath = CrashAnalysisWriter.AnalysisPathFor(dir, c.Id);
                var analysis = CrashAnalysisWriter.TryRead(analysisPath);
                var sidecar = CrashSidecarWriter.TryRead(c.SidecarPath);
                var hint = analysis?.ExceptionHint
                    ?? sidecar?.ExceptionHint
                    ?? WindowsExceptionHints.Describe(
                        int.TryParse(c.TargetExitCode, out var ec) ? ec : null);
                var summary = new CrashSummaryDto(
                    c.Id, c.Project, c.Iteration, c.Mutator, c.InputHash, c.InputPath,
                    c.MiniDumpPath, c.TargetExitCode, c.TriageTag, c.SidecarPath, c.RunId, c.At);
                var triage = CrashTriage.Classify(analysis, sidecar, summary);

                results.Add(new CrashSummaryDto(
                    c.Id,
                    c.Project,
                    c.Iteration,
                    c.Mutator,
                    c.InputHash,
                    c.InputPath,
                    c.MiniDumpPath,
                    c.TargetExitCode,
                    c.TriageTag,
                    c.SidecarPath,
                    c.RunId,
                    c.At,
                    triage.Class,
                    triage.Severity,
                    triage.FaultAddress ?? analysis?.FaultAddress,
                    triage.ExceptionHint ?? hint,
                    triage.ClusterKey));
            }
        }

        return results.OrderByDescending(c => c.ObservedAt).ToList();
    }

    public static IReadOnlyList<CrashClusterDto> ListClusters(string? repoRoot = null, string? projectFilter = null)
    {
        var crashes = ListAll(repoRoot, projectFilter);
        return CrashCluster.Build(crashes, repoRoot)
            .Select(c => new CrashClusterDto(
                c.ClusterId,
                c.Project,
                c.Count,
                c.RepresentativeId,
                c.RepresentativeHash,
                c.RepresentativeMutator,
                c.LengthBucket,
                c.CrashClass,
                c.Severity,
                c.ExceptionHint,
                c.FaultAddress))
            .ToList();
    }

    public static CrashDetailDto? GetDetail(Guid id, string? repoRoot = null)
    {
        foreach (var summary in ListAll(repoRoot))
        {
            if (summary.Id != id)
                continue;
            if (!File.Exists(summary.InputPath))
            {
                var missingTriage = CrashTriage.Classify(null, null, summary);
                return new CrashDetailDto(summary, 0, "(file missing)", "(file missing)", null, null, missingTriage);
            }

            var bytes = File.ReadAllBytes(summary.InputPath);
            var previewLen = Math.Min(bytes.Length, 256);
            var hex = string.Join(' ', bytes.AsSpan(0, previewLen).ToArray().Select(b => b.ToString("X2")));
            if (bytes.Length > previewLen)
                hex += " …";
            var ascii = BuildAsciiPreview(bytes, previewLen);
            var sidecar = CrashSidecarWriter.TryRead(summary.SidecarPath);
            var crashesDir = Path.GetDirectoryName(summary.InputPath)!;
            var analysisPath = CrashAnalysisWriter.AnalysisPathFor(crashesDir, summary.Id);
            var analysis = CrashAnalysisWriter.TryRead(analysisPath)
                ?? (summary.MiniDumpPath is not null
                    ? CrashAnalysisWriter.AnalyzeDump(summary.MiniDumpPath)
                    : null);
            var triage = CrashTriage.Classify(analysis, sidecar, summary, bytes);
            return new CrashDetailDto(summary, bytes.Length, hex, ascii, sidecar, analysis, triage);
        }
        return null;
    }

    internal static string BuildAsciiPreview(ReadOnlySpan<byte> bytes, int previewLen)
    {
        var chars = new char[previewLen];
        for (var i = 0; i < previewLen; i++)
        {
            var b = bytes[i];
            chars[i] = b is >= 32 and <= 126 ? (char)b : '.';
        }
        var text = new string(chars);
        if (bytes.Length > previewLen)
            text += " …";
        return text;
    }

    public static IReadOnlyList<TargetProfileDto> ListTargets(string? repoRoot = null)
    {
        repoRoot ??= FindRepoRoot();
        if (repoRoot is null)
            return [];

        var projectsDir = Path.Combine(repoRoot, "projects");
        var list = new List<TargetProfileDto>();
        foreach (var path in ProjectLoader.DiscoverAll(repoRoot))
        {
            try
            {
                var p = ProjectLoader.Load(path);
                list.Add(new TargetProfileDto(p.Name, p.Kind, p.Description, path));
            }
            catch { /* skip invalid project */ }
        }
        return list;
    }
}

public sealed class ReplayEngine
{
    public async Task<TargetRunResult> ReplayAsync(
        ProjectConfig project,
        string yamlPath,
        byte[] payload,
        CancellationToken cancellationToken = default)
    {
        Process? server = null;
        if (project.Kind.Equals("tcp", StringComparison.OrdinalIgnoreCase) && project.Target.LongLived)
            server = TargetRunner.StartTarget(project, yamlPath, null);

        try
        {
            return await TargetRunner.RunPayloadAsync(project, yamlPath, payload, server, cancellationToken);
        }
        finally
        {
            if (server is { HasExited: false })
            {
                server.Kill(entireProcessTree: true);
                server.Dispose();
            }
        }
    }
}
