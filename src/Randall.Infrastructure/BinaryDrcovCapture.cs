using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Optional Dragon Dance sidecar: binary drcov (no <c>-dump_text</c>) next to Randfuzz text traces.
/// Fuzz path stays text for <see cref="DrcovParser"/>; binary logs live under <c>traces-binary/</c>.
/// </summary>
public static class BinaryDrcovCapture
{
    public const string RelativeDirName = "traces-binary";

    public static string BinaryTraceDir(string corpusDir) =>
        Path.Combine(corpusDir, RelativeDirName);

    public static string BinaryTraceDirForProject(ProjectConfig project, string yamlPath)
    {
        var corpusDir = ProjectLoader.ResolvePath(yamlPath, project.Fuzz.CorpusDir);
        return BinaryTraceDir(corpusDir);
    }

    /// <summary>
    /// One-shot binary drcov for Dragon Dance. File targets only (needs <c>{file}</c> input bytes).
    /// </summary>
    public static async Task<BinaryCaptureResult> CaptureFileAsync(
        ProjectConfig project,
        string yamlPath,
        byte[] input,
        string? outputDir = null,
        CancellationToken cancellationToken = default)
    {
        var dynamo = DynamoRioRunner.Discover();
        if (!dynamo.IsAvailable)
        {
            return new BinaryCaptureResult(
                false,
                null,
                null,
                $"DynamoRIO not found — {DynamoRioRunner.InstallHint}");
        }

        var kind = (project.Kind ?? "file").Trim().ToLowerInvariant();
        if (kind is not ("file" or "harness"))
        {
            return new BinaryCaptureResult(
                false,
                null,
                null,
                "Binary drcov sidecar is for file/harness targets. For TCP, capture manually with drrun (no -dump_text).");
        }

        var dir = string.IsNullOrWhiteSpace(outputDir)
            ? BinaryTraceDirForProject(project, yamlPath)
            : Path.GetFullPath(outputDir);
        Directory.CreateDirectory(dir);

        var run = await dynamo.RunWithCoverageAsync(
            project,
            yamlPath,
            input,
            dir,
            dumpText: false,
            cancellationToken);

        return new BinaryCaptureResult(
            run.Success && !string.IsNullOrWhiteSpace(run.TracePath),
            run.TracePath,
            run.ExitCode,
            run.Success
                ? $"binary drcov → {run.TracePath}"
                : run.Detail);
    }

    /// <summary>Copy newest binary log(s) into an export directory for Dragon Dance.</summary>
    public static IReadOnlyList<string> CopySidecarsInto(string corpusDir, string exportDir, int maxFiles = 3)
    {
        var binDir = BinaryTraceDir(corpusDir);
        if (!Directory.Exists(binDir))
            return [];

        Directory.CreateDirectory(exportDir);
        var copied = new List<string>();
        foreach (var src in Directory.EnumerateFiles(binDir, "*.log")
                     .Select(p => new FileInfo(p))
                     .Where(f => f.Exists && f.Length > 0)
                     .OrderByDescending(f => f.LastWriteTimeUtc)
                     .Take(Math.Max(1, maxFiles)))
        {
            var destName = "binary_" + src.Name;
            var dest = Path.Combine(exportDir, destName);
            File.Copy(src.FullName, dest, overwrite: true);
            copied.Add(dest);
        }

        return copied;
    }

    public static string? FindLatest(string corpusDir)
    {
        var binDir = BinaryTraceDir(corpusDir);
        if (!Directory.Exists(binDir))
            return null;
        return Directory.EnumerateFiles(binDir, "*.log")
            .Select(p => new FileInfo(p))
            .Where(f => f.Exists && f.Length > 0)
            .OrderByDescending(f => f.LastWriteTimeUtc)
            .Select(f => f.FullName)
            .FirstOrDefault();
    }
}

public sealed record BinaryCaptureResult(
    bool Success,
    string? TracePath,
    int? ExitCode,
    string Detail);
