using System.Diagnostics;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>Leg 4 — Stalk: DynamoRIO drrun + drcov wrapper (Windows + Linux).</summary>
public sealed class DynamoRioRunner
{
    public string? DrrunPath { get; init; }
    public string? DrCovClientPath { get; init; }

    public static DynamoRioRunner Discover()
    {
        var env = Environment.GetEnvironmentVariable("DYNAMORIO_HOME");
        if (!string.IsNullOrWhiteSpace(env))
        {
            var fromEnv = FindDrrunUnder(env);
            if (fromEnv is not null)
                return new DynamoRioRunner { DrrunPath = fromEnv };
        }

        var repoRoot = CrashCatalog.FindRepoRoot();
        if (repoRoot is not null)
        {
            var local = FindDrrunUnder(Path.Combine(repoRoot, "tools", "dynamorio"));
            if (local is not null)
                return new DynamoRioRunner { DrrunPath = local };

            var toolsDir = Path.Combine(repoRoot, "tools");
            if (Directory.Exists(toolsDir))
            {
                foreach (var dir in Directory.EnumerateDirectories(toolsDir, "DynamoRIO-*"))
                {
                    var candidate = FindDrrunUnder(dir);
                    if (candidate is not null)
                        return new DynamoRioRunner { DrrunPath = candidate };
                }
            }
        }

        if (OperatingSystem.IsWindows())
        {
            foreach (var home in new[] { @"C:\DynamoRIO", @"C:\tools\dynamorio" })
            {
                var candidate = FindDrrunUnder(home);
                if (candidate is not null)
                    return new DynamoRioRunner { DrrunPath = candidate };
            }
        }
        else
        {
            foreach (var home in new[]
                     {
                         "/opt/dynamorio",
                         "/usr/local/dynamorio",
                         Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                             "dynamorio"),
                     })
            {
                var candidate = FindDrrunUnder(home);
                if (candidate is not null)
                    return new DynamoRioRunner { DrrunPath = candidate };
            }
        }

        return new DynamoRioRunner();
    }

    /// <summary>
    /// Resolve <c>bin64/drrun[.exe]</c> (preferred) or <c>bin32/drrun[.exe]</c> under a DynamoRIO home.
    /// </summary>
    internal static string? FindDrrunUnder(string home)
    {
        if (string.IsNullOrWhiteSpace(home) || !Directory.Exists(home))
            return null;

        foreach (var bin in new[] { "bin64", "bin32" })
        {
            foreach (var name in DrrunNames)
            {
                var path = Path.Combine(home, bin, name);
                if (File.Exists(path))
                    return path;
            }
        }

        return null;
    }

    private static readonly string[] DrrunNames = OperatingSystem.IsWindows()
        ? ["drrun.exe", "drrun"]
        : ["drrun", "drrun.exe"];

    public bool IsAvailable => !string.IsNullOrWhiteSpace(DrrunPath) && File.Exists(DrrunPath);

    public static string InstallHint =>
        OperatingSystem.IsWindows()
            ? "run scripts/install-dynamorio.ps1 or set DYNAMORIO_HOME"
            : "run scripts/install-dynamorio.sh or set DYNAMORIO_HOME";

    public async Task<DrcovRunResult> RunWithCoverageAsync(
        ProjectConfig project,
        string yamlPath,
        byte[] input,
        string traceDir,
        CancellationToken cancellationToken = default)
    {
        if (!IsAvailable)
        {
            return new DrcovRunResult(
                false,
                null,
                null,
                $"DynamoRIO not found — {InstallHint}");
        }

        Directory.CreateDirectory(traceDir);
        var targetExe = ProjectLoader.ResolvePath(yamlPath, project.Target.Executable);
        if (!File.Exists(targetExe))
            return new DrcovRunResult(false, null, null, $"Target not found: {targetExe}");

        var inputFile = Path.Combine(traceDir, $"input_{Guid.NewGuid():N}.bin");
        await File.WriteAllBytesAsync(inputFile, input, cancellationToken);

        var args = project.Target.Args.Select(a =>
            a.Replace("{file}", inputFile, StringComparison.OrdinalIgnoreCase)).ToList();

        var psi = new ProcessStartInfo
        {
            FileName = DrrunPath,
            Arguments =
                $"-t drcov -dump_text -logdir \"{traceDir}\" -- \"{targetExe}\" {string.Join(' ', args)}",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            WorkingDirectory = Path.GetDirectoryName(targetExe) ?? traceDir,
        };

        using var process = Process.Start(psi);
        if (process is null)
            return new DrcovRunResult(false, null, null, "Failed to start drrun");

        await process.WaitForExitAsync(cancellationToken);
        var logPath = Directory.EnumerateFiles(traceDir, "*.log")
            .OrderByDescending(File.GetLastWriteTimeUtc)
            .FirstOrDefault();

        return new DrcovRunResult(
            process.ExitCode == 0,
            logPath,
            process.ExitCode,
            process.ExitCode == 0 ? "ok" : $"exit {process.ExitCode}");
    }

    public Process? StartInstrumentedTarget(
        ProjectConfig project,
        string yamlPath,
        string traceDir)
    {
        if (!IsAvailable)
            return null;

        var targetExe = ProjectLoader.ResolvePath(yamlPath, project.Target.Executable);
        if (!File.Exists(targetExe))
            return null;

        Directory.CreateDirectory(traceDir);
        var args = project.Target.Args.Count > 0
            ? string.Join(' ', project.Target.Args)
            : "";

        var workDir = string.IsNullOrWhiteSpace(project.Target.WorkingDirectory)
            ? Path.GetDirectoryName(targetExe) ?? traceDir
            : ProjectLoader.ResolvePath(yamlPath, project.Target.WorkingDirectory);

        var psi = new ProcessStartInfo
        {
            FileName = DrrunPath,
            Arguments = $"-t drcov -dump_text -logdir \"{traceDir}\" -- \"{targetExe}\" {args}".Trim(),
            UseShellExecute = false,
            WorkingDirectory = workDir,
        };

        return Process.Start(psi);
    }

    public string? CollectLatestTrace(string traceDir)
    {
        if (!Directory.Exists(traceDir))
            return null;
        return Directory.EnumerateFiles(traceDir, "*.log")
            .OrderByDescending(File.GetLastWriteTimeUtc)
            .FirstOrDefault();
    }

    public async Task StopInstrumentedAsync(Process? process, CancellationToken cancellationToken = default)
    {
        if (process is { HasExited: false })
        {
            try { process.Kill(entireProcessTree: true); }
            catch { /* ignore */ }
            try { await process.WaitForExitAsync(cancellationToken); }
            catch { /* ignore */ }
        }
        try { process?.Dispose(); }
        catch { /* ignore */ }
    }
}

public sealed record DrcovRunResult(
    bool Success,
    string? TracePath,
    int? ExitCode,
    string Detail);
