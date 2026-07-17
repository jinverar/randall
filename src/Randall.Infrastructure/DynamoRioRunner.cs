using System.Diagnostics;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>Leg 4 — Stalk: DynamoRIO drrun + drcov wrapper (Phase 2 scaffold).</summary>
public sealed class DynamoRioRunner
{
    public string? DrrunPath { get; init; }
    public string? DrCovClientPath { get; init; }

    public static DynamoRioRunner Discover()
    {
        var env = Environment.GetEnvironmentVariable("DYNAMORIO_HOME");
        if (!string.IsNullOrWhiteSpace(env))
        {
            var drrun = Path.Combine(env, "bin64", "drrun.exe");
            if (File.Exists(drrun))
                return new DynamoRioRunner { DrrunPath = drrun };
        }

        var repoRoot = CrashCatalog.FindRepoRoot();
        if (repoRoot is not null)
        {
            var local = Path.Combine(repoRoot, "tools", "dynamorio", "bin64", "drrun.exe");
            if (File.Exists(local))
                return new DynamoRioRunner { DrrunPath = local };

            var toolsDir = Path.Combine(repoRoot, "tools");
            if (Directory.Exists(toolsDir))
            {
                foreach (var dir in Directory.EnumerateDirectories(toolsDir, "DynamoRIO-*"))
                {
                    var candidate = Path.Combine(dir, "bin64", "drrun.exe");
                    if (File.Exists(candidate))
                        return new DynamoRioRunner { DrrunPath = candidate };
                }
            }
        }

        foreach (var candidate in new[]
        {
            @"C:\DynamoRIO\bin64\drrun.exe",
            @"C:\tools\dynamorio\bin64\drrun.exe",
        })
        {
            if (File.Exists(candidate))
                return new DynamoRioRunner { DrrunPath = candidate };
        }

        return new DynamoRioRunner();
    }

    public bool IsAvailable => !string.IsNullOrWhiteSpace(DrrunPath) && File.Exists(DrrunPath);

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
                "DynamoRIO not found — run scripts/install-dynamorio.ps1 or set DYNAMORIO_HOME");
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
            Arguments = $"-t drcov -dump_text -- \"{targetExe}\" {string.Join(' ', args)}",
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
            process.Kill(entireProcessTree: true);
            try { await process.WaitForExitAsync(cancellationToken); }
            catch { /* ignore */ }
        }
        process?.Dispose();
    }
}

public sealed record DrcovRunResult(
    bool Success,
    string? TracePath,
    int? ExitCode,
    string Detail);
