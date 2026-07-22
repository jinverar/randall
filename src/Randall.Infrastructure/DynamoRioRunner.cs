using System.Diagnostics;
using System.Runtime.InteropServices;
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

    /// <param name="dumpText">
    /// When true (default), emit text BB tables for <see cref="DrcovParser"/>.
    /// When false, emit binary drcov for Dragon Dance (<c>traces-binary/</c>).
    /// </param>
    public async Task<DrcovRunResult> RunWithCoverageAsync(
        ProjectConfig project,
        string yamlPath,
        byte[] input,
        string traceDir,
        bool dumpText = true,
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
        var declared = ProjectLoader.ResolvePath(yamlPath, project.Target.Executable);
        var targetExe = ExecutableResolver.FindExisting(declared);
        if (targetExe is null)
            return new DrcovRunResult(false, null, null, $"Target not found: {declared}");

        var inputFile = Path.Combine(traceDir, $"input_{Guid.NewGuid():N}.bin");
        await File.WriteAllBytesAsync(inputFile, input, cancellationToken);

        var args = project.Target.Args.Select(a =>
            a.Replace("{file}", inputFile, StringComparison.OrdinalIgnoreCase)).ToList();

        var before = SnapshotLogTimes(traceDir);
        var psi = new ProcessStartInfo
        {
            FileName = DrrunPath,
            Arguments = BuildDrcovArgs(traceDir, targetExe, string.Join(' ', args), dumpText),
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            WorkingDirectory = Path.GetDirectoryName(targetExe) ?? traceDir,
        };

        using var process = Process.Start(psi);
        if (process is null)
            return new DrcovRunResult(false, null, null, "Failed to start drrun");

        await process.WaitForExitAsync(cancellationToken);
        var logPath = NewestLogSince(traceDir, before)
                      ?? Directory.EnumerateFiles(traceDir, "*.log")
                          .OrderByDescending(File.GetLastWriteTimeUtc)
                          .FirstOrDefault();

        return new DrcovRunResult(
            process.ExitCode == 0,
            logPath,
            process.ExitCode,
            process.ExitCode == 0 ? "ok" : $"exit {process.ExitCode}");
    }

    /// <param name="dumpText">Default true for Randfuzz stalking; false for Dragon Dance binary logs.</param>
    public Process? StartInstrumentedTarget(
        ProjectConfig project,
        string yamlPath,
        string traceDir,
        bool dumpText = true)
    {
        if (!IsAvailable)
            return null;

        var declared = ProjectLoader.ResolvePath(yamlPath, project.Target.Executable);
        var targetExe = ExecutableResolver.FindExisting(declared);
        if (targetExe is null)
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
            Arguments = BuildDrcovArgs(traceDir, targetExe, args, dumpText),
            UseShellExecute = false,
            WorkingDirectory = workDir,
        };

        return Process.Start(psi);
    }

    public static string BuildDrcovArgs(string traceDir, string targetExe, string targetArgs, bool dumpText)
    {
        var dump = dumpText ? "-dump_text " : "";
        var tail = string.IsNullOrWhiteSpace(targetArgs)
            ? $"-- \"{targetExe}\""
            : $"-- \"{targetExe}\" {targetArgs.Trim()}";
        return $"-t drcov {dump}-logdir \"{traceDir}\" {tail}".Trim();
    }

    private static Dictionary<string, DateTime> SnapshotLogTimes(string traceDir)
    {
        var map = new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
        if (!Directory.Exists(traceDir))
            return map;
        foreach (var f in Directory.EnumerateFiles(traceDir, "*.log"))
            map[f] = File.GetLastWriteTimeUtc(f);
        return map;
    }

    private static string? NewestLogSince(string traceDir, Dictionary<string, DateTime> before)
    {
        if (!Directory.Exists(traceDir))
            return null;
        return Directory.EnumerateFiles(traceDir, "*.log")
            .Select(p => new FileInfo(p))
            .Where(f => f.Exists && f.Length > 0)
            .Where(f => !before.TryGetValue(f.FullName, out var t) || f.LastWriteTimeUtc > t)
            .OrderByDescending(f => f.LastWriteTimeUtc)
            .Select(f => f.FullName)
            .FirstOrDefault();
    }

    public string? CollectLatestTrace(string traceDir)
    {
        if (!Directory.Exists(traceDir))
            return null;
        // Prefer non-empty logs — SIGKILL'd drrun leaves a 0-byte placeholder that would
        // otherwise win on LastWriteTime and starve CoverageSet of edges.
        return Directory.EnumerateFiles(traceDir, "*.log")
            .Select(p => new FileInfo(p))
            .Where(f => f.Exists && f.Length > 0)
            .OrderByDescending(f => f.LastWriteTimeUtc)
            .Select(f => f.FullName)
            .FirstOrDefault();
    }

    public async Task StopInstrumentedAsync(Process? process, CancellationToken cancellationToken = default)
    {
        if (process is { HasExited: false })
        {
            // drcov only flushes the BB table on a clean exit. SIGKILL leaves a 0-byte .log
            // (common on Linux). Ask nicely first, then escalate.
            try
            {
                if (!OperatingSystem.IsWindows())
                    TryUnixSignal(process.Id, SigTerm);
                else
                    process.Kill(entireProcessTree: true);
            }
            catch { /* ignore */ }

            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                cts.CancelAfter(TimeSpan.FromSeconds(3));
                await process.WaitForExitAsync(cts.Token);
            }
            catch (OperationCanceledException)
            {
                try { process.Kill(entireProcessTree: true); }
                catch { /* ignore */ }
                try { await process.WaitForExitAsync(cancellationToken); }
                catch { /* ignore */ }
            }
            catch { /* ignore */ }
        }
        try { process?.Dispose(); }
        catch { /* ignore */ }
    }

    private const int SigTerm = 15;

    private static void TryUnixSignal(int pid, int signal)
    {
        if (pid <= 0)
            return;
        try { UnixKill(pid, signal); }
        catch { /* ignore — fall through to Kill() */ }
    }

    [DllImport("libc", EntryPoint = "kill", SetLastError = true)]
    private static extern int UnixKill(int pid, int sig);
}

public sealed record DrcovRunResult(
    bool Success,
    string? TracePath,
    int? ExitCode,
    string Detail);
