using System.Diagnostics;
using System.Text;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>End-to-end regression for Scream: spawn native AV process → attach → dump.</summary>
public static class ScreamSelftest
{
    public sealed record Result(
        bool Ok,
        string Message,
        string? DumpPath,
        ScreamExceptionInfo? Exception,
        CrashAnalysisDto? Analysis,
        IReadOnlyList<string> Events);

    public static async Task<Result> RunAsync(
        string? repoRoot = null,
        string? exePath = null,
        CancellationToken cancellationToken = default)
    {
        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var outDir = Path.Combine(repoRoot, "targets", "screamcrash");
        Directory.CreateDirectory(outDir);

        exePath ??= Path.Combine(outDir, "scream_crash.exe");
        if (!File.Exists(exePath))
        {
            exePath = await TryBuildNativeCrashAsync(repoRoot, outDir, cancellationToken);
            if (exePath is null)
            {
                return new Result(false,
                    "scream_crash.exe not found — need gcc (run scripts/build-screamcrash.ps1)",
                    null, null, null, []);
            }
        }

        var dumpsDir = Path.Combine(repoRoot, "data", "crashes", "screamcrash", "dumps");
        Directory.CreateDirectory(dumpsDir);

        var psi = new ProcessStartInfo
        {
            FileName = exePath,
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = Path.GetDirectoryName(exePath)!,
        };

        using var target = Process.Start(psi);
        if (target is null)
            return new Result(false, "failed to start scream_crash.exe", null, null, null, []);

        try
        {
            // Attach immediately — native target sleeps ~1.5s then AVs.
            using var watcher = ScreamWatcher.Start(target.Id, dumpsDir);
            var attached = await watcher.WaitUntilAttachedAsync(TimeSpan.FromSeconds(5), cancellationToken);
            if (!attached)
            {
                return new Result(false,
                    $"scream attach/ready failed: {watcher.LastError ?? watcher.Phase}",
                    null, null, null, watcher.EventLog);
            }

            var dumpTask = watcher.Completion;
            var finished = await Task.WhenAny(dumpTask, Task.Delay(TimeSpan.FromSeconds(15), cancellationToken));
            if (finished != dumpTask)
            {
                return new Result(false,
                    $"timeout waiting for dump (phase={watcher.Phase}, err={watcher.LastError})",
                    watcher.TryExistingDumpPath(), watcher.ExceptionInfo, null, watcher.EventLog);
            }

            var dump = await dumpTask;
            var analysis = dump is not null ? CrashAnalysisWriter.AnalyzeDump(dump) : null;
            if (analysis is not { Ok: true } && watcher.ExceptionInfo is { } live)
            {
                analysis = new CrashAnalysisDto(
                    true, dump, $"0x{live.ExceptionCode:X8}", live.ExceptionHint,
                    live.FaultAddress, null, live.Registers, [], null);
            }

            var code = watcher.ExceptionInfo?.ExceptionCode
                       ?? ParseCode(analysis?.ExceptionCode);
            var isAv = code == 0xC0000005;
            var hasDump = dump is not null && File.Exists(dump) && new FileInfo(dump).Length > 0;

            if (hasDump && isAv)
            {
                return new Result(true,
                    $"PASS dump={Path.GetFileName(dump)} {watcher.ExceptionInfo?.ExceptionHint ?? analysis?.ExceptionHint} ({watcher.ExceptionInfo?.Chance})",
                    dump, watcher.ExceptionInfo, analysis, watcher.EventLog);
            }

            return new Result(false,
                $"FAIL want ACCESS_VIOLATION dump={(hasDump ? "yes" : "no")} code=0x{code:X8} phase={watcher.Phase} err={watcher.LastError}",
                dump, watcher.ExceptionInfo, analysis, watcher.EventLog);
        }
        finally
        {
            try
            {
                if (!target.HasExited)
                    target.Kill(entireProcessTree: true);
            }
            catch { /* ignore */ }
        }
    }

    private static async Task<string?> TryBuildNativeCrashAsync(
        string repoRoot,
        string outDir,
        CancellationToken cancellationToken)
    {
        var script = Path.Combine(repoRoot, "scripts", "build-screamcrash.ps1");
        if (!File.Exists(script))
            return null;

        var psi = new ProcessStartInfo
        {
            FileName = "powershell",
            Arguments = $"-NoProfile -ExecutionPolicy Bypass -File \"{script}\"",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            WorkingDirectory = repoRoot,
        };
        using var p = Process.Start(psi);
        if (p is null)
            return null;
        await p.WaitForExitAsync(cancellationToken);
        var exe = Path.Combine(outDir, "scream_crash.exe");
        return p.ExitCode == 0 && File.Exists(exe) ? exe : null;
    }

    private static uint ParseCode(string? code)
    {
        if (string.IsNullOrWhiteSpace(code))
            return 0;
        var hex = code.Trim();
        if (hex.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            hex = hex[2..];
        return uint.TryParse(hex, System.Globalization.NumberStyles.HexNumber, null, out var v) ? v : 0;
    }
}
