using System.Diagnostics;
using System.Text;

namespace Randall.Infrastructure;

/// <summary>
/// Linux crash triage — the Unix counterpart to the Windows Scream/minidump pipeline. Runs a target
/// under glibc heap hardening (see <see cref="LinuxHeapSentinel"/>), captures the abort/ASan output
/// and signal, optionally pulls a gdb (GEF-enhanced) backtrace from a core file, and classifies the
/// crash into a named memory-corruption primitive (see <see cref="HeapCorruptionClassifier"/>).
/// </summary>
public static class LinuxCrashTriage
{
    public sealed record TriageResult(
        int ExitCode,
        int? Signal,
        string? SignalName,
        string CapturedOutput,
        string? Backtrace,
        HeapCorruptionClassifier.HeapFinding? Finding);

    /// <summary>
    /// Runs <paramref name="exe"/> once (optionally feeding <paramref name="stdinBytes"/>), captures
    /// stderr/stdout, and classifies any crash. Heap hardening is on unless <paramref name="harden"/>
    /// is false. Does not throw on target crash — a crash is the expected outcome.
    /// </summary>
    public static TriageResult RunOnce(
        string exe,
        IReadOnlyList<string>? args = null,
        byte[]? stdinBytes = null,
        bool harden = true,
        int timeoutMs = 10_000)
    {
        var psi = new ProcessStartInfo
        {
            FileName = exe,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardError = true,
            RedirectStandardOutput = true,
            RedirectStandardInput = stdinBytes is not null,
        };
        foreach (var a in args ?? [])
            psi.ArgumentList.Add(a);
        if (harden && OperatingSystem.IsLinux())
            LinuxHeapSentinel.Apply(psi.Environment);

        using var proc = Process.Start(psi) ?? throw new InvalidOperationException($"failed to start {exe}");

        var captured = new StringBuilder();
        proc.OutputDataReceived += (_, e) => { if (e.Data is not null) lock (captured) captured.AppendLine(e.Data); };
        proc.ErrorDataReceived += (_, e) => { if (e.Data is not null) lock (captured) captured.AppendLine(e.Data); };
        proc.BeginOutputReadLine();
        proc.BeginErrorReadLine();

        if (stdinBytes is not null)
        {
            try
            {
                proc.StandardInput.BaseStream.Write(stdinBytes, 0, stdinBytes.Length);
                proc.StandardInput.Close();
            }
            catch { /* target may have died before reading all input */ }
        }

        if (!proc.WaitForExit(timeoutMs))
        {
            try { proc.Kill(entireProcessTree: true); } catch { /* ignore */ }
            proc.WaitForExit(2000);
        }
        proc.WaitForExit(); // flush async readers

        var exit = proc.ExitCode;
        // POSIX shells encode a fatal signal as 128 + signum in the exit code.
        int? signal = exit is > 128 and < 192 ? exit - 128 : null;
        var text = captured.ToString();
        var finding = HeapCorruptionClassifier.Classify(text)
                      ?? (signal is not null ? HeapCorruptionClassifier.Classify(SignalName(signal.Value)) : null);

        return new TriageResult(exit, signal, signal is null ? null : SignalName(signal.Value), text, null, finding);
    }

    /// <summary>
    /// Pulls a backtrace from a core file with gdb (GEF loads automatically if installed) and
    /// re-classifies using the combined output. Returns the input result unchanged if gdb is missing.
    /// </summary>
    public static TriageResult AnalyzeCore(TriageResult result, string exe, string corePath)
    {
        var gdb = LinuxToolPaths.Find(new LinuxToolPaths.LinuxTool("linux:gdb", "gdb", "", "", "GDB_PATH"));
        if (gdb is null || !File.Exists(corePath))
            return result;

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = gdb,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            foreach (var a in new[]
                     {
                         "-batch", "-nx",
                         "-ex", "set pagination off",
                         "-ex", "bt",
                         "-ex", "info registers rip rsp",
                         exe, corePath,
                     })
                psi.ArgumentList.Add(a);

            using var proc = Process.Start(psi)!;
            var bt = proc.StandardOutput.ReadToEnd() + proc.StandardError.ReadToEnd();
            proc.WaitForExit(15_000);

            var finding = result.Finding
                          ?? HeapCorruptionClassifier.Classify(result.CapturedOutput + "\n" + bt);
            return result with { Backtrace = bt, Finding = finding };
        }
        catch
        {
            return result;
        }
    }

    private static string SignalName(int sig) => sig switch
    {
        4 => "SIGILL",
        6 => "SIGABRT",
        7 => "SIGBUS",
        8 => "SIGFPE",
        11 => "SIGSEGV",
        _ => $"signal {sig}",
    };
}
