using System.Text.Json;
using System.Text.RegularExpressions;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Auto-analyze Linux <c>.core</c> dumps captured during fuzz — counterpart to Windows
/// <see cref="CrashAnalysisWriter"/> / <see cref="MiniDumpAnalyzer"/>. Soft-fails when gdb is missing.
/// </summary>
public static partial class LinuxCrashAnalysisWriter
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    public static bool LooksLikeLinuxCore(string? path) =>
        !string.IsNullOrWhiteSpace(path)
        && path.EndsWith(".core", StringComparison.OrdinalIgnoreCase)
        && File.Exists(path);

    public sealed record HeapTriageSidecar(
        bool Ok,
        string? CorePath,
        string? ExePath,
        int? ExitCode,
        int? Signal,
        string? SignalName,
        HeapCorruptionClassifier.HeapFinding? Finding,
        string? BacktraceTail,
        string? Error);

    public sealed record AutoAnalyzeResult(
        CrashAnalysisDto Analysis,
        string AnalysisPath,
        string? HeapTriagePath,
        string? ExploitGuidePath,
        string SummaryLine);

    /// <summary>
    /// Run gdb core triage + optional exploit guide; write <c>*_analysis.json</c>,
    /// <c>*_heap_triage.json</c>, and <c>*_exploit_guide.json</c>.
    /// </summary>
    public static AutoAnalyzeResult Analyze(
        string crashesDir,
        Guid crashId,
        string corePath,
        string? exePath,
        int? exitCode = null,
        int? patternLen = null,
        string? projectName = null)
    {
        var exe = ExecutableResolver.FindExisting(exePath) ?? exePath;
        var stub = SeedFromExitAndSidecar(corePath, exitCode);

        LinuxCrashTriage.TriageResult triage;
        string? error = null;
        try
        {
            if (string.IsNullOrWhiteSpace(exe) || !File.Exists(exe))
            {
                error = $"target executable not found for core triage: {exePath}";
                triage = stub;
            }
            else
            {
                triage = LinuxCrashTriage.AnalyzeCore(stub, exe, corePath);
            }
        }
        catch (Exception ex)
        {
            error = ex.Message;
            triage = stub;
        }

        var regs = TryParseRegisters(triage.Backtrace);
        var fault = TryParseFaultAddress(triage.Backtrace);
        var hint = triage.Finding?.Primitive
                   ?? triage.SignalName
                   ?? stub.SignalName
                   ?? "linux-core";

        var analysis = new CrashAnalysisDto(
            Ok: error is null && (triage.Backtrace is not null || triage.Finding is not null || triage.Signal is not null),
            DumpPath: corePath,
            ExceptionCode: triage.Signal is int s ? $"SIG/{s}" : exitCode?.ToString(),
            ExceptionHint: hint,
            FaultAddress: fault,
            FaultModule: null,
            Registers: regs,
            LoadedModules: [],
            Error: error ?? (triage.Backtrace is null && LinuxToolPaths.Find(
                new LinuxToolPaths.LinuxTool("linux:gdb", "gdb", "", "", "GDB_PATH")) is null
                ? "gdb not found — install gdb for backtrace triage"
                : null));

        // Mark ok if we at least have signal metadata from the sidecar / exit code.
        if (!analysis.Ok && triage.Signal is not null)
        {
            analysis = analysis with { Ok = true, Error = analysis.Error };
        }

        var analysisPath = CrashAnalysisWriter.Write(crashesDir, crashId, analysis);

        var btTail = triage.Backtrace is null
            ? null
            : string.Join('\n', triage.Backtrace.Split('\n').TakeLast(40));

        var heapDto = new HeapTriageSidecar(
            Ok: analysis.Ok,
            CorePath: corePath,
            ExePath: exe,
            ExitCode: triage.ExitCode != 0 ? triage.ExitCode : exitCode,
            Signal: triage.Signal,
            SignalName: triage.SignalName,
            Finding: triage.Finding,
            BacktraceTail: btTail,
            Error: analysis.Error);

        var heapPath = Path.Combine(crashesDir, $"{crashId:N}_heap_triage.json");
        File.WriteAllText(heapPath, JsonSerializer.Serialize(heapDto, JsonOptions));

        string? guidePath = null;
        if (!string.IsNullOrWhiteSpace(exe) && File.Exists(exe))
        {
            try
            {
                var guide = ExploitGuide.Build(exe, corePath, patternLen, projectName);
                guidePath = Path.Combine(crashesDir, $"{crashId:N}_exploit_guide.json");
                File.WriteAllText(guidePath, JsonSerializer.Serialize(guide, JsonOptions));
            }
            catch
            {
                guidePath = null;
            }
        }

        var summary = triage.Finding is { } f
            ? $"{f.Primitive} ({f.Category}) tier={f.Tier} {f.Cwe}"
            : $"{hint}" + (fault is not null ? $" @ {fault}" : "");

        return new AutoAnalyzeResult(analysis, analysisPath, heapPath, guidePath, summary);
    }

    private static LinuxCrashTriage.TriageResult SeedFromExitAndSidecar(string corePath, int? exitCode)
    {
        int? signal = null;
        string? signalName = null;
        var code = exitCode ?? 0;

        var sidecar = Path.ChangeExtension(corePath, ".linux.json");
        // cores are named foo.core → sidecar is foo.linux.json (not foo.core.linux.json)
        var sibling = corePath.EndsWith(".core", StringComparison.OrdinalIgnoreCase)
            ? corePath[..^5] + ".linux.json"
            : sidecar;

        foreach (var path in new[] { sibling, sidecar })
        {
            if (!File.Exists(path))
                continue;
            try
            {
                using var doc = JsonDocument.Parse(File.ReadAllText(path));
                var root = doc.RootElement;
                if (root.TryGetProperty("exitCode", out var ec) && ec.ValueKind == JsonValueKind.Number)
                    code = ec.GetInt32();
                if (root.TryGetProperty("signal", out var sig) && sig.ValueKind == JsonValueKind.Number)
                    signal = sig.GetInt32();
                if (root.TryGetProperty("signalName", out var sn) && sn.ValueKind == JsonValueKind.String)
                    signalName = sn.GetString();
                break;
            }
            catch { /* ignore */ }
        }

        if (signal is null && code is >= 129 and <= 159)
        {
            signal = code - 128;
            signalName ??= signal.Value switch
            {
                4 => "SIGILL",
                6 => "SIGABRT",
                7 => "SIGBUS",
                8 => "SIGFPE",
                11 => "SIGSEGV",
                _ => $"signal {signal}",
            };
        }

        return new LinuxCrashTriage.TriageResult(
            code, signal, signalName, "", null, null);
    }

    private static RegisterSnapshotDto? TryParseRegisters(string? backtrace)
    {
        if (string.IsNullOrWhiteSpace(backtrace))
            return null;

        string? Pick(string name)
        {
            var match = Regex.Match(
                backtrace,
                $@"\b{Regex.Escape(name)}\s+0x([0-9a-fA-F]+)",
                RegexOptions.IgnoreCase);
            return match.Success ? "0x" + match.Groups[1].Value : null;
        }

        var rip = Pick("rip") ?? Pick("eip");
        var rsp = Pick("rsp") ?? Pick("esp");
        var rbp = Pick("rbp") ?? Pick("ebp");
        var rax = Pick("rax") ?? Pick("eax");
        var rbx = Pick("rbx") ?? Pick("ebx");
        var rcx = Pick("rcx") ?? Pick("ecx");
        var rdx = Pick("rdx") ?? Pick("edx");

        if (rip is null && rsp is null && rbp is null)
            return null;

        return new RegisterSnapshotDto(rip, rsp, rbp, rax, rbx, rcx, rdx);
    }

    private static string? TryParseFaultAddress(string? backtrace)
    {
        if (string.IsNullOrWhiteSpace(backtrace))
            return null;
        var m = FaultFrame().Match(backtrace);
        return m.Success ? m.Groups[1].Value : null;
    }

    [GeneratedRegex(@"#0\s+(0x[0-9a-fA-F]+)")]
    private static partial Regex FaultFrame();
}
