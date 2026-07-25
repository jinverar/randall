using System.Diagnostics;
using System.Text.Json;
using System.Text.RegularExpressions;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Headless cdb <c>!analyze -v</c> and optional <c>!exploitable</c> (msec.dll) on Windows minidumps.
/// Counterpart to <see cref="LinuxCrashAnalysisWriter"/> for Linux cores.
/// </summary>
public static partial class WindowsCdbCrashAnalysisWriter
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    public sealed record CdbTriageSidecar(
        bool Ok,
        string? DumpPath,
        string? AnalyzeTextPath,
        string? ExploitableTextPath,
        string? TriageJsonPath,
        string? ExceptionCode,
        string? ExceptionHint,
        string? FaultAddress,
        string? FaultModule,
        string? ExploitableClassification,
        string? ExploitableDescription,
        bool MsecAvailable,
        bool AnalyzeTimedOut,
        string? Error);

    public sealed record AutoAnalyzeResult(
        CdbTriageSidecar Sidecar,
        string SummaryLine);

    public static bool LooksLikeWindowsDump(string? path) =>
        !string.IsNullOrWhiteSpace(path)
        && File.Exists(path)
        && !LinuxCrashAnalysisWriter.LooksLikeLinuxCore(path)
        && (path.EndsWith(".dmp", StringComparison.OrdinalIgnoreCase)
            || path.EndsWith(".mdmp", StringComparison.OrdinalIgnoreCase));

    public static string TriagePathFor(string crashesDir, Guid crashId) =>
        Path.Combine(crashesDir, $"{crashId:N}_cdb_triage.json");

    public static string AnalyzeTextPathFor(string crashesDir, Guid crashId) =>
        Path.Combine(crashesDir, $"{crashId:N}_analyze.txt");

    public static string ExploitableTextPathFor(string crashesDir, Guid crashId) =>
        Path.Combine(crashesDir, $"{crashId:N}_exploitable.txt");

    public static CdbTriageSidecar? TryRead(string? triagePath)
    {
        if (string.IsNullOrWhiteSpace(triagePath) || !File.Exists(triagePath))
            return null;
        try
        {
            return JsonSerializer.Deserialize<CdbTriageSidecar>(File.ReadAllText(triagePath));
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Run cdb on a minidump; write <c>*_analyze.txt</c>, optional <c>*_exploitable.txt</c>,
    /// and <c>*_cdb_triage.json</c>.
    /// </summary>
    public static AutoAnalyzeResult Analyze(
        string crashesDir,
        Guid crashId,
        string dumpPath,
        bool runExploitable = true,
        int timeoutMs = 90_000,
        CrashSidecarDto? crashSidecar = null)
    {
        if (!LooksLikeWindowsDump(dumpPath))
        {
            var bad = new CdbTriageSidecar(
                false, dumpPath, null, null, null, null, null, null, null, null, null,
                false, false, "not a Windows minidump");
            return new AutoAnalyzeResult(bad, "cdb triage skipped — not a Windows minidump");
        }

        var cdb = DebuggerTools.FindCdb();
        if (cdb is null)
        {
            var noCdb = new CdbTriageSidecar(
                false, dumpPath, null, null, null, null, null, null, null, null, null,
                false, false,
                "cdb not found — install Debugging Tools (scripts/install-debuggers.ps1)");
            WriteSidecar(crashesDir, crashId, noCdb);
            return new AutoAnalyzeResult(noCdb, "cdb triage skipped — cdb not found");
        }

        var msec = runExploitable ? DebuggerTools.FindMsecDll() : null;
        var script = BuildScript(msec);
        var timedOut = false;
        string text;
        try
        {
            (text, timedOut) = RunCdb(cdb, dumpPath, script, timeoutMs);
        }
        catch (Exception ex)
        {
            var fail = new CdbTriageSidecar(
                false, dumpPath, null, null, null, null, null, null, null, null, null,
                msec is not null, false, ex.Message);
            WriteSidecar(crashesDir, crashId, fail);
            return new AutoAnalyzeResult(fail, $"cdb triage failed: {ex.Message}");
        }

        var analyzeBlock = ExtractBlock(text, "RANDFUZZ_ANALYZE_BEGIN", "RANDFUZZ_ANALYZE_END");
        var exploitableBlock = ExtractBlock(text, "RANDFUZZ_EXPLOITABLE_BEGIN", "RANDFUZZ_EXPLOITABLE_END");
        var exrBlock = ExtractBlock(text, "RANDFUZZ_EXR_BEGIN", "RANDFUZZ_EXR_END");
        var regsBlock = ExtractBlock(text, "RANDFUZZ_REGS_BEGIN", "RANDFUZZ_REGS_END");
        var stackBlock = ExtractBlock(text, "RANDFUZZ_STACK_BEGIN", "RANDFUZZ_STACK_END");
        var disasmBlock = ExtractBlock(text, "RANDFUZZ_DISASM_BEGIN", "RANDFUZZ_DISASM_END");
        var memBlock = ExtractBlock(text, "RANDFUZZ_MEM_BEGIN", "RANDFUZZ_MEM_END");

        var analyzePath = AnalyzeTextPathFor(crashesDir, crashId);
        File.WriteAllText(analyzePath, string.IsNullOrWhiteSpace(analyzeBlock) ? text : analyzeBlock);

        string? exploitablePath = null;
        if (msec is not null)
        {
            exploitablePath = ExploitableTextPathFor(crashesDir, crashId);
            File.WriteAllText(exploitablePath,
                string.IsNullOrWhiteSpace(exploitableBlock)
                    ? "(msec loaded but !exploitable produced no output)"
                    : exploitableBlock);
        }

        var parsedAnalyze = ParseAnalyzeOutput(analyzeBlock.Length > 0 ? analyzeBlock : text);
        var parsedExploitable = ParseExploitableOutput(exploitableBlock);

        var sidecar = new CdbTriageSidecar(
            Ok: !timedOut && analyzeBlock.Length > 0,
            DumpPath: dumpPath,
            AnalyzeTextPath: analyzePath,
            ExploitableTextPath: exploitablePath,
            TriageJsonPath: null,
            ExceptionCode: parsedAnalyze.ExceptionCode,
            ExceptionHint: parsedAnalyze.ExceptionHint,
            FaultAddress: parsedAnalyze.FaultAddress,
            FaultModule: parsedAnalyze.FaultModule,
            ExploitableClassification: parsedExploitable.Classification,
            ExploitableDescription: parsedExploitable.Description,
            MsecAvailable: msec is not null,
            AnalyzeTimedOut: timedOut,
            Error: timedOut
                ? $"cdb !analyze timed out after {timeoutMs}ms — partial output saved"
                : analyzeBlock.Length == 0
                    ? "cdb ran but !analyze produced no parseable output"
                    : msec is null && runExploitable
                        ? "msec.dll not found — !exploitable skipped (see docs/CRASH_ANALYSIS.md)"
                        : null);

        var triagePath = WriteSidecar(crashesDir, crashId, sidecar with { TriageJsonPath = TriagePathFor(crashesDir, crashId) });

        // Same CDB session → structured DebuggerObservation (Scream Investigator).
        DebuggerObservation? debuggerObs = null;
        try
        {
            debuggerObs = ScreamInvestigator.PersistFromCdbBlocks(
                crashesDir,
                crashId,
                dumpPath,
                analyzeBlock.Length > 0 ? analyzeBlock : text,
                exrBlock,
                regsBlock,
                stackBlock,
                disasmBlock,
                memBlock,
                exploitableBlock,
                timedOut,
                crashSidecar);
        }
        catch
        {
            /* observation is best-effort */
        }

        try
        {
            byte[]? payload = null;
            if (crashSidecar?.InputPath is { } inputPath && File.Exists(inputPath))
            {
                try { payload = File.ReadAllBytes(inputPath); }
                catch { /* ignore */ }
            }

            var triage = CrashTriage.Classify(
                null, crashSidecar, null, payload, sidecar.ExploitableClassification, debuggerObs);
            CorruptionChainBuilder.PersistForCrash(
                crashesDir,
                crashId,
                crashSidecar?.Project ?? "?",
                crashSidecar,
                debuggerObs,
                triage,
                payload);
        }
        catch
        {
            /* corruption chain is best-effort */
        }

        var summary = BuildSummary(sidecar);
        return new AutoAnalyzeResult(sidecar with { TriageJsonPath = triagePath }, summary);
    }

    private static string WriteSidecar(string crashesDir, Guid crashId, CdbTriageSidecar sidecar)
    {
        var path = TriagePathFor(crashesDir, crashId);
        File.WriteAllText(path, JsonSerializer.Serialize(sidecar, JsonOptions));
        return path;
    }

    /// <summary>
    /// Headless CDB script: !analyze plus register/stack/disasm/memory probes for Scream Investigator.
    /// </summary>
    internal static string BuildScript(string? msecPath)
    {
        var lines = new List<string>
        {
            DebuggerTools.FormatSympathScriptCommand(),
            ".echo RANDFUZZ_ANALYZE_BEGIN",
            "!analyze -v",
            ".echo RANDFUZZ_ANALYZE_END",
            ".echo RANDFUZZ_EXR_BEGIN",
            ".exr -1",
            ".echo RANDFUZZ_EXR_END",
            ".echo RANDFUZZ_REGS_BEGIN",
            "r",
            ".echo RANDFUZZ_REGS_END",
            ".echo RANDFUZZ_STACK_BEGIN",
            "kv 16",
            ".echo RANDFUZZ_STACK_END",
            ".echo RANDFUZZ_DISASM_BEGIN",
            "u @rip-20 L16",
            ".echo RANDFUZZ_DISASM_END",
            ".echo RANDFUZZ_MEM_BEGIN",
            "dq @rsp L20",
            ".echo RANDFUZZ_MEM_END",
        };
        if (msecPath is not null)
        {
            lines.Add(".echo RANDFUZZ_EXPLOITABLE_BEGIN");
            lines.Add($".load \"{msecPath.Replace("\"", "\\\"")}\"");
            lines.Add("!exploitable");
            lines.Add(".echo RANDFUZZ_EXPLOITABLE_END");
        }

        lines.Add("qd");
        return string.Join("; ", lines);
    }

    internal static (string Text, bool TimedOut) RunCdb(string cdb, string dumpPath, string script, int timeoutMs)
    {
        var symArgs = DebuggerTools.FormatSymbolCommandLineArgs();
        var psi = new ProcessStartInfo
        {
            FileName = cdb,
            Arguments = $"{symArgs} -z \"{dumpPath}\" -c \"{script.Replace("\"", "\\\"")}\"",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };

        using var proc = Process.Start(psi)
                       ?? throw new InvalidOperationException("Failed to start cdb");
        var stdoutTask = proc.StandardOutput.ReadToEndAsync();
        var stderrTask = proc.StandardError.ReadToEndAsync();
        var timedOut = !proc.WaitForExit(timeoutMs);
        if (timedOut)
        {
            try { proc.Kill(entireProcessTree: true); } catch { /* ignore */ }
        }

        var text = stdoutTask.GetAwaiter().GetResult() + "\n" + stderrTask.GetAwaiter().GetResult();
        return (text, timedOut);
    }

    public static string ExtractBlock(string text, string begin, string end)
    {
        var lines = new List<string>();
        var started = false;
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            if (line.Contains(begin, StringComparison.Ordinal))
            {
                started = true;
                continue;
            }

            if (line.Contains(end, StringComparison.Ordinal))
                break;
            if (started)
                lines.Add(line);
        }

        return string.Join('\n', lines).Trim();
    }

    public sealed record ParsedAnalyze(
        string? ExceptionCode,
        string? ExceptionHint,
        string? FaultAddress,
        string? FaultModule);

    public static ParsedAnalyze ParseAnalyzeOutput(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
            return new ParsedAnalyze(null, null, null, null);

        string? code = null;
        string? hint = null;
        string? fault = null;
        string? module = null;

        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim();
            if (code is null)
            {
                var ex = ExceptionCodeLine().Match(line);
                if (ex.Success)
                {
                    code = ex.Groups[1].Value;
                    hint = ex.Groups[2].Value.Trim();
                    if (string.IsNullOrWhiteSpace(hint) && ParseHex(code) is uint parsedCode)
                        hint = WindowsExceptionHints.DescribeCode(parsedCode);
                }
            }

            if (fault is null)
            {
                var rip = FaultIpLine().Match(line);
                if (rip.Success)
                    fault = NormalizeAddr(rip.Groups[1].Value);
            }

            if (module is null)
            {
                var mod = FaultModuleLine().Match(line);
                if (mod.Success)
                    module = mod.Groups[1].Value.Trim();
            }
        }

        return new ParsedAnalyze(code, hint, fault, module);
    }

    public sealed record ParsedExploitable(string? Classification, string? Description);

    public static ParsedExploitable ParseExploitableOutput(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
            return new ParsedExploitable(null, null);

        string? classification = null;
        var descriptionLines = new List<string>();
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim();
            if (classification is null)
            {
                var m = ExploitableClassLine().Match(line);
                if (m.Success)
                    classification = m.Groups[1].Value.Trim().ToUpperInvariant();
            }

            if (line.Length > 0 && !line.StartsWith("HostMachine", StringComparison.OrdinalIgnoreCase))
                descriptionLines.Add(line);
        }

        var description = descriptionLines.Count == 0
            ? null
            : string.Join('\n', descriptionLines.Take(8));
        return new ParsedExploitable(classification, description);
    }

    private static string BuildSummary(CdbTriageSidecar sidecar)
    {
        if (sidecar.AnalyzeTimedOut)
            return "cdb !analyze timed out — partial output saved";
        if (!sidecar.Ok && sidecar.Error is not null)
            return sidecar.Error;
        var parts = new List<string> { "cdb !analyze" };
        if (sidecar.ExceptionHint is not null)
            parts.Add(sidecar.ExceptionHint);
        if (sidecar.FaultAddress is not null)
            parts.Add($"@ {sidecar.FaultAddress}");
        if (sidecar.ExploitableClassification is not null)
            parts.Add($"!exploitable={sidecar.ExploitableClassification}");
        else if (sidecar.MsecAvailable)
            parts.Add("!exploitable ran");
        return string.Join(" · ", parts);
    }

    private static uint? ParseHex(string? hex)
    {
        if (string.IsNullOrWhiteSpace(hex))
            return null;
        var h = hex.Trim();
        if (h.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            h = h[2..];
        return uint.TryParse(h, System.Globalization.NumberStyles.HexNumber, null, out var v) ? v : null;
    }

    private static string? NormalizeAddr(string addr)
    {
        var a = addr.Trim();
        if (!a.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            a = "0x" + a;
        return a;
    }

    [GeneratedRegex(@"EXCEPTION_CODE:\s*\(?([0-9A-Fa-fx]+)\)?(?:\s*\(([^)]+)\))?", RegexOptions.IgnoreCase)]
    private static partial Regex ExceptionCodeLine();

    [GeneratedRegex(@"FAULTING_IP:\s*([0-9A-Fa-fx]+)", RegexOptions.IgnoreCase)]
    private static partial Regex FaultIpLine();

    [GeneratedRegex(@"FAULTING_MODULE:\s*(.+)$", RegexOptions.IgnoreCase)]
    private static partial Regex FaultModuleLine();

    [GeneratedRegex(
        @"(?:Exploitability\s+Classification|Classification):\s*([A-Z_ ]+)",
        RegexOptions.IgnoreCase)]
    private static partial Regex ExploitableClassLine();
}
