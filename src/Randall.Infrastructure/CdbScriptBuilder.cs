using System.Text;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Deterministic CDB command scripts with <c>RANDFUZZ_*</c> section markers.
/// Centralizes probe lists previously duplicated across headless triage, heap lens, wait attach, and GUI open.
/// </summary>
public static class CdbScriptBuilder
{
    /// <summary>Build a semicolon-separated one-liner for <c>cdb -c</c>.</summary>
    public static string BuildInline(CdbProbePlan plan, CdbScriptOptions? options = null) =>
        string.Join("; ", BuildLines(plan, options ?? CdbScriptOptions.Default));

    /// <summary>Build a newline-separated script for <c>cdb -cf</c>.</summary>
    public static string BuildFile(CdbProbePlan plan, CdbScriptOptions? options = null) =>
        string.Join(Environment.NewLine, BuildLines(plan, options ?? CdbScriptOptions.Default));

    /// <summary>Write a <c>-cf</c> script and return its path.</summary>
    public static string WriteTempScript(CdbProbePlan plan, CdbScriptOptions? options = null, string? prefix = null)
    {
        options ??= CdbScriptOptions.Default;
        var path = Path.Combine(Path.GetTempPath(), $"{prefix ?? "randfuzz_cdb"}_{Guid.NewGuid():N}.txt");
        File.WriteAllText(path, BuildFile(plan, options), Encoding.UTF8);
        return path;
    }

    internal static IReadOnlyList<string> BuildLines(CdbProbePlan plan, CdbScriptOptions options)
    {
        return plan switch
        {
            CdbProbePlan.StandardCrash or CdbProbePlan.DeepScream => BuildStandardCrashLines(options),
            CdbProbePlan.HeapCrash => BuildHeapCrashLines(),
            CdbProbePlan.InteractiveOpen => BuildInteractiveOpenLines(options),
            CdbProbePlan.WaitAttach => BuildWaitAttachLines(options),
            _ => throw new ArgumentOutOfRangeException(nameof(plan), plan, "Unknown CDB probe plan"),
        };
    }

    private static List<string> BuildStandardCrashLines(CdbScriptOptions options)
    {
        var lines = new List<string>
        {
            DebuggerTools.FormatSympathScriptCommand(),
            ".symfix",
            ".reload /f /n",
        };

        AppendSection(lines, CdbProbeSection.Analyze, "!analyze -v");
        AppendSection(lines, CdbProbeSection.Exception, ".exr -1");
        lines.Add(".ecxr");
        AppendSection(lines, CdbProbeSection.Regs, "r");
        AppendSection(lines, CdbProbeSection.Stack, "kv");
        AppendSection(lines, CdbProbeSection.Modules, "lm");
        AppendSection(lines, CdbProbeSection.Disasm, "u @rip-20 @rip+40");
        AppendSection(lines, CdbProbeSection.Memory, "dq @rsp L40");
        AppendSection(lines, CdbProbeSection.Heap, "!heap -s");
        AppendSection(lines, CdbProbeSection.Address, "!address $exceptioninformation[1]");

        if (options.MsecDllPath is not null)
        {
            AppendSection(lines, CdbProbeSection.Exploitable,
                $".load \"{options.MsecDllPath.Replace("\"", "\\\"")}\"",
                "!exploitable");
        }

        lines.Add("qd");
        return lines;
    }

    private static List<string> BuildHeapCrashLines()
    {
        var lines = new List<string>();
        AppendSection(lines, CdbProbeSection.Heap, "!heap -s");
        AppendSection(lines, CdbProbeSection.PageHeap, "!heap -p");
        lines.Add("qd");
        return lines;
    }

    private static List<string> BuildInteractiveOpenLines(CdbScriptOptions options)
    {
        var lines = new List<string> { DebuggerTools.FormatSympathScriptCommand() };
        foreach (var echo in options.PreambleEchoes)
            lines.Add(echo);

        if (options.RunAnalyzeIfMissing)
        {
            lines.Add(".echo Running !analyze -v (headless cdb did not run or produced no output)");
            lines.Add("!analyze -v");
        }
        else if (options.AnalyzeAlreadySavedPath is not null)
        {
            lines.Add($".echo Headless cdb !analyze already saved: {options.AnalyzeAlreadySavedPath.Replace('\\', '/')}");
            lines.Add(".echo (see Crashes tab or open *_analyze.txt in an editor)");
        }

        lines.Add(".echo === registers / stack ===");
        lines.Add("r");
        lines.Add("k");
        lines.Add("lm");
        if (options.WalkScriptHint is not null)
            lines.Add($".echo Full walk: $$>a< {options.WalkScriptHint}");
        return lines;
    }

    /// <summary>
    /// Live attach wait policy:
    /// 1) ignore attach break-in via <c>g</c> after second-chance filters are set;
    /// 2) continue harmless first-chance exceptions (<c>sxn</c> = notify/second-chance only);
    /// 3) dump + quit on unhandled second-chance crash.
    /// </summary>
    private static List<string> BuildWaitAttachLines(CdbScriptOptions options)
    {
        if (string.IsNullOrWhiteSpace(options.DumpPath))
            throw new InvalidOperationException("WaitAttach plan requires CdbScriptOptions.DumpPath");

        var dump = options.DumpPath.Replace("\"", "\\\"");
        var lines = new List<string>();
        AppendSection(lines, CdbProbeSection.WaitAttach,
            ".echo RANDFUZZ_EXCEPTION_POLICY second-chance-only",
            "sxn av",
            "sxn bpe",
            "sxn c0000005",
            "sxn c000001d",
            "sxn c0000094",
            "sxn c00000fd",
            "sxn e06d7363",
            "g");
        AppendSection(lines, CdbProbeSection.CrashCapture,
            $".dump /ma \"{dump}\"",
            "qd");
        return lines;
    }

    private static void AppendSection(List<string> lines, CdbProbeSection section, params string[] commands)
    {
        lines.Add(CdbMarkers.BeginEcho(section));
        lines.AddRange(commands);
        lines.Add(CdbMarkers.EndEcho(section));
    }
}

/// <summary>Options passed to <see cref="CdbScriptBuilder"/> per plan.</summary>
public sealed record CdbScriptOptions
{
    public static CdbScriptOptions Default { get; } = new();

    public string? MsecDllPath { get; init; }
    public string? DumpPath { get; init; }
    public IReadOnlyList<string> PreambleEchoes { get; init; } = [];
    public bool RunAnalyzeIfMissing { get; init; }
    public string? AnalyzeAlreadySavedPath { get; init; }
    public string? WalkScriptHint { get; init; }
}

/// <summary>RANDFUZZ_* marker names shared by script builder and transcript parser.</summary>
public static class CdbMarkers
{
    public static string Begin(CdbProbeSection section) => SectionNames[section] + "_BEGIN";
    public static string End(CdbProbeSection section) => SectionNames[section] + "_END";
    public static string BeginEcho(CdbProbeSection section) => $".echo {Begin(section)}";
    public static string EndEcho(CdbProbeSection section) => $".echo {End(section)}";

    private static readonly IReadOnlyDictionary<CdbProbeSection, string> SectionNames =
        new Dictionary<CdbProbeSection, string>
        {
            [CdbProbeSection.Analyze] = "RANDFUZZ_ANALYZE",
            [CdbProbeSection.Exception] = "RANDFUZZ_EXR",
            [CdbProbeSection.Context] = "RANDFUZZ_CONTEXT",
            [CdbProbeSection.Regs] = "RANDFUZZ_REGS",
            [CdbProbeSection.Stack] = "RANDFUZZ_STACK",
            [CdbProbeSection.Disasm] = "RANDFUZZ_DISASM",
            [CdbProbeSection.Memory] = "RANDFUZZ_MEM",
            [CdbProbeSection.Heap] = "RANDFUZZ_HEAP",
            [CdbProbeSection.PageHeap] = "RANDFUZZ_PAGEHEAP",
            [CdbProbeSection.Modules] = "RANDFUZZ_LM",
            [CdbProbeSection.Address] = "RANDFUZZ_ADDRESS",
            [CdbProbeSection.Exploitable] = "RANDFUZZ_EXPLOITABLE",
            [CdbProbeSection.WaitAttach] = "RANDFUZZ_WAIT_ATTACH",
            [CdbProbeSection.CrashCapture] = "RANDFUZZ_CRASH_CAPTURE",
        };
}
