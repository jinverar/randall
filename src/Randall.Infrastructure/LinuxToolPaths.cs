namespace Randall.Infrastructure;

/// <summary>
/// Discovery for the Linux fuzzing / triage toolchain — the Unix counterparts to the Windows
/// Sysinternals + WinDbg stack. Everything is located on <c>PATH</c> (optionally overridden by an
/// env var, or dropped into the repo <c>tools/</c> directory) so the doctor can report a ready /
/// missing status per tool. Pure discovery: nothing here launches a process.
/// </summary>
public static class LinuxToolPaths
{
    /// <summary>Describes one Linux tool: what it is and how to install it when missing.</summary>
    public sealed record LinuxTool(string Id, string Command, string Role, string InstallHint, string? EnvVar = null);

    /// <summary>
    /// Linux observation / triage toolchain — the vendor-neutral Unix counterparts to Randfuzz's
    /// Windows Sysinternals + WinDbg stack. These complement Randfuzz's own fuzzing engine; they are
    /// deliberately NOT third-party fuzzing engines (no AFL/honggfuzz) — coverage-guided fuzzing
    /// stays on Randfuzz's own stalk backend (with DynamoRIO as an optional external adapter, same
    /// as on Windows). Ids are prefixed <c>linux:</c> so the doctor/UI can scope them to Linux.
    /// </summary>
    public static readonly IReadOnlyList<LinuxTool> Catalog =
    [
        new("linux:gdb", "gdb", "attach + core-dump crash triage (WinDbg counterpart)",
            "apt install gdb", "GDB_PATH"),
        new("linux:lldb", "lldb", "LLVM debugger — alternative crash triage",
            "apt install lldb", "LLDB_PATH"),
        new("linux:strace", "strace", "syscall trace bookend (Procmon counterpart)",
            "apt install strace", "STRACE_PATH"),
        new("linux:ltrace", "ltrace", "library-call trace bookend",
            "apt install ltrace", "LTRACE_PATH"),
        new("linux:tcpdump", "tcpdump", "packet capture bookend (pktmon counterpart)",
            "apt install tcpdump", "TCPDUMP_PATH"),
        new("linux:perf", "perf", "performance + coverage sampling (ETW counterpart)",
            "apt install linux-tools-common linux-tools-generic", "PERF_PATH"),
        new("linux:valgrind", "valgrind", "memory-error detection on crashing inputs",
            "apt install valgrind", "VALGRIND_PATH"),
        new("linux:clang", "clang", "ASan/UBSan sanitizer build instrumentation (-fsanitize=address,undefined)",
            "apt install clang", "CLANG_PATH"),
    ];

    /// <summary>Resolves a catalog tool to a concrete path, or null when not installed.</summary>
    public static string? Find(LinuxTool tool)
    {
        if (!string.IsNullOrWhiteSpace(tool.EnvVar))
        {
            var fromEnv = Environment.GetEnvironmentVariable(tool.EnvVar);
            if (!string.IsNullOrWhiteSpace(fromEnv) && File.Exists(fromEnv))
                return fromEnv;
        }

        var repoRoot = CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var inTools = Path.Combine(repoRoot, "tools", tool.Command);
        if (File.Exists(inTools))
            return inTools;

        return FindOnPath(tool.Command);
    }

    private static string? FindOnPath(string command)
    {
        var pathEnv = Environment.GetEnvironmentVariable("PATH") ?? "";
        foreach (var dir in pathEnv.Split(Path.PathSeparator))
        {
            if (string.IsNullOrWhiteSpace(dir)) continue;
            var candidate = Path.Combine(dir.Trim('"'), command);
            if (File.Exists(candidate))
                return candidate;
        }

        return null;
    }
}
