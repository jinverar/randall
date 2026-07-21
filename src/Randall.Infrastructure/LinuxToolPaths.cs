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
    /// Optional coverage-guided engine adapters. Like DynamoRIO, these are detected and offered but
    /// never required — Randfuzz's own engine remains the default. Enable per project on Linux to
    /// borrow their speed / comparison-solving (CMPLOG); crashes + corpora interop back into Randfuzz.
    /// </summary>
    public static readonly IReadOnlyList<LinuxTool> OptionalEngines =
    [
        new("linux:afl", "afl-fuzz",
            "OPTIONAL external adapter — AFL++ coverage-guided engine (fork-server + CMPLOG); not required",
            "apt install afl++  (or build AFLplusplus)", "AFL_PATH"),
        new("linux:honggfuzz", "honggfuzz",
            "OPTIONAL external adapter — honggfuzz coverage-guided engine; not required",
            "apt install honggfuzz  (or build from source)", "HONGGFUZZ_PATH"),
    ];

    /// <summary>
    /// Linux toolchain surfaced by the doctor/UI. Two groups, both prefixed <c>linux:</c>:
    /// <list type="bullet">
    /// <item><b>Observation / triage</b> — vendor-neutral Unix counterparts to Randfuzz's Windows
    /// Sysinternals + WinDbg stack (gdb, strace, tcpdump, perf, valgrind, clang sanitizers).</item>
    /// <item><b>Optional external engine adapters</b> (see <see cref="OptionalEngines"/>) — AFL++ /
    /// honggfuzz, treated exactly like the DynamoRIO adapter: auto-detected, never required, and
    /// never the default. Randfuzz's own generation + stalk engine drives fuzzing unless a user
    /// explicitly opts into one of these per project.</item>
    /// </list>
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
        .. OptionalEngines,
    ];

    /// <summary>A detected gdb enhancement (GEF / pwndbg / PEDA) and where it was found.</summary>
    public sealed record GdbEnhancement(string Kind, string Path);

    /// <summary>
    /// Detects an installed gdb enhancement for richer crash triage, preferring GEF (modern,
    /// multi-arch, actively maintained) over pwndbg, then legacy PEDA. Detection looks at env
    /// overrides, well-known install files, and any <c>source</c> lines in <c>~/.gdbinit</c>.
    /// Returns the first match by preference, or null when plain gdb has no enhancement.
    /// </summary>
    public static GdbEnhancement? FindGdbEnhancement()
    {
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (string.IsNullOrWhiteSpace(home))
            home = Environment.GetEnvironmentVariable("HOME") ?? "";

        // (Kind, env-var override, candidate install files) in preference order: GEF > pwndbg > PEDA.
        var candidates = new (string Kind, string EnvVar, string[] Files, string[] InitMarkers)[]
        {
            ("gef", "GEF_PATH",
                [Combine(home, ".gdbinit-gef.py"), Combine(home, ".gef.py"), "/usr/share/gef/gef.py", "/opt/gef/gef.py"],
                ["gef.py", "gef-"]),
            ("pwndbg", "PWNDBG_PATH",
                [Combine(home, "pwndbg/gdbinit.py"), "/usr/share/pwndbg/gdbinit.py", "/opt/pwndbg/gdbinit.py"],
                ["pwndbg"]),
            ("peda", "PEDA_PATH",
                [Combine(home, "peda/peda.py"), "/usr/share/peda/peda.py", "/opt/peda/peda.py"],
                ["peda.py"]),
        };

        // Parse ~/.gdbinit once so a `source .../gef.py` style line counts as installed.
        string gdbInit = "";
        try
        {
            var initPath = Combine(home, ".gdbinit");
            if (File.Exists(initPath))
                gdbInit = File.ReadAllText(initPath);
        }
        catch { /* ignore unreadable init */ }

        foreach (var (kind, envVar, files, markers) in candidates)
        {
            var fromEnv = Environment.GetEnvironmentVariable(envVar);
            if (!string.IsNullOrWhiteSpace(fromEnv) && File.Exists(fromEnv))
                return new GdbEnhancement(kind, fromEnv);

            foreach (var file in files)
            {
                if (!string.IsNullOrWhiteSpace(file) && File.Exists(file))
                    return new GdbEnhancement(kind, file);
            }

            if (gdbInit.Length > 0 &&
                markers.Any(m => gdbInit.Contains(m, StringComparison.OrdinalIgnoreCase)))
                return new GdbEnhancement(kind, Combine(home, ".gdbinit"));
        }

        return null;
    }

    private static string Combine(string home, string relative) =>
        string.IsNullOrEmpty(home) ? relative : Path.Combine(home, relative);

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
