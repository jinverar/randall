using System.Diagnostics;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>Discover WinDbg, WinDbg Preview, cdb, and ProcDump for crash triage.</summary>
public static class DebuggerTools
{
    public const string KindAuto = "auto";
    public const string KindWinDbg = "windbg";
    public const string KindWinDbgPreview = "windbg-preview";
    public const string KindCdb = "cdb";

    public static DebuggerToolsDto Probe()
    {
        var windbg = FindWinDbg();
        var preview = FindWinDbgPreview();
        var cdb = FindCdb();
        var procdump = FindProcDump();

        var tools = new List<DebuggerToolDto>
        {
            new("scream", "Randfuzz Scream watcher", true, null,
                "wait", "randall scream watch -p <pid>  (built-in debug-attach → minidump)"),
            new("windbg-preview", "WinDbg Preview", preview is not null, preview,
                "gui", preview is null ? null : $"\"{preview}\" -z <dump.dmp>"),
            new("windbg", "WinDbg (classic)", windbg is not null, windbg,
                "gui", windbg is null ? null : $"\"{windbg}\" -z <dump.dmp>"),
            new("cdb", "cdb (console)", cdb is not null, cdb,
                "wait", cdb is null ? null : $"\"{cdb}\" -p <pid> -c \"g; .dump /ma dump.dmp; qd\""),
            new("procdump", "ProcDump (optional)", procdump is not null, procdump,
                "wait", procdump is null ? null : $"\"{procdump}\" -ma -e -accepteula -p <pid> dump.dmp"),
        };

        var preferredGui = preview ?? windbg;
        return new DebuggerToolsDto(
            tools,
            preferredGui is null ? null : (preview is not null ? KindWinDbgPreview : KindWinDbg),
            "scream");
    }

    public static string? ResolveGuiPath(string kind)
    {
        kind = NormalizeKind(kind);
        return kind switch
        {
            KindWinDbgPreview => FindWinDbgPreview() ?? FindWinDbg(),
            KindWinDbg => FindWinDbg() ?? FindWinDbgPreview(),
            KindCdb => FindCdb(),
            _ => FindWinDbgPreview() ?? FindWinDbg() ?? FindCdb(),
        };
    }

    public static string ResolveGuiKind(string kind)
    {
        kind = NormalizeKind(kind);
        if (kind is KindWinDbg or KindWinDbgPreview or KindCdb)
        {
            if (ResolveGuiPath(kind) is not null)
                return kind;
        }

        if (FindWinDbgPreview() is not null) return KindWinDbgPreview;
        if (FindWinDbg() is not null) return KindWinDbg;
        if (FindCdb() is not null) return KindCdb;
        return KindAuto;
    }

    public static string? FindWinDbg() => FirstExisting(
        FromPath("windbg.exe"),
        KitDebugger("windbg.exe"),
        EnvPath("WINDBG_PATH"),
        @"C:\Debuggers\windbg.exe",
        @"C:\tools\debugging\windbg.exe");

    public static string? FindWinDbgPreview()
    {
        var direct = FirstExisting(
            FromPath("WinDbgX.exe"),
            FromPath("DbgX.Shell.exe"),
            EnvPath("WINDBGX_PATH"),
            Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Microsoft", "WindowsApps", "WinDbgX.exe"),
            Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Microsoft", "WinDbg", "DbgX.Shell.exe"));
        if (direct is not null)
            return direct;

        try
        {
            var apps = @"C:\Program Files\WindowsApps";
            if (Directory.Exists(apps))
            {
                foreach (var dir in Directory.EnumerateDirectories(apps, "Microsoft.WinDbg_*"))
                {
                    var shell = Path.Combine(dir, "DbgX.Shell.exe");
                    if (File.Exists(shell))
                        return shell;
                }
            }
        }
        catch
        {
            /* WindowsApps may deny enumeration */
        }

        return null;
    }

    public static string? FindCdb() => FirstExisting(
        FromPath("cdb.exe"),
        KitDebugger("cdb.exe"),
        EnvPath("CDB_PATH"));

    public static string? FindProcDump() => FirstExisting(
        FromPath("procdump.exe"),
        FromPath("procdump64.exe"),
        EnvPath("PROCDUMP_PATH"),
        RepoTool("procdump.exe"),
        RepoTool("procdump64.exe"),
        @"C:\Sysinternals\procdump.exe",
        @"C:\tools\procdump.exe");

    public static string NormalizeKind(string? kind)
    {
        var k = (kind ?? KindAuto).Trim().ToLowerInvariant();
        return k switch
        {
            "preview" or "windbgx" or "windbg-preview" or "dbgx" => KindWinDbgPreview,
            "classic" or "windbg" => KindWinDbg,
            "cdb" or "ntsd" => KindCdb,
            _ => KindAuto,
        };
    }

    private static string? KitDebugger(string exe)
    {
        foreach (var root in new[]
                 {
                     @"C:\Program Files\Windows Kits\10\Debuggers\x64",
                     @"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64",
                     @"C:\Program Files\Windows Kits\10\Debuggers\x86",
                     @"C:\Program Files (x86)\Windows Kits\10\Debuggers\x86",
                 })
        {
            var p = Path.Combine(root, exe);
            if (File.Exists(p))
                return p;
        }

        // Newest Kits install under versioned folders
        foreach (var kits in new[]
                 {
                     @"C:\Program Files\Windows Kits\10\Debuggers",
                     @"C:\Program Files (x86)\Windows Kits\10\Debuggers",
                 })
        {
            if (!Directory.Exists(kits))
                continue;
            foreach (var dir in Directory.EnumerateDirectories(kits))
            {
                var p = Path.Combine(dir, exe);
                if (File.Exists(p))
                    return p;
            }
        }

        return null;
    }

    private static string? RepoTool(string name)
    {
        var root = CrashCatalog.FindRepoRoot();
        if (root is null) return null;
        var p = Path.Combine(root, "tools", name);
        return File.Exists(p) ? p : null;
    }

    private static string? EnvPath(string name)
    {
        var v = Environment.GetEnvironmentVariable(name);
        return !string.IsNullOrWhiteSpace(v) && File.Exists(v) ? v : null;
    }

    private static string? FromPath(string exe)
    {
        var pathEnv = Environment.GetEnvironmentVariable("PATH") ?? "";
        foreach (var dir in pathEnv.Split(Path.PathSeparator))
        {
            if (string.IsNullOrWhiteSpace(dir)) continue;
            var p = Path.Combine(dir.Trim('"'), exe);
            if (File.Exists(p))
                return p;
        }

        return null;
    }

    private static string? FirstExisting(params string?[] candidates)
    {
        foreach (var c in candidates)
        {
            if (!string.IsNullOrWhiteSpace(c) && File.Exists(c))
                return c;
        }

        return null;
    }

    public static bool ExistsOnPath(string name)
    {
        if (!name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            name += ".exe";
        return FromPath(name) is not null;
    }

    public static ProcessStartInfo BuildStartInfo(string exe, string arguments, bool gui)
    {
        return new ProcessStartInfo
        {
            FileName = exe,
            Arguments = arguments,
            UseShellExecute = gui,
            CreateNoWindow = !gui,
        };
    }
}
