using System.Text;
using System.Text.Json;
using Randall.Contracts;

namespace Randall.Infrastructure.Rop;

/// <summary>
/// Export a WinDbg Preview walk JSON + script hints beside a scream canister.
/// </summary>
public static class RandfuzzDbgWalk
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    public static string ScriptsDir(string? repoRoot = null) =>
        Path.Combine(repoRoot ?? CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory(),
            "tools", "randfuzzdbg", "scripts");

    public static WindbgWalkReportDto BuildForCrash(Guid crashId, string? repoRoot = null)
    {
        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var detail = CrashCatalog.GetDetail(crashId, repoRoot);
        if (detail is null)
            return new WindbgWalkReportDto(crashId, null, null, null, null, [], [], [],
                "crash not found", Error: "crash not found");

        var dump = detail.Summary.MiniDumpPath ?? detail.Analysis?.DumpPath ?? detail.Sidecar?.MiniDumpPath;
        var regs = new List<string>();
        if (detail.Analysis?.Registers is { } r)
        {
            void Add(string n, string? v)
            {
                if (!string.IsNullOrWhiteSpace(v)) regs.Add($"{n}={v}");
            }

            Add("rip", r.Rip);
            Add("rsp", r.Rsp);
            Add("rbp", r.Rbp);
            Add("rax", r.Rax);
            Add("rbx", r.Rbx);
            Add("rcx", r.Rcx);
            Add("rdx", r.Rdx);
        }

        var modules = detail.Analysis?.LoadedModules?.Take(24).ToList() ?? [];
        string? controlledReg = detail.Triage?.IpLooksControlled == true ? "IP/fault (triage)" : null;
        int? controlledOff = detail.Triage?.PatternDepthBytes;

        var scriptDir = ScriptsDir(repoRoot).Replace('\\', '/');
        var scriptLines = new List<string>
        {
            $"$$ RandfuzzDbg walk for crash {crashId:N}",
            $"$$ dump: {dump ?? "(none)"}",
            $"$$ Open dump: randall debug open -i {crashId:N} --kind windbg-preview",
            $"$$>a< {scriptDir}/rf_walk.txt",
            ".echo === RANDFUZZ WALK ===",
            "r",
            "k",
            "!peb",
            "lm",
        };
        if (!string.IsNullOrWhiteSpace(dump))
            scriptLines.Insert(1, $"$$ windbg -z \"{dump}\"");

        var crashesDir = Path.Combine(repoRoot, "data", "crashes", detail.Summary.Project);
        Directory.CreateDirectory(crashesDir);
        var walkPath = Path.Combine(crashesDir, $"{crashId:N}_windbg_walk.json");
        var ropPath = Path.Combine(crashesDir, $"{crashId:N}_rop.json");
        if (!File.Exists(ropPath)) ropPath = null;

        var report = new WindbgWalkReportDto(
            crashId,
            dump?.Replace('\\', '/'),
            detail.Summary.Project,
            controlledReg,
            controlledOff,
            regs,
            modules,
            scriptLines,
            $"windbg-walk: crash {crashId:N}" + (dump is null ? " (no dump yet)" : ""),
            walkPath.Replace('\\', '/'),
            ropPath?.Replace('\\', '/'));

        try
        {
            File.WriteAllText(walkPath, JsonSerializer.Serialize(report, JsonOpts));
        }
        catch (Exception ex)
        {
            return report with { Error = ex.Message, SummaryLine = report.SummaryLine + " · write failed" };
        }

        return report;
    }

    public static string FormatScriptHelp(string? repoRoot = null)
    {
        var dir = ScriptsDir(repoRoot);
        var sb = new StringBuilder();
        sb.AppendLine("RandfuzzDbg scripts:");
        sb.AppendLine($"  {Path.Combine(dir, "rf_walk.txt")}");
        sb.AppendLine($"  {Path.Combine(dir, "rf_load.txt")}");
        sb.AppendLine();
        sb.AppendLine("WinDbg Preview:");
        sb.AppendLine("  1) randall debug open -i <crash-guid> --kind windbg-preview");
        sb.AppendLine($"  2) $$>a< {Path.Combine(dir, "rf_walk.txt").Replace('\\', '/')}");
        sb.AppendLine();
        sb.AppendLine("Extension DLL (Windows lab build): tools/randfuzzdbg/README.md");
        return sb.ToString();
    }
}
