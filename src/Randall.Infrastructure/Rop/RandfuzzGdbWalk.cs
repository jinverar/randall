using System.Text;
using System.Text.Json;
using Randall.Contracts;

namespace Randall.Infrastructure.Rop;

/// <summary>
/// Linux GDB/GEF walk JSON + script hints beside a scream canister (RandfuzzDbg twin).
/// </summary>
public static class RandfuzzGdbWalk
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
    };

    public static string ScriptsDir(string? repoRoot = null) =>
        Path.Combine(repoRoot ?? CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory(),
            "tools", "randfuzzgdb", "scripts");

    public static GdbWalkReportDto BuildForCrash(Guid crashId, string? repoRoot = null)
    {
        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var detail = CrashCatalog.GetDetail(crashId, repoRoot);
        if (detail is null)
            return new GdbWalkReportDto(crashId, null, null, null, null, [], [], [],
                "crash not found", Error: "crash not found");

        var core = detail.Summary.MiniDumpPath ?? detail.Analysis?.DumpPath ?? detail.Sidecar?.MiniDumpPath;
        // Prefer .core paths on Linux; keep whatever exists.
        if (core is not null && !File.Exists(core))
            core = null;

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

        var crashesDir = Path.Combine(repoRoot, "data", "crashes", detail.Summary.Project);
        Directory.CreateDirectory(crashesDir);
        var guidePath = Path.Combine(crashesDir, $"{crashId:N}_exploit_guide.json");
        if (File.Exists(guidePath))
        {
            try
            {
                using var doc = JsonDocument.Parse(File.ReadAllText(guidePath));
                var root = doc.RootElement;
                if (root.TryGetProperty("controlledRegister", out var cr) && cr.ValueKind == JsonValueKind.String)
                    controlledReg = cr.GetString() ?? controlledReg;
                if (root.TryGetProperty("controlledOffset", out var co) && co.TryGetInt32(out var off))
                    controlledOff = off;
            }
            catch { /* ignore */ }
        }

        var scriptDir = ScriptsDir(repoRoot).Replace('\\', '/');
        var scriptLines = new List<string>
        {
            $"# Randfuzz GDB walk for crash {crashId:N}",
            $"# core: {core ?? "(none)"}",
            $"# gdb -q <exe> {core ?? "<core>"}",
            $"# source {scriptDir}/rf_gdb.txt",
            "set pagination off",
            "info registers",
            "bt 16",
            "info proc mappings",
            "x/32gx $sp",
        };
        if (controlledOff is { } cOff)
            scriptLines.Insert(1, $"# CONTROL {(controlledReg ?? "IP")} @ offset {cOff}");

        var walkPath = Path.Combine(crashesDir, $"{crashId:N}_gdb_walk.json");
        var ropPath = Path.Combine(crashesDir, $"{crashId:N}_rop.json");
        if (!File.Exists(ropPath)) ropPath = null;
        var badPath = Path.Combine(crashesDir, $"{crashId:N}_badchars.json");
        if (!File.Exists(badPath)) badPath = null;

        var candidates = RopStudio.ResolveCrashModules(detail, repoRoot, maxModules: 6)
            .Select(p => p.Replace('\\', '/'))
            .ToList();

        var summary = $"gdb-walk: crash {crashId:N}" + (core is null ? " (no core yet)" : "");
        if (controlledOff is { } offSum)
            summary += $" · CONTROL@ {offSum}";

        var report = new GdbWalkReportDto(
            crashId,
            core?.Replace('\\', '/'),
            detail.Summary.Project,
            controlledReg,
            controlledOff,
            regs,
            modules,
            scriptLines,
            summary,
            walkPath.Replace('\\', '/'),
            ropPath?.Replace('\\', '/'),
            badPath?.Replace('\\', '/'),
            ExceptionHint: detail.Analysis?.ExceptionHint ?? detail.Summary.ExceptionHint,
            ModuleCandidates: candidates);

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
        sb.AppendLine("RandfuzzGdb scripts (Linux twin of RandfuzzDbg):");
        sb.AppendLine($"  {Path.Combine(dir, "rf_gdb.txt")}");
        sb.AppendLine();
        sb.AppendLine("GDB/GEF:");
        sb.AppendLine("  1) randall gdb walk -i <crash-guid>");
        sb.AppendLine("  2) gdb -q <exe> <core>");
        sb.AppendLine($"  3) source {Path.Combine(dir, "rf_gdb.txt").Replace('\\', '/')}");
        sb.AppendLine();
        sb.AppendLine("Host: randall scream walk -i <guid> · docs/WINDBG_FUZZ_PKG.md");
        return sb.ToString();
    }
}
