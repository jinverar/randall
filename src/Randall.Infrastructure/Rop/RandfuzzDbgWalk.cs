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

        // Prefer CONTROL from sibling exploit guide when present.
        var crashesDir = Path.Combine(repoRoot, "data", "crashes", detail.Summary.Project);
        var guidePath = Path.Combine(crashesDir, $"{crashId:N}_exploit_guide.json");
        if (File.Exists(guidePath))
        {
            try
            {
                using var doc = JsonDocument.Parse(File.ReadAllText(guidePath));
                var root = doc.RootElement;
                if (root.TryGetProperty("controlledRegister", out var cr) && cr.ValueKind == JsonValueKind.String)
                {
                    var reg = cr.GetString();
                    if (!string.IsNullOrWhiteSpace(reg))
                        controlledReg = reg;
                }
                else if (root.TryGetProperty("ControlledRegister", out var cr2) && cr2.ValueKind == JsonValueKind.String)
                {
                    var reg = cr2.GetString();
                    if (!string.IsNullOrWhiteSpace(reg))
                        controlledReg = reg;
                }

                if (root.TryGetProperty("controlledOffset", out var co) && co.TryGetInt32(out var off))
                    controlledOff = off;
                else if (root.TryGetProperty("ControlledOffset", out var co2) && co2.TryGetInt32(out var off2))
                    controlledOff = off2;
            }
            catch
            {
                /* ignore malformed guide */
            }
        }

        var scriptDir = ScriptsDir(repoRoot).Replace('\\', '/');
        var scriptLines = new List<string>
        {
            $"$$ RandfuzzDbg walk for crash {crashId:N}",
            $"$$ dump: {dump ?? "(none)"}",
            $"$$ Open dump: randall debug open -i {crashId:N} --kind windbg-preview",
            $"$$>a< {scriptDir}/rf_walk.txt",
            ".echo === RANDFUZZ WALK ===",
        };
        if (controlledOff is { } cOff)
            scriptLines.Add($"$$ CONTROL {(controlledReg ?? "IP")} @ offset {cOff}");
        scriptLines.AddRange(["r", "k", "!peb", "lm"]);
        if (!string.IsNullOrWhiteSpace(dump))
            scriptLines.Insert(1, $"$$ windbg -z \"{dump}\"");

        Directory.CreateDirectory(crashesDir);
        var walkPath = Path.Combine(crashesDir, $"{crashId:N}_windbg_walk.json");
        var ropPath = Path.Combine(crashesDir, $"{crashId:N}_rop.json");
        if (!File.Exists(ropPath)) ropPath = null;
        var badPath = Path.Combine(crashesDir, $"{crashId:N}_badchars.json");
        if (!File.Exists(badPath)) badPath = null;

        var summary = $"windbg-walk: crash {crashId:N}" + (dump is null ? " (no dump yet)" : "");
        if (controlledOff is { } offSum)
            summary += $" · CONTROL@ {offSum}";

        // Ranked existing module paths for multi-module ROP harvest.
        var candidates = RopStudio.ResolveCrashModules(detail, repoRoot, maxModules: 6)
            .Select(p => p.Replace('\\', '/'))
            .ToList();

        var report = new WindbgWalkReportDto(
            crashId,
            dump?.Replace('\\', '/'),
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
