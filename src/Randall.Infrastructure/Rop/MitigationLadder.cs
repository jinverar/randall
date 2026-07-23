using System.Text.Json;
using Randall.Contracts;

namespace Randall.Infrastructure.Rop;

/// <summary>
/// Mitigation ladder diff — compare vulnlab-{basic,nx,aslr,modern} and hint sketch goals.
/// </summary>
public static class MitigationLadder
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
    };

    private static readonly string[] TierOrder = ["basic", "nx", "aslr", "modern"];

    public static LadderDiffReportDto Diff(
        Guid? crashId = null,
        string? project = null,
        string? repoRoot = null,
        bool scanGadgets = true)
    {
        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var labRoot = Path.Combine(repoRoot, "targets", "vulnlab");
        var rows = new List<LadderTierRowDto>();
        var findings = new List<string>();

        foreach (var tier in TierOrder)
        {
            var exe = Path.Combine(labRoot, $"vulnlab-{tier}");
            var exists = File.Exists(exe);
            if (!exists)
            {
                rows.Add(new LadderTierRowDto(tier, exe.Replace('\\', '/'), false,
                    false, false, false, "?", false,
                    Note: "missing — run scripts/build-mitigation-lab.sh",
                    SketchGoalHint: GoalForTierName(tier)));
                continue;
            }

            var mit = MitigationInspector.Inspect(exe);
            int? gadgets = null, rets = null, pivots = null, plts = null;
            if (scanGadgets)
            {
                try
                {
                    var scan = RopGadgetScanner.Scan(exe, writeCache: true, preferCache: true, repoRoot: repoRoot);
                    if (scan.Error is null)
                    {
                        gadgets = scan.GadgetCount;
                        rets = scan.Gadgets.Count(g => g.Kind is "ret" or "retn");
                        pivots = scan.Gadgets.Count(g =>
                            g.Kind is "xchg-sp" or "leave-ret" || g.Tags.Contains("pivot"));
                        plts = scan.Gadgets.Count(g => g.Tags.Contains("plt"));
                    }
                }
                catch { /* optional */ }
            }

            rows.Add(new LadderTierRowDto(
                tier,
                exe.Replace('\\', '/'),
                true,
                mit.Nx,
                mit.Canary,
                mit.Pie,
                mit.Relro,
                mit.Fortify,
                gadgets,
                rets,
                pivots,
                plts,
                GoalForTierName(tier),
                $"tier={mit.Tier}"));
        }

        findings.Add("basic: classic CONTROL / ret → control sketch (exec stack still possible — out of ROP Studio scope)");
        findings.Add("nx: NX on → pivot/write ROP sketches (no stack shellcode)");
        findings.Add("aslr: PIE → leak-first sketches (PLT/GOT-adjacent citations); rebase VAs after a leak");
        findings.Add("modern: canary + full harden → canary wall; sketch explains blockers, not a bypass blob");

        string? ctrlReg = null;
        int? ctrlOff = null;
        if (crashId is { } id)
        {
            var detail = CrashCatalog.GetDetail(id, repoRoot);
            project ??= detail?.Summary.Project;
            var side = RopStudio.LoadSidecars(id, repoRoot);
            ctrlReg = side?.Walk?.ControlledRegister;
            ctrlOff = side?.Walk?.ControlledOffset;
            if (ctrlOff is { } off)
                findings.Add(
                    $"crash {id:N}: CONTROL {(ctrlReg ?? "IP")} @ {off} — re-validate on each tier (canary/PIE change the story)");
            else
                findings.Add($"crash {id:N}: no CONTROL sidecar yet — run scream walk / exploit guide first");
        }

        var present = rows.Count(r => r.Exists);
        var cmds = new List<string>
        {
            "scripts/build-mitigation-lab.sh",
            "randall checksec --exe targets/vulnlab/vulnlab-nx",
            "randall rop scan --exe targets/vulnlab/vulnlab-nx",
            "randall scream walk -i <crash-guid> --goal auto",
        };
        if (crashId is { } cid)
            cmds.Add($"randall scream walk -i {cid:N} --goal auto");

        var summary = present == 0
            ? "ladder-diff: no vulnlab binaries — build with scripts/build-mitigation-lab.sh"
            : $"ladder-diff: {present}/{TierOrder.Length} tiers present" +
              (ctrlOff is { } c ? $" · CONTROL@{c}" : "");

        string? outPath = null;
        if (crashId is { } outId && !string.IsNullOrWhiteSpace(project))
        {
            var dir = Path.Combine(repoRoot, "data", "crashes", project);
            Directory.CreateDirectory(dir);
            outPath = Path.Combine(dir, $"{outId:N}_ladder.json");
        }
        else
        {
            var dir = Path.Combine(repoRoot, "data", "rop");
            Directory.CreateDirectory(dir);
            outPath = Path.Combine(dir, $"ladder-diff-{DateTimeOffset.UtcNow:yyyyMMdd_HHmmss}.json");
        }

        var report = new LadderDiffReportDto(
            labRoot.Replace('\\', '/'),
            rows,
            findings,
            cmds,
            summary,
            crashId,
            ctrlReg,
            ctrlOff,
            outPath.Replace('\\', '/'));

        try
        {
            File.WriteAllText(outPath, JsonSerializer.Serialize(report, JsonOpts));
        }
        catch (Exception ex)
        {
            return report with { Error = ex.Message };
        }

        return report;
    }

    public static string GoalForTierName(string tier) => tier.ToLowerInvariant() switch
    {
        "basic" => "control",
        "nx" => "pivot",
        "aslr" => "leak",
        "modern" => "canary",
        _ => "auto",
    };
}
