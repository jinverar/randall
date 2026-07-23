using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;
using Randall.Contracts;

namespace Randall.Infrastructure.Rop;

/// <summary>
/// Search gadgets and build constrained chain <em>sketches</em> (ordered citations — no payloads).
/// </summary>
public static class RopStudio
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    public static RopSearchReportDto Search(
        string modulePath,
        string need,
        string? badCharsHex = null,
        int limit = 40,
        string? archHint = null,
        string? repoRoot = null)
    {
        need = (need ?? "ret").Trim().ToLowerInvariant();
        var scan = RopGadgetScanner.Scan(modulePath, archHint, repoRoot: repoRoot, writeCache: true);
        if (scan.Error is not null)
            return new RopSearchReportDto(modulePath, need, [], "rop-search failed: " + scan.Error);

        var bad = ParseBadChars(badCharsHex);
        var rejected = new List<string>();
        var hits = new List<RopGadgetDto>();
        foreach (var g in scan.Gadgets)
        {
            if (!MatchesNeed(g, need)) continue;
            if (ContainsBadChar(g.BytesHex, bad))
            {
                rejected.Add($"{g.Address} hits badchar");
                continue;
            }

            hits.Add(g);
            if (hits.Count >= Math.Clamp(limit, 1, 200)) break;
        }

        return new RopSearchReportDto(
            modulePath.Replace('\\', '/'),
            need,
            hits,
            $"rop-search: {hits.Count} hit(s) for '{need}'" +
            (bad.Count > 0 ? $" · badchars filtered" : ""),
            rejected.Take(8).ToList());
    }

    public static RopSketchReportDto Sketch(
        string modulePath,
        string goal = "control",
        string? badCharsHex = null,
        int maxSteps = 8,
        string? archHint = null,
        string? repoRoot = null,
        string? outputPath = null)
    {
        goal = (goal ?? "control").Trim().ToLowerInvariant();
        maxSteps = Math.Clamp(maxSteps, 1, 16);
        var scan = RopGadgetScanner.Scan(modulePath, archHint, repoRoot: repoRoot, writeCache: true);
        if (scan.Error is not null)
            return new RopSketchReportDto(modulePath, goal, scan.Arch, [],
                "rop-sketch failed: " + scan.Error, [], Error: scan.Error);

        var bad = ParseBadChars(badCharsHex);
        var clean = scan.Gadgets.Where(g => !ContainsBadChar(g.BytesHex, bad)).ToList();
        var steps = new List<RopSketchStepDto>();
        var constraints = new List<string>
        {
            "sketch only — no shellcode / payload bytes",
            "authorized lab binaries",
        };
        if (bad.Count > 0)
            constraints.Add("badchars: " + string.Join(" ", bad.Select(b => $"\\x{b:x2}")));

        switch (goal)
        {
            case "pivot":
                Pick(steps, clean, g => g.Kind is "xchg-sp" || g.Tags.Contains("pivot"),
                    "pivot", "stack pivot candidate");
                Pick(steps, clean, g => g.Kind.StartsWith("add-sp", StringComparison.Ordinal),
                    "adjust-sp", "adjust stack after pivot");
                Pick(steps, clean, g => g.Kind == "ret", "ret", "return / continue chain");
                break;
            case "write":
                // Register-load sketch toward a write-what-where — citations only.
                foreach (var reg in (scan.Arch == "x86"
                             ? new[] { "eax", "ecx", "edx", "ebx" }
                             : new[] { "rdi", "rsi", "rdx", "rax", "rcx" }))
                {
                    Pick(steps, clean, g => g.Kind == $"pop-{reg}",
                        "load-" + reg, $"load {reg} from controlled stack");
                    if (steps.Count >= maxSteps - 1) break;
                }

                Pick(steps, clean, g => g.Kind == "ret", "ret", "return into next controlled dword/qword");
                constraints.Add("write goal: arrange pops for address/value regs — you supply the memory write primitive separately");
                break;
            default: // control
                Pick(steps, clean, g => g.Kind == "ret", "entry", "controlled return lands on ret gadget / chain head");
                Pick(steps, clean, g => g.Kind.StartsWith("pop-", StringComparison.Ordinal)
                                        && g.Kind != "pop-pop-ret",
                    "load-reg", "optional register load from controlled stack");
                Pick(steps, clean, g => g.Kind == "pop-pop-ret", "seh-ish", "pop-pop-ret (SEH-style lab)");
                break;
        }

        steps = steps.Take(maxSteps).Select((s, i) => s with { Index = i + 1 }).ToList();
        var summary = steps.Count == 0
            ? $"rop-sketch: no gadgets for goal '{goal}' (try scan first / relax badchars)"
            : $"rop-sketch: {steps.Count} step(s) · goal={goal} · {Path.GetFileName(modulePath)}";

        string? outPath = outputPath;
        if (string.IsNullOrWhiteSpace(outPath))
        {
            var repo = repoRoot ?? CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
            outPath = Path.Combine(RopGadgetScanner.CacheDir(repo),
                Path.GetFileNameWithoutExtension(modulePath) + $".sketch-{goal}.json");
        }

        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(outPath)!);
            var report = new RopSketchReportDto(
                modulePath.Replace('\\', '/'), goal, scan.Arch, steps, summary, constraints,
                outPath.Replace('\\', '/'));
            File.WriteAllText(outPath, JsonSerializer.Serialize(report, JsonOpts));
            return report;
        }
        catch
        {
            return new RopSketchReportDto(
                modulePath.Replace('\\', '/'), goal, scan.Arch, steps, summary, constraints);
        }
    }

    public static RopSketchReportDto FromCrash(
        Guid crashId,
        string goal = "pivot",
        string? badCharsHex = null,
        string? repoRoot = null)
    {
        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var detail = CrashCatalog.GetDetail(crashId, repoRoot);
        if (detail is null)
            return new RopSketchReportDto("", goal, "unknown", [], "crash not found", [],
                Error: "crash not found");

        var exe = detail.Sidecar?.TargetDetail;
        if (!string.IsNullOrWhiteSpace(exe) && !File.Exists(exe))
            exe = null;
        exe ??= TryResolveProjectExe(detail.Summary.Project, repoRoot);
        if (string.IsNullOrWhiteSpace(exe) || !File.Exists(exe))
        {
            exe = detail.Analysis?.LoadedModules?
                .Select(m => m.Split(' ', 2)[0].Trim())
                .FirstOrDefault(p => p.Length > 2 && File.Exists(p));
        }

        if (string.IsNullOrWhiteSpace(exe) || !File.Exists(exe))
            return new RopSketchReportDto("", goal, "unknown", [],
                "no module path on crash — pass --exe or ensure sidecar TargetDetail / analysis modules",
                [], Error: "no module");

        var crashesDir = Path.Combine(repoRoot, "data", "crashes", detail.Summary.Project);
        Directory.CreateDirectory(crashesDir);
        var outPath = Path.Combine(crashesDir, $"{crashId:N}_rop.json");
        var sketch = Sketch(exe, goal, badCharsHex, repoRoot: repoRoot, outputPath: outPath);
        return sketch with
        {
            SummaryLine = sketch.SummaryLine + $" · crash {crashId:N}",
        };
    }

    public static bool ContainsBadChar(string bytesHex, IReadOnlyCollection<byte> bad)
    {
        if (bad.Count == 0 || string.IsNullOrWhiteSpace(bytesHex)) return false;
        var hex = bytesHex.Replace(" ", "", StringComparison.Ordinal);
        if (hex.Length % 2 != 0) return false;
        for (var i = 0; i < hex.Length; i += 2)
        {
            if (!byte.TryParse(hex.AsSpan(i, 2), NumberStyles.HexNumber, null, out var b))
                continue;
            if (bad.Contains(b)) return true;
        }

        return false;
    }

    public static List<byte> ParseBadChars(string? spec)
    {
        var set = new HashSet<byte>();
        if (string.IsNullOrWhiteSpace(spec)) return [];
        // \x00\x0a or 00 0a 0d or 000a0d
        foreach (Match m in Regex.Matches(spec, @"\\x([0-9a-fA-F]{2})"))
            set.Add(Convert.ToByte(m.Groups[1].Value, 16));
        foreach (Match m in Regex.Matches(spec, @"\b([0-9a-fA-F]{2})\b"))
            set.Add(Convert.ToByte(m.Groups[1].Value, 16));
        return set.OrderBy(b => b).ToList();
    }

    private static bool MatchesNeed(RopGadgetDto g, string need)
    {
        if (need is "any" or "*") return true;
        if (need is "pivot")
            return g.Tags.Contains("pivot") || g.Kind is "xchg-sp" or "add-sp" or "leave-ret";
        if (need is "seh" or "pop-pop-ret")
            return g.Kind == "pop-pop-ret";
        if (need.StartsWith("pop", StringComparison.Ordinal))
            return g.Kind.Equals(need, StringComparison.OrdinalIgnoreCase)
                   || g.Kind.StartsWith("pop-", StringComparison.OrdinalIgnoreCase)
                   && need.Contains(g.Kind["pop-".Length..], StringComparison.OrdinalIgnoreCase);
        return g.Kind.Equals(need, StringComparison.OrdinalIgnoreCase)
               || g.Tags.Any(t => t.Equals(need, StringComparison.OrdinalIgnoreCase))
               || g.Instruction.Contains(need, StringComparison.OrdinalIgnoreCase);
    }

    private static void Pick(
        List<RopSketchStepDto> steps,
        List<RopGadgetDto> pool,
        Func<RopGadgetDto, bool> pred,
        string role,
        string why)
    {
        if (steps.Any(s => s.Role == role)) return;
        var hit = pool.FirstOrDefault(pred);
        if (hit is null) return;
        steps.Add(new RopSketchStepDto(steps.Count + 1, role, hit, why));
    }

    private static string? TryResolveProjectExe(string? project, string repoRoot)
    {
        if (string.IsNullOrWhiteSpace(project)) return null;
        foreach (var candidate in new[]
                 {
                     Path.Combine(repoRoot, "projects", project + ".yaml"),
                     Path.Combine(repoRoot, "projects", project + ".yml"),
                 })
        {
            if (!File.Exists(candidate)) continue;
            try
            {
                var proj = ProjectLoader.Load(candidate);
                if (string.IsNullOrWhiteSpace(proj.Target.Executable)) return null;
                var declared = ProjectLoader.ResolvePath(candidate, proj.Target.Executable);
                return ExecutableResolver.FindExisting(declared) ?? declared;
            }
            catch
            {
                return null;
            }
        }

        return null;
    }
}
