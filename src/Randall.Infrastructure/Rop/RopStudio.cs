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
        PropertyNameCaseInsensitive = true,
    };

    /// <summary>
    /// Map goal=auto (or empty) to a tier-aware sketch goal from checksec.
    /// </summary>
    public static string ResolveSketchGoal(string? goal, string? modulePath)
    {
        var g = (goal ?? "auto").Trim().ToLowerInvariant();
        if (g is not ("auto" or "" or "tier"))
            return g is "leak" or "canary" or "pivot" or "write" or "control" ? g : "control";

        if (string.IsNullOrWhiteSpace(modulePath) || !File.Exists(modulePath))
            return "pivot";

        try
        {
            var mit = MitigationInspector.Inspect(modulePath);
            if (mit.Canary) return "canary";
            if (mit.Pie) return "leak";
            if (mit.Nx) return "pivot";
            return "control";
        }
        catch
        {
            return "pivot";
        }
    }

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
        foreach (var g in scan.Gadgets.OrderBy(g => g.Size).ThenBy(g => g.Address, StringComparer.OrdinalIgnoreCase))
        {
            if (!MatchesNeed(g, need)) continue;
            if (GadgetHitsBadChars(g, bad))
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

    public static RopSearchReportDto SearchFromCrash(
        Guid crashId,
        string need = "ret",
        string? badCharsHex = null,
        int limit = 40,
        string? repoRoot = null)
    {
        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var detail = CrashCatalog.GetDetail(crashId, repoRoot);
        if (detail is null)
            return new RopSearchReportDto("", need, [], "crash not found", ["crash not found"]);

        var exe = ResolveCrashModule(detail, repoRoot);
        if (exe is null)
            return new RopSearchReportDto("", need, [], "no module path on crash", ["no module"]);

        if (string.IsNullOrWhiteSpace(badCharsHex))
        {
            var learned = RopBadCharLearner.LearnFromCrash(crashId, repoRoot);
            if (learned.Error is null && !string.IsNullOrWhiteSpace(learned.BadCharsHex))
                badCharsHex = learned.BadCharsHex;
        }

        var modules = ResolveCrashModules(detail, repoRoot, maxModules: 3);
        if (modules.Count <= 1)
            return Search(exe, need, badCharsHex, limit, repoRoot: repoRoot);

        // Merge hits across a few ranked modules.
        var bad = ParseBadChars(badCharsHex);
        var hits = new List<RopGadgetDto>();
        var rejected = new List<string>();
        foreach (var mod in modules)
        {
            var scan = RopGadgetScanner.Scan(mod, repoRoot: repoRoot, writeCache: true);
            if (scan.Error is not null) continue;
            foreach (var g in scan.Gadgets.OrderBy(g => g.Size)
                         .ThenBy(g => g.Address, StringComparer.OrdinalIgnoreCase))
            {
                if (!MatchesNeed(g, need)) continue;
                if (GadgetHitsBadChars(g, bad))
                {
                    rejected.Add($"{g.Address} hits badchar");
                    continue;
                }

                hits.Add(g);
                if (hits.Count >= Math.Clamp(limit, 1, 200)) break;
            }

            if (hits.Count >= Math.Clamp(limit, 1, 200)) break;
        }

        return new RopSearchReportDto(
            string.Join(" + ", modules.Select(Path.GetFileName)),
            need,
            hits,
            $"rop-search: {hits.Count} hit(s) for '{need}' across {modules.Count} module(s)" +
            (bad.Count > 0 ? " · badchars filtered" : ""),
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
        goal = ResolveSketchGoal(goal, modulePath);
        maxSteps = Math.Clamp(maxSteps, 1, 16);
        var scan = RopGadgetScanner.Scan(modulePath, archHint, repoRoot: repoRoot, writeCache: true);
        if (scan.Error is not null)
            return new RopSketchReportDto(modulePath, goal, scan.Arch, [],
                "rop-sketch failed: " + scan.Error, [], Error: scan.Error);

        var bad = ParseBadChars(badCharsHex);
        var clean = scan.Gadgets.Where(g => !GadgetHitsBadChars(g, bad)).ToList();
        var steps = new List<RopSketchStepDto>();
        var constraints = new List<string>
        {
            "sketch only — no shellcode / payload bytes",
            "authorized lab binaries",
        };
        if (bad.Count > 0)
            constraints.Add("badchars: " + string.Join(" ", bad.Select(b => $"\\x{b:x2}")) +
                            " (insn + address bytes)");

        try
        {
            var mit = MitigationInspector.Inspect(modulePath);
            constraints.Add(
                $"mitigations: tier={mit.Tier} NX={YesNo(mit.Nx)} canary={YesNo(mit.Canary)} PIE={YesNo(mit.Pie)} RELRO={mit.Relro}");
            if (mit.Nx)
                constraints.Add("NX on — prefer ROP/JOP sketches over shellcode (out of scope anyway)");
            if (mit.Pie)
                constraints.Add("PIE/ASLR — gadget VAs need a leak / rebase in the live lab");
        }
        catch
        {
            /* optional */
        }

        switch (goal)
        {
            case "pivot":
                Pick(steps, clean, g => g.Kind is "xchg-sp" || g.Tags.Contains("pivot"),
                    "pivot", "stack pivot candidate");
                Pick(steps, clean, g => g.Kind.StartsWith("add-sp", StringComparison.Ordinal),
                    "adjust-sp", "adjust stack after pivot");
                Pick(steps, clean, g => g.Kind == "ret", "ret", "return / continue chain");
                break;
            case "leak":
                // Info-leak setup citations (PLT/GOT-adjacent / ABI register loads) — no payload.
                constraints.Add("leak goal: cite gadgets toward an info-leak setup under PIE/ASLR — not a packed leak exploit");
                Pick(steps, clean, g => g.Tags.Contains("plt"),
                    "plt", "PLT-adjacent gadget (leak / call surface)");
                foreach (var reg in (scan.Arch == "x86"
                             ? new[] { "eax", "ecx", "edx" }
                             : new[] { "rdi", "rsi", "rdx" }))
                {
                    Pick(steps, clean, g => g.Kind == $"pop-{reg}",
                        "load-" + reg, $"ABI load {reg} (leak setup citation)");
                    if (steps.Count >= maxSteps - 1) break;
                }
                Pick(steps, clean, g => g.Kind.StartsWith("call-", StringComparison.Ordinal)
                                        || g.Kind.StartsWith("jmp-", StringComparison.Ordinal),
                    "transfer", "call/jmp-reg toward PLT / resolved symbol");
                Pick(steps, clean, g => g.Kind == "ret", "ret", "return / continue chain");
                break;
            case "canary":
                constraints.Add("canary goal: stack protector present — sketch documents the wall (no bypass blob)");
                constraints.Add("next lab step: leak canary / bypass separately; ROP Studio stays citation-only");
                Pick(steps, clean, g => g.Kind == "ret", "entry", "ret still useful after a future canary bypass");
                Pick(steps, clean, g => g.Kind.StartsWith("pop-", StringComparison.Ordinal)
                                        && g.Kind != "pop-pop-ret",
                    "load-reg", "register load for post-canary chain planning");
                Pick(steps, clean, g => g.Tags.Contains("plt"),
                    "plt", "PLT citation if you later chain after a leak");
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

                Pick(steps, clean, g => g.Kind == "mov-rm" && g.Tags.Contains("write"),
                    "store", "memory write gadget citation (arrange addr/value regs first)");
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
        string? repoRoot = null,
        string? exeOverride = null,
        int maxModules = 3)
    {
        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var detail = CrashCatalog.GetDetail(crashId, repoRoot);
        if (detail is null)
            return new RopSketchReportDto("", goal, "unknown", [], "crash not found", [],
                Error: "crash not found");

        maxModules = Math.Clamp(maxModules, 1, 8);
        var modules = ResolveCrashModules(detail, repoRoot, exeOverride, maxModules);
        if (modules.Count == 0)
            return new RopSketchReportDto("", goal, "unknown", [],
                "no module path on crash — pass --exe or ensure sidecar TargetDetail / analysis modules",
                [], Error: "no module");

        goal = ResolveSketchGoal(goal, modules[0]);

        // Auto-learn badchars from crashing input when caller did not pass a filter.
        var bad = badCharsHex;
        if (string.IsNullOrWhiteSpace(bad))
        {
            var learned = RopBadCharLearner.LearnFromCrash(crashId, repoRoot);
            if (learned.Error is null && !string.IsNullOrWhiteSpace(learned.BadCharsHex))
                bad = learned.BadCharsHex;
        }

        var crashesDir = Path.Combine(repoRoot, "data", "crashes", detail.Summary.Project);
        Directory.CreateDirectory(crashesDir);
        var outPath = Path.Combine(crashesDir, $"{crashId:N}_rop.json");
        var sketch = SketchModules(modules, goal, bad, repoRoot: repoRoot, outputPath: outPath);
        return sketch with
        {
            SummaryLine = sketch.SummaryLine + $" · crash {crashId:N}" +
                          (string.IsNullOrWhiteSpace(bad) ? "" : " · badchars auto") +
                          (modules.Count > 1 ? $" · {modules.Count} modules" : ""),
        };
    }

    /// <summary>Sketch across multiple modules (merged gadget pool).</summary>
    public static RopSketchReportDto SketchModules(
        IReadOnlyList<string> modulePaths,
        string goal = "control",
        string? badCharsHex = null,
        int maxSteps = 8,
        string? archHint = null,
        string? repoRoot = null,
        string? outputPath = null)
    {
        goal = (goal ?? "control").Trim().ToLowerInvariant();
        maxSteps = Math.Clamp(maxSteps, 1, 16);
        var scanned = new List<string>();
        var all = new List<RopGadgetDto>();
        var arch = "unknown";
        string? primary = null;

        foreach (var raw in modulePaths)
        {
            if (string.IsNullOrWhiteSpace(raw) || !File.Exists(raw)) continue;
            var path = Path.GetFullPath(raw);
            var scan = RopGadgetScanner.Scan(path, archHint, repoRoot: repoRoot, writeCache: true);
            if (scan.Error is not null || scan.Gadgets.Count == 0) continue;
            primary ??= path;
            arch = scan.Arch;
            scanned.Add(path.Replace('\\', '/'));
            all.AddRange(scan.Gadgets);
            if (scanned.Count >= 8) break;
        }

        if (primary is null || all.Count == 0)
            return new RopSketchReportDto("", goal, arch, [],
                "rop-sketch: no gadgets across modules", [], Error: "no gadgets",
                ModulesScanned: scanned);

        // Reuse single-module sketch path by temporarily writing via internal pool sketch.
        return SketchFromPool(primary, goal, all, arch, badCharsHex, maxSteps, repoRoot, outputPath, scanned);
    }

    public static RopSidecarsDto? LoadSidecars(Guid crashId, string? repoRoot = null)
    {
        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var detail = CrashCatalog.GetDetail(crashId, repoRoot);
        if (detail is null) return null;

        var dir = Path.Combine(repoRoot, "data", "crashes", detail.Summary.Project);
        var ropPath = Path.Combine(dir, $"{crashId:N}_rop.json");
        var walkPath = Path.Combine(dir, $"{crashId:N}_windbg_walk.json");
        var badPath = Path.Combine(dir, $"{crashId:N}_badchars.json");
        var guidePath = Path.Combine(dir, $"{crashId:N}_exploit_guide.json");

        RopSketchReportDto? sketch = null;
        WindbgWalkReportDto? walk = null;
        RopBadCharReportDto? bad = null;

        try
        {
            if (File.Exists(ropPath))
                sketch = JsonSerializer.Deserialize<RopSketchReportDto>(File.ReadAllText(ropPath), JsonOpts);
        }
        catch { /* ignore */ }

        try
        {
            if (File.Exists(walkPath))
                walk = JsonSerializer.Deserialize<WindbgWalkReportDto>(File.ReadAllText(walkPath), JsonOpts);
        }
        catch { /* ignore */ }

        try
        {
            if (File.Exists(badPath))
                bad = JsonSerializer.Deserialize<RopBadCharReportDto>(File.ReadAllText(badPath), JsonOpts);
        }
        catch { /* ignore */ }

        var parts = new List<string>();
        if (sketch?.Steps.Count > 0) parts.Add($"sketch {sketch.Steps.Count} step(s)");
        if (walk is not null) parts.Add("walk");
        if (bad is not null) parts.Add("badchars");
        if (File.Exists(guidePath)) parts.Add("guide");

        return new RopSidecarsDto(
            crashId,
            detail.Summary.Project,
            File.Exists(ropPath) ? ropPath.Replace('\\', '/') : null,
            File.Exists(walkPath) ? walkPath.Replace('\\', '/') : null,
            File.Exists(badPath) ? badPath.Replace('\\', '/') : null,
            File.Exists(guidePath) ? guidePath.Replace('\\', '/') : null,
            sketch,
            walk,
            bad,
            parts.Count == 0
                ? "no ROP/WinDbg sidecars yet"
                : "sidecars: " + string.Join(" · ", parts));
    }

    public static IReadOnlyList<string> ResolveCrashModules(
        CrashDetailDto detail,
        string repoRoot,
        string? exeOverride = null,
        int maxModules = 3)
    {
        maxModules = Math.Clamp(maxModules, 1, 8);
        var ranked = new List<(string Path, int Rank)>();

        void Consider(string? path, int rank)
        {
            if (string.IsNullOrWhiteSpace(path)) return;
            path = path.Trim().Trim('"');
            // LoadedModules lines may be "C:\\foo.exe" or "foo.exe base ..."
            if (path.Contains(' ') && !File.Exists(path))
                path = path.Split(' ', 2)[0].Trim();
            if (path.Length < 3) return;
            try { path = Path.GetFullPath(path); } catch { return; }
            if (!File.Exists(path)) return;
            if (!LooksLikePeOrElf(path)) return;
            if (ranked.Any(r => r.Path.Equals(path, StringComparison.OrdinalIgnoreCase))) return;
            ranked.Add((path, rank));
        }

        Consider(exeOverride, 0);
        Consider(detail.Sidecar?.TargetDetail, 1);
        Consider(TryResolveProjectExe(detail.Summary.Project, repoRoot), 2);

        var project = detail.Summary.Project ?? "";
        foreach (var line in detail.Analysis?.LoadedModules ?? [])
        {
            var path = line.Split(' ', 2)[0].Trim();
            var rank = 10;
            if (!string.IsNullOrWhiteSpace(project) &&
                path.Contains(project, StringComparison.OrdinalIgnoreCase))
                rank = 3;
            else if (IsSystemModule(path))
                rank = 20;
            else
                rank = 8;
            Consider(path, rank);
        }

        return ranked
            .OrderBy(r => r.Rank)
            .ThenBy(r => Path.GetFileName(r.Path), StringComparer.OrdinalIgnoreCase)
            .Select(r => r.Path)
            .Take(maxModules)
            .ToList();
    }

    private static RopSketchReportDto SketchFromPool(
        string primaryModule,
        string goal,
        List<RopGadgetDto> gadgets,
        string arch,
        string? badCharsHex,
        int maxSteps,
        string? repoRoot,
        string? outputPath,
        IReadOnlyList<string> scanned)
    {
        goal = ResolveSketchGoal(goal, primaryModule);
        var bad = ParseBadChars(badCharsHex);
        var clean = gadgets.Where(g => !GadgetHitsBadChars(g, bad)).ToList();
        var steps = new List<RopSketchStepDto>();
        var constraints = new List<string>
        {
            "sketch only — no shellcode / payload bytes",
            "authorized lab binaries",
        };
        if (bad.Count > 0)
            constraints.Add("badchars: " + string.Join(" ", bad.Select(b => $"\\x{b:x2}")) +
                            " (insn + address bytes)");
        if (scanned.Count > 1)
            constraints.Add("modules: " + string.Join(", ", scanned.Select(Path.GetFileName)));

        try
        {
            var mit = MitigationInspector.Inspect(primaryModule);
            constraints.Add(
                $"mitigations: tier={mit.Tier} NX={YesNo(mit.Nx)} canary={YesNo(mit.Canary)} PIE={YesNo(mit.Pie)} RELRO={mit.Relro}");
            if (mit.Nx)
                constraints.Add("NX on — prefer ROP/JOP sketches over shellcode (out of scope anyway)");
            if (mit.Pie)
                constraints.Add("PIE/ASLR — gadget VAs need a leak / rebase in the live lab");
        }
        catch { /* optional */ }

        switch (goal)
        {
            case "pivot":
                Pick(steps, clean, g => g.Kind is "xchg-sp" || g.Tags.Contains("pivot"),
                    "pivot", "stack pivot candidate");
                Pick(steps, clean, g => g.Kind.StartsWith("add-sp", StringComparison.Ordinal),
                    "adjust-sp", "adjust stack after pivot");
                Pick(steps, clean, g => g.Kind == "ret", "ret", "return / continue chain");
                break;
            case "leak":
                // Info-leak setup citations (PLT/GOT-adjacent / ABI register loads) — no payload.
                constraints.Add("leak goal: cite gadgets toward an info-leak setup under PIE/ASLR — not a packed leak exploit");
                Pick(steps, clean, g => g.Tags.Contains("plt"),
                    "plt", "PLT-adjacent gadget (leak / call surface)");
                foreach (var reg in (arch == "x86"
                             ? new[] { "eax", "ecx", "edx" }
                             : new[] { "rdi", "rsi", "rdx" }))
                {
                    Pick(steps, clean, g => g.Kind == $"pop-{reg}",
                        "load-" + reg, $"ABI load {reg} (leak setup citation)");
                    if (steps.Count >= maxSteps - 1) break;
                }
                Pick(steps, clean, g => g.Kind.StartsWith("call-", StringComparison.Ordinal)
                                        || g.Kind.StartsWith("jmp-", StringComparison.Ordinal),
                    "transfer", "call/jmp-reg toward PLT / resolved symbol");
                Pick(steps, clean, g => g.Kind == "ret", "ret", "return / continue chain");
                break;
            case "canary":
                constraints.Add("canary goal: stack protector present — sketch documents the wall (no bypass blob)");
                constraints.Add("next lab step: leak canary / bypass separately; ROP Studio stays citation-only");
                Pick(steps, clean, g => g.Kind == "ret", "entry", "ret still useful after a future canary bypass");
                Pick(steps, clean, g => g.Kind.StartsWith("pop-", StringComparison.Ordinal)
                                        && g.Kind != "pop-pop-ret",
                    "load-reg", "register load for post-canary chain planning");
                Pick(steps, clean, g => g.Tags.Contains("plt"),
                    "plt", "PLT citation if you later chain after a leak");
                break;
            case "write":
                foreach (var reg in (arch == "x86"
                             ? new[] { "eax", "ecx", "edx", "ebx" }
                             : new[] { "rdi", "rsi", "rdx", "rax", "rcx" }))
                {
                    Pick(steps, clean, g => g.Kind == $"pop-{reg}",
                        "load-" + reg, $"load {reg} from controlled stack");
                    if (steps.Count >= maxSteps - 1) break;
                }

                Pick(steps, clean, g => g.Kind == "mov-rm" && g.Tags.Contains("write"),
                    "store", "memory write gadget citation (arrange addr/value regs first)");
                Pick(steps, clean, g => g.Kind == "ret", "ret", "return into next controlled dword/qword");
                constraints.Add("write goal: arrange pops for address/value regs — you supply the memory write primitive separately");
                break;
            default:
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
            : $"rop-sketch: {steps.Count} step(s) · goal={goal} · {Path.GetFileName(primaryModule)}" +
              (scanned.Count > 1 ? $" (+{scanned.Count - 1} modules)" : "");

        string? outPath = outputPath;
        if (string.IsNullOrWhiteSpace(outPath))
        {
            var repo = repoRoot ?? CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
            outPath = Path.Combine(RopGadgetScanner.CacheDir(repo),
                Path.GetFileNameWithoutExtension(primaryModule) + $".sketch-{goal}.json");
        }

        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(outPath)!);
            var report = new RopSketchReportDto(
                primaryModule.Replace('\\', '/'), goal, arch, steps, summary, constraints,
                outPath.Replace('\\', '/'), ModulesScanned: scanned);
            File.WriteAllText(outPath, JsonSerializer.Serialize(report, JsonOpts));
            return report;
        }
        catch
        {
            return new RopSketchReportDto(
                primaryModule.Replace('\\', '/'), goal, arch, steps, summary, constraints,
                ModulesScanned: scanned);
        }
    }

    public static bool GadgetHitsBadChars(RopGadgetDto g, IReadOnlyCollection<byte> bad)
    {
        if (bad.Count == 0) return false;
        if (ContainsBadChar(g.BytesHex, bad)) return true;
        return AddressContainsBadChar(g.Address, bad);
    }

    public static bool AddressContainsBadChar(string address, IReadOnlyCollection<byte> bad)
    {
        if (bad.Count == 0 || string.IsNullOrWhiteSpace(address)) return false;
        var hex = address.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            ? address[2..]
            : address;
        if (!ulong.TryParse(hex, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var va))
            return false;
        // Pointer width: 4 bytes for VA fitting in 32-bit space, else 8 (avoids false nulls on high half).
        var width = va > uint.MaxValue ? 8 : 4;
        for (var i = 0; i < width; i++)
        {
            var b = (byte)((va >> (8 * i)) & 0xff);
            if (bad.Contains(b)) return true;
        }

        return false;
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
        if (need is "plt")
            return g.Tags.Contains("plt");
        if (need is "write" or "mov-rm")
            return g.Kind == "mov-rm";
        if (need.StartsWith("pop", StringComparison.Ordinal))
            return g.Kind.Equals(need, StringComparison.OrdinalIgnoreCase)
                   || g.Kind.StartsWith("pop-", StringComparison.OrdinalIgnoreCase)
                   && need.Contains(g.Kind["pop-".Length..], StringComparison.OrdinalIgnoreCase);
        return g.Kind.Equals(need, StringComparison.OrdinalIgnoreCase)
               || g.Tags.Any(t => t.Equals(need, StringComparison.OrdinalIgnoreCase))
               || g.Instruction.Contains(need, StringComparison.OrdinalIgnoreCase)
               || (g.Symbol is not null && g.Symbol.Contains(need, StringComparison.OrdinalIgnoreCase));
    }

    private static void Pick(
        List<RopSketchStepDto> steps,
        List<RopGadgetDto> pool,
        Func<RopGadgetDto, bool> pred,
        string role,
        string why)
    {
        if (steps.Any(s => s.Role == role)) return;
        // Prefer shortest encodings, then stable address order.
        var hit = pool.Where(pred).OrderBy(g => g.Size)
            .ThenBy(g => g.Address, StringComparer.OrdinalIgnoreCase)
            .FirstOrDefault();
        if (hit is null) return;
        var whyExtra = hit.Symbol is null ? why : why + $" · near {hit.Symbol}";
        steps.Add(new RopSketchStepDto(steps.Count + 1, role, hit, whyExtra));
    }

    private static string YesNo(bool v) => v ? "yes" : "no";

    private static string? ResolveCrashModule(CrashDetailDto detail, string repoRoot) =>
        ResolveCrashModules(detail, repoRoot, maxModules: 1).FirstOrDefault();

    private static bool LooksLikePeOrElf(string path)
    {
        try
        {
            using var fs = File.OpenRead(path);
            Span<byte> hdr = stackalloc byte[4];
            if (fs.Read(hdr) < 2) return false;
            if (hdr[0] == 0x4D && hdr[1] == 0x5A) return true;
            return hdr[0] == 0x7F && hdr[1] == (byte)'E' && hdr[2] == (byte)'L' && hdr[3] == (byte)'F';
        }
        catch
        {
            return false;
        }
    }

    private static bool IsSystemModule(string path)
    {
        var p = path.Replace('/', '\\');
        return p.Contains(@"\Windows\", StringComparison.OrdinalIgnoreCase)
               || p.Contains(@"\System32\", StringComparison.OrdinalIgnoreCase)
               || p.Contains(@"\SysWOW64\", StringComparison.OrdinalIgnoreCase)
               || p.Contains("/usr/lib", StringComparison.OrdinalIgnoreCase)
               || p.Contains("/lib/", StringComparison.OrdinalIgnoreCase)
               || p.StartsWith("/lib64/", StringComparison.OrdinalIgnoreCase);
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
