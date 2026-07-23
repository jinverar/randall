using System.Text.Json;
using Randall.Contracts;

namespace Randall.Infrastructure.Rop;

/// <summary>
/// One-shot scream → CONTROL → badchars → sketch → debugger walk playbook.
/// Lab-only; no shellcode / payloads.
/// </summary>
public static class ScreamWalk
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
    };

    public static ScreamWalkReportDto Run(
        Guid crashId,
        string goal = "auto",
        string? badCharsHex = null,
        string? exeOverride = null,
        int maxModules = 3,
        string? repoRoot = null)
    {
        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var detail = CrashCatalog.GetDetail(crashId, repoRoot);
        if (detail is null)
            return new ScreamWalkReportDto(crashId, "", goal, null, null, null, [],
                "scream-walk: crash not found", Error: "crash not found");

        var steps = new List<ScreamWalkStepDto>();
        var n = 0;
        ScreamWalkStepDto Step(string id, string title, string status, string? detail = null,
            IReadOnlyList<string>? cmds = null, string? artifact = null) =>
            new(++n, id, title, status, detail, cmds, artifact);

        var crashesDir = Path.Combine(repoRoot, "data", "crashes", detail.Summary.Project);
        Directory.CreateDirectory(crashesDir);

        // 1) CONTROL from triage / exploit guide
        string? ctrlReg = detail.Triage?.IpLooksControlled == true ? "IP/fault (triage)" : null;
        int? ctrlOff = detail.Triage?.PatternDepthBytes;
        var guidePath = Path.Combine(crashesDir, $"{crashId:N}_exploit_guide.json");
        if (File.Exists(guidePath))
        {
            try
            {
                using var doc = JsonDocument.Parse(File.ReadAllText(guidePath));
                var root = doc.RootElement;
                if (TryGetString(root, "controlledRegister", out var r) ||
                    TryGetString(root, "ControlledRegister", out r))
                    ctrlReg = r;
                if (TryGetInt(root, "controlledOffset", out var o) ||
                    TryGetInt(root, "ControlledOffset", out o))
                    ctrlOff = o;
            }
            catch { /* ignore */ }
        }

        steps.Add(Step("control", "CONTROL offset",
            ctrlOff is not null ? "ok" : "info",
            ctrlOff is { } off
                ? $"{ctrlReg ?? "IP"} @ {off}"
                : "no CONTROL yet — run exploit guide / pattern offset",
            [
                $"randall exploit guide --exe <target> --core <core>",
                $"randall pattern offset -q <faulting-value>",
            ],
            File.Exists(guidePath) ? guidePath.Replace('\\', '/') : null));

        // 2) Badchars
        string? badPath = null;
        string? badHex = badCharsHex;
        try
        {
            var learned = string.IsNullOrWhiteSpace(badCharsHex)
                ? RopBadCharLearner.LearnFromCrash(crashId, repoRoot)
                : null;
            if (learned is not null && learned.Error is null)
            {
                badHex = learned.BadCharsHex;
                badPath = learned.OutputPath;
                steps.Add(Step("badchars", "Learn badchars", "ok", learned.SummaryLine,
                    [$"randall rop badchars -i {crashId:N}"], badPath));
            }
            else if (!string.IsNullOrWhiteSpace(badCharsHex))
            {
                steps.Add(Step("badchars", "Badchars (caller)", "ok", badCharsHex));
            }
            else
            {
                steps.Add(Step("badchars", "Learn badchars", "skip",
                    learned?.Error ?? "no input to learn from"));
            }
        }
        catch (Exception ex)
        {
            steps.Add(Step("badchars", "Learn badchars", "fail", ex.Message));
        }

        // 3) Resolve modules + adaptive goal
        var modules = RopStudio.ResolveCrashModules(detail, repoRoot, exeOverride, maxModules);
        var primary = modules.FirstOrDefault() ?? exeOverride;
        var goalResolved = RopStudio.ResolveSketchGoal(goal, primary);
        string? mitLabel = null;
        if (!string.IsNullOrWhiteSpace(primary) && File.Exists(primary))
        {
            try
            {
                var mit = MitigationInspector.Inspect(primary);
                mitLabel = $"{mit.Tier} (NX={YesNo(mit.Nx)} canary={YesNo(mit.Canary)} PIE={YesNo(mit.Pie)})";
            }
            catch { /* ignore */ }
        }

        steps.Add(Step("goal", "Sketch goal", "ok",
            goal is "auto" or null or ""
                ? $"auto → {goalResolved}" + (mitLabel is null ? "" : $" · {mitLabel}")
                : $"{goalResolved}" + (mitLabel is null ? "" : $" · {mitLabel}"),
            [$"randall rop from-crash -i {crashId:N} --goal {goalResolved}"]));

        // 4) ROP sketch
        string? ropPath = null;
        try
        {
            var sketch = RopStudio.FromCrash(crashId, goalResolved, badHex, repoRoot, exeOverride, maxModules);
            ropPath = sketch.OutputPath;
            steps.Add(Step("sketch", "ROP Studio sketch",
                sketch.Error is null && sketch.Steps.Count > 0 ? "ok" :
                sketch.Error is null ? "info" : "fail",
                sketch.SummaryLine,
                [$"randall rop from-crash -i {crashId:N} --goal {goalResolved}",
                    $"randall rop show -i {crashId:N}"],
                ropPath));
        }
        catch (Exception ex)
        {
            steps.Add(Step("sketch", "ROP Studio sketch", "fail", ex.Message));
        }

        // 5) WinDbg walk (always write JSON; useful even without dump)
        string? windbgPath = null;
        try
        {
            var walk = RandfuzzDbgWalk.BuildForCrash(crashId, repoRoot);
            windbgPath = walk.WalkPath;
            steps.Add(Step("windbg", "WinDbg / RandfuzzDbg walk",
                walk.Error is null ? "ok" : "fail",
                walk.SummaryLine,
                [
                    $"randall windbg walk -i {crashId:N}",
                    $"randall debug open -i {crashId:N} --kind windbg-preview",
                    "$$>a< tools/randfuzzdbg/scripts/rf_walk.txt",
                ],
                windbgPath));
        }
        catch (Exception ex)
        {
            steps.Add(Step("windbg", "WinDbg walk", "fail", ex.Message));
        }

        // 6) GDB walk (Linux core / ELF path)
        string? gdbPath = null;
        try
        {
            var gdb = RandfuzzGdbWalk.BuildForCrash(crashId, repoRoot);
            gdbPath = gdb.WalkPath;
            var hasCore = !string.IsNullOrWhiteSpace(gdb.CorePath);
            steps.Add(Step("gdb", "GDB / GEF walk",
                gdb.Error is null ? (hasCore ? "ok" : "info") : "fail",
                gdb.SummaryLine,
                [
                    $"randall gdb walk -i {crashId:N}",
                    "gdb -q <exe> <core>  # then: source tools/randfuzzgdb/scripts/rf_gdb.txt",
                ],
                gdbPath));
        }
        catch (Exception ex)
        {
            steps.Add(Step("gdb", "GDB walk", "fail", ex.Message));
        }

        // 7) Ladder hint
        steps.Add(Step("ladder", "Mitigation ladder", "info",
            "Climb vulnlab-basic → nx → aslr → modern; sketches change with NX/ASLR/canary",
            [
                "randall ladder diff" + (string.IsNullOrWhiteSpace(detail.Summary.Project) ? "" : $" -p {detail.Summary.Project}"),
                $"randall ladder diff -i {crashId:N}",
                "docs/MITIGATION_LAB.md",
            ]));

        var playbookPath = Path.Combine(crashesDir, $"{crashId:N}_scream_walk.json");
        var okCount = steps.Count(s => s.Status == "ok");
        var summary =
            $"scream-walk: {okCount}/{steps.Count} ok · goal={goalResolved}" +
            (ctrlOff is { } c ? $" · CONTROL@{c}" : "") +
            (mitLabel is null ? "" : $" · {mitLabel}");

        var report = new ScreamWalkReportDto(
            crashId,
            detail.Summary.Project,
            goalResolved,
            ctrlReg,
            ctrlOff,
            mitLabel,
            steps,
            summary,
            playbookPath.Replace('\\', '/'),
            ropPath,
            windbgPath,
            gdbPath,
            badPath);

        try
        {
            File.WriteAllText(playbookPath, JsonSerializer.Serialize(report, JsonOpts));
        }
        catch (Exception ex)
        {
            return report with { Error = ex.Message, SummaryLine = summary + " · write failed" };
        }

        return report;
    }

    private static string YesNo(bool v) => v ? "yes" : "no";

    private static bool TryGetString(JsonElement root, string name, out string? value)
    {
        value = null;
        if (!root.TryGetProperty(name, out var el) || el.ValueKind != JsonValueKind.String)
            return false;
        value = el.GetString();
        return !string.IsNullOrWhiteSpace(value);
    }

    private static bool TryGetInt(JsonElement root, string name, out int value)
    {
        value = 0;
        return root.TryGetProperty(name, out var el) && el.TryGetInt32(out value);
    }
}
