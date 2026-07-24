using System.Text;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Builds analysis-worthy post-crash intelligence: exploit-<b>test</b> probes, Scare Floor
/// recipe recommendations, coverage/missed-block notes, and GDB command packs.
/// Triage / research only — no shellcode or weaponized payloads.
/// </summary>
public static class CrashIntelAdvisor
{
    public static CrashIntelDto Build(
        ProjectConfig project,
        string yamlPath,
        string commandName,
        string mutatorName,
        byte[] payload,
        TargetRunResult result,
        string? exePath = null,
        CrashTriageDto? triage = null,
        Guid? crashId = null,
        int newEdgesAtCrash = 0,
        int totalEdgesAtCrash = 0,
        bool coverageGuided = false)
    {
        _ = yamlPath;
        exePath ??= ResolveExe(project);
        var exit = result.ExitCode;
        var detail = result.Detail ?? "";
        var transport = project.Transport;
        var kind = project.Kind;
        var idHint = crashId?.ToString("N") ?? "<crash-guid>";

        var findings = new List<string>();
        var tests = new List<string>();
        var recipes = new List<string>();
        var coverage = new List<string>();
        var gdb = new List<string>();
        var next = new List<string>();

        findings.Add($"project={project.Name} kind={kind} command={commandName} mutator={mutatorName}");
        findings.Add($"payload_len={payload.Length} exit={exit?.ToString() ?? "?"} detail={Trim(detail, 120)}");
        findings.Add($"transport={transport.Host}:{transport.Port}/{kind}");

        // Engine arming status — honest about what ran
        findings.Add(project.Oracles is { Enabled: true }
            ? "oracle: ON — semantic judgment armed for this project"
            : "oracle: OFF — enable oracles.enabled for wrong-but-alive detection (docs/ORACLES.md)");
        findings.Add(project.Magician is { Enabled: true }
            ? "magician: ON — campaign adjustments armed"
            : "magician: OFF — optional; enable after oracles for intervention (docs/MAGICIAN.md)");
        findings.Add(project.Joker is { Enabled: true }
            ? $"joker: ON (chance={project.Joker.Chance})"
            : "joker: OFF — high-entropy stacking not armed");
        findings.Add(project.BugHunter is { Enabled: true }
            ? "bugHunter: ON — AI/human hunt arming enabled"
            : "bugHunter: OFF — optional AI-codegen hunt (docs/BUG_HUNTER.md)");

        var hyp = InferHypothesis(commandName, mutatorName, exit, detail, payload.Length, triage);
        var headline = triage is { Severity: not null, Class: not null }
            ? $"{triage.Severity}/{triage.Class}: {hyp}"
            : hyp;

        if (exit is 139 or unchecked((int)0xC0000005))
            findings.Add("signal shape looks like SIGSEGV / ACCESS_VIOLATION — capture a core before restarts eat evidence");
        else if (exit is 134)
            findings.Add("exit 134 (SIGABRT) — often heap arena / assert; prefer heaptriage + ASan rebuild");
        else if (exit is not null)
            findings.Add($"non-zero exit {exit} — confirm whether lab Environment.Exit vs real fault");

        if (mutatorName.Contains("boundary", StringComparison.OrdinalIgnoreCase) ||
            mutatorName.Contains("interesting", StringComparison.OrdinalIgnoreCase) ||
            commandName.Contains("len", StringComparison.OrdinalIgnoreCase))
        {
            findings.Add("length/boundary mutator involved — strong length-lie / off-by-one hypothesis");
        }

        if (payload.Length is >= 64 and <= 512)
            findings.Add($"payload size {payload.Length} is in classic smash / table-overflow range — good candidate for cyclic depth");

        // —— Coverage / missed blocks / depth ——
        coverage.Add(coverageGuided
            ? $"coverageGuided=ON · edges at crash: new={newEdgesAtCrash} total={totalEdgesAtCrash}"
            : "coverageGuided=OFF — no BB/edge stalk this run; cannot claim depth or missed-block completeness");
        if (!coverageGuided || totalEdgesAtCrash == 0)
        {
            coverage.Add("depth: UNKNOWN / shallow crash likely — enable fuzz.coverageGuided (+ coverageTcpSpawn for TCP) with DynamoRIO to measure how far you got");
            coverage.Add("missed blocks: not measured — run `randall stalk map -p <project>` after a coverage-guided layer");
        }
        else
        {
            coverage.Add(newEdgesAtCrash > 0
                ? $"depth signal: +{newEdgesAtCrash} novel edges at scream — you reached new code vs prior corpus"
                : "depth signal: 0 novel edges at scream — crash may be on an already-seen path (repro / shallow)");
            coverage.Add($"randall stalk map -p {project.Name} -c projects/{project.Name}.yaml  # missed / frontier gaps");
            coverage.Add($"randall stalk compare -p {project.Name}   # layer diff after baseline vs fuzzier");
        }
        coverage.Add("reverse engineering: Randfuzz stalk map = strings/imports/missed BB gaps — NOT full function decompile (use Ghidra/IDA for that)");

        // —— Exploit-test recommendations (probes, not payloads) ——
        tests.Add("Reproduce once with the saved .bin before mutating further (dedupe / confirm stability).");
        tests.Add("Enable core dumps (`ulimit -c unlimited`) and re-replay so GDB has a core to inspect.");
        tests.Add("Run checksec on the target — NX/canary/PIE/RELRO change which tests are informative.");
        tests.Add("Replace the crashing field with a cyclic pattern (`randall pattern create`) and re-replay; ask whether RIP/saved-return holds pattern bytes.");
        tests.Add("If length fields were mutated: binary-search the minimal length that still crashes (stability + depth).");
        tests.Add("Compare a near-miss (same command, smaller length) vs the crash — note which bytes flip the outcome.");
        if (exit is 134 || detail.Contains("heap", StringComparison.OrdinalIgnoreCase))
            tests.Add("Run `randall heaptriage` on the core — classify tcache / UAF / overflow before assuming stack smash.");
        if (kind is "tcp" or "udp")
            tests.Add("Confirm the crash is in the parser path (one PDU) vs session teardown — single-shot replay vs multi-step flow.");
        tests.Add("Only after CONTROL (register/offset) is measured: `randall scream walk` + ROP Studio sketches — not payload writing.");

        // —— Recipe recommendations (Scare Floor / better crash cases) ——
        recipes.AddRange(BuildRecipeRecommendations(project, commandName, mutatorName, payload.Length));

        // —— GDB command pack ——
        var exe = exePath is { Length: > 0 } ? Sh(exePath) : "<target-exe>";
        var core = "<core-or-dump>";
        var enh = LinuxToolPaths.FindGdbEnhancement()?.Kind ?? "gdb";
        gdb.Add($"{enh} -q {exe} {core}");
        gdb.Add("set pagination off");
        gdb.Add("bt full");
        gdb.Add("info registers");
        gdb.Add("x/32gx $rsp");
        gdb.Add("x/16i $pc");
        gdb.Add("info proc mappings");
        gdb.Add("# gef/pwndbg: context · telescope $rsp 32 · pattern search <value>");
        gdb.Add($"# live attach (if still hung): {enh} -q -p <pid>  then  generate-core-file");
        if (kind is "tcp" or "udp")
        {
            gdb.Add($"# replay under gdb: {enh} -q --args {exe} -p {transport.Port} --host 127.0.0.1");
            gdb.Add("# then: run · (from another shell) send the .bin · bt when it stops");
        }

        // —— Next CLI ——
        next.Add($"randall replay -c {RelProject(project)} -i {Sh(FindInputHint(project, payload))}");
        next.Add($"randall checksec --exe {exe}");
        next.Add($"randall heaptriage --exe {exe} --core {core}");
        next.Add($"randall pattern create -l {Math.Clamp(payload.Length * 2, 200, 800)}");
        next.Add($"randall stalk map -p {project.Name} -c {RelProject(project)}");
        next.Add($"randall case recipes -p {project.Name}");
        next.Add($"randall scream walk -i {idHint} --goal auto");
        next.Add($"randall gdb walk -i {idHint}");
        next.Add($"randall exploit guide --exe {exe} --core {core}");
        next.Add($"randall crashes pack -p {project.Name}");
        if (project.Oracles is not { Enabled: true })
            next.Add("# optional deepen: set oracles.enabled + magician.enabled (+ joker) in YAML, then re-fuzz");

        return new CrashIntelDto(
            Headline: headline,
            Hypothesis: hyp,
            Findings: findings,
            ExploitTestRecommendations: tests,
            RecipeRecommendations: recipes,
            CoverageNotes: coverage,
            GdbCommands: gdb,
            NextCliCommands: next);
    }

    /// <summary>Build intel from an already-saved sidecar (for `crashes` / detail views).</summary>
    public static CrashIntelDto BuildFromSidecar(
        CrashSidecarDto sidecar,
        ProjectConfig? project = null,
        string? exePath = null,
        CrashTriageDto? triage = null)
    {
        if (sidecar.Intel is not null &&
            sidecar.Intel.RecipeRecommendations.Count > 0 &&
            sidecar.Intel.CoverageNotes.Count > 0)
            return sidecar.Intel;

        project ??= TryLoadProject(sidecar) ?? new ProjectConfig
        {
            Name = sidecar.Project,
            Kind = sidecar.Transport.Kind,
            Transport = new TransportConfig
            {
                Host = sidecar.Transport.Host,
                Port = sidecar.Transport.Port,
                Tls = sidecar.Transport.Tls,
            },
        };

        byte[] payload = [];
        try
        {
            if (File.Exists(sidecar.InputPath))
                payload = File.ReadAllBytes(sidecar.InputPath);
        }
        catch { /* ignore */ }

        var result = new TargetRunResult(
            Crashed: true,
            ExitCode: sidecar.ExitCode,
            MiniDumpPath: sidecar.MiniDumpPath,
            Detail: sidecar.TargetDetail ?? "",
            ResponseBytes: null);

        var rebuilt = Build(
            project,
            sidecar.FuzzSnapshot.ConfigPath,
            sidecar.Command,
            sidecar.Mutator,
            payload,
            result,
            exePath,
            triage,
            sidecar.CrashId,
            sidecar.NewEdgesAtCrash,
            sidecar.TotalEdgesAtCrash,
            sidecar.FuzzSnapshot.CoverageGuided);

        // Prefer stored intel sections when present (older sidecars without recipe/coverage).
        if (sidecar.Intel is { } old)
        {
            return rebuilt with
            {
                Headline = old.Headline,
                Hypothesis = old.Hypothesis,
                Findings = old.Findings.Count > 0 ? old.Findings : rebuilt.Findings,
                ExploitTestRecommendations = old.ExploitTestRecommendations.Count > 0
                    ? old.ExploitTestRecommendations
                    : rebuilt.ExploitTestRecommendations,
                GdbCommands = old.GdbCommands.Count > 0 ? old.GdbCommands : rebuilt.GdbCommands,
                NextCliCommands = old.NextCliCommands.Count > 0 ? old.NextCliCommands : rebuilt.NextCliCommands,
            };
        }

        return rebuilt;
    }

    public static string FormatConsole(CrashIntelDto intel, int width = 78)
    {
        var sb = new StringBuilder();
        sb.AppendLine(new string('─', Math.Min(width, 78)));
        sb.AppendLine($"INTEL  {intel.Headline}");
        sb.AppendLine($"  hyp: {intel.Hypothesis}");
        sb.AppendLine("FINDINGS");
        foreach (var f in intel.Findings)
            sb.AppendLine($"  • {f}");
        sb.AppendLine("COVERAGE / DEPTH / MISSED BLOCKS");
        foreach (var c in intel.CoverageNotes)
            sb.AppendLine($"  • {c}");
        sb.AppendLine("RECIPE RECOMMENDATIONS (better crash cases)");
        foreach (var r in intel.RecipeRecommendations)
            sb.AppendLine($"  → {r}");
        sb.AppendLine("EXPLOIT-TEST RECOMMENDATIONS (probes — not payloads)");
        foreach (var t in intel.ExploitTestRecommendations)
            sb.AppendLine($"  → {t}");
        sb.AppendLine("GDB COMMANDS");
        foreach (var g in intel.GdbCommands)
            sb.AppendLine($"  $ {g}");
        sb.AppendLine("NEXT CLI");
        foreach (var n in intel.NextCliCommands)
            sb.AppendLine($"  $ {n}");
        sb.AppendLine($"  note: {intel.Disclaimer}");
        sb.AppendLine(new string('─', Math.Min(width, 78)));
        return sb.ToString().TrimEnd();
    }

    public static string WriteIntelFiles(string crashesDir, Guid crashId, string project, int iteration, string inputHash, CrashIntelDto intel)
    {
        Directory.CreateDirectory(crashesDir);
        var baseName = $"{project}_{iteration}_{inputHash}";
        var txt = Path.Combine(crashesDir, $"{baseName}_intel.txt");
        File.WriteAllText(txt, FormatConsole(intel) + Environment.NewLine);
        var byId = Path.Combine(crashesDir, $"{crashId:N}_intel.txt");
        File.WriteAllText(byId, FormatConsole(intel) + Environment.NewLine);
        return txt;
    }

    private static IEnumerable<string> BuildRecipeRecommendations(
        ProjectConfig project,
        string command,
        string mutator,
        int payloadLen)
    {
        var cmd = command.ToUpperInvariant();
        var list = new List<string>
        {
            $"Scare Floor → open project '{project.Name}' → Save recipe from the crashing command model, then queue 3–5 seed variants (docs/CASE_BUILDER.md)",
            $"randall case recipes -p {project.Name}   # list/load/append saved recipes",
        };

        if (cmd.Contains("HELLO") || cmd.Contains("NAME") || cmd.Contains("INFER") || cmd.Contains("PROMPT"))
        {
            list.Add("Recipe: oversized length-prefix + short body (length-lie) and max-int length field (0xFFFF / 0x7FFFFFFF)");
            list.Add("Recipe: cyclic pattern in the name/prompt body at the crashing length (depth measurement)");
        }

        if (cmd.Contains("SLEW") || cmd.Contains("ROUTE") || cmd.Contains("TRAJ") || cmd.Contains("JOINT") || cmd.Contains("TRACK"))
        {
            list.Add("Recipe: table-size smash — bump count/qty just past the lab limit, keep element size fixed");
            list.Add("Recipe: count=0 and count=1 near-misses beside the boom seed (stability bracket)");
        }

        if (cmd.Contains("CONFIG") || cmd.Contains("PARAM") || cmd.Contains("ADMIN") || cmd.Contains("TOOL"))
        {
            list.Add("Recipe: key/value length mismatch — long key + empty value, and `__internal__*` / `admin` shaped keys from ai_codegen_mistakes dict");
            list.Add("Dictionary harvest: add protocol tokens from banner/responses into Scare Floor dictionary");
        }

        if (mutator.Contains("boundary", StringComparison.OrdinalIgnoreCase) ||
            mutator.Contains("interesting", StringComparison.OrdinalIgnoreCase))
        {
            list.Add("Mutator bias: keep boundary+interesting high; add dictionary + expand for framed fields");
        }

        if (payloadLen < 32)
            list.Add("Seed ladder: keep the small boom, plus medium (64–128) and large (256–400) clones of the same frame shape");
        else
            list.Add("Seed ladder: shrink the crashing seed by half repeatedly until it stops crashing — queue the last crashing size");

        if (project.SessionFlows.Count > 0)
            list.Add("Session recipe: multi-step flow that reaches the crashing command last (mutateStep: last) — already partially modeled; add a flow that hits rarely-used commands");

        list.Add("Optional AI seed: `randall ai seed -c projects/<name>.yaml` (or Scare Floor AI recipe) for extra starting inputs — docs/AI_SEED.md");
        list.Add("After new recipes: fuzzier stalk layer → `randall stalk map` to see if missed blocks shrink");
        return list;
    }

    private static string InferHypothesis(
        string command,
        string mutator,
        int? exit,
        string detail,
        int len,
        CrashTriageDto? triage)
    {
        if (triage?.IpLooksControlled == true)
            return "fault PC / IP looks controlled — measure offset with cyclic pattern before anything else";
        if (triage?.StackLooksSmashed == true)
            return "stack-smash signals present — confirm saved return vs local buffer with GDB bt/telescope";
        if (mutator.Contains("boundary", StringComparison.OrdinalIgnoreCase) ||
            mutator.Contains("interesting", StringComparison.OrdinalIgnoreCase))
            return "boundary/interesting mutation likely hit a length or table-size check";
        if (command.Contains("len", StringComparison.OrdinalIgnoreCase) ||
            command.Contains("HELLO", StringComparison.OrdinalIgnoreCase) ||
            command.Contains("TRACK", StringComparison.OrdinalIgnoreCase) ||
            command.Contains("INFER", StringComparison.OrdinalIgnoreCase))
            return $"command '{command}' suggests a framed field parser — test claimed length vs body size";
        if (exit is 134)
            return "abort/heap-shaped exit — test under heaptriage / ASan before stack narratives";
        if (len > 128)
            return "large crashing input — test whether overflow depth correlates with length prefix";
        if (detail.Contains("SIGSEGV", StringComparison.OrdinalIgnoreCase) || exit is 139)
            return "segfault-shaped exit — capture core and inspect $pc / $sp before declaring CONTROL";
        return "unique crash bottled — reproduce, classify stack vs heap, then measure control depth";
    }

    private static ProjectConfig? TryLoadProject(CrashSidecarDto sidecar)
    {
        try
        {
            var path = sidecar.FuzzSnapshot.ConfigPath;
            if (!string.IsNullOrWhiteSpace(path) && File.Exists(path))
                return ProjectLoader.Load(path);
        }
        catch { /* ignore */ }
        return null;
    }

    private static string? ResolveExe(ProjectConfig project)
    {
        try
        {
            var root = CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
            var rel = project.Target.Executable.Replace('/', Path.DirectorySeparatorChar);
            var declared = Path.IsPathRooted(rel) ? rel : Path.GetFullPath(Path.Combine(root, "projects", rel));
            if (!File.Exists(declared))
            {
                var alt = Path.GetFullPath(Path.Combine(root, rel.TrimStart('.', Path.DirectorySeparatorChar)));
                if (File.Exists(alt)) declared = alt;
            }
            return ExecutableResolver.FindExisting(declared) ?? declared;
        }
        catch
        {
            return project.Target.Executable;
        }
    }

    private static string FindInputHint(ProjectConfig project, byte[] payload)
    {
        _ = payload;
        return $"data/crashes/{project.Name}/<saved>.bin";
    }

    private static string RelProject(ProjectConfig project) =>
        $"projects/{project.Name}.yaml";

    private static string Sh(string s) =>
        s.Contains(' ') ? $"\"{s}\"" : s;

    private static string Trim(string s, int max) =>
        s.Length <= max ? s : s[..max] + "…";
}
