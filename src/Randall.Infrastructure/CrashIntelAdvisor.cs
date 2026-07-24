using System.Text;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Builds analysis-worthy post-crash intelligence: exploit-<b>test</b> recommendations and
/// GDB command packs. Triage / research only — no shellcode or weaponized payloads.
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
        Guid? crashId = null)
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
        var gdb = new List<string>();
        var next = new List<string>();

        findings.Add($"project={project.Name} kind={kind} command={commandName} mutator={mutatorName}");
        findings.Add($"payload_len={payload.Length} exit={exit?.ToString() ?? "?"} detail={Trim(detail, 120)}");
        findings.Add($"transport={transport.Host}:{transport.Port}/{kind}");

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
        next.Add($"randall scream walk -i {idHint} --goal auto");
        next.Add($"randall gdb walk -i {idHint}");
        next.Add($"randall exploit guide --exe {exe} --core {core}");
        next.Add($"randall crashes pack -p {project.Name}");

        return new CrashIntelDto(
            Headline: headline,
            Hypothesis: hyp,
            Findings: findings,
            ExploitTestRecommendations: tests,
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
        if (sidecar.Intel is not null)
            return sidecar.Intel;

        project ??= new ProjectConfig
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

        return Build(
            project,
            sidecar.FuzzSnapshot.ConfigPath,
            sidecar.Command,
            sidecar.Mutator,
            payload,
            result,
            exePath,
            triage,
            sidecar.CrashId);
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
        // Stable name keyed by crash id for scream-walk / UI lookups
        var byId = Path.Combine(crashesDir, $"{crashId:N}_intel.txt");
        File.WriteAllText(byId, FormatConsole(intel) + Environment.NewLine);
        return txt;
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

    private static string? ResolveExe(ProjectConfig project)
    {
        try
        {
            var root = CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
            var rel = project.Target.Executable.Replace('/', Path.DirectorySeparatorChar);
            var declared = Path.IsPathRooted(rel) ? rel : Path.GetFullPath(Path.Combine(root, "projects", rel));
            // project paths are usually ../targets/...
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
