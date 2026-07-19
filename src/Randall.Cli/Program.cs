using System.Diagnostics;
using Randall.Contracts;
using Randall.Infrastructure;

if (args.Length == 0 || args[0] is "-h" or "--help" or "help")
{
    PrintHelp();
    return 0;
}

return args[0].ToLowerInvariant() switch
{
    "legs" => PrintLegs(),
    "version" => PrintVersion(),
    "targets" => ListTargets(args.Skip(1).ToArray()),
    "serve" => RunServe(args.Skip(1).ToArray()),
    "agent" => RunAgent(args.Skip(1).ToArray()),
    "fuzz" => await RunFuzzAsync(args.Skip(1).ToArray()),
    "crashes" => await RunCrashesAsync(args.Skip(1).ToArray()),
    "replay" => await ReplayCrashAsync(args.Skip(1).ToArray()),
    "proxy" => await RunProxyAsync(args.Skip(1).ToArray()),
    "campaign" => await RunCampaignAsync(args.Skip(1).ToArray()),
    "pack" => await RunPackAsync(args.Skip(1).ToArray()),
    "bundle" => RunBundle(args.Skip(1).ToArray()),
    "export" => RunExport(args.Skip(1).ToArray()),
    "doctor" => RunDoctor(args.Skip(1).ToArray()),
    "graph" => RunGraph(args.Skip(1).ToArray()),
    "analyze" => RunAnalyze(args.Skip(1).ToArray()),
    "memory" or "lens" => RunMemoryLens(args.Skip(1).ToArray()),
    "stalk" => RunStalk(args.Skip(1).ToArray()),
    "debug" => RunDebug(args.Skip(1).ToArray()),
    "scream" => await RunScream(args.Skip(1).ToArray()),
    "case" => RunCase(args.Skip(1).ToArray()),
    "labs" or "lab" => RunLabs(args.Skip(1).ToArray()),
    "runtime" or "rt" => RunRuntime(args.Skip(1).ToArray()),
    "harness-worker" => RunHarnessWorker(args.Skip(1).ToArray()),
    _ => Unknown(args[0]),
};

static void PrintHelp()
{
    Console.WriteLine("""
        Randfuzz by Randall — generation + coverage-guided fuzzing for Windows

        Usage:
          randall targets              List lab project profiles
          randall fuzz -c <project>    Fuzz a project profile (see targets)
          randall fuzz -c <project> --dry-run
          randall crashes [-p name]    List saved crashes
          randall crashes pack -p name [-o zip] [--no-runs]   Offline crash/dump/lens pack
          randall crashes unpack -i zip   Import pack into data/crashes
          randall crashes pull -a http://vm:5000 -p name [-o zip]  Pull pack from agent
          randall replay -c <project> -i <crash.bin>
          randall proxy [--listen N] [--target host:port]
          randall campaign -c campaigns/lab-smoke.yaml
          randall pack -o publish/standalone
          randall bundle export -c projects/vulnserver.yaml -o bundles/vulnserver.zip
          randall bundle import -i bundles/vulnserver.zip -o projects/imported
          randall doctor -c <project>     Preflight lab checks before fuzzing
          randall graph -c <project>        Validate sessionGraph + print Mermaid
          randall analyze -i <crash-guid>   Minidump triage (registers, fault PC)
          randall memory -i <crash-guid>    Memory lens (UAF fill, regions, neighborhood)
          randall memory --pid N            Live VirtualQueryEx sample
          randall stalk layers -p <project>              List stalk layers
          randall stalk compare -p <project> [layerIds…] Diff layered coverage
          randall stalk export -p <project> --format idc|ghidra|edges [-o dir]
          randall stalk from-crash -i <crash-guid> [--tag crash]
          randall scream watch -p <pid> [-o dumpsDir]   Built-in exception dump watcher
          randall scream selftest          Lab AV target → attach → dump regression
          randall debug tools
          randall debug open -i <crash-guid> [--kind windbg|windbg-preview]
          randall debug attach -p <pid> | -t <project> [--kind …]
          randall fuzz -c <project> --debugger wait|attach|both [--open-on-crash]
          randall case ops|new|preview|save-seed|mutators   Build seeds / YAML targets
          randall labs                     List lab servers (running / stopped)
          randall labs start|stop <id>     Start/stop one lab (127.0.0.1)
          randall labs stop-all            Stop every randall-vuln* lab
          randall runtime                  Target Runtime slots (start/stop/restart)
          randall runtime start -c <yaml>  Start project exe via Target Runtime
          randall runtime start --id X --exe path [--arg a]* [--port N]
          randall runtime stop|restart <id>
          randall runtime stop-all
          randall harness-worker --dll <native.dll> [--export LLVMFuzzerTestOneInput]
          randall export -i <crash-guid>
          randall serve [--port N] [--bind host]   Web UI + API (localhost)
          randall agent [--port N] [--bind host]   Lab agent (all interfaces)
          randall legs                 Eight legs feature map
          randall version

        Lab projects (projects/*.yaml):
          vulnserver   TCP multi-command session graph (TRUN, GMON, …)
          file-text    Generic structured text / XML file template
          file-framed  Generic length-prefixed binary file template
          local/*      Private profiles (gitignored — projects/local/)
          _TEMPLATE_*  Copy templates — name: becomes Target profile

        Advanced mutators (see docs/FUZZING.md):
          havoc        AFL-style stacked mutations
          interesting  libFuzzer-style integer injection
          dictionary   Token / format-string injection
          splice       Corpus crossover
          arith        Single-byte arithmetic delta
          duplicate    Repeat a random seed chunk
          shuffle      Swap short spans in the seed

        Docs: docs/CUSTOM_TARGETS.md · docs/CASE_BUILDER.md · docs/TARGETS.md
        """);
}

static int PrintLegs()
{
    foreach (var (id, title, summary) in RandallLegs.All)
        Console.WriteLine($"  {title} [{id}] — {summary}");
    return 0;
}

static int PrintVersion()
{
    Console.WriteLine("Randfuzz by Randall 0.16.0-alpha (Phase 16 — edge counters + crash analyze)");
    return 0;
}

static int ListTargets(string[] args)
{
    foreach (var t in CrashCatalog.ListTargets())
    {
        Console.WriteLine($"{t.Name,-12} [{t.Kind}] {t.Description}");
        Console.WriteLine($"             {t.ConfigPath}");
    }
    return 0;
}

static async Task<int> RunFuzzAsync(string[] args)
{
    string? config = null;
    var dryRun = false;
    var coverage = false;
    int? maxIterations = null;
    string? debuggerMode = null;
    string? debuggerKind = null;
    bool? openOnCrash = null;
    for (var i = 0; i < args.Length; i++)
    {
        if (args[i] is "-c" or "--config" && i + 1 < args.Length)
            config = args[++i];
        else if (args[i] is "--dry-run")
            dryRun = true;
        else if (args[i] is "--coverage")
            coverage = true;
        else if (args[i] is "--max-iterations" && i + 1 < args.Length &&
                 int.TryParse(args[++i], out var max))
            maxIterations = max;
        else if (args[i] is "--debugger" && i + 1 < args.Length)
            debuggerMode = args[++i];
        else if (args[i] is "--debugger-kind" && i + 1 < args.Length)
            debuggerKind = args[++i];
        else if (args[i] is "--open-on-crash")
            openOnCrash = true;
    }

    if (config is null)
    {
        Console.Error.WriteLine(
            "Usage: randall fuzz -c projects/vulnserver.yaml [--dry-run] [--coverage] [--max-iterations N]");
        Console.Error.WriteLine(
            "       [--debugger none|attach|wait|both] [--debugger-kind auto|windbg|windbg-preview] [--open-on-crash]");
        return 1;
    }

    var yamlPath = Path.GetFullPath(config);
    var project = ProjectLoader.Load(yamlPath);
    Console.WriteLine($"Fuzzing: {project.Name} ({project.Kind}) — {project.Description}");
    if (dryRun)
        Console.WriteLine("[dry-run mode]");
    if (coverage || project.Fuzz.CoverageGuided)
    {
        var dr = DynamoRioRunner.Discover();
        Console.WriteLine(dr.IsAvailable
            ? $"Coverage-guided via DynamoRIO: {dr.DrrunPath}"
            : "Coverage requested but DynamoRIO not found — run scripts/install-dynamorio.ps1");
    }

    var mode = debuggerMode ?? project.Fuzz.DebuggerMode;
    if (!string.IsNullOrWhiteSpace(mode) && !mode.Equals("none", StringComparison.OrdinalIgnoreCase))
    {
        var tools = DebuggerTools.Probe();
        Console.WriteLine($"Debugger mode: {mode} (gui={tools.PreferredGui ?? "none"}, wait={tools.PreferredWait ?? "none"})");
    }

    var engine = new FuzzEngine();
    var result = await engine.RunAsync(
        project,
        yamlPath,
        new FuzzRunOptions(
            dryRun,
            coverage || project.Fuzz.CoverageGuided,
            maxIterations,
            null,
            debuggerMode,
            debuggerKind,
            openOnCrash));
    Console.WriteLine($"Done: {result.Iterations} iterations, {result.CrashesFound} crashes");
    return 0;
}

static async Task<int> RunCrashesAsync(string[] args)
{
    if (args.Length > 0)
    {
        return args[0].ToLowerInvariant() switch
        {
            "pack" => RunCrashesPack(args.Skip(1).ToArray()),
            "unpack" or "import" => RunCrashesUnpack(args.Skip(1).ToArray()),
            "pull" => await RunCrashesPullAsync(args.Skip(1).ToArray()),
            _ => ListCrashes(args),
        };
    }

    return ListCrashes(args);
}

static int ListCrashes(string[] args)
{
    string? projectFilter = null;
    for (var i = 0; i < args.Length - 1; i++)
    {
        if (args[i] is "-p" or "--project")
            projectFilter = args[++i];
    }

    foreach (var c in CrashCatalog.ListAll(projectFilter: projectFilter))
    {
        var dump = c.MiniDumpPath is not null ? $" dump={c.MiniDumpPath}" : "";
        var sev = c.Severity is not null ? $" [{c.Severity}/{c.CrashClass}]" : "";
        Console.WriteLine(
            $"{c.ObservedAt:u} {c.Project} iter={c.Iteration} {c.Mutator}{sev} exit={c.TargetExitCode}{dump}");
        Console.WriteLine($"             {c.InputPath}");
        if (c.FaultAddress is not null || c.ExceptionHint is not null)
            Console.WriteLine($"             {c.ExceptionHint ?? ""} @ {c.FaultAddress ?? "?"}");
    }
    return 0;
}

static int RunCrashesPack(string[] args)
{
    string? project = null;
    string? output = null;
    var includeRuns = true;
    for (var i = 0; i < args.Length; i++)
    {
        if (args[i] is "-p" or "--project" && i + 1 < args.Length)
            project = args[++i];
        else if (args[i] is "-o" or "--output" && i + 1 < args.Length)
            output = args[++i];
        else if (args[i] is "--no-runs")
            includeRuns = false;
    }

    if (string.IsNullOrWhiteSpace(project))
    {
        Console.Error.WriteLine("Usage: randall crashes pack -p <project> [-o data/exports/pack.zip] [--no-runs]");
        return 1;
    }

    try
    {
        var result = CrashArtifactPack.Export(project, output, includeRuns);
        Console.WriteLine(
            $"Crash pack exported: {result.Path} ({result.SizeBytes / 1024} KB) " +
            $"crashes={result.CrashCount} runs={result.RunCount}");
        return 0;
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine(ex.Message);
        return 1;
    }
}

static int RunCrashesUnpack(string[] args)
{
    string? zip = null;
    for (var i = 0; i < args.Length; i++)
    {
        if (args[i] is "-i" or "--input" or "--zip" && i + 1 < args.Length)
            zip = args[++i];
        else if (!args[i].StartsWith('-') && zip is null)
            zip = args[i];
    }

    if (string.IsNullOrWhiteSpace(zip))
    {
        Console.Error.WriteLine("Usage: randall crashes unpack -i <pack.zip>");
        return 1;
    }

    try
    {
        var result = CrashArtifactPack.Import(Path.GetFullPath(zip));
        Console.WriteLine(result.Message);
        Console.WriteLine($"  project={result.Project}");
        Console.WriteLine($"  crashesDir={result.CrashesDir}");
        return 0;
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine(ex.Message);
        return 1;
    }
}

static async Task<int> RunCrashesPullAsync(string[] args)
{
    string? agent = null;
    string? project = null;
    string? output = null;
    var includeRuns = true;
    var doImport = false;
    for (var i = 0; i < args.Length; i++)
    {
        if (args[i] is "-a" or "--agent" && i + 1 < args.Length)
            agent = args[++i];
        else if (args[i] is "-p" or "--project" && i + 1 < args.Length)
            project = args[++i];
        else if (args[i] is "-o" or "--output" && i + 1 < args.Length)
            output = args[++i];
        else if (args[i] is "--no-runs")
            includeRuns = false;
        else if (args[i] is "--import")
            doImport = true;
    }

    if (string.IsNullOrWhiteSpace(agent) || string.IsNullOrWhiteSpace(project))
    {
        Console.Error.WriteLine(
            "Usage: randall crashes pull -a http://192.168.x.x:5000 -p <project> [-o zip] [--import] [--no-runs]");
        return 1;
    }

    try
    {
        var result = await CrashArtifactPack.PullFromAgentAsync(agent, project, output, includeRuns);
        Console.WriteLine(
            $"Pulled from agent: {result.Path} ({result.SizeBytes / 1024} KB) " +
            $"crashes={result.CrashCount} runs={result.RunCount}");
        if (doImport)
        {
            var imported = CrashArtifactPack.Import(result.Path);
            Console.WriteLine(imported.Message);
        }
        else
        {
            Console.WriteLine("Tip: randall crashes unpack -i <zip>  (or add --import)");
        }

        return 0;
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine(ex.Message);
        return 1;
    }
}

static async Task<int> ReplayCrashAsync(string[] args)
{
    string? config = null;
    string? input = null;
    for (var i = 0; i < args.Length; i++)
    {
        if (args[i] is "-c" or "--config" && i + 1 < args.Length)
            config = args[++i];
        else if (args[i] is "-i" or "--input" && i + 1 < args.Length)
            input = args[++i];
    }

    if (config is null || input is null)
    {
        Console.Error.WriteLine("Usage: randall replay -c projects/vulnserver.yaml -i path/to/crash.bin");
        return 1;
    }

    var yamlPath = Path.GetFullPath(config);
    var inputPath = Path.GetFullPath(input);
    if (!File.Exists(inputPath))
    {
        Console.Error.WriteLine($"File not found: {inputPath}");
        return 1;
    }

    var project = ProjectLoader.Load(yamlPath);
    var payload = await File.ReadAllBytesAsync(inputPath);
    Console.WriteLine($"Replaying {payload.Length} bytes against {project.Name} ({project.Kind})");

    var engine = new ReplayEngine();
    var result = await engine.ReplayAsync(project, yamlPath, payload);
    Console.WriteLine(
        result.Crashed
            ? $"CRASH reproduced — {result.Detail} exit={result.ExitCode}"
            : $"No crash — {result.Detail}");
    if (result.MiniDumpPath is not null)
        Console.WriteLine($"Minidump: {result.MiniDumpPath}");
    return result.Crashed ? 0 : 2;
}

static async Task<int> RunProxyAsync(string[] args)
{
    var listen = 9998;
    var targetHost = "127.0.0.1";
    var targetPort = 9999;
    for (var i = 0; i < args.Length - 1; i++)
    {
        if (args[i] is "--listen" or "-l" && int.TryParse(args[i + 1], out var lp))
            listen = lp;
        else if (args[i] is "--target" or "-t")
        {
            var parts = args[++i].Split(':');
            targetHost = parts[0];
            if (parts.Length > 1)
                int.TryParse(parts[1], out targetPort);
        }
    }

    var proxy = new ProxyManager();
    if (!proxy.Start(new ProxyStartRequest(targetHost, targetPort, listen, "cli")))
    {
        Console.Error.WriteLine("Proxy already running.");
        return 1;
    }

    Console.WriteLine($"MITM proxy: 127.0.0.1:{listen} → {targetHost}:{targetPort}");
    Console.WriteLine("Point your client at the listen port. Press Ctrl+C to stop.");

    var tcs = new TaskCompletionSource();
    Console.CancelKeyPress += (_, e) =>
    {
        e.Cancel = true;
        tcs.TrySetResult();
    };
    await tcs.Task;
    await proxy.StopAsync();
    Console.WriteLine($"Captured {proxy.Messages().Count} messages.");
    return 0;
}

static async Task<int> RunCampaignAsync(string[] args)
{
    string? config = null;
    for (var i = 0; i < args.Length - 1; i++)
    {
        if (args[i] is "-c" or "--config")
            config = args[++i];
    }
    if (config is null)
    {
        Console.Error.WriteLine("Usage: randall campaign -c campaigns/lab-smoke.yaml");
        Console.WriteLine("Campaigns:");
        foreach (var c in PluginCatalog.ListCampaigns())
            Console.WriteLine($"  {c}");
        return 1;
    }

    var yamlPath = Path.GetFullPath(config);
    var campaign = CampaignLoader.Load(yamlPath);
    Console.WriteLine($"Campaign: {campaign.Name} — {campaign.Description}");
    Console.WriteLine($"Runs: {campaign.Runs.Count}");

    var runner = new CampaignRunner();
    var result = await runner.RunAsync(campaign, yamlPath);
    foreach (var run in result.Runs)
    {
        var status = run.Success ? "ok" : $"FAIL {run.Error}";
        Console.WriteLine($"  {run.Project,-12} iter={run.Iterations} crashes={run.Crashes} [{status}]");
    }
    Console.WriteLine($"Total crashes: {result.TotalCrashes}");
    return result.Success ? 0 : 2;
}

static async Task<int> RunPackAsync(string[] args)
{
    var output = "publish/standalone";
    for (var i = 0; i < args.Length - 1; i++)
    {
        if (args[i] is "-o" or "--output")
            output = args[++i];
    }

    var root = CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
    Console.WriteLine($"Packing portable Randfuzz → {output}");
    var result = await PortablePacker.PackAsync(root, output);
    Console.WriteLine($"Done: {result.OutputPath} ({result.SizeBytes / 1024 / 1024} MB)");
    Console.WriteLine($"Included: {result.Included.Length} paths");
    return 0;
}

static int RunBundle(string[] args)
{
    if (args.Length == 0)
    {
        PrintBundleUsage();
        return 1;
    }

    return args[0].ToLowerInvariant() switch
    {
        "export" => BundleExport(args.Skip(1).ToArray()),
        "import" => BundleImport(args.Skip(1).ToArray()),
        _ => BundleExport(args),
    };
}

static void PrintBundleUsage()
{
    Console.Error.WriteLine("Usage:");
    Console.Error.WriteLine("  randall bundle export -c projects/vulnserver.yaml [-o bundles/out.zip]");
    Console.Error.WriteLine("  randall bundle import -i bundles/vulnserver.zip [-o projects/imported]");
    Console.Error.WriteLine("  randall bundle -c projects/vulnserver.yaml   (export shorthand)");
}

static int BundleExport(string[] args)
{
    string? config = null;
    string? output = null;
    for (var i = 0; i < args.Length - 1; i++)
    {
        if (args[i] is "-c" or "--config")
            config = args[++i];
        else if (args[i] is "-o" or "--output")
            output = args[++i];
    }
    if (config is null)
    {
        PrintBundleUsage();
        return 1;
    }
    var path = ProjectBundle.Export(Path.GetFullPath(config), output);
    var size = new FileInfo(path).Length;
    Console.WriteLine($"Project bundle exported: {path} ({size / 1024} KB)");
    return 0;
}

static int BundleImport(string[] args)
{
    string? input = null;
    string? output = null;
    for (var i = 0; i < args.Length - 1; i++)
    {
        if (args[i] is "-i" or "--input")
            input = args[++i];
        else if (args[i] is "-o" or "--output")
            output = args[++i];
    }
    if (input is null)
    {
        PrintBundleUsage();
        return 1;
    }
    var path = ProjectBundle.Import(Path.GetFullPath(input), output);
    Console.WriteLine($"Project bundle imported: {path}");
    return 0;
}

static int RunExport(string[] args)
{
    Guid? id = null;
    for (var i = 0; i < args.Length - 1; i++)
    {
        if (args[i] is "-i" or "--id" && Guid.TryParse(args[++i], out var g))
            id = g;
    }

    if (id is null)
    {
        Console.Error.WriteLine("Usage: randall export -i <crash-guid>");
        Console.Error.WriteLine("Tip: randall crashes — copy Id from index or web UI.");
        return 1;
    }

    var bundle = CrashStalker.ExportBundle(id.Value);
    if (bundle is null)
    {
        Console.Error.WriteLine($"Crash not found: {id}");
        return 1;
    }

    Console.WriteLine($"Triage bundle exported to:\n  {bundle.ExportPath}");
    return 0;
}

static int RunDoctor(string[] args)
{
    string? config = null;
    var strict = false;
    for (var i = 0; i < args.Length; i++)
    {
        if (args[i] is "-c" or "--config" && i + 1 < args.Length)
            config = args[++i];
        else if (args[i] is "--strict")
            strict = true;
    }

    if (config is null)
    {
        Console.Error.WriteLine("Usage: randall doctor -c projects/vulnserver.yaml [--strict]");
        return 1;
    }

    var report = LabDoctor.Examine(Path.GetFullPath(config), requireTarget: strict);
    foreach (var check in report.Checks)
    {
        var icon = check.Status switch { "ok" => "✓", "warn" => "!", _ => "✗" };
        Console.WriteLine($"  [{icon}] {check.Id,-24} {check.Message}");
    }

    Console.WriteLine();
    Console.WriteLine(report.Ready
        ? $"Ready to fuzz {report.Project}."
        : $"Not ready — fix failures above, then: randall fuzz -c {config} --dry-run");

    return report.Ready ? 0 : 1;
}

static int RunGraph(string[] args)
{
    string? config = null;
    var json = false;
    for (var i = 0; i < args.Length; i++)
    {
        if (args[i] is "-c" or "--config" && i + 1 < args.Length)
            config = args[++i];
        else if (args[i] is "--json")
            json = true;
    }

    if (config is null)
    {
        Console.Error.WriteLine("Usage: randall graph -c projects/vulnftp.yaml [--json]");
        return 1;
    }

    var yamlPath = Path.GetFullPath(config);
    var project = ProjectLoader.Load(yamlPath);
    var report = SessionGraphValidator.Validate(project, yamlPath);

    if (json)
    {
        Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(report));
        return report.Valid ? 0 : 1;
    }

    if (project.SessionGraph is null)
    {
        Console.WriteLine($"{project.Name}: no sessionGraph defined.");
        Console.WriteLine("Use sessionFlows for linear chains, or add sessionGraph for response branching.");
        if (report.Commands.Count > 0)
            Console.WriteLine($"Session commands: {string.Join(", ", report.Commands)}");
        return 0;
    }

    Console.WriteLine($"Session graph: {project.Name} (start={report.Start}, mutate={report.Mutate})");
    foreach (var err in report.Errors)
        Console.Error.WriteLine($"  error: {err}");
    foreach (var warn in report.Warnings)
        Console.WriteLine($"  warn: {warn}");

    if (!string.IsNullOrWhiteSpace(report.Mermaid))
    {
        Console.WriteLine();
        Console.WriteLine("Mermaid (paste into mermaid.live):");
        Console.WriteLine(report.Mermaid);
    }

    return report.Valid ? 0 : 1;
}

static int RunAnalyze(string[] args)
{
    Guid? id = null;
    string? dumpPath = null;
    var json = false;
    for (var i = 0; i < args.Length; i++)
    {
        if (args[i] is "-i" or "--id" && i + 1 < args.Length && Guid.TryParse(args[i + 1], out var g))
        {
            id = g;
            i++;
        }
        else if (args[i] is "-d" or "--dump" && i + 1 < args.Length)
        {
            dumpPath = Path.GetFullPath(args[++i]);
        }
        else if (args[i] is "--json")
            json = true;
    }

    CrashAnalysisDto? analysis = null;
    CrashDetailDto? detail = null;
    if (id is not null)
    {
        detail = CrashCatalog.GetDetail(id.Value);
        if (detail is null)
        {
            Console.Error.WriteLine($"Crash not found: {id}");
            return 1;
        }
        analysis = detail.Analysis;
        if (analysis is null && detail.Summary.MiniDumpPath is not null)
            analysis = CrashAnalysisWriter.AnalyzeDump(detail.Summary.MiniDumpPath);
        if (analysis is null)
        {
            Console.Error.WriteLine($"No minidump for crash {id}. Replay with a crashing target first.");
            return 1;
        }
    }
    else if (dumpPath is not null)
    {
        if (!File.Exists(dumpPath))
        {
            Console.Error.WriteLine($"File not found: {dumpPath}");
            return 1;
        }
        analysis = CrashAnalysisWriter.AnalyzeDump(dumpPath);
    }
    else
    {
        Console.Error.WriteLine("Usage: randall analyze -i <crash-guid> [--json]");
        Console.Error.WriteLine("       randall analyze -d path/to/crash.dmp [--json]");
        return 1;
    }

    if (json)
    {
        Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(analysis,
            new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));
        return analysis!.Ok ? 0 : 2;
    }

    if (!analysis!.Ok)
    {
        Console.Error.WriteLine($"Analysis failed: {analysis.Error}");
        return 2;
    }

    Console.WriteLine($"Exception: {analysis.ExceptionHint} ({analysis.ExceptionCode})");
    Console.WriteLine($"Fault:     {analysis.FaultAddress}" +
                      (analysis.FaultModule is not null ? $" in {analysis.FaultModule}" : ""));
    if (analysis.Registers is { } r)
    {
        Console.WriteLine($"RIP={r.Rip} RSP={r.Rsp} RBP={r.Rbp}");
        Console.WriteLine($"RAX={r.Rax} RBX={r.Rbx} RCX={r.Rcx} RDX={r.Rdx}");
    }
    if (analysis.LoadedModules.Count > 0)
    {
        Console.WriteLine("Modules:");
        foreach (var m in analysis.LoadedModules.Take(8))
            Console.WriteLine($"  {m}");
        if (analysis.LoadedModules.Count > 8)
            Console.WriteLine($"  … +{analysis.LoadedModules.Count - 8} more");
    }

    if (detail?.Triage is { } t)
    {
        Console.WriteLine($"Triage:    {t.Severity} / {t.Class}");
        Console.WriteLine($"           {t.Summary}");
        if (t.PatternDepthBytes is not null)
            Console.WriteLine($"Depth:     offset {t.PatternDepthBytes} — {t.PatternNote}");
    }

    return 0;
}

static int RunMemoryLens(string[] args)
{
    Guid? id = null;
    string? dumpPath = null;
    int? pid = null;
    var json = false;
    for (var i = 0; i < args.Length; i++)
    {
        if (args[i] is "-i" or "--id" && i + 1 < args.Length && Guid.TryParse(args[i + 1], out var g))
        {
            id = g;
            i++;
        }
        else if (args[i] is "-d" or "--dump" && i + 1 < args.Length)
            dumpPath = Path.GetFullPath(args[++i]);
        else if (args[i] is "--pid" && i + 1 < args.Length && int.TryParse(args[i + 1], out var p))
        {
            pid = p;
            i++;
        }
        else if (args[i] is "--json")
            json = true;
    }

    MemoryLensReportDto report;
    if (pid is not null && id is null && dumpPath is null)
    {
        report = MemoryLensAnalyzer.AnalyzeLivePid(pid.Value);
    }
    else if (id is not null)
    {
        var detail = CrashCatalog.GetDetail(id.Value);
        if (detail is null)
        {
            Console.Error.WriteLine($"Crash not found: {id}");
            return 1;
        }

        var repo = CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var crashesDir = Path.Combine(repo, "data", "crashes", detail.Summary.Project);
        report = MemoryLensWriter.TryRead(crashesDir, id.Value)
                 ?? MemoryLensAnalyzer.AnalyzeDump(
                     detail.Summary.MiniDumpPath ?? dumpPath, detail.Analysis, pid);
        if (report.Ok)
            MemoryLensWriter.Write(crashesDir, id.Value, report);
    }
    else if (dumpPath is not null)
    {
        report = MemoryLensAnalyzer.AnalyzeDump(dumpPath, null, pid);
    }
    else
    {
        Console.Error.WriteLine("Usage: randall memory -i <crash-guid> [--json]");
        Console.Error.WriteLine("       randall memory -d path/to/crash.dmp [--json]");
        Console.Error.WriteLine("       randall memory --pid <pid>");
        return 1;
    }

    if (json)
    {
        Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(report,
            new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));
        return report.Ok ? 0 : 2;
    }

    Console.WriteLine(MemoryLensWriter.FormatText(report));
    return report.Ok ? 0 : 2;
}

static int RunStalk(string[] args)
{
    if (args.Length == 0 || args[0] is "-h" or "--help" or "help")
    {
        Console.WriteLine("""
            Usage:
              randall stalk layers -p <project>
              randall stalk compare -p <project> [layerId…]
              randall stalk export -p <project> --format idc|ghidra|edges [-o dir] [layerId…]
              randall stalk from-crash -i <crash-guid> [--tag crash] [--label text]
            """);
        return 0;
    }

    var sub = args[0].ToLowerInvariant();
    var rest = args.Skip(1).ToArray();
    return sub switch
    {
        "layers" => StalkLayers(rest),
        "compare" => StalkCompare(rest),
        "export" => StalkExport(rest),
        "from-crash" => StalkFromCrash(rest),
        _ => Unknown($"stalk {args[0]}"),
    };
}

static int StalkLayers(string[] args)
{
    var project = RequireProject(args);
    if (project is null)
        return 1;

    var layers = StalkCampaignStore.ListLayers(project);
    if (layers.Count == 0)
    {
        Console.WriteLine($"{project}: no stalk layers yet.");
        return 0;
    }

    foreach (var l in layers)
    {
        Console.WriteLine(
            $"{l.Id}  [{l.Tag}] blocks={l.BlockCount}  {l.Label}  {l.CreatedAt:u}");
        if (!string.IsNullOrWhiteSpace(l.CrashId))
            Console.WriteLine($"             crash={l.CrashId}");
    }
    return 0;
}

static int StalkCompare(string[] args)
{
    var project = RequireProject(args);
    if (project is null)
        return 1;

    var layerIds = PositionalIds(args);
    var cmp = StalkCampaignStore.Compare(project, layerIds);
    Console.WriteLine($"{cmp.Project}: {cmp.LayerIds.Count} layers · union={cmp.UnionBlocks} shared={cmp.SharedBlocks}");
    foreach (var d in cmp.Deltas)
        Console.WriteLine($"  {d.LayerId} [{d.Tag}] unique={d.UniqueBlocks} +vsPrev={d.NewVsPrevious}");
    foreach (var b in cmp.Blocks.Take(24))
        Console.WriteLine($"  {b.Kind,-10} {b.Module}:{b.Address}  ({b.FirstLayerTag})");
    if (cmp.Blocks.Count > 24)
        Console.WriteLine($"  … +{cmp.Blocks.Count - 24} more blocks");
    return 0;
}

static int StalkExport(string[] args)
{
    var project = RequireProject(args);
    if (project is null)
        return 1;

    string format = "idc";
    string? output = null;
    for (var i = 0; i < args.Length; i++)
    {
        if (args[i] is "--format" or "-f" && i + 1 < args.Length)
            format = args[++i];
        else if (args[i] is "-o" or "--output" && i + 1 < args.Length)
            output = args[++i];
    }

    try
    {
        var result = StalkCoverageExport.Export(new StalkExportRequest(
            project,
            PositionalIds(args),
            format,
            output));
        Console.WriteLine($"Exported {result.Format}: {result.BlockCount} blocks → {result.OutputPath}");
        foreach (var f in result.Files)
            Console.WriteLine($"  {f}");
        return 0;
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine(ex.Message);
        return 1;
    }
}

static int StalkFromCrash(string[] args)
{
    Guid? id = null;
    string tag = "crash";
    string? label = null;
    for (var i = 0; i < args.Length; i++)
    {
        if (args[i] is "-i" or "--id" && i + 1 < args.Length && Guid.TryParse(args[i + 1], out var g))
        {
            id = g;
            i++;
        }
        else if (args[i] is "--tag" && i + 1 < args.Length)
            tag = args[++i];
        else if (args[i] is "--label" && i + 1 < args.Length)
            label = args[++i];
    }

    if (id is null)
    {
        Console.Error.WriteLine("Usage: randall stalk from-crash -i <crash-guid> [--tag crash]");
        return 1;
    }

    var detail = CrashCatalog.GetDetail(id.Value);
    if (detail is null)
    {
        Console.Error.WriteLine($"Crash not found: {id}");
        return 1;
    }

    try
    {
        var layer = StalkCampaignStore.AddLayer(new StalkLayerCreateRequest(
            detail.Summary.Project,
            tag,
            label ?? $"crash {detail.Summary.Id.ToString("N")[..8]}",
            null,
            null,
            null,
            detail.Summary.Id.ToString(),
            detail.Triage?.Summary));
        Console.WriteLine($"Stalk layer {layer.Id} [{layer.Tag}] blocks={layer.BlockCount} project={layer.Project}");
        return 0;
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine(ex.Message);
        return 1;
    }
}

static string? RequireProject(string[] args)
{
    for (var i = 0; i < args.Length - 1; i++)
    {
        if (args[i] is "-p" or "--project")
            return args[i + 1];
    }
    Console.Error.WriteLine("Missing -p <project>");
    return null;
}

static IReadOnlyList<string> PositionalIds(string[] args)
{
    var ids = new List<string>();
    for (var i = 0; i < args.Length; i++)
    {
        if (args[i] is "-p" or "--project" or "--format" or "-f" or "-o" or "--output" or "--tag" or "--label" or "-i" or "--id")
        {
            i++;
            continue;
        }
        if (args[i].StartsWith('-'))
            continue;
        ids.Add(args[i]);
    }
    return ids;
}

static async Task<int> RunScream(string[] args)
{
    if (args.Length == 0 || args[0] is "-h" or "--help" or "help")
    {
        Console.WriteLine("""
            Randfuzz Scream — first-party exception watcher (replaces ProcDump for wait mode)

            Usage:
              randall scream watch -p <pid> [-o dumpsDir]
              randall scream watch -t <project> [-o dumpsDir]
              randall scream selftest              Build/run lab AV target + verify dump

            Attaches as debugger, waits for a second-chance exception, writes a full
            minidump, then terminates the target. Used automatically by:
              randall fuzz -c projects/screamcrash.yaml --debugger wait
            """);
        return 0;
    }

    var sub = args[0].ToLowerInvariant();
    if (sub is "selftest" or "test")
        return await RunScreamSelftestAsync();
    if (sub is not "watch")
        return Unknown($"scream {args[0]}");

    int? pid = null;
    string? project = null;
    string? outDir = null;
    for (var i = 1; i < args.Length; i++)
    {
        if (args[i] is "-p" or "--pid" && i + 1 < args.Length && int.TryParse(args[i + 1], out var p))
        {
            pid = p;
            i++;
        }
        else if (args[i] is "-t" or "--project" && i + 1 < args.Length)
            project = args[++i];
        else if (args[i] is "-o" or "--output" && i + 1 < args.Length)
            outDir = args[++i];
    }

    if (pid is null && project is not null)
        pid = DebuggerSession.FindProjectPid(project);
    if (pid is null)
    {
        Console.Error.WriteLine("Usage: randall scream watch -p <pid> | -t <project> [-o dumpsDir]");
        return 1;
    }

    outDir ??= Path.Combine(
        CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory(),
        "data", "crashes", "dumps");
    Directory.CreateDirectory(outDir);

    Console.WriteLine($"Scream watching PID {pid} → {outDir}");
    using var watcher = ScreamWatcher.Start(pid.Value, outDir);
    var attached = await watcher.WaitUntilAttachedAsync(TimeSpan.FromSeconds(5));
    if (!attached)
    {
        Console.Error.WriteLine($"Attach failed: {watcher.LastError ?? watcher.Phase}");
        return 2;
    }

    Console.WriteLine($"Attached ({(watcher.IsWow64 ? "wow64" : "x64")}). Waiting for second-chance…");
    Console.WriteLine($"Dump path: {watcher.DumpPath}");

    var dump = await watcher.Completion;
    Console.WriteLine($"Phase: {watcher.Phase}");
    if (dump is null)
    {
        Console.Error.WriteLine(watcher.LastError is not null
            ? $"No dump: {watcher.LastError}"
            : "No dump captured (process exited without second-chance exception).");
        return 2;
    }

    Console.WriteLine($"Dump: {dump}");
    if (watcher.ExceptionInfo is { } ex)
    {
        Console.WriteLine($"Exception: {ex.ExceptionHint} ({ex.ExceptionCode:X8}) @ {ex.FaultAddress}");
        if (ex.Registers is { } r)
            Console.WriteLine($"RIP={r.Rip} RSP={r.Rsp} RAX={r.Rax}");
    }

    var analysis = CrashAnalysisWriter.AnalyzeDump(dump);
    if (analysis.Ok)
        Console.WriteLine($"Analyze: {analysis.ExceptionHint} @ {analysis.FaultAddress}");
    else if (watcher.ExceptionInfo is not null)
        Console.WriteLine("Analyze: using live scream exception info (dump stream optional)");
    else
        Console.WriteLine($"Analyze: {analysis.Error}");

    return 0;
}

static async Task<int> RunScreamSelftestAsync()
{
    Console.WriteLine("Scream selftest — native AV process, attach, verify dump…");
    var result = await ScreamSelftest.RunAsync();
    Console.WriteLine(result.Message);
    if (result.DumpPath is not null)
        Console.WriteLine($"Dump: {result.DumpPath}");
    if (result.Exception is { } ex)
        Console.WriteLine($"Live: {ex.ExceptionHint} @ {ex.FaultAddress} rip={ex.Registers?.Rip} ({ex.Chance})");
    if (result.Analysis is { Ok: true } a)
        Console.WriteLine($"Analyze: {a.ExceptionHint} @ {a.FaultAddress}");
    if (result.Events.Count > 0)
        Console.WriteLine("Events: " + string.Join(" | ", result.Events.Take(12)));
    return result.Ok ? 0 : 2;
}

static int RunDebug(string[] args)
{
    if (args.Length == 0 || args[0] is "-h" or "--help" or "help")
    {
        Console.WriteLine("""
            Usage:
              randall debug tools
              randall debug open -i <crash-guid> [--kind windbg|windbg-preview|cdb]
              randall debug open -d <dump.dmp> [--kind …]
              randall debug attach -p <pid> [--kind …] [--break]
              randall debug attach -t <project> [--kind …]
            """);
        return 0;
    }

    var sub = args[0].ToLowerInvariant();
    var rest = args.Skip(1).ToArray();
    return sub switch
    {
        "tools" => DebugTools(),
        "open" => DebugOpen(rest),
        "attach" => DebugAttach(rest),
        _ => Unknown($"debug {args[0]}"),
    };
}

static int DebugTools()
{
    var probe = DebuggerTools.Probe();
    Console.WriteLine($"Preferred GUI:  {probe.PreferredGui ?? "(none)"}");
    Console.WriteLine($"Preferred wait: {probe.PreferredWait ?? "(none)"}");
    foreach (var t in probe.Tools)
    {
        var mark = t.Available ? "ready" : "missing";
        Console.WriteLine($"  [{mark}] {t.Name}");
        if (t.Path is not null)
            Console.WriteLine($"           {t.Path}");
        if (t.CommandHint is not null)
            Console.WriteLine($"           {t.CommandHint}");
    }
    return 0;
}

static int DebugOpen(string[] args)
{
    Guid? id = null;
    string? dump = null;
    var kind = "auto";
    for (var i = 0; i < args.Length; i++)
    {
        if (args[i] is "-i" or "--id" && i + 1 < args.Length && Guid.TryParse(args[i + 1], out var g))
        {
            id = g;
            i++;
        }
        else if (args[i] is "-d" or "--dump" && i + 1 < args.Length)
            dump = args[++i];
        else if (args[i] is "--kind" or "-k" && i + 1 < args.Length)
            kind = args[++i];
    }

    DebuggerLaunchResultDto result;
    if (id is not null)
        result = DebuggerSession.OpenCrash(id.Value, kind);
    else if (dump is not null)
        result = DebuggerSession.OpenDump(dump, kind);
    else
    {
        Console.Error.WriteLine("Usage: randall debug open -i <crash-guid> | -d <dump.dmp>");
        return 1;
    }

    Console.WriteLine(result.Message);
    return result.Ok ? 0 : 1;
}

static int DebugAttach(string[] args)
{
    int? pid = null;
    string? project = null;
    var kind = "auto";
    var go = true;
    for (var i = 0; i < args.Length; i++)
    {
        if (args[i] is "-p" or "--pid" && i + 1 < args.Length && int.TryParse(args[i + 1], out var p))
        {
            pid = p;
            i++;
        }
        else if (args[i] is "-t" or "--project" && i + 1 < args.Length)
            project = args[++i];
        else if (args[i] is "--kind" or "-k" && i + 1 < args.Length)
            kind = args[++i];
        else if (args[i] is "--break")
            go = false;
    }

    DebuggerLaunchResultDto result;
    if (pid is not null)
        result = DebuggerSession.Attach(pid.Value, kind, go);
    else if (project is not null)
        result = DebuggerSession.AttachProject(project, kind, go);
    else
    {
        Console.Error.WriteLine("Usage: randall debug attach -p <pid> | -t <project>");
        return 1;
    }

    Console.WriteLine(result.Message);
    return result.Ok ? 0 : 1;
}

static int RunServe(string[] args) => RunWebHost(args, defaultBind: "127.0.0.1", label: "web UI");

static int RunAgent(string[] args) => RunWebHost(args, defaultBind: "0.0.0.0", label: "lab agent");

static int RunWebHost(string[] args, string defaultBind, string label)
{
    var port = 5000;
    var bind = defaultBind;
    for (var i = 0; i < args.Length; i++)
    {
        if (args[i] is "--port" or "-p" && i + 1 < args.Length && int.TryParse(args[i + 1], out var p))
        {
            port = p;
            i++;
        }
        else if (args[i] is "--bind" or "-b" && i + 1 < args.Length)
        {
            bind = args[i + 1];
            i++;
        }
    }

    var serverProject = FindServerProjectPath();
    if (serverProject is null)
    {
        Console.Error.WriteLine("Could not locate Randall.Server.csproj.");
        return 1;
    }

    var urls = $"http://{bind}:{port}";
    Console.WriteLine($"Starting Randfuzz {label} at {urls}");
    if (bind is "0.0.0.0" or "*")
        Console.WriteLine($"LAN clients: http://<this-machine-ip>:{port}");

    var psi = new ProcessStartInfo
    {
        FileName = "dotnet",
        Arguments = $"run --project \"{serverProject}\" --urls {urls}",
        UseShellExecute = false,
    };
    using var process = Process.Start(psi);
    if (process is null)
        return 1;
    process.WaitForExit();
    return process.ExitCode;
}

static string? FindServerProjectPath()
{
    var dir = new DirectoryInfo(AppContext.BaseDirectory);
    while (dir is not null)
    {
        var candidate = Path.Combine(dir.FullName, "src", "Randall.Server", "Randall.Server.csproj");
        if (File.Exists(candidate))
            return candidate;
        dir = dir.Parent;
    }
    return null;
}

static int RunCase(string[] args)
{
    if (args.Length == 0 || args[0] is "-h" or "--help" or "help")
    {
        Console.WriteLine("""
            Randfuzz case builder — seeds, dictionaries, YAML targets

            Usage:
              randall case ops
              randall case new --name <id> [--kind tcp|udp|file] [--host H] [--port N]
                               [--exe path] [--desc text] [--public]
              randall case update -p <project> [--host H] [--port N] [--exe path] [--desc text]
              randall case preview [--static T] [--text T] [--delim T] [--hex H]
                                   [--repeat C] [--crlf] [--null] [--cyclic N]
              randall case save-seed -p <project> [--file name.bin] [same preview flags…]
              randall case from-file -p <project> --file sample.bin [--exact]
                    Upload a sample → print template recipe; --exact also saves the raw seed
              randall case from-stream -p <project> --file capture.txt [--hex] [--apply]
                    Split blank-line / --- separated capture into session PDUs
              randall case apply-session -p <project> --recipe NAME [--flow id] [--mutate last|all] [--models]
                    Materialize a saved session recipe into sessionCommands/Flows
              randall case promote -p <project> --name proto [--recipe NAME | --static …]
                    Promote Scare Floor blocks → projects/.../protocols/*.yaml
              randall case idl -p <project> --name stub --file iface.idl
                    Minimal typedef struct → protocols/*.yaml stub field map
              randall case packs                              List protocol packs
              randall case packs --load ID -p <project>       Load pack recipe into project recipes/
              randall case recipes -p <project>               List Scare Floor recipes
              randall case recipes -p <project> --load NAME   Print a saved recipe
              randall case mutators -p <project>              List mutators
              randall case mutators -p <project> --set a,b,c  Update YAML mutators

            The YAML name: field is the Target profile label in the web UI.
            Docs: docs/CUSTOM_TARGETS.md · docs/CASE_BUILDER.md
            """);
        return 0;
    }

    var sub = args[0].ToLowerInvariant();
    var rest = args.Skip(1).ToArray();
    try
    {
        return sub switch
        {
            "ops" => CaseOps(),
            "new" or "create" => CaseNew(rest),
            "update" or "edit" => CaseUpdate(rest),
            "preview" => CasePreview(rest),
            "save-seed" or "seed" => CaseSaveSeed(rest),
            "from-file" or "import-file" or "template" => CaseFromFile(rest),
            "from-stream" or "stream" => CaseFromStream(rest),
            "apply-session" or "apply" => CaseApplySession(rest),
            "promote" => CasePromote(rest),
            "idl" => CaseIdl(rest),
            "packs" or "pack" => CasePacks(rest),
            "recipes" or "recipe" => CaseRecipes(rest),
            "mutators" or "mutator" => CaseMutators(rest),
            _ => Unknown($"case {args[0]}"),
        };
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine(ex.Message);
        return 1;
    }
}

static int CaseOps()
{
    foreach (var op in CaseRecipeEngine.ListOps())
        Console.WriteLine($"{op.Id,-12} {op.Name} — {op.Description}");
    return 0;
}

static int CaseNew(string[] args)
{
    string? name = null, kind = "tcp", host = "127.0.0.1", exe = null, desc = null;
    string? extension = null, fileFormat = null;
    var port = 8080;
    var local = true;
    for (var i = 0; i < args.Length; i++)
    {
        switch (args[i])
        {
            case "--name" or "-n" when i + 1 < args.Length: name = args[++i]; break;
            case "--kind" or "-k" when i + 1 < args.Length: kind = args[++i]; break;
            case "--host" when i + 1 < args.Length: host = args[++i]; break;
            case "--port" when i + 1 < args.Length: port = int.Parse(args[++i]); break;
            case "--exe" or "--executable" when i + 1 < args.Length: exe = args[++i]; break;
            case "--desc" or "--description" when i + 1 < args.Length: desc = args[++i]; break;
            case "--ext" or "--extension" when i + 1 < args.Length: extension = args[++i]; break;
            case "--format" when i + 1 < args.Length: fileFormat = args[++i]; break;
            case "--public": local = false; break;
            case "--local": local = true; break;
        }
    }

    if (string.IsNullOrWhiteSpace(name))
    {
        Console.Error.WriteLine(
            "Usage: randall case new --name <id> [--kind tcp|udp|file] [--ext .bin] [--format file-xml|file-framed|file-magic|file-blank]");
        return 1;
    }

    var r = CaseRecipeStore.CreateProject(new CaseNewProjectRequest(
        name, kind, desc, host, port, exe, local, extension, fileFormat));
    Console.WriteLine(r.Message);
    if (r.Path is not null)
        Console.WriteLine(r.Path);
    return r.Ok ? 0 : 1;
}

static int CaseUpdate(string[] args)
{
    string? project = null, host = null, exe = null, desc = null;
    int? port = null;
    bool? longLived = null;
    for (var i = 0; i < args.Length; i++)
    {
        switch (args[i])
        {
            case "-p" or "--project" when i + 1 < args.Length: project = args[++i]; break;
            case "--host" when i + 1 < args.Length: host = args[++i]; break;
            case "--port" when i + 1 < args.Length: port = int.Parse(args[++i]); break;
            case "--exe" or "--executable" when i + 1 < args.Length: exe = args[++i]; break;
            case "--desc" or "--description" when i + 1 < args.Length: desc = args[++i]; break;
            case "--long-lived": longLived = true; break;
            case "--no-long-lived": longLived = false; break;
        }
    }

    if (string.IsNullOrWhiteSpace(project))
    {
        Console.Error.WriteLine("Usage: randall case update -p <project> [--host H] [--port N] [--exe path] [--desc text]");
        return 1;
    }

    var r = CaseRecipeStore.UpdateProject(new CaseUpdateProjectRequest(
        project, desc, host, port, exe, longLived));
    Console.WriteLine(r.Message);
    return r.Ok ? 0 : 1;
}

static int CasePreview(string[] args)
{
    var steps = ParseCaseSteps(args);
    var preview = CaseRecipeEngine.Preview(steps);
    Console.WriteLine($"{preview.Length} bytes");
    Console.WriteLine($"ASCII: {preview.AsciiPreview}");
    Console.WriteLine($"HEX:   {preview.HexPreview}");
    if (preview.DictionaryHints.Count > 0)
        Console.WriteLine("Dict:  " + string.Join(" | ", preview.DictionaryHints));
    foreach (var n in preview.Notes)
        Console.WriteLine($"note:  {n}");
    return 0;
}

static int CaseSaveSeed(string[] args)
{
    string? project = null, file = null;
    var stepArgs = new List<string>();
    for (var i = 0; i < args.Length; i++)
    {
        if ((args[i] is "-p" or "--project") && i + 1 < args.Length)
            project = args[++i];
        else if ((args[i] is "--file" or "-f" or "-o") && i + 1 < args.Length)
            file = args[++i];
        else
            stepArgs.Add(args[i]);
    }

    if (string.IsNullOrWhiteSpace(project))
    {
        Console.Error.WriteLine("Usage: randall case save-seed -p <project> [--file name.bin] --static …");
        return 1;
    }

    var steps = ParseCaseSteps(stepArgs.ToArray());
    if (steps.Count == 0)
    {
        Console.Error.WriteLine("Provide at least one block flag (--static, --text, --hex, --crlf, …)");
        return 1;
    }

    var r = CaseRecipeStore.SaveSeed(new CaseSaveSeedRequest(project, file ?? "", steps, true));
    Console.WriteLine(r.Message);
    return r.Ok ? 0 : 1;
}

/// <summary>Build a fuzz template recipe from a sample file; optionally save the exact bytes as a seed.</summary>
static int CaseFromFile(string[] args)
{
    string? project = null, file = null, outName = null;
    var exact = false;
    for (var i = 0; i < args.Length; i++)
    {
        if ((args[i] is "-p" or "--project") && i + 1 < args.Length)
            project = args[++i];
        else if ((args[i] is "--file" or "-f" or "-i") && i + 1 < args.Length)
            file = args[++i];
        else if ((args[i] is "--out" or "-o" or "--name") && i + 1 < args.Length)
            outName = args[++i];
        else if (args[i] is "--exact" or "--raw" or "--save")
            exact = true;
    }

    if (string.IsNullOrWhiteSpace(file) || !File.Exists(file))
    {
        Console.Error.WriteLine("Usage: randall case from-file -p <project> --file sample.bin [--exact] [--out name.bin]");
        return 1;
    }

    var bytes = File.ReadAllBytes(file);
    var imported = CaseRecipeEngine.SuggestFromBytes(bytes, Path.GetFileName(file));
    Console.WriteLine($"Format: {imported.DetectedFormat ?? "unknown"} · {imported.Length} bytes · {imported.SuggestedSteps.Count} block(s)");
    foreach (var n in imported.Notes ?? [])
        Console.WriteLine($"  note: {n}");
    Console.WriteLine();
    Console.WriteLine("Template recipe:");
    foreach (var s in imported.SuggestedSteps)
    {
        var bits = new List<string> { s.Op };
        if (!string.IsNullOrWhiteSpace(s.Value))
            bits.Add(s.Value!.Length > 48 ? s.Value[..48] + "…" : s.Value);
        if (s.Count is int c)
            bits.Add($"count={c}");
        if (!string.IsNullOrWhiteSpace(s.Format))
            bits.Add($"fmt={s.Format}");
        bits.Add($"role={s.Role}");
        Console.WriteLine("  " + string.Join(" ", bits));
    }

    if (!exact)
    {
        Console.WriteLine();
        Console.WriteLine("Tip: add --exact to write the original file into the project's seeds/ folder.");
        return 0;
    }

    if (string.IsNullOrWhiteSpace(project))
    {
        Console.Error.WriteLine("--exact requires -p <project>");
        return 1;
    }

    var seedName = outName ?? imported.SuggestedSeedName ?? Path.GetFileName(file);
    var saved = CaseRecipeStore.SaveRawSeed(new CaseSaveRawSeedRequest(
        project,
        seedName!,
        Convert.ToBase64String(bytes)));
    Console.WriteLine();
    Console.WriteLine(saved.Message);
    return saved.Ok ? 0 : 1;
}

static int CaseFromStream(string[] args)
{
    string? project = null, file = null, flow = null, mutate = "last";
    var asHex = false;
    var apply = false;
    for (var i = 0; i < args.Length; i++)
    {
        if ((args[i] is "-p" or "--project") && i + 1 < args.Length)
            project = args[++i];
        else if ((args[i] is "--file" or "-f" or "-i") && i + 1 < args.Length)
            file = args[++i];
        else if ((args[i] is "--flow" or "--name") && i + 1 < args.Length)
            flow = args[++i];
        else if (args[i] is "--mutate" && i + 1 < args.Length)
            mutate = args[++i];
        else if (args[i] is "--hex")
            asHex = true;
        else if (args[i] is "--apply")
            apply = true;
    }

    if (string.IsNullOrWhiteSpace(file) || !File.Exists(file))
    {
        Console.Error.WriteLine(
            "Usage: randall case from-stream -p <project> --file capture.txt [--hex] [--apply] [--flow name]");
        return 1;
    }

    if (apply && string.IsNullOrWhiteSpace(project))
    {
        Console.Error.WriteLine("--apply requires -p <project>");
        return 1;
    }

    var text = File.ReadAllText(file);
    var result = CaseRecipeStore.FromStream(new CaseFromStreamRequest(
        text, asHex, project, apply, flow, mutate));
    Console.WriteLine($"Session: {result.StepCount} PDU(s)");
    foreach (var n in result.Notes)
        Console.WriteLine($"  note: {n}");
    foreach (var s in result.SessionSteps)
    {
        Console.WriteLine($"  [{s.Name}] blocks={s.Blocks.Count}" +
                          (s.ReadBanner ? " readBanner" : "") +
                          (!string.IsNullOrWhiteSpace(s.ExpectResponse) ? $" expect={s.ExpectResponse}" : ""));
    }

    if (result.Applied is not null)
        Console.WriteLine(result.Applied.Message);
    else if (!apply)
        Console.WriteLine("Tip: add --apply to write sessionCommands/Flows into the project YAML.");
    return result.Applied is { Ok: false } ? 1 : 0;
}

static int CaseApplySession(string[] args)
{
    string? project = null, recipe = null, flow = null, mutate = "last";
    var preferModels = false;
    for (var i = 0; i < args.Length; i++)
    {
        if ((args[i] is "-p" or "--project") && i + 1 < args.Length)
            project = args[++i];
        else if ((args[i] is "--recipe" or "-r" or "--load") && i + 1 < args.Length)
            recipe = args[++i];
        else if ((args[i] is "--flow" or "--name") && i + 1 < args.Length)
            flow = args[++i];
        else if (args[i] is "--mutate" && i + 1 < args.Length)
            mutate = args[++i];
        else if (args[i] is "--models" or "--prefer-models")
            preferModels = true;
    }

    if (string.IsNullOrWhiteSpace(project) || string.IsNullOrWhiteSpace(recipe))
    {
        Console.Error.WriteLine(
            "Usage: randall case apply-session -p <project> --recipe NAME [--flow id] [--mutate last|all] [--models]");
        return 1;
    }

    var loaded = CaseRecipeStore.LoadRecipe(project, recipe);
    var steps = loaded.SessionSteps;
    if (steps is null || steps.Count == 0)
    {
        steps =
        [
            new CaseSessionStepDto(loaded.Name, loaded.Steps, ReadBanner: true),
        ];
    }

    var r = CaseRecipeStore.ApplySessionRecipe(new CaseApplySessionRequest(
        project,
        string.IsNullOrWhiteSpace(flow) ? loaded.Name : flow!,
        steps,
        string.IsNullOrWhiteSpace(mutate) ? (loaded.MutateStep ?? "last") : mutate,
        0.5,
        preferModels));
    Console.WriteLine(r.Message);
    return r.Ok ? 0 : 1;
}

static int CaseIdl(string[] args)
{
    string? project = null, name = null, file = null, desc = null;
    for (var i = 0; i < args.Length; i++)
    {
        if ((args[i] is "-p" or "--project") && i + 1 < args.Length)
            project = args[++i];
        else if ((args[i] is "--name" or "-n") && i + 1 < args.Length)
            name = args[++i];
        else if ((args[i] is "--file" or "-f") && i + 1 < args.Length)
            file = args[++i];
        else if ((args[i] is "--desc" or "--description") && i + 1 < args.Length)
            desc = args[++i];
    }

    if (string.IsNullOrWhiteSpace(project) || string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(file))
    {
        Console.Error.WriteLine("Usage: randall case idl -p <project> --name stub --file iface.idl");
        return 1;
    }

    if (!File.Exists(file))
    {
        Console.Error.WriteLine($"IDL file not found: {file}");
        return 1;
    }

    var r = CaseRecipeStore.ImportIdl(new CaseIdlRequest(project, name, File.ReadAllText(file), desc));
    Console.WriteLine(r.Message);
    foreach (var f in r.Fields)
        Console.WriteLine($"  - {f}");
    if (r.AbsolutePath is not null)
        Console.WriteLine(r.AbsolutePath);
    return r.Ok ? 0 : 1;
}

static int CasePromote(string[] args)
{
    string? project = null, name = null, recipe = null, desc = null;
    for (var i = 0; i < args.Length; i++)
    {
        if ((args[i] is "-p" or "--project") && i + 1 < args.Length)
            project = args[++i];
        else if ((args[i] is "--name" or "-n") && i + 1 < args.Length)
            name = args[++i];
        else if ((args[i] is "--recipe" or "-r") && i + 1 < args.Length)
            recipe = args[++i];
        else if ((args[i] is "--desc" or "--description") && i + 1 < args.Length)
            desc = args[++i];
    }

    if (string.IsNullOrWhiteSpace(project) || string.IsNullOrWhiteSpace(name))
    {
        Console.Error.WriteLine("Usage: randall case promote -p <project> --name proto [--recipe NAME]");
        return 1;
    }

    IReadOnlyList<CaseStepDto> steps;
    if (!string.IsNullOrWhiteSpace(recipe))
    {
        var loaded = CaseRecipeStore.LoadRecipe(project, recipe);
        if (loaded.SessionSteps is { Count: > 0 })
            steps = loaded.SessionSteps[^1].Blocks;
        else
            steps = loaded.Steps;
    }
    else
    {
        steps = ParseCaseSteps(args);
    }

    if (steps.Count == 0)
    {
        Console.Error.WriteLine("No blocks — pass --recipe NAME or --static/--text flags");
        return 1;
    }

    var r = CaseRecipeStore.PromoteToProtocol(new CasePromoteRequest(project, name, steps, desc));
    Console.WriteLine(r.Message);
    if (r.AbsolutePath is not null)
        Console.WriteLine(r.AbsolutePath);
    return r.Ok ? 0 : 1;
}

static int CasePacks(string[] args)
{
    string? load = null, project = null;
    for (var i = 0; i < args.Length; i++)
    {
        if ((args[i] is "--load" or "-l") && i + 1 < args.Length)
            load = args[++i];
        else if ((args[i] is "-p" or "--project") && i + 1 < args.Length)
            project = args[++i];
    }

    if (string.IsNullOrWhiteSpace(load))
    {
        foreach (var p in CaseRecipeStore.ListPacks())
            Console.WriteLine(
                $"{p.Id,-16} {p.Name,-28} {p.SessionStepCount,2} PDUs  {p.Description}");
        return 0;
    }

    var recipe = CaseRecipeStore.LoadPack(load);
    Console.WriteLine($"{recipe.Name} — {(recipe.SessionSteps?.Count ?? 0)} PDU(s)");
    if (!string.IsNullOrWhiteSpace(project))
    {
        var saved = CaseRecipeStore.SaveRecipe(new CaseSaveRecipeRequest(
            project,
            recipe.Name,
            recipe.Steps,
            recipe.Description,
            recipe.SuggestedSeedName,
            recipe.SessionSteps,
            recipe.MutateStep,
            recipe.Kind));
        Console.WriteLine(saved.Message);
        return saved.Ok ? 0 : 1;
    }

    foreach (var s in recipe.SessionSteps ?? [])
        Console.WriteLine($"  [{s.Name}] blocks={s.Blocks.Count}");
    Console.WriteLine("Tip: add -p <project> to save the pack into that project's recipes/");
    return 0;
}

static int CaseRecipes(string[] args)
{
    string? project = null, load = null;
    for (var i = 0; i < args.Length; i++)
    {
        if ((args[i] is "-p" or "--project") && i + 1 < args.Length)
            project = args[++i];
        else if ((args[i] is "--load" or "-l") && i + 1 < args.Length)
            load = args[++i];
    }

    if (string.IsNullOrWhiteSpace(project))
    {
        Console.Error.WriteLine("Usage: randall case recipes -p <project> [--load name]");
        return 1;
    }

    if (!string.IsNullOrWhiteSpace(load))
    {
        var recipe = CaseRecipeStore.LoadRecipe(project, load);
        var session = recipe.SessionSteps;
        if (session is { Count: > 0 })
        {
            Console.WriteLine(
                $"{recipe.Name} — session {session.Count} PDU(s) mutate={recipe.MutateStep ?? "last"} — {recipe.UpdatedAt:u}");
            if (!string.IsNullOrWhiteSpace(recipe.Description))
                Console.WriteLine(recipe.Description);
            foreach (var pdu in session)
            {
                Console.WriteLine(
                    $"  [{pdu.Name}] blocks={pdu.Blocks.Count}" +
                    (pdu.ReadBanner ? " readBanner" : "") +
                    (!string.IsNullOrWhiteSpace(pdu.ExpectResponse) ? $" expect={pdu.ExpectResponse}" : ""));
                foreach (var s in pdu.Blocks)
                    Console.WriteLine($"    {s.Op} {(s.Value ?? "")} role={s.Role}");
            }
            return 0;
        }

        Console.WriteLine($"{recipe.Name} — {recipe.Steps.Count} blocks — {recipe.UpdatedAt:u}");
        if (!string.IsNullOrWhiteSpace(recipe.Description))
            Console.WriteLine(recipe.Description);
        foreach (var s in recipe.Steps)
            Console.WriteLine($"  {s.Op} {(s.Value ?? "")} role={s.Role}");
        return 0;
    }

    foreach (var r in CaseRecipeStore.ListRecipes(project))
    {
        var kind = r.SessionStepCount > 0 ? $"{r.SessionStepCount} PDUs" : $"{r.StepCount} blocks";
        Console.WriteLine($"{r.Name,-24} {kind,10}  {r.UpdatedAt:yyyy-MM-dd HH:mm}  {r.Description}");
    }
    return 0;
}

static int CaseMutators(string[] args)
{
    string? project = null, set = null;
    for (var i = 0; i < args.Length; i++)
    {
        if ((args[i] is "-p" or "--project") && i + 1 < args.Length)
            project = args[++i];
        else if (args[i] is "--set" && i + 1 < args.Length)
            set = args[++i];
    }

    if (string.IsNullOrWhiteSpace(project))
    {
        Console.Error.WriteLine("Usage: randall case mutators -p <project> [--set bitflip,havoc,dictionary]");
        return 1;
    }

    if (set is null)
    {
        var profile = CaseRecipeStore.GetProfile(project)
                      ?? throw new ArgumentException($"Unknown project: {project}");
        Console.WriteLine($"Active:  {string.Join(", ", profile.Mutators)}");
        Console.WriteLine($"Avail:   {string.Join(", ", profile.AvailableMutators)}");
        return 0;
    }

    var list = set.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    var r = CaseRecipeStore.SetMutators(new CaseMutatorsRequest(project, list));
    Console.WriteLine(r.Message);
    return r.Ok ? 0 : 1;
}

static List<CaseStepDto> ParseCaseSteps(string[] args)
{
    var steps = new List<CaseStepDto>();
    for (var i = 0; i < args.Length; i++)
    {
        switch (args[i])
        {
            case "--static" when i + 1 < args.Length:
                steps.Add(new CaseStepDto("static", args[++i], Role: "static"));
                break;
            case "--text" when i + 1 < args.Length:
                steps.Add(new CaseStepDto("text", args[++i], Role: "fuzzable"));
                break;
            case "--delim" when i + 1 < args.Length:
                steps.Add(new CaseStepDto("delim", args[++i], Role: "fuzzable"));
                break;
            case "--hex" when i + 1 < args.Length:
                steps.Add(new CaseStepDto("hex", args[++i]));
                break;
            case "--repeat" when i + 1 < args.Length:
                steps.Add(new CaseStepDto("repeat", "A", int.Parse(args[++i])));
                break;
            case "--cyclic" when i + 1 < args.Length:
                steps.Add(new CaseStepDto("cyclic", Count: int.Parse(args[++i])));
                break;
            case "--crlf":
                steps.Add(new CaseStepDto("crlf"));
                break;
            case "--lf":
                steps.Add(new CaseStepDto("lf"));
                break;
            case "--null":
                steps.Add(new CaseStepDto("null"));
                break;
        }
    }
    return steps;
}

static int RunLabs(string[] args)
{
    if (args.Length == 0 || args[0] is "-h" or "--help" or "help" or "list" or "status")
    {
        foreach (var lab in LabServerManager.List())
        {
            var state = !lab.ExeExists ? "not-built" : lab.Running ? (lab.Reachable ? "running" : "starting") : "stopped";
            Console.WriteLine(
                $"{lab.Id,-12} {lab.Protocol}/{lab.Port,-5} {state,-10} pid={(lab.Pid?.ToString() ?? "-"),-6} {lab.Name}");
        }

        Console.WriteLine();
        Console.WriteLine("Tips: labs start on 127.0.0.1 only. UI: Fuzz → Lab servers. Rebuild: .\\scripts\\build-all-lab-targets.ps1");
        Console.WriteLine("Target Runtime (arbitrary exe): randall runtime — see docs/TARGET_RUNTIME.md");
        return 0;
    }

    var sub = args[0].ToLowerInvariant();
    if (sub is "stop-all" or "stopall")
    {
        var r = LabServerManager.StopAll();
        Console.WriteLine(r.Message);
        return r.Ok ? 0 : 1;
    }

    if ((sub is "start" or "stop") && args.Length >= 2)
    {
        var id = args[1];
        var r = sub == "start" ? LabServerManager.Start(id) : LabServerManager.Stop(id);
        Console.WriteLine(r.Message);
        return r.Ok ? 0 : 1;
    }

    Console.Error.WriteLine("Usage: randall labs | labs start <id> | labs stop <id> | labs stop-all");
    return 1;
}

static int RunHarnessWorker(string[] args)
{
    string? dll = null;
    var export = "LLVMFuzzerTestOneInput";
    for (var i = 0; i < args.Length; i++)
    {
        if (args[i] is "--dll" or "-d" && i + 1 < args.Length)
            dll = args[++i];
        else if (args[i] is "--export" or "-e" && i + 1 < args.Length)
            export = args[++i];
    }

    if (string.IsNullOrWhiteSpace(dll))
    {
        Console.Error.WriteLine("Usage: randall harness-worker --dll <native.dll> [--export LLVMFuzzerTestOneInput]");
        return 1;
    }

    return NativeHarnessWorkerHost.Run(dll, export);
}

static int RunRuntime(string[] args)
{
    if (args.Length == 0 || args[0] is "-h" or "--help" or "help" or "list" or "status")
    {
        var list = TargetRuntimeService.List();
        Console.WriteLine($"Target Runtime on {list.MachineName} — {list.Slots.Count} slot(s)");
        if (list.Slots.Count == 0)
        {
            Console.WriteLine("(empty — start with: randall runtime start -c projects/vulnserver.yaml)");
            return 0;
        }

        foreach (var s in list.Slots)
        {
            var state = s.Running ? (s.PortReachable == true ? "running" : "started") : "stopped";
            var port = s.WaitPort is int p ? $":{p}" : "";
            Console.WriteLine(
                $"{s.Id,-20} {state,-10} pid={(s.Pid?.ToString() ?? "-"),-6} {port,-6} {s.Message}");
        }

        return 0;
    }

    var sub = args[0].ToLowerInvariant();
    if (sub is "stop-all" or "stopall")
    {
        var r = TargetRuntimeService.StopAll();
        Console.WriteLine(r.Message);
        return r.Ok ? 0 : 1;
    }

    if ((sub is "stop" or "restart") && args.Length >= 2)
    {
        var id = args[1];
        var r = sub == "stop" ? TargetRuntimeService.Stop(id) : TargetRuntimeService.Restart(id);
        Console.WriteLine(r.Message);
        return r.Ok ? 0 : 1;
    }

    if (sub == "start")
    {
        string? yaml = null;
        string? id = null;
        string? exe = null;
        var startArgs = new List<string>();
        int? port = null;
        string host = "127.0.0.1";
        var pageHeap = false;
        for (var i = 1; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "-c":
                case "--config":
                case "--project":
                    if (i + 1 < args.Length) yaml = args[++i];
                    break;
                case "--id":
                    if (i + 1 < args.Length) id = args[++i];
                    break;
                case "--exe":
                case "--executable":
                    if (i + 1 < args.Length) exe = args[++i];
                    break;
                case "--arg":
                    if (i + 1 < args.Length) startArgs.Add(args[++i]);
                    break;
                case "--port":
                    if (i + 1 < args.Length && int.TryParse(args[++i], out var p)) port = p;
                    break;
                case "--host":
                    if (i + 1 < args.Length) host = args[++i];
                    break;
                case "--page-heap":
                    pageHeap = true;
                    break;
            }
        }

        TargetRuntimeStatusDto st;
        if (!string.IsNullOrWhiteSpace(yaml))
            st = TargetRuntimeService.StartFromProject(yaml, id);
        else if (!string.IsNullOrWhiteSpace(exe) && !string.IsNullOrWhiteSpace(id))
        {
            st = TargetRuntimeService.Start(new TargetRuntimeStartRequest(
                Id: id!,
                Executable: exe!,
                Args: startArgs,
                WaitPort: port,
                WaitHost: host,
                PageHeap: pageHeap));
        }
        else
        {
            Console.Error.WriteLine(
                "Usage:\n  randall runtime start -c <project.yaml> [--id name]\n  randall runtime start --id name --exe path [--arg a]* [--port N] [--host H]");
            return 1;
        }

        Console.WriteLine(st.Message);
        if (st.Running)
            Console.WriteLine($"  id={st.Id} pid={st.Pid} port={st.WaitHost}:{st.WaitPort} reachable={st.PortReachable}");
        return st.Ok ? 0 : 1;
    }

    if (sub == "get" && args.Length >= 2)
    {
        var st = TargetRuntimeService.Status(args[1]);
        Console.WriteLine($"{st.Id}: running={st.Running} pid={st.Pid} — {st.Message}");
        return st.Ok ? 0 : 1;
    }

    Console.Error.WriteLine(
        "Usage: randall runtime | runtime start -c <yaml> | runtime start --id X --exe path | runtime stop|restart <id> | runtime stop-all");
    return 1;
}

static int Unknown(string command)
{
    Console.Error.WriteLine($"Unknown command: {command}");
    PrintHelp();
    return 1;
}
