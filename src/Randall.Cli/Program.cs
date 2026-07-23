using System.Diagnostics;
using Randall.Contracts;
using Randall.Infrastructure;
using Randall.Infrastructure.BugHunt;
using Randall.Infrastructure.Magician;
using Randall.Infrastructure.Oracles;
using Randall.Infrastructure.Rop;

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
    "notify" => await RunNotifyAsync(args.Skip(1).ToArray()),
    "graph" => RunGraph(args.Skip(1).ToArray()),
    "analyze" => RunAnalyze(args.Skip(1).ToArray()),
    "heaptriage" or "heap" => RunHeapTriage(args.Skip(1).ToArray()),
    "checksec" => RunCheckSec(args.Skip(1).ToArray()),
    "pattern" => RunPattern(args.Skip(1).ToArray()),
    "exploitdev" or "expdev" => RunExploitDev(args.Skip(1).ToArray()),
    "exploit" => RunExploit(args.Skip(1).ToArray()),
    "rop" => RunRop(args.Skip(1).ToArray()),
    "stack" => RunStack(args.Skip(1).ToArray()),
    "windbg" or "randfuzzdbg" or "rfdbg" => RunWindbg(args.Skip(1).ToArray()),
    "memory" or "lens" => RunMemoryLens(args.Skip(1).ToArray()),
    "stalk" => RunStalk(args.Skip(1).ToArray()),
    "debug" => RunDebug(args.Skip(1).ToArray()),
    "scream" => await RunScream(args.Skip(1).ToArray()),
    "ladder" => RunLadder(args.Skip(1).ToArray()),
    "gdb" => RunGdb(args.Skip(1).ToArray()),
    "case" => RunCase(args.Skip(1).ToArray()),
    "oracles" or "oracle" => RunOracles(args.Skip(1).ToArray()),
    "magician" or "mage" or "spell" or "spells" => RunMagician(args.Skip(1).ToArray()),
    "hunt" or "bughunter" or "bug-hunter" => RunHunt(args.Skip(1).ToArray()),
    "ai" => await RunAiAsync(args.Skip(1).ToArray()),
    "labs" or "lab" => RunLabs(args.Skip(1).ToArray()),
    "runtime" or "rt" => RunRuntime(args.Skip(1).ToArray()),
    "recorders" or "recorder" => RunRecorders(args.Skip(1).ToArray()),
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
          randall pack -o publish/standalone [--rid win-x64|linux-x64|…]
          randall bundle export -c projects/vulnserver.yaml -o bundles/vulnserver.zip
          randall bundle import -i bundles/vulnserver.zip -o projects/imported
          randall doctor -c <project>     Preflight lab checks before fuzzing
          randall notify test -c <project|campaign>   Test Discord/email channels
          randall graph -c <project>        Validate sessionGraph + print Mermaid
          randall analyze -i <crash-guid>   Minidump triage (registers, fault PC)
          randall heaptriage --exe <path> [--input f] [--core f] [--no-harden] [-- args…]
                                            Linux heap crash triage (tcache/UAF/overflow classifier)
          randall checksec --exe <path>     ELF exploit-mitigation report (NX/canary/PIE/RELRO/FORTIFY) + ASLR state
          randall pattern create -l N       Cyclic (mona-style) pattern for offset discovery
          randall pattern offset -q <val> [-l N]   Find offset of a value/register in the pattern
          randall exploitdev --exe <p> --core <c> [--pattern-len N]   Faulting registers + RIP offset
          randall exploit guide --exe <p> [--core c] [--pattern-len N]
                                            Triage playbook → offset, then ROP Studio / WinDbg walk
          randall rop scan --exe <path> [--arch x64|x86]
          randall rop search --exe <path> --need pop-rdi [--badchars "00 0a"]
          randall rop sketch --exe <path> --goal auto|pivot|write|control|leak|canary
          randall rop from-crash -i <crash-guid> [--goal auto] [--exe path] [--modules N]
          randall rop show -i <crash-guid>       Existing ROP/walk/badchars sidecars
          randall rop badchars -i <crash-guid>   Learn badchars from crashing input
          randall windbg scripts            RandfuzzDbg script paths
          randall windbg walk -i <crash-guid>   Write *_windbg_walk.json + script hints
          randall memory -i <crash-guid>    Memory lens (UAF fill, regions, neighborhood)
          randall memory --pid N            Live VirtualQueryEx sample
          randall stalk layers -p <project>              List stalk layers
          randall stalk compare -p <project> [layerIds…] Diff layered coverage
          randall stalk missed -p <project> [--limit N]  Missed blocks + fuzz ideas
          randall stalk inventory -p <project> --import <file>  BB inventory for never-hit
          randall stalk dynapstalker <drcov.log> <exe> <out.idc|.py> [--format idc|ghidra] [--color …]
          randall stalk ghidra-pack -p <project> [-o dir]     First-class Ghidra stalk pack
          randall stalk capture-binary -p <project> [-i seed] Dragon Dance binary drcov
          randall stalk map -p <project> [-c yaml] [--binary path]  In-app stalk map (strings/imports)
          randall stalk export -p <project> --format idc|ghidra|edges [-o dir]
          randall stalk from-crash -i <crash-guid> [--tag crash]
          randall scream watch -p <pid> [-o dumpsDir]   Built-in exception dump watcher
          randall scream walk -i <crash-guid> [--goal auto]  CONTROL→stack→badchars→sketch→walk
          randall stack lens -i <crash-guid> [--window N]    Dump-native CONTROL map (stack slots)
          randall scream selftest          Lab AV target → attach → dump regression
          randall ladder diff [-i crash] [-p project]    Mitigation ladder compare (vulnlab tiers)
          randall gdb walk -i <crash-guid>               Linux GDB/GEF walk JSON (+ scripts)
          randall gdb scripts                            Print GDB script paths
          randall debug tools
          randall debug open -i <crash-guid> [--kind windbg|windbg-preview]
          randall debug attach -p <pid> | -t <project> [--kind …]
          randall fuzz -c <project> --debugger wait|attach|both [--open-on-crash]
          randall case ops|new|preview|save-seed|mutators   Build seeds / YAML targets
          randall oracles [-p name] [--json]   Oracle engine: list findings (judgment/report)
          randall magician [spells|cast|log]   Magician: spells / summons for Oracle needs
          randall hunt -d <src> [-c yaml --arm]  Bug Hunter: AI/human analysis + arm campaign
          randall hunt attribution|mistakes   Bug Hunter subcommands
          randall ai seed -c <project> […]    Optional AI seed recipe (docs/AI_SEED.md)
          randall ai hunt|attribution|mistakes  Aliases → Bug Hunter
          randall labs                     List lab servers (running / stopped)
          randall labs start|stop <id>     Start/stop one lab (127.0.0.1)
          randall labs stop-all            Stop every randall-vuln* lab
          randall runtime                  Target Runtime slots (start/stop/restart)
          randall runtime start -c <yaml>  Start project exe via Target Runtime
          randall runtime start --id X --exe path [--arg a]* [--port N]
          randall runtime stop|restart <id>
          randall runtime stop-all
          randall recorders stop         Stop orphaned Procmon/DebugView/ProcDump/WPR/pktmon/tshark
          randall harness-worker --dll <native.dll> [--export LLVMFuzzerTestOneInput]
          randall export -i <crash-guid>
          randall serve [--port N] [--bind host] [--token SECRET] [--allow-open]
          randall agent [--port N] [--bind host] [--token SECRET] [--allow-open]
                                                        Lab agent defaults to 0.0.0.0 (token required)
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
          cyclic       Metasploit-style pattern (exploit-dev offset practice)

        Docs: docs/ORACLES.md · docs/BUG_HUNTER.md · docs/WEB_FUZZ.md · docs/TARGETS.md
        Web apps: projects/webapp.yaml (kind: http) · Exploit-dev: projects/vulnlab-offset.yaml
        """);
}

static async Task<int> RunAiAsync(string[] args)
{
    // Dispatcher: seed recipes vs Bug Hunter (hunt/attribution/mistakes).
    if (args.Length == 0 || args[0] is "-h" or "--help" or "help")
    {
        Console.WriteLine("""
            Randfuzz AI helpers

            Usage:
              randall ai seed -c <project.yaml> [--dry-run|--fixture f|--count N|--update-yaml]
                    Optional LLM seed/dictionary recipe (docs/AI_SEED.md) — not on the fuzz hot path
              randall ai hunt -d <sourceDir> [-c project.yaml] [--arm]
              randall ai attribution -d <sourceDir>
              randall ai mistakes
                    Bug Hunter aliases (docs/BUG_HUNTER.md) — prefer: randall hunt …

            Env for ai seed:
              RANDALL_AI_API_KEY or OPENAI_API_KEY
              RANDALL_AI_BASE_URL   (default https://api.openai.com/v1)
              RANDALL_AI_MODEL      (default gpt-4o-mini)
            """);
        return 0;
    }

    var sub = args[0].ToLowerInvariant();
    var rest = args.Skip(1).ToArray();
    return sub switch
    {
        "seed" or "seeds" or "recipe" or "dict" => await RunAiSeedAsync(rest),
        "hunt" or "badcode" or "bugs" or "plan" or "analyze"
            or "attribution" or "code" or "scan" or "mistakes" or "catalog"
            => RunHunt(args),
        // `randall ai -d …` → Bug Hunter analyze
        "-d" or "--dir" or "--root" or "-c" or "--config" or "--arm" or "--json"
            => RunHunt(args),
        _ => Unknown($"ai {args[0]}"),
    };
}

static async Task<int> RunAiSeedAsync(string[] args)
{
    string? config = null;
    string? fixture = null;
    string? promptHint = null;
    string? outDir = null;
    string? dictPath = null;
    var dryRun = false;
    var updateYaml = false;
    var count = 6;

    for (var i = 0; i < args.Length; i++)
    {
        switch (args[i])
        {
            case "-c" or "--config" when i + 1 < args.Length:
                config = args[++i];
                break;
            case "--fixture" when i + 1 < args.Length:
                fixture = args[++i];
                break;
            case "--prompt" or "--hint" when i + 1 < args.Length:
                promptHint = args[++i];
                break;
            case "--out-dir" when i + 1 < args.Length:
                outDir = args[++i];
                break;
            case "--dict" when i + 1 < args.Length:
                dictPath = args[++i];
                break;
            case "--count" when i + 1 < args.Length:
                if (!int.TryParse(args[++i], out count) || count < 1)
                {
                    Console.Error.WriteLine("--count must be a positive integer");
                    return 1;
                }
                count = Math.Clamp(count, 1, 32);
                break;
            case "--dry-run":
                dryRun = true;
                break;
            case "--update-yaml":
                updateYaml = true;
                break;
            case "-h" or "--help":
                return await RunAiAsync(["help"]);
        }
    }

    if (string.IsNullOrWhiteSpace(config))
    {
        Console.Error.WriteLine("Usage: randall ai seed -c <project.yaml> [--dry-run|--fixture f]");
        return 1;
    }

    var yamlPath = Path.GetFullPath(config);
    ProjectConfig project;
    try { project = ProjectLoader.Load(yamlPath); }
    catch (Exception ex)
    {
        Console.Error.WriteLine(ex.Message);
        return 1;
    }

    Console.WriteLine($"AI seed recipe for '{project.Name}' ({project.Kind})");

    if (dryRun)
    {
        var prompt = AiSeedRecipe.BuildPrompt(project, yamlPath, count, promptHint);
        Console.WriteLine("--- prompt ---");
        Console.WriteLine(prompt);
        Console.WriteLine("--- end prompt ---");
        var settings = AiSeedSettings.FromEnvironment();
        Console.WriteLine(settings.HasApiKey
            ? $"API key: set ({AiSeedSettings.EnvApiKey} / {AiSeedSettings.EnvApiKeyAlt}) model={settings.Model}"
            : $"API key: not set — live generate needs {AiSeedSettings.EnvApiKey} or --fixture");
        return 0;
    }

    AiSeedRecipe.RecipeResult recipe;
    try
    {
        if (!string.IsNullOrWhiteSpace(fixture))
        {
            var fixturePath = Path.GetFullPath(fixture);
            if (!File.Exists(fixturePath))
            {
                Console.Error.WriteLine($"Fixture not found: {fixturePath}");
                return 1;
            }
            Console.WriteLine($"Using fixture: {fixturePath}");
            recipe = AiSeedRecipe.LoadFixture(fixturePath);
        }
        else
        {
            var settings = AiSeedSettings.FromEnvironment();
            Console.WriteLine($"Calling {settings.BaseUrl} model={settings.Model}…");
            recipe = await AiSeedRecipe.GenerateAsync(project, yamlPath, settings, count, promptHint);
        }
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine(ex.Message);
        return 1;
    }

    if (recipe.Seeds.Count == 0 && recipe.Dictionary.Count == 0)
    {
        Console.Error.WriteLine("Recipe contained no seeds or dictionary tokens.");
        return 1;
    }

    if (!string.IsNullOrWhiteSpace(recipe.Notes))
        Console.WriteLine($"Notes: {recipe.Notes}");

    var applied = AiSeedRecipe.Apply(
        project, yamlPath, recipe, outDir, dictPath, updateYaml);

    foreach (var p in applied.SeedPaths)
        Console.WriteLine($"  seed → {p}");
    if (applied.DictionaryPath is not null)
        Console.WriteLine($"  dict → {applied.DictionaryPath}");
    Console.WriteLine($"  recipe json → {applied.RecipeJsonPath}");
    Console.WriteLine(
        $"Done: {applied.SeedCount} seed(s), {applied.DictionaryCount} dict token(s)." +
        (updateYaml ? " Project YAML updated." : " Re-run with --update-yaml to wire seeds into the project."));
    Console.WriteLine("Next: randall fuzz -c " + config);
    return 0;
}

static int RunHunt(string[] args)
{
    if (args.Length == 0 || args[0] is "-h" or "--help" or "help")
    {
        Console.WriteLine("""
            Bug Hunter engine — AI/human code analysis (docs/BUG_HUNTER.md)

            Separate from the Oracle engine (docs/ORACLES.md), which only judges
            observations and reports findings.

            Usage:
              randall hunt -d <sourceDir> [-c project.yaml] [-o outDir] [--arm]
                    Analyze sources → prioritize AI blocks → suggest oracle/dict arming
              randall hunt attribution -d <sourceDir> [-o outDir] [--json] [--ext .cs,.c,.py]
              randall hunt mistakes [--emit-yaml]
              randall ai seed …            Optional seed recipe (docs/AI_SEED.md)
              randall ai hunt|mistakes …   Aliases of randall hunt …

            Attribution is heuristic. Prefer /* BEGIN AI */ … /* END AI */ annotations.
            Bug Hunter suggests what to look for; Oracle decides if a run was wrong.
            """);
        return 0;
    }

    var sub = args[0].ToLowerInvariant();
    // `randall hunt -d …` (no subcommand) is the analyze/arm entry.
    if (sub is "-d" or "--dir" or "--root" or "-c" or "--config" or "-o" or "--out" or "--arm" or "--json")
        return RunAiHunt(args);

    var rest = args.Skip(1).ToArray();
    return sub switch
    {
        "attribution" or "code" or "scan" => RunAiAttribution(rest),
        "plan" or "analyze" or "badcode" or "bugs" => RunAiHunt(rest),
        "mistakes" or "catalog" => RunAiMistakes(rest),
        _ => Unknown($"hunt {args[0]}"),
    };
}

static int RunAiHunt(string[] args)
{
    string? dir = null;
    string? config = null;
    string? outDir = null;
    var arm = false;
    var json = false;
    for (var i = 0; i < args.Length; i++)
    {
        switch (args[i])
        {
            case "-d" or "--dir" or "--root" when i + 1 < args.Length:
                dir = args[++i];
                break;
            case "-c" or "--config" when i + 1 < args.Length:
                config = args[++i];
                break;
            case "-o" or "--out" when i + 1 < args.Length:
                outDir = args[++i];
                break;
            case "--arm":
                arm = true;
                break;
            case "--json":
                json = true;
                break;
            case "-h" or "--help":
                return RunHunt(["help"]);
        }
    }

    if (string.IsNullOrWhiteSpace(dir))
    {
        Console.Error.WriteLine("Usage: randall ai hunt -d <sourceDir> [-c project.yaml] [--arm]");
        return 1;
    }

    BugHunterScanDto scan;
    try { scan = BugHunterEngine.Scan(dir); }
    catch (Exception ex)
    {
        Console.Error.WriteLine(ex.Message);
        return 1;
    }

    var plan = BugHunterEngine.Plan(scan);
    var dest = outDir ?? Path.Combine(
        CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory(), "data", "ai_code");
    Directory.CreateDirectory(dest);
    try
    {
        BugHunterAttribution.PersistReport(scan, dest);
        File.WriteAllText(Path.Combine(dest, "hunt_plan.md"), BugHunterPlanner.RenderPlanMarkdown(plan));
        File.WriteAllText(Path.Combine(dest, "hunt_arm_snippet.yaml"), BugHunterPlanner.RenderArmedYamlSnippet());
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"Warning: could not write hunt artifacts: {ex.Message}");
    }

    if (json)
    {
        Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(plan,
            new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));
    }
    else
    {
        Console.WriteLine("AI bad-code hunt");
        Console.WriteLine(plan.Summary);
        Console.WriteLine($"Mistake classes: {string.Join(", ", plan.MistakeClasses)}");
        Console.WriteLine($"Oracle focus: {string.Join(", ", plan.OracleFocus)}");
        Console.WriteLine($"Dictionary: {plan.DictionaryHint}");
        Console.WriteLine();
        Console.WriteLine("Priority AI-generated code blocks to fuzz against:");
        foreach (var b in plan.PriorityAiBlocks.Take(20))
        {
            Console.WriteLine($"  [{b.Confidence:0.00}] {b.Path}:{b.StartLine}-{b.EndLine}");
            var preview = b.Preview.Replace('\r', ' ').Replace('\n', ' ');
            if (preview.Length > 100)
                preview = preview[..100] + "…";
            Console.WriteLine($"           {preview}");
        }

        Console.WriteLine();
        Console.WriteLine($"Plan: {Path.Combine(dest, "hunt_plan.md")}");
        Console.WriteLine($"Snippet: {Path.Combine(dest, "hunt_arm_snippet.yaml")}");
    }

    if (arm)
    {
        if (string.IsNullOrWhiteSpace(config))
        {
            Console.Error.WriteLine("--arm requires -c <project.yaml>");
            return 1;
        }

        var yamlPath = Path.GetFullPath(config);
        ProjectConfig project;
        try { project = ProjectLoader.Load(yamlPath); }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex.Message);
            return 1;
        }

        // Ensure source root is recorded for fuzz-start scans.
        project.BugHunter ??= new BugHunterConfig();
        var relRoot = Path.GetRelativePath(ProjectLoader.ResolveProjectRoot(yamlPath), Path.GetFullPath(dir))
            .Replace('\\', '/');
        if (!project.BugHunter.SourceRoots.Any(r => r.Equals(relRoot, StringComparison.OrdinalIgnoreCase) ||
                                                 r.Equals(dir, StringComparison.OrdinalIgnoreCase)))
            project.BugHunter.SourceRoots.Add(relRoot.StartsWith("..") || relRoot.Contains(':') ? Path.GetFullPath(dir) : relRoot);

        var note = BugHunterEngine.ArmProject(project, yamlPath, plan);
        try
        {
            AppendHuntArmToYaml(yamlPath, project.BugHunter.SourceRoots.Last(), project.DictionaryFile);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Warning: could not patch YAML ({ex.Message}). In-memory arm still applied for this process only.");
            Console.Error.WriteLine("Merge data/ai_code/hunt_arm_snippet.yaml manually, then fuzz.");
            return 1;
        }

        Console.WriteLine();
        Console.WriteLine($"Armed project {yamlPath}");
        Console.WriteLine($"  {note}");
        Console.WriteLine($"Next: randall fuzz -c {config}");
    }
    else
    {
        Console.WriteLine();
        Console.WriteLine("Arm a project: randall hunt -d <src> -c projects/foo.yaml --arm");
        Console.WriteLine("Then:             randall fuzz -c projects/foo.yaml");
    }

    return 0;
}

static void AppendHuntArmToYaml(string yamlPath, string sourceRoot, string? dictionaryFile)
{
    var text = File.ReadAllText(yamlPath);
    if (!text.Contains("bugHunter:", StringComparison.Ordinal) &&
        !text.Contains("aiCode:", StringComparison.Ordinal))
    {
        text = text.TrimEnd() + Environment.NewLine + """
            bugHunter:
              enabled: true
              scanOnFuzzStart: true
              autoArmOracles: true
              autoArmDictionary: true
              sourceRoots:
            """ + Environment.NewLine +
            $"    - {sourceRoot}" + Environment.NewLine;
    }
    else if (!text.Contains(sourceRoot, StringComparison.OrdinalIgnoreCase))
    {
        // Best-effort: append root under bugHunter/aiCode.sourceRoots if block exists.
        var idx = text.IndexOf("sourceRoots:", StringComparison.Ordinal);
        if (idx >= 0)
        {
            var lineEnd = text.IndexOf('\n', idx);
            if (lineEnd < 0) lineEnd = text.Length;
            text = text.Insert(lineEnd + 1, $"    - {sourceRoot}{Environment.NewLine}");
        }
    }

    if (!text.Contains("ai_codegen_mistakes", StringComparison.OrdinalIgnoreCase))
    {
        var dict = dictionaryFile ?? "dictionaries/ai_codegen_mistakes.txt";
        if (!text.Contains("dictionaryFile:", StringComparison.Ordinal))
            text = text.TrimEnd() + Environment.NewLine + $"dictionaryFile: {dict}" + Environment.NewLine;
    }

    if (!text.Contains("oracles:", StringComparison.Ordinal))
    {
        text = text.TrimEnd() + Environment.NewLine + """
            oracles:
              enabled: true
            """ + Environment.NewLine;
    }

    File.WriteAllText(yamlPath, text);
}

static int RunAiAttribution(string[] args)
{
    string? dir = null;
    string? outDir = null;
    string? extList = null;
    var json = false;
    for (var i = 0; i < args.Length; i++)
    {
        switch (args[i])
        {
            case "-d" or "--dir" or "--root" when i + 1 < args.Length:
                dir = args[++i];
                break;
            case "-o" or "--out" when i + 1 < args.Length:
                outDir = args[++i];
                break;
            case "--ext" when i + 1 < args.Length:
                extList = args[++i];
                break;
            case "--json":
                json = true;
                break;
            case "-h" or "--help":
                return RunHunt(["help"]);
        }
    }

    if (string.IsNullOrWhiteSpace(dir))
    {
        Console.Error.WriteLine("Usage: randall ai attribution -d <sourceDir> [-o outDir]");
        return 1;
    }

    IEnumerable<string>? exts = null;
    if (!string.IsNullOrWhiteSpace(extList))
        exts = extList.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    BugHunterScanDto scan;
    try { scan = BugHunterEngine.Scan(dir, exts); }
    catch (Exception ex)
    {
        Console.Error.WriteLine(ex.Message);
        return 1;
    }

    var dest = outDir ?? Path.Combine(
        CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory(), "data", "ai_code");
    string? reportPath = null;
    try { reportPath = BugHunterAttribution.PersistReport(scan, dest); }
    catch (Exception ex) { Console.Error.WriteLine($"Warning: could not write report: {ex.Message}"); }

    if (json)
    {
        Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(scan,
            new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));
        return 0;
    }

    Console.WriteLine($"AI code attribution — {scan.Root}");
    Console.WriteLine(
        $"Files {scan.FilesScanned} · AI blocks {scan.AiBlocks} · Human {scan.HumanBlocks} · Unknown {scan.UnknownBlocks}");
    Console.WriteLine("Oracle focus: " + string.Join(", ", scan.SuggestedOracleFocus));
    Console.WriteLine("Mistake classes: " + string.Join(", ", scan.SuggestedMistakeClasses));
    Console.WriteLine();
    Console.WriteLine("Top AI-attributed blocks:");
    foreach (var b in scan.Blocks
                 .Where(b => b.Provenance is BugHunterProvenance.LikelyAi or BugHunterProvenance.AnnotatedAi)
                 .OrderByDescending(b => b.Confidence)
                 .Take(15))
    {
        Console.WriteLine(
            $"  [{b.Provenance} {b.Confidence:0.00}] {b.Path}:{b.StartLine}-{b.EndLine}  ({string.Join(", ", b.Signals.Take(3))})");
    }

    Console.WriteLine();
    Console.WriteLine("Top human-attributed blocks:");
    foreach (var b in scan.Blocks
                 .Where(b => b.Provenance is BugHunterProvenance.LikelyHuman or BugHunterProvenance.AnnotatedHuman)
                 .Take(10))
    {
        Console.WriteLine($"  [{b.Provenance}] {b.Path}:{b.StartLine}-{b.EndLine}");
    }

    if (reportPath is not null)
    {
        Console.WriteLine();
        Console.WriteLine($"Report: {reportPath}");
        Console.WriteLine($"Markdown: {Path.ChangeExtension(reportPath, ".md")}");
    }

    Console.WriteLine();
    Console.WriteLine("Next: enable oracles for suggested focus (docs/ORACLES.md) + dictionary ai_codegen_mistakes.txt");
    return 0;
}

static int RunAiMistakes(string[] args)
{
    var emitYaml = args.Any(a => a is "--emit-yaml" or "--yaml");
    if (emitYaml)
    {
        Console.WriteLine("""
            # Starter snippet — Bug Hunter + Oracle (docs/BUG_HUNTER.md · docs/ORACLES.md)
            bugHunter:
              enabled: true
              sourceRoots:
                - ../targets/local/myservice
            oracles:
              enabled: true
              retainOnViolation: true
              promoteExpectResponse: true
              auth:
                - id: no-ok-before-auth
                  type: forbidUntil
                  forbidResponse: "OK"
                  untilResponse: "AUTH_OK"
              state:
                - id: order
                  type: commandRequiresPrior
                  forCommand: REQUEST
                  priorCommand: AUTH
                  priorResponse: AUTH_OK
              integer:
                - id: length
                  type: lengthPrefix
                  offset: 0
                  width: 4
                  endian: le
                  covers: rest
                  maxPlausible: 1048576
              structure:
                - id: min-hdr
                  type: minSize
                  bytes: 8
                  onlyWhenAccepted: true
              resource:
                - id: resp-cap
                  type: maxResponseBytes
                  maxBytes: 1048576
            dictionaryFile: dictionaries/ai_codegen_mistakes.txt
            mutators:
              - dictionary
              - interesting
              - boundary
              - havoc
              - expand
            """);
        return 0;
    }

    Console.WriteLine("Bug Hunter mistake catalog (docs/BUG_HUNTER.md)");
    Console.WriteLine("Channels: Oracle = judgment · Seed = inputs · Static = scan · Hybrid = both");
    Console.WriteLine("Sources: OWASP-in-codegen patterns + AISW-style AI-induced weaknesses");
    Console.WriteLine();
    foreach (var m in BugHunterMistakes.All)
    {
        Console.WriteLine($"[{m.Id}] {m.Title}  {{{m.Channel}}}");
        Console.WriteLine($"  {m.Description}");
        Console.WriteLine($"  Hunt with: {m.HuntWith}");
        if (m.OracleHints.Count > 0)
            Console.WriteLine($"  Oracle: {string.Join(", ", m.OracleHints)}");
        if (m.SeedHints.Count > 0)
            Console.WriteLine($"  Seeds:  {string.Join("; ", m.SeedHints)}");
        if (m.Refs.Count > 0)
            Console.WriteLine($"  Refs:   {string.Join(", ", m.Refs)}");
        Console.WriteLine();
    }

    Console.WriteLine($"Oracle/Hybrid classes: {BugHunterMistakes.OracleArmed.Count()}");
    Console.WriteLine($"Seed/Hybrid classes:   {BugHunterMistakes.SeedArmed.Count()}");
    Console.WriteLine("Dictionary: projects/dictionaries/ai_codegen_mistakes.txt");
    Console.WriteLine("Emit YAML starter: randall hunt mistakes --emit-yaml");
    return 0;
}

static int RunMagician(string[] args)
{
    if (args.Length == 0 || args[0] is "-h" or "--help" or "help")
    {
        Console.WriteLine("""
            Magician engine — spells & summons (docs/MAGICIAN.md)

            The Oracle judges and can request help (knight / army / bots / hunter).
            The Magician casts spells on the fuzz campaign and summons helpers.

            Usage:
              randall magician spells
              randall magician cast -c <project.yaml> --need knight|army|bots|hunter|dictionary|energy|rearm|joker
              randall magician joker                 # Joker chaos help
              randall magician [-p <project>] [--json]     # recent casts from spells.jsonl

            Path: data/crashes/<project>/_magician/spells.jsonl
            Joker watch: data/crashes/<project>/_magician/joker_watch.jsonl
            """);
        return 0;
    }

    var rest = args;
    var sub = args[0].ToLowerInvariant();
    if (sub is "spells" or "catalog")
    {
        Console.Write(MagicianEngine.DescribeCatalog());
        return 0;
    }

    if (sub is "joker")
    {
        Console.Write(JokerEngine.Describe());
        return 0;
    }

    if (sub is "cast")
    {
        rest = args.Skip(1).ToArray();
        string? config = null;
        string? need = null;
        string? reason = null;
        for (var i = 0; i < rest.Length; i++)
        {
            switch (rest[i])
            {
                case "-c" or "--config" when i + 1 < rest.Length:
                    config = rest[++i];
                    break;
                case "--need" or "-n" when i + 1 < rest.Length:
                    need = rest[++i];
                    break;
                case "--reason" when i + 1 < rest.Length:
                    reason = rest[++i];
                    break;
            }
        }

        if (string.IsNullOrWhiteSpace(config) || string.IsNullOrWhiteSpace(need))
        {
                Console.Error.WriteLine(
                "Usage: randall magician cast -c projects/ai-badcode-hunt.yaml --need knight|army|bots|hunter|joker|…");
            return 1;
        }

        try
        {
            var path = Path.GetFullPath(config);
            var project = ProjectLoader.Load(path);
            project.Magician ??= new MagicianConfig();
            project.Magician.Enabled = true;
            var cast = MagicianEngine.CastNeed(project, path, need, reason);
            Console.WriteLine($"Magician cast on {project.Name}: {cast.Summary}");
            foreach (var s in cast.Spells)
                Console.WriteLine($"  • {s.Spell}" + (s.Summon is null ? "" : $" → summoned {s.Summon}") + $" — {s.Detail}");
            if (cast.DictionaryTokensAdded.Count > 0)
                Console.WriteLine($"  tokens: {string.Join(", ", cast.DictionaryTokensAdded.Take(8))}");
            if (cast.MutatorsEnsured.Count > 0)
                Console.WriteLine($"  mutators: {string.Join(", ", cast.MutatorsEnsured.Distinct())}");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex.Message);
            return 1;
        }
    }

    // Default: list spell log (also accept "log" / "casts")
    if (sub is "log" or "casts" or "list")
        rest = args.Skip(1).ToArray();

    string? projectFilter = null;
    var json = false;
    for (var i = 0; i < rest.Length; i++)
    {
        switch (rest[i])
        {
            case "-p" or "--project" when i + 1 < rest.Length:
                projectFilter = rest[++i];
                break;
            case "--json":
                json = true;
                break;
            case "-c" or "--config" when i + 1 < rest.Length:
                // convenience: derive project name from yaml
                try
                {
                    var p = ProjectLoader.Load(Path.GetFullPath(rest[++i]));
                    projectFilter = p.Name;
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine(ex.Message);
                    return 1;
                }
                break;
        }
    }

    var repo = CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
    var crashesRoot = Path.Combine(repo, "data", "crashes");
    if (!Directory.Exists(crashesRoot))
    {
        Console.WriteLine("No Magician casts yet (data/crashes missing).");
        return 0;
    }

    var all = new List<MagicianSpellDto>();
    foreach (var dir in Directory.EnumerateDirectories(crashesRoot))
    {
        if (projectFilter is not null &&
            !Path.GetFileName(dir).Equals(projectFilter, StringComparison.OrdinalIgnoreCase))
            continue;
        var mageDir = Path.Combine(dir, "_magician");
        if (!Directory.Exists(mageDir))
            continue;
        all.AddRange(new MagicianSpellStore(mageDir).List(projectFilter));
    }

    if (all.Count == 0)
    {
        Console.WriteLine(projectFilter is null
            ? "No Magician casts yet. Enable magician: + oracles: and fuzz, or: randall magician cast -c … --need army"
            : $"No Magician casts for '{projectFilter}'.");
        return 0;
    }

    all = all.OrderByDescending(s => s.At).ToList();
    if (json)
    {
        Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(all,
            new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));
        return 0;
    }

    foreach (var s in all.Take(200))
    {
        var summon = s.Summon is null ? "" : $" →{s.Summon}";
        Console.WriteLine(
            $"{s.At:u} {s.Project} [{s.Spell}{summon}] iter={s.Iteration} " +
            $"{s.RuleClass}/{s.RuleId} — {s.Detail}");
    }

    if (all.Count > 200)
        Console.WriteLine($"… {all.Count - 200} more (use --json)");
    return 0;
}

static int RunOracles(string[] args)
{
    if (args.Length > 0 && args[0] is "-h" or "--help" or "help")
    {
        Console.WriteLine("""
            List hybrid semantic oracle findings (docs/ORACLES.md)

            Usage:
              randall oracles [-p <project>] [--json]

            Findings are written during fuzz when projects enable `oracles:`.
            Path: data/crashes/<project>/_oracles/oracle_findings.jsonl
            """);
        return 0;
    }

    string? project = null;
    var json = false;
    for (var i = 0; i < args.Length; i++)
    {
        switch (args[i])
        {
            case "-p" or "--project" when i + 1 < args.Length:
                project = args[++i];
                break;
            case "--json":
                json = true;
                break;
        }
    }

    var repo = CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
    var crashesRoot = Path.Combine(repo, "data", "crashes");
    if (!Directory.Exists(crashesRoot))
    {
        Console.WriteLine("No oracle findings yet (data/crashes missing).");
        return 0;
    }

    var dirs = Directory.EnumerateDirectories(crashesRoot)
        .Where(d => project is null ||
                    Path.GetFileName(d).Equals(project, StringComparison.OrdinalIgnoreCase))
        .Select(d => Path.Combine(d, "_oracles"))
        .Where(Directory.Exists)
        .ToList();

    var all = new List<OracleFindingDto>();
    foreach (var dir in dirs)
        all.AddRange(new OracleFindingStore(dir).List(project));

    if (all.Count == 0)
    {
        Console.WriteLine(project is null
            ? "No oracle findings yet. Enable oracles: in a project YAML and fuzz."
            : $"No oracle findings for '{project}'.");
        return 0;
    }

    all = all.OrderByDescending(f => f.At).ToList();
    if (json)
    {
        Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(all,
            new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));
        return 0;
    }

    foreach (var f in all.Take(200))
    {
        Console.WriteLine(
            $"{f.At:u} {f.Project} [{f.Severity}/{f.RuleClass}] {f.RuleId} " +
            $"iter={f.Iteration} hash={f.InputHash[..Math.Min(8, f.InputHash.Length)]} " +
            $"expected={f.ExpectedRelation} actual={f.ActualRelation}");
    }

    if (all.Count > 200)
        Console.WriteLine($"… {all.Count - 200} more (use --json)");
    return 0;
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
    string? profile = null;
    var unlimited = false;
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
        else if (args[i] is "--profile" or "--stalk-profile" && i + 1 < args.Length)
            profile = args[++i];
        else if (args[i] is "--unlimited")
            unlimited = true;
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
            "       [--profile basic|fuzz|fuzzier] [--unlimited]  (unlimited bug stalking — stop with Ctrl-C)");
        Console.Error.WriteLine(
            "       [--debugger none|attach|wait|both] [--debugger-kind auto|windbg|windbg-preview] [--open-on-crash]");
        return 1;
    }

    var yamlPath = Path.GetFullPath(config);
    var project = ProjectLoader.Load(yamlPath);

    if (profile is not null)
    {
        if (!StalkProfiles.IsKnown(profile))
        {
            Console.Error.WriteLine($"Unknown --profile '{profile}'. Use: {string.Join(" | ", StalkProfiles.Names)}");
            return 1;
        }
        var covAvail = coverage || project.Fuzz.CoverageGuided || DynamoRioRunner.Discover().IsAvailable;
        var applied = StalkProfiles.Apply(project, profile, covAvail);
        coverage = coverage || applied.CoverageGuided;
        Console.WriteLine($"Stalk profile: {applied.Name} — {applied.Blurb}");
    }

    // Unlimited stalking: run until stopped (Ctrl-C) or the crash budget is hit.
    if (unlimited)
        maxIterations = int.MaxValue;

    Console.WriteLine($"Fuzzing: {project.Name} ({project.Kind}) — {project.Description}");
    var engineId = ExternalEngineCampaign.Normalize(project.Fuzz.Engine);
    if (ExternalEngineCampaign.IsExternal(engineId))
        Console.WriteLine($"Engine: {engineId} (external campaign — docs/ENGINE_ADAPTERS.md)");
    else
        Console.WriteLine("Engine: randall (own generation + stalk)");
    if (dryRun)
        Console.WriteLine("[dry-run mode]");
    if (coverage || project.Fuzz.CoverageGuided)
    {
        var dr = DynamoRioRunner.Discover();
        Console.WriteLine(dr.IsAvailable
            ? $"Coverage-guided via DynamoRIO: {dr.DrrunPath}"
            : $"Coverage requested but DynamoRIO not found — {DynamoRioRunner.InstallHint}");
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
    string? token = null;
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
        else if (args[i] is "--token" or "--agent-token" && i + 1 < args.Length)
            token = args[++i];
        else if (args[i] is "--no-runs")
            includeRuns = false;
        else if (args[i] is "--import")
            doImport = true;
    }

    if (string.IsNullOrWhiteSpace(agent) || string.IsNullOrWhiteSpace(project))
    {
        Console.Error.WriteLine(
            "Usage: randall crashes pull -a http://192.168.x.x:5000 -p <project> [-o zip] [--token SECRET] [--import] [--no-runs]");
        return 1;
    }

    try
    {
        var result = await CrashArtifactPack.PullFromAgentAsync(
            agent, project, output, includeRuns, token: token);
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
    string? rid = null;
    for (var i = 0; i < args.Length; i++)
    {
        if (args[i] is "-o" or "--output" && i + 1 < args.Length)
            output = args[++i];
        else if (args[i] is "--rid" && i + 1 < args.Length)
            rid = args[++i];
    }

    var root = CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
    rid ??= PortablePacker.DefaultRid();
    Console.WriteLine($"Packing portable Randfuzz → {output} (rid={rid})");
    var result = await PortablePacker.PackAsync(root, output, rid);
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

static int RunPattern(string[] args)
{
    if (args.Length == 0)
    {
        Console.Error.WriteLine("Usage: randall pattern create -l <len>");
        Console.Error.WriteLine("       randall pattern offset -q <ascii|0xhex> [-l <patternLen>]");
        return 1;
    }

    var sub = args[0].ToLowerInvariant();
    int len = PatternTools.MaxUnique;
    string? query = null;
    for (var i = 1; i < args.Length; i++)
    {
        if (args[i] is "-l" or "--length" && i + 1 < args.Length && int.TryParse(args[++i], out var n)) len = n;
        else if (args[i] is "-q" or "--query" && i + 1 < args.Length) query = args[++i];
    }

    if (sub == "create")
    {
        if (len > PatternTools.MaxUnique)
            Console.Error.WriteLine($"warning: {len} > {PatternTools.MaxUnique} unique max — pattern will repeat.");
        Console.WriteLine(PatternTools.Create(len));
        return 0;
    }
    if (sub == "offset")
    {
        if (query is null) { Console.Error.WriteLine("offset needs -q <ascii|0xhex>"); return 1; }
        var off = PatternTools.Offset(query, len);
        if (off < 0) { Console.WriteLine($"'{query}' not found in cyclic pattern (len {len})."); return 1; }
        Console.WriteLine($"Offset of {query} = {off} bytes");
        return 0;
    }
    Console.Error.WriteLine($"Unknown pattern subcommand '{sub}' (create|offset)");
    return 1;
}

static int RunExploit(string[] args)
{
    if (args.Length == 0 || args[0] is "-h" or "--help")
    {
        Console.WriteLine("""
            Usage:
              randall exploit guide --exe <path> [--core <core>] [--pattern-len N]
            Scope: register control + offset counting only. No shellcode / payload templates.
            """);
        return 0;
    }
    var sub = args[0].ToLowerInvariant();
    var rest = args.Skip(1).ToArray();
    return sub switch
    {
        "guide" => RunExploitGuide(rest),
        "template" => RefuseExploitTemplate(),
        _ => Unknown($"exploit {args[0]}"),
    };
}

static int RefuseExploitTemplate()
{
    Console.Error.WriteLine(
        "exploit template is disabled — no shellcode / payload skeletons.");
    Console.Error.WriteLine(
        "Use: randall scream walk -i <crash-guid> · randall rop sketch · randall ladder diff");
    Console.Error.WriteLine(
        "  (gadget catalogs + chain sketches for lab targets — docs/WINDBG_FUZZ_PKG.md)");
    return 2;
}

static int RunExploitGuide(string[] args)
{
    string? exe = null, core = null, host = "127.0.0.1", project = null;
    int? patternLen = null; int port = 9999;
    for (var i = 0; i < args.Length; i++)
    {
        if (args[i] is "--exe" && i + 1 < args.Length) exe = args[++i];
        else if (args[i] is "--core" && i + 1 < args.Length) core = args[++i];
        else if (args[i] is "--pattern-len" && i + 1 < args.Length && int.TryParse(args[++i], out var n)) patternLen = n;
        else if (args[i] is "--host" && i + 1 < args.Length) host = args[++i];
        else if (args[i] is "--port" && i + 1 < args.Length && int.TryParse(args[++i], out var p)) port = p;
        else if (args[i] is "--project" && i + 1 < args.Length) project = args[++i];
    }
    if (exe is null) { Console.Error.WriteLine("Usage: randall exploit guide --exe <path> [--core c] [--pattern-len N] [--host H] [--port P]"); return 1; }
    exe = ExecutableResolver.FindExisting(Path.GetFullPath(exe)) ?? Path.GetFullPath(exe);
    if (!File.Exists(exe)) { Console.Error.WriteLine($"exe not found: {exe}"); return 1; }
    core = core is null ? null : Path.GetFullPath(core);

    var plan = ExploitGuide.Build(exe, core, patternLen, project, host!, port);
    Console.WriteLine($"╔═ Scream triage (registers + offsets): {plan.Target} ═╗");
    Console.WriteLine($"  difficulty: {plan.Difficulty}");
    Console.WriteLine("  findings:");
    foreach (var f in plan.Findings) Console.WriteLine($"    • {f}");
    Console.WriteLine();
    foreach (var s in plan.Steps)
    {
        Console.WriteLine($"  [{s.Number}] {s.Title}");
        Console.WriteLine($"       why: {s.Why}");
        foreach (var c in s.Commands) Console.WriteLine($"       $ {c}");
        Console.WriteLine();
    }
    return 0;
}

static int RunExploitDev(string[] args)
{
    string? exe = null, core = null;
    int? patternLen = null;
    for (var i = 0; i < args.Length; i++)
    {
        if (args[i] is "--exe" && i + 1 < args.Length) exe = args[++i];
        else if (args[i] is "--core" && i + 1 < args.Length) core = args[++i];
        else if (args[i] is "--pattern-len" && i + 1 < args.Length && int.TryParse(args[++i], out var n)) patternLen = n;
    }

    if (exe is null || core is null)
    {
        Console.Error.WriteLine("Usage: randall exploitdev --exe <path> --core <core> [--pattern-len N]");
        Console.Error.WriteLine("  Reads faulting registers from the core (gdb) and, with --pattern-len,");
        Console.Error.WriteLine("  reports the cyclic-pattern offset that controls RIP (mona findmsp style).");
        return 1;
    }
    exe = ExecutableResolver.FindExisting(Path.GetFullPath(exe)) ?? Path.GetFullPath(exe);
    core = Path.GetFullPath(core);
    if (!File.Exists(exe)) { Console.Error.WriteLine($"exe not found: {exe}"); return 1; }
    if (!File.Exists(core)) { Console.Error.WriteLine($"core not found: {core}"); return 1; }

    var regs = ExploitDevTools.CoreRegisters(exe, core);
    if (regs.Count == 0)
    {
        Console.Error.WriteLine("Could not read registers (gdb missing or core unreadable).");
        return 1;
    }

    var is32 = regs.ContainsKey("eip");
    var ipReg = is32 ? "eip" : "rip";
    var spExpr = is32 ? "$esp" : "$rsp";
    var wordFmt = is32 ? "wx" : "gx";
    var regList = is32
        ? new[] { "eip", "esp", "ebp", "eax", "ebx", "ecx", "edx" }
        : new[] { "rip", "rsp", "rbp", "rax", "rdi", "rsi" };

    Console.WriteLine($"exploitdev: {Path.GetFileName(exe)}  core={Path.GetFileName(core)}  ({(is32 ? "x86 / EIP" : "x86-64 / RIP")})");
    foreach (var reg in regList)
        if (regs.TryGetValue(reg, out var v)) Console.WriteLine($"  {reg,-4}= {v}");

    if (patternLen is not null)
    {
        Console.WriteLine();
        Console.WriteLine("  ══ cyclic-pattern control (mona findmsp) ══");
        var any = false;
        foreach (var reg in regList)
        {
            if (!regs.TryGetValue(reg, out var val)) continue;
            var off = PatternTools.Offset(val, patternLen.Value);
            if (off >= 0)
            {
                any = true;
                Console.WriteLine($"  {reg.ToUpperInvariant()} controlled at offset {off}  ({val})");
            }
        }
        // A ret to a bad address faults at the ret, so the saved return address is on the
        // stack — scan it to recover the control offset (findmsp). Arch-aware (esp/wx vs rsp/gx).
        foreach (var w in ExploitDevTools.CoreStackWords(exe, core, 40, spExpr, wordFmt))
        {
            var off = PatternTools.Offset(w, patternLen.Value);
            if (off >= 0)
            {
                any = true;
                Console.WriteLine($"  saved return address (stack) controlled at offset {off}  ({w})");
                break;
            }
        }
        if (!any)
            Console.WriteLine($"  No register/stack slot held cyclic-pattern bytes at len {patternLen} " +
                "(canary/PIE tier, partial overwrite, or wrong --pattern-len).");
        else
            Console.WriteLine("  → pad to the offset, then place your value in that register's slot.");
    }
    return 0;
}

static int RunCheckSec(string[] args)
{
    string? exe = null;
    for (var i = 0; i < args.Length; i++)
        if (args[i] is "--exe" or "-e" && i + 1 < args.Length) exe = args[++i];

    if (exe is null)
    {
        Console.Error.WriteLine("Usage: randall checksec --exe <path>");
        return 1;
    }
    exe = Path.GetFullPath(exe);
    var resolved = ExecutableResolver.FindExisting(exe) ?? exe;
    if (!File.Exists(resolved)) { Console.Error.WriteLine($"Not found: {exe}"); return 1; }

    var m = MitigationInspector.Inspect(resolved);
    string yn(bool b) => b ? "✓ enabled" : "✗ MISSING";
    Console.WriteLine($"checksec: {Path.GetFileName(resolved)}   (tier: {m.Tier})");
    Console.WriteLine($"  NX / DEP        : {yn(m.Nx)}");
    Console.WriteLine($"  Stack canary    : {yn(m.Canary)}");
    Console.WriteLine($"  PIE (ASLR-able) : {yn(m.Pie)}");
    Console.WriteLine($"  RELRO           : {m.Relro}");
    Console.WriteLine($"  FORTIFY_SOURCE  : {yn(m.Fortify)}");
    if (!m.ReadelfUsed)
        Console.WriteLine("  (readelf unavailable — install binutils for accurate results)");

    var aslr = AslrControl.Read();
    Console.WriteLine();
    Console.WriteLine($"System ASLR      : {aslr.Label}" + (aslr.Value is not null ? $" (randomize_va_space={aslr.Value})" : ""));
    Console.WriteLine($"  change         : {aslr.HowToChange}");
    return 0;
}

static int RunHeapTriage(string[] args)
{
    string? exe = null;
    string? input = null;
    string? core = null;
    string? textFile = null;
    var harden = true;
    var targetArgs = new List<string>();
    for (var i = 0; i < args.Length; i++)
    {
        switch (args[i])
        {
            case "--exe" when i + 1 < args.Length: exe = args[++i]; break;
            case "--input" or "-i" when i + 1 < args.Length: input = args[++i]; break;
            case "--core" when i + 1 < args.Length: core = args[++i]; break;
            case "--text-file" when i + 1 < args.Length: textFile = args[++i]; break;
            case "--no-harden": harden = false; break;
            case "--": targetArgs.AddRange(args.Skip(i + 1)); i = args.Length; break;
        }
    }

    if (!OperatingSystem.IsLinux())
        Console.WriteLine("Note: heap triage targets Linux glibc/ASan; on this host results are best-effort.\n");

    // Text-only mode: classify a captured stderr/ASan log.
    if (textFile is not null)
    {
        if (!File.Exists(textFile)) { Console.Error.WriteLine($"Not found: {textFile}"); return 1; }
        var finding = HeapCorruptionClassifier.Classify(File.ReadAllText(textFile));
        return PrintHeapFinding(finding, null, null);
    }

    if (exe is null)
    {
        Console.Error.WriteLine("Usage: randall heaptriage --exe <path> [--input file] [--core file] [--no-harden] [-- args…]");
        Console.Error.WriteLine("       randall heaptriage --text-file <stderr.log>");
        return 1;
    }

    exe = Path.GetFullPath(exe);
    if (!File.Exists(exe)) { Console.Error.WriteLine($"Executable not found: {exe}"); return 1; }

    byte[]? stdinBytes = input is not null && File.Exists(input) ? File.ReadAllBytes(input) : null;
    Console.WriteLine($"Heap triage: {Path.GetFileName(exe)}  (hardening={(harden ? "on" : "off")})");
    if (harden)
        Console.WriteLine($"  armed: {LinuxHeapSentinel.Summary}");

    var result = LinuxCrashTriage.RunOnce(exe, targetArgs, stdinBytes, harden);
    if (core is not null)
        result = LinuxCrashTriage.AnalyzeCore(result, exe, Path.GetFullPath(core));

    Console.WriteLine($"  exit={result.ExitCode}" +
        (result.Signal is not null ? $"  signal={result.SignalName}" : "  (clean exit)"));
    if (!string.IsNullOrWhiteSpace(result.CapturedOutput))
    {
        Console.WriteLine("  --- target output (tail) ---");
        foreach (var line in TailLines(result.CapturedOutput, 8))
            Console.WriteLine($"  | {line}");
    }
    if (result.Backtrace is not null)
        Console.WriteLine("  (gdb backtrace captured)");

    return PrintHeapFinding(result.Finding, result.Signal, result.SignalName);
}

static int PrintHeapFinding(HeapCorruptionClassifier.HeapFinding? f, int? signal, string? signalName)
{
    Console.WriteLine();
    if (f is null)
    {
        Console.WriteLine(signal is not null
            ? $"Crash detected ({signalName}) but no memory-corruption signature matched — inspect manually."
            : "No crash / no memory-corruption signature detected.");
        return signal is not null ? 2 : 0;
    }

    Console.WriteLine("  ══ Memory-corruption finding ══");
    Console.WriteLine($"   primitive : {f.Primitive}");
    Console.WriteLine($"   category  : {f.Category}   {f.Cwe}");
    Console.WriteLine($"   severity  : {f.Severity}");
    Console.WriteLine($"   tier      : {f.Tier}");
    Console.WriteLine($"   audience  : {f.Audience}");
    Console.WriteLine($"   evidence  : {f.Evidence}");
    return 2;
}

static IEnumerable<string> TailLines(string text, int n)
{
    var lines = text.Replace("\r", "").Split('\n', StringSplitOptions.RemoveEmptyEntries);
    return lines.Length <= n ? lines : lines[^n..];
}

static int RunDoctor(string[] args)
{
    string? config = null;
    var strict = false;
    string? platform = null;
    for (var i = 0; i < args.Length; i++)
    {
        if (args[i] is "-c" or "--config" && i + 1 < args.Length)
            config = args[++i];
        else if (args[i] is "--strict")
            strict = true;
        else if (args[i] is "--platform" && i + 1 < args.Length)
            platform = args[++i];
    }

    if (config is null)
    {
        Console.Error.WriteLine("Usage: randall doctor -c projects/vulnserver.yaml [--strict] [--platform auto|windows|linux]");
        return 1;
    }

    var report = LabDoctor.Examine(Path.GetFullPath(config), requireTarget: strict, platform: platform);
    Console.WriteLine($"Platform: fuzzing={report.Platform} (host={report.HostPlatform})");
    foreach (var check in report.Checks)
    {
        var icon = check.Status switch { "ok" => "✓", "warn" => "!", _ => "✗" };
        Console.WriteLine($"  [{icon}] {check.Id,-24} {check.Message}");
    }

    Console.WriteLine();
    if (report.Ready)
    {
        Console.WriteLine($"Ready to fuzz {report.Project}.");
        foreach (var line in LabDoctor.NextSteps(report, config))
            Console.WriteLine($"  Next: {line}");
    }
    else
    {
        Console.WriteLine($"Not ready — fix failures above, then: randall fuzz -c {config} --dry-run");
    }

    return report.Ready ? 0 : 1;
}

static async Task<int> RunNotifyAsync(string[] args)
{
    if (args.Length == 0 || args[0] is "-h" or "--help")
    {
        Console.WriteLine("""
            Usage:
              randall notify test -c projects/local/myservice.yaml
              randall notify test -c campaigns/nightly-lab.yaml

            Sends a one-shot test message on every enabled Discord/email channel
            in the YAML notifications: block. Secrets via env:
              RANDALL_DISCORD_WEBHOOK
              RANDALL_SMTP_HOST / RANDALL_SMTP_USER / RANDALL_SMTP_PASSWORD
              RANDALL_SMTP_FROM / RANDALL_SMTP_TO
            Docs: docs/NOTIFICATIONS.md
            """);
        return 0;
    }

    if (!args[0].Equals("test", StringComparison.OrdinalIgnoreCase))
    {
        Console.Error.WriteLine("Unknown notify subcommand. Try: randall notify test -c <yaml>");
        return 1;
    }

    string? config = null;
    for (var i = 1; i < args.Length; i++)
    {
        if (args[i] is "-c" or "--config" && i + 1 < args.Length)
            config = args[++i];
    }

    if (config is null)
    {
        Console.Error.WriteLine("Usage: randall notify test -c projects/local/myservice.yaml");
        return 1;
    }

    var full = Path.GetFullPath(config);
    if (!File.Exists(full))
    {
        Console.Error.WriteLine($"Not found: {full}");
        return 1;
    }

    NotificationsConfig? notifications = null;
    string source;
    try
    {
        // Prefer project YAML; fall back to campaign YAML.
        try
        {
            var project = ProjectLoader.Load(full);
            notifications = project.Notifications;
            source = $"project:{project.Name}";
        }
        catch
        {
            var campaign = CampaignLoader.Load(full);
            notifications = campaign.Notifications;
            source = $"campaign:{campaign.Name}";
        }
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"Failed to load YAML: {ex.Message}");
        return 1;
    }

    if (notifications is null)
    {
        Console.Error.WriteLine(
            "No notifications: block in YAML. Copy docs/templates/notifications.yaml into your project.");
        return 1;
    }

    // Force-enable for the test so operators can dry-run a disabled block.
    notifications.Enabled = true;
    if (!notifications.Discord.Enabled && !notifications.Email.Enabled)
    {
        Console.Error.WriteLine("Enable discord.enabled and/or email.enabled under notifications:");
        return 1;
    }

    Console.WriteLine($"Testing notifications from {source} ({NotificationSettings.Describe(notifications)})…");
    var results = await NotificationDispatcher.SendTestAsync(notifications);
    var ok = true;
    foreach (var r in results)
    {
        Console.WriteLine($"  [{(r.Ok ? "ok" : "fail")}] {r.Channel,-8} {r.Message}");
        if (!r.Ok) ok = false;
    }

    return ok ? 0 : 1;
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
              randall stalk missed -p <project> [--limit 40]
              randall stalk inventory -p <project> --import <blocks.txt|drcov.log>
              randall stalk dynapstalker <drcov.log> <process.exe> <out.idc|.py> [--format idc|ghidra] [--color 0x00ffff]
              randall stalk export -p <project> --format idc|ghidra|edges [-o dir] [layerId…]
              randall stalk ghidra-pack -p <project> [-o dir]   Bundle Ghidra scripts + layer export
              randall stalk capture-binary -p <project> [-i seed.bin] [-o dir]
                                            Binary drcov (no -dump_text) for Dragon Dance
              randall stalk map -p <project> [-c yaml] [--binary path] [--limit N]
                                            In-Randall stalk map: missed + PE/ELF strings/imports
              randall stalk from-crash -i <crash-guid> [--tag crash] [--label text]
              randall stalk bench -c <project> [--profiles basic,fuzz,fuzzier] [--scale N]
            """);
        return 0;
    }

    var sub = args[0].ToLowerInvariant();
    var rest = args.Skip(1).ToArray();
    return sub switch
    {
        "layers" => StalkLayers(rest),
        "compare" => StalkCompare(rest),
        "missed" => StalkMissed(rest),
        "inventory" => StalkInventory(rest),
        "dynapstalker" or "drcov2idc" => StalkDynapstalker(rest),
        "ghidra-pack" or "ghidra" => StalkGhidraPack(rest),
        "capture-binary" or "binary-drcov" or "dragon-dance" => StalkCaptureBinary(rest).GetAwaiter().GetResult(),
        "map" or "stalk-map" or "surface" => StalkMap(rest),
        "export" => StalkExport(rest),
        "from-crash" => StalkFromCrash(rest),
        "bench" => StalkBench(rest),
        _ => Unknown($"stalk {args[0]}"),
    };
}

static int StalkMap(string[] args)
{
    var project = RequireProject(args);
    if (project is null)
        return 1;

    string? config = null, binary = null;
    var limit = 40;
    for (var i = 0; i < args.Length; i++)
    {
        if (args[i] is "-c" or "--config" && i + 1 < args.Length)
            config = args[++i];
        else if (args[i] is "--binary" or "-b" && i + 1 < args.Length)
            binary = args[++i];
        else if (args[i] is "--limit" or "-n" && i + 1 < args.Length && int.TryParse(args[++i], out var n))
            limit = n;
    }

    try
    {
        var map = StalkMapBuilder.Build(
            project,
            yamlPath: config is null ? null : Path.GetFullPath(config),
            binaryPath: binary is null ? null : Path.GetFullPath(binary),
            limit: limit);

        Console.WriteLine($"Stalk map: {map.Project}");
        Console.WriteLine($"  Binary:  {map.BinaryPath ?? "(none)"}  [{map.Format}]");
        Console.WriteLine($"  {map.Summary}");
        Console.WriteLine();

        if (map.InterestingImports.Count > 0)
        {
            Console.WriteLine("Interesting imports:");
            foreach (var imp in map.InterestingImports.Take(12))
                Console.WriteLine($"  {imp.Library}!{imp.Function}  {(imp.ThunkRva is null ? "" : "@ " + imp.ThunkRva)}");
            Console.WriteLine();
        }

        if (map.HotStrings.Count > 0)
        {
            Console.WriteLine("Hot strings:");
            foreach (var s in map.HotStrings.Take(12))
                Console.WriteLine($"  {s.Rva} [{s.Section}]  \"{TrimConsole(s.Text, 60)}\"");
            Console.WriteLine();
        }

        Console.WriteLine("Surface ideas:");
        foreach (var idea in map.SurfaceIdeas.Take(8))
        {
            Console.WriteLine($"  [{idea.Priority}] {idea.Title}");
            Console.WriteLine($"         {idea.Detail}");
        }

        Console.WriteLine();
        Console.WriteLine($"Hotspots (top {Math.Min(limit, map.Hotspots.Count)}):");
        foreach (var h in map.Hotspots.Take(limit))
        {
            var surf = h.SurfaceKind;
            var near = "";
            if (h.NearbyStrings.Count > 0)
                near += " str=" + string.Join("|", h.NearbyStrings.Take(2).Select(t => TrimConsole(t, 24)));
            if (h.NearbyImports.Count > 0)
                near += " imp=" + string.Join("|", h.NearbyImports.Take(2));
            Console.WriteLine(
                $"  [{h.BoostedScore}] {h.Block.Category} {h.Block.Module}:{h.Block.Address}  " +
                $"sec={h.Section ?? "-"}  kind={surf}{near}");
            Console.WriteLine($"         {h.Block.WhyMissed}");
        }

        Console.WriteLine();
        Console.WriteLine("Deep dive when needed: randall stalk ghidra-pack -p " + project);
        return 0;
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine(ex.Message);
        return 1;
    }
}

static string TrimConsole(string s, int max) =>
    s.Length <= max ? s : s[..(max - 1)] + "…";

static async Task<int> StalkCaptureBinary(string[] args)
{
    string? projectName = null;
    string? configPath = null;
    string? inputPath = null;
    string? outputDir = null;
    for (var i = 0; i < args.Length; i++)
    {
        if (args[i] is "-p" or "--project" && i + 1 < args.Length)
            projectName = args[++i];
        else if (args[i] is "-c" or "--config" && i + 1 < args.Length)
            configPath = args[++i];
        else if (args[i] is "-i" or "--input" && i + 1 < args.Length)
            inputPath = args[++i];
        else if (args[i] is "-o" or "--output" && i + 1 < args.Length)
            outputDir = args[++i];
    }

    if (configPath is null && projectName is null)
    {
        Console.Error.WriteLine("Usage: randall stalk capture-binary -p <project>|-c <yaml> [-i seed.bin] [-o dir]");
        Console.Error.WriteLine("  Writes binary drcov (no -dump_text) for Dragon Dance → corpus/traces-binary/");
        Console.Error.WriteLine("  Enable during fuzz: fuzz.captureBinaryDrcov: true");
        return 1;
    }

    try
    {
        var root = CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var yamlPath = configPath is not null
            ? Path.GetFullPath(configPath)
            : ResolveProjectYaml(root, projectName!);
        if (yamlPath is null || !File.Exists(yamlPath))
        {
            Console.Error.WriteLine($"Project YAML not found for '{projectName ?? configPath}'");
            return 1;
        }

        var project = ProjectLoader.Load(yamlPath);
        byte[] input;
        if (!string.IsNullOrWhiteSpace(inputPath))
        {
            input = await File.ReadAllBytesAsync(Path.GetFullPath(inputPath));
        }
        else
        {
            // Prefer first seed path from YAML, else a tiny placeholder
            var seedRel = project.Seeds.FirstOrDefault();
            if (!string.IsNullOrWhiteSpace(seedRel))
            {
                var seedFull = ProjectLoader.ResolvePath(yamlPath, seedRel);
                if (File.Exists(seedFull))
                    input = await File.ReadAllBytesAsync(seedFull);
                else
                    input = "RANDFUZZ_BINARY_DRCOV"u8.ToArray();
            }
            else
            {
                input = "RANDFUZZ_BINARY_DRCOV"u8.ToArray();
            }
        }

        var result = await BinaryDrcovCapture.CaptureFileAsync(project, yamlPath, input, outputDir);
        if (!result.Success)
        {
            Console.Error.WriteLine(result.Detail);
            return 1;
        }

        Console.WriteLine($"Binary drcov (Dragon Dance): {result.TracePath}");
        Console.WriteLine("Import that *.log in Ghidra → Dragon Dance (NOT the text sample.drcov.log).");
        Console.WriteLine("Primary Randfuzz colors: randall stalk ghidra-pack -p " + project.Name);
        return 0;
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine(ex.Message);
        return 1;
    }
}

static string? ResolveProjectYaml(string repoRoot, string projectName)
{
    var name = projectName.Trim();
    if (name.EndsWith(".yaml", StringComparison.OrdinalIgnoreCase) ||
        name.EndsWith(".yml", StringComparison.OrdinalIgnoreCase))
        return Path.GetFullPath(name);

    var candidates = new[]
    {
        Path.Combine(repoRoot, "projects", name + ".yaml"),
        Path.Combine(repoRoot, "projects", name + ".yml"),
        Path.Combine(repoRoot, "projects", "local", name + ".yaml"),
        Path.Combine(repoRoot, "projects", name, "project.yaml"),
    };
    return candidates.FirstOrDefault(File.Exists);
}

static int StalkGhidraPack(string[] args)
{
    var project = RequireProject(args);
    if (project is null)
        return 1;

    string? output = null;
    for (var i = 0; i < args.Length; i++)
    {
        if (args[i] is "-o" or "--output" && i + 1 < args.Length)
            output = args[++i];
    }

    try
    {
        var result = StalkCoverageExport.Export(new StalkExportRequest(
            project,
            [],
            "ghidra",
            output));
        var root = CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var tools = Path.Combine(root, "tools", "ghidra");
        Console.WriteLine($"Ghidra pack: {result.BlockCount} blocks → {result.OutputPath}");
        Console.WriteLine($"Installable scripts: {tools}");
        Console.WriteLine("Docs: docs/GHIDRA_INTEGRATION.md");
        Console.WriteLine("Ghidra → Script Manager → run *_stalk_layers.py (open matching module first).");
        return 0;
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine(ex.Message);
        return 1;
    }
}

static int StalkDynapstalker(string[] args)
{
    // PDF / Dynapstalker: <drcov.log> <process.exe> <out.idc|out.py> [--format idc|ghidra] [--color 0x00ffff]
    string? log = null, process = null, output = null, color = null, format = null;
    var positionals = new List<string>();
    for (var i = 0; i < args.Length; i++)
    {
        if (args[i] is "--color" or "-c" && i + 1 < args.Length)
            color = args[++i];
        else if (args[i] is "--format" or "-f" && i + 1 < args.Length)
            format = args[++i];
        else if (!args[i].StartsWith('-'))
            positionals.Add(args[i]);
    }

    if (positionals.Count >= 1) log = positionals[0];
    if (positionals.Count >= 2) process = positionals[1];
    if (positionals.Count >= 3) output = positionals[2];

    if (log is null || process is null || output is null)
    {
        Console.Error.WriteLine("Usage: randall stalk dynapstalker <drcov.log> <process.exe> <out.idc|out.py> [--format idc|ghidra] [--color 0x00ffff]");
        Console.Error.WriteLine("  IDA:    … out.idc --color 0x00ffff");
        Console.Error.WriteLine("  Ghidra: … out.py --format ghidra --color 0x00ffff");
        Console.Error.WriteLine("  Load oldest script first; uncolored blocks = missed. Requires drcov -dump_text.");
        return 1;
    }

    try
    {
        var result = DynapstalkerExport.Export(Path.GetFullPath(log), process, Path.GetFullPath(output), format ?? "", color);
        Console.WriteLine($"Dynapstalker {result.Format}: {result.BlockCount} blocks → {result.OutputPath}");
        Console.WriteLine(result.Format == "ghidra"
            ? "Ghidra: Script Manager → run oldest script first; plain blocks remain missed (imageBase+RVA)."
            : "IDA: File → Script file — load oldest IDC first; white blocks remain missed.");
        return 0;
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine(ex.Message);
        return 1;
    }
}

static int StalkMissed(string[] args)
{
    var project = RequireProject(args);
    if (project is null)
        return 1;

    var limit = 40;
    for (var i = 0; i < args.Length; i++)
    {
        if (args[i] is "--limit" or "-n" && i + 1 < args.Length && int.TryParse(args[++i], out var n))
            limit = n;
    }

    var report = MissedBlockAnalyzer.Analyze(project, limit: limit);
    Console.WriteLine($"{report.Project}: missed blocks [{report.Mode}]");
    Console.WriteLine($"  {report.Summary}");
    Console.WriteLine($"  hit={report.HitCount} inventory={report.InventoryCount} missed={report.MissedCount}");
    Console.WriteLine($"  {report.WorkflowHint}");
    Console.WriteLine();

    if (report.Categories.Count > 0)
    {
        Console.WriteLine("Categories:");
        foreach (var c in report.Categories)
            Console.WriteLine($"  {c.Count,4}  {c.Label,-22}  {c.Description}");
        Console.WriteLine();
    }

    if (report.TopIdeas.Count > 0)
    {
        Console.WriteLine("Top fuzz ideas:");
        foreach (var idea in report.TopIdeas.Take(8))
        {
            Console.WriteLine($"  [{idea.Priority}] {idea.Title}");
            Console.WriteLine($"         {idea.Detail}");
            if (!string.IsNullOrWhiteSpace(idea.CliHint))
                Console.WriteLine($"         CLI: {idea.CliHint}");
            if (!string.IsNullOrWhiteSpace(idea.UiHint))
                Console.WriteLine($"         UI:  {idea.UiHint}");
        }
        Console.WriteLine();
    }

    if (report.Blocks.Count == 0)
    {
        Console.WriteLine("No missed-block findings yet.");
        return 0;
    }

    Console.WriteLine("Missed / gap samples:");
    foreach (var b in report.Blocks.Take(limit))
    {
        Console.WriteLine($"  [{b.Category}] {b.Module}:{b.Address}  (score {b.PriorityScore})");
        Console.WriteLine($"         why: {b.WhyMissed}");
        var tip = b.Ideas.FirstOrDefault();
        if (tip is not null)
            Console.WriteLine($"         tip: {tip.Title}");
    }

    return 0;
}

static int StalkInventory(string[] args)
{
    var project = RequireProject(args);
    if (project is null)
        return 1;

    string? importPath = null;
    for (var i = 0; i < args.Length; i++)
    {
        if (args[i] is "--import" or "-i" && i + 1 < args.Length)
            importPath = args[++i];
    }

    if (importPath is null)
    {
        Console.Error.WriteLine("Usage: randall stalk inventory -p <project> --import <blocks.txt|drcov.log>");
        Console.Error.WriteLine("  blocks.txt lines: moduleId:0xstart:size   (same as edges.txt / drcov keys)");
        return 1;
    }

    try
    {
        var result = MissedBlockAnalyzer.ImportInventory(project, Path.GetFullPath(importPath));
        Console.WriteLine($"Inventory imported: {result.BlockCount} blocks → {result.InventoryPath}");
        Console.WriteLine("Next: randall stalk missed -p " + project);
        return 0;
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine(ex.Message);
        return 1;
    }
}

static int StalkBench(string[] args)
{
    string? config = null;
    var profiles = new List<string>(StalkProfiles.Names);
    var scale = 1.0;
    for (var i = 0; i < args.Length; i++)
    {
        if (args[i] is "-c" or "--config" && i + 1 < args.Length) config = args[++i];
        else if (args[i] is "--profiles" && i + 1 < args.Length)
            profiles = args[++i].Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();
        else if (args[i] is "--scale" && i + 1 < args.Length && double.TryParse(args[++i], out var s))
            scale = s;
    }

    if (config is null)
    {
        Console.Error.WriteLine("Usage: randall stalk bench -c projects/vulnserver.yaml [--profiles basic,fuzz,fuzzier] [--scale N]");
        return 1;
    }
    foreach (var p in profiles)
        if (!StalkProfiles.IsKnown(p)) { Console.Error.WriteLine($"Unknown profile '{p}'. Use: {string.Join(" | ", StalkProfiles.Names)}"); return 1; }

    return StalkBenchAsync(Path.GetFullPath(config), profiles, scale).GetAwaiter().GetResult();
}

static async Task<int> StalkBenchAsync(string yamlPath, List<string> profiles, double scale)
{
    var covAvail = DynamoRioRunner.Discover().IsAvailable;
    Console.WriteLine($"Stalk bench: {Path.GetFileNameWithoutExtension(yamlPath)}  (coverage backend: {(covAvail ? "DynamoRIO" : "corpus-novelty")})");
    Console.WriteLine();

    var rows = new List<(string Profile, int Iters, int Crashes, int Unique, int Corpus, int Novel, int Edges, double Secs)>();
    foreach (var name in profiles)
    {
        var project = ProjectLoader.Load(yamlPath);
        var prof = StalkProfiles.Apply(project, name, covAvail,
            iterationsOverride: (int)Math.Max(1, Math.Round(StalkProfiles.Get(name).Iterations * scale)));
        var sink = new StalkBenchSink();
        var sw = System.Diagnostics.Stopwatch.StartNew();
        Console.WriteLine($"→ running '{name}' ({project.Fuzz.MaxIterations} iters, havoc={project.Fuzz.HavocDepth}, power={project.Fuzz.PowerSchedule}, graphBias={project.Fuzz.SessionGraphBias})…");
        var engine = new FuzzEngine();
        var result = await engine.RunAsync(project, yamlPath,
            new FuzzRunOptions(false, project.Fuzz.CoverageGuided, project.Fuzz.MaxIterations, sink));
        sw.Stop();
        var unique = result.Crashes.Select(c => c.StackHash).Distinct().Count();
        rows.Add((name, result.Iterations, result.CrashesFound, unique, result.CorpusAdded,
            sink.NovelInputs, sink.MaxEdges, sw.Elapsed.TotalSeconds));
    }

    Console.WriteLine();
    Console.WriteLine("Comparison (stalking intensity):");
    Console.WriteLine($"  {"profile",-9} {"iters",6} {"crashes",8} {"unique",7} {"corpus+",8} {"novel",6} {"edges",6} {"secs",7} {"crash/1k",9}");
    Console.WriteLine($"  {new string('-', 74)}");
    foreach (var r in rows)
    {
        var per1k = r.Iters > 0 ? r.Crashes * 1000.0 / r.Iters : 0;
        Console.WriteLine($"  {r.Profile,-9} {r.Iters,6} {r.Crashes,8} {r.Unique,7} {r.Corpus,8} {r.Novel,6} {r.Edges,6} {r.Secs,7:F1} {per1k,9:F1}");
    }
    Console.WriteLine();
    Console.WriteLine("novel = inputs that expanded the frontier (stalking signal); edges = coverage edges (DynamoRIO only).");
    return 0;
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

static int RunStack(string[] args)
{
    if (args.Length == 0 || args[0] is "-h" or "--help" or "help")
    {
        Console.WriteLine("""
            Usage:
              randall stack lens -i <crash-guid> [--window 128] [--exe path] [--json]

            Stack Lens — dump-native CONTROL map (stack slots × crashing input).
            Writes *_stack_lens.json. Lab-only; no payloads. See docs/WINDBG_FUZZ_PKG.md.
            """);
        return 0;
    }

    var sub = args[0].ToLowerInvariant();
    if (sub is not ("lens" or "map" or "control"))
        return Unknown($"stack {args[0]}");

    Guid? crashId = null;
    var window = 128;
    string? exe = null;
    var json = false;
    for (var i = 1; i < args.Length; i++)
    {
        if (args[i] is "-h" or "--help" or "help")
        {
            Console.WriteLine("Usage: randall stack lens -i <crash-guid> [--window 128]");
            return 0;
        }
        if (args[i] is "-i" or "--id" or "--crash" && i + 1 < args.Length && Guid.TryParse(args[i + 1], out var g))
        { crashId = g; i++; }
        else if (args[i] is "--window" or "-w" && i + 1 < args.Length && int.TryParse(args[i + 1], out var w))
        { window = w; i++; }
        else if (args[i] is "--exe" or "-e" && i + 1 < args.Length) exe = args[++i];
        else if (args[i] is "--json") json = true;
    }

    if (crashId is null)
    {
        Console.Error.WriteLine("Usage: randall stack lens -i <crash-guid> [--window 128]");
        return 1;
    }

    var report = StackLens.AnalyzeCrash(crashId.Value, window, exe);
    if (json)
    {
        Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(report, new System.Text.Json.JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase,
        }));
        return report.Error is null ? 0 : 2;
    }

    Console.WriteLine(report.SummaryLine);
    if (report.SpValue is not null)
        Console.WriteLine($"  {report.SpRegister ?? "SP"}={report.SpValue}  arch={report.Arch}  source={report.Source}");
    if (report.PrimaryControl is { } pc)
        Console.WriteLine($"  CONTROL: {pc.Where} = {pc.ValueHex}" +
                          (pc.InputOffset is { } o ? $" @ input {o}" : "") +
                          $" [{pc.Role}]");
    foreach (var w in report.Words.Take(24))
    {
        var slot = w.OffsetFromSp >= 0
            ? $"{report.SpRegister ?? "SP"}+0x{w.OffsetFromSp:X2}"
            : w.AddressHex;
        var off = w.InputOffset is { } io ? $" @ {io}" : "";
        var sym = w.SymbolHint is null ? "" : $" ({w.SymbolHint})";
        Console.WriteLine($"  {slot,-12} {w.ValueHex,-18} {w.Role,-14}{off}{sym}");
        if (!string.IsNullOrWhiteSpace(w.Note))
            Console.WriteLine($"               {w.Note}");
    }
    if (report.Words.Count > 24)
        Console.WriteLine($"  … {report.Words.Count - 24} more (use --json)");
    if (report.OutputPath is not null)
        Console.WriteLine("Wrote: " + report.OutputPath);
    return report.Error is null ? 0 : 2;
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
              randall scream walk -i <crash-guid> [--goal auto|pivot|leak|canary|…] [--json]
              randall scream selftest              Build/run lab AV target + verify dump

            watch: attach as debugger, wait for second-chance, write minidump.
            walk:  one-shot playbook — CONTROL → badchars → ROP sketch → WinDbg/GDB walks.
            """);
        return 0;
    }

    var sub = args[0].ToLowerInvariant();
    if (sub is "selftest" or "test")
        return await RunScreamSelftestAsync();
    if (sub is "walk" or "playbook")
        return RunScreamWalk(args.Skip(1).ToArray());
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


static int RunScreamWalk(string[] args)
{
    if (args.Length == 0 || args[0] is "-h" or "--help" or "help")
    {
        Console.WriteLine("""
            Usage:
              randall scream walk -i <crash-guid> [--goal auto|pivot|leak|canary|…] [--json]

            One-shot playbook: CONTROL → badchars → ROP sketch → WinDbg/GDB walks.
            Writes *_scream_walk.json beside the crash. See docs/WINDBG_FUZZ_PKG.md.
            """);
        return 0;
    }

    Guid? crashId = null;
    string goal = "auto";
    string? bad = null;
    string? exe = null;
    var json = false;
    var maxModules = 3;
    for (var i = 0; i < args.Length; i++)
    {
        if (args[i] is "-i" or "--id" or "--crash" && i + 1 < args.Length && Guid.TryParse(args[i + 1], out var g))
        { crashId = g; i++; }
        else if (args[i] is "--goal" or "-g" && i + 1 < args.Length) goal = args[++i];
        else if (args[i] is "--badchars" or "--bad" && i + 1 < args.Length) bad = args[++i];
        else if (args[i] is "--exe" or "-e" && i + 1 < args.Length) exe = args[++i];
        else if (args[i] is "--modules" && i + 1 < args.Length && int.TryParse(args[i + 1], out var mm))
        { maxModules = mm; i++; }
        else if (args[i] is "--json") json = true;
        else if (args[i] is "-h" or "--help")
        {
            Console.WriteLine("Usage: randall scream walk -i <crash-guid> [--goal auto]");
            return 0;
        }
    }

    if (crashId is null)
    {
        Console.Error.WriteLine("Usage: randall scream walk -i <crash-guid> [--goal auto]");
        return 1;
    }

    var report = ScreamWalk.Run(crashId.Value, goal, bad, exe, maxModules);
    if (json)
    {
        Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(report, new System.Text.Json.JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase,
        }));
        return report.Error is null ? 0 : 2;
    }

    Console.WriteLine(report.SummaryLine);
    foreach (var s in report.Steps)
    {
        Console.WriteLine($"  [{s.Index}] {s.Status,-4} {s.Title}: {s.Detail}");
        if (s.ArtifactPath is not null)
            Console.WriteLine($"         → {s.ArtifactPath}");
    }
    if (report.PlaybookPath is not null)
        Console.WriteLine("Playbook: " + report.PlaybookPath);
    return report.Error is null ? 0 : 2;
}

static int RunLadder(string[] args)
{
    if (args.Length == 0 || args[0] is "-h" or "--help" or "help")
    {
        Console.WriteLine("""
            Usage:
              randall ladder diff [-i <crash-guid>] [-p <project>] [--json]
              randall ladder diff --no-scan

            Compare vulnlab-{basic,nx,aslr,modern} mitigations + gadget counts.
            """);
        return 0;
    }

    var sub = args[0].ToLowerInvariant();
    if (sub is not ("diff" or "compare" or "climb"))
        return Unknown($"ladder {args[0]}");

    Guid? crashId = null;
    string? project = null;
    var json = false;
    var scan = true;
    for (var i = 1; i < args.Length; i++)
    {
        if (args[i] is "-h" or "--help" or "help")
        {
            Console.WriteLine("""
                Usage:
                  randall ladder diff [-i <crash-guid>] [-p <project>] [--json]
                  randall ladder diff --no-scan

                Compare vulnlab-{basic,nx,aslr,modern} mitigations + gadget counts.
                """);
            return 0;
        }
        if (args[i] is "-i" or "--id" or "--crash" && i + 1 < args.Length && Guid.TryParse(args[i + 1], out var g))
        { crashId = g; i++; }
        else if (args[i] is "-p" or "--project" && i + 1 < args.Length) project = args[++i];
        else if (args[i] is "--no-scan") scan = false;
        else if (args[i] is "--json") json = true;
    }

    var report = MitigationLadder.Diff(crashId, project, scanGadgets: scan);
    if (json)
    {
        Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(report, new System.Text.Json.JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase,
        }));
        return report.Error is null ? 0 : 2;
    }

    Console.WriteLine(report.SummaryLine);
    Console.WriteLine($"{"tier",-8} {"NX",-4} {"can",-4} {"PIE",-4} {"RELRO",-8} {"gadgets",-8} goal");
    foreach (var t in report.Tiers)
    {
        if (!t.Exists)
        {
            Console.WriteLine($"{t.Tier,-8} (missing)  hint={t.SketchGoalHint}");
            continue;
        }
        Console.WriteLine(
            $"{t.Tier,-8} {(t.Nx ? "yes" : "no"),-4} {(t.Canary ? "yes" : "no"),-4} {(t.Pie ? "yes" : "no"),-4} {t.Relro,-8} {(t.GadgetCount?.ToString() ?? "-"),-8} {t.SketchGoalHint}");
    }
    foreach (var f in report.Findings)
        Console.WriteLine("  · " + f);
    if (report.OutputPath is not null)
        Console.WriteLine("Wrote: " + report.OutputPath);
    return report.Error is null ? 0 : 2;
}

static int RunGdb(string[] args)
{
    if (args.Length == 0 || args[0] is "-h" or "--help" or "help")
    {
        Console.WriteLine("""
            Usage:
              randall gdb scripts
              randall gdb walk -i <crash-guid> [--json]

            Linux GDB/GEF walk twin of RandfuzzDbg (docs/WINDBG_FUZZ_PKG.md).
            """);
        return 0;
    }

    var sub = args[0].ToLowerInvariant();
    if (sub is "scripts" or "script")
    {
        Console.Write(RandfuzzGdbWalk.FormatScriptHelp());
        return 0;
    }

    if (sub is "walk" or "export")
    {
        Guid? id = null;
        var json = false;
        for (var i = 1; i < args.Length; i++)
        {
            if (args[i] is "-h" or "--help" or "help")
            {
                Console.WriteLine("""
                    Usage:
                      randall gdb walk -i <crash-guid> [--json]

                    Linux GDB/GEF walk twin of RandfuzzDbg. Writes *_gdb_walk.json.
                    """);
                return 0;
            }
            if (args[i] is "-i" or "--id" && i + 1 < args.Length && Guid.TryParse(args[i + 1], out var g))
            { id = g; i++; }
            else if (args[i] is "--json") json = true;
        }
        if (id is null)
        {
            Console.Error.WriteLine("Usage: randall gdb walk -i <crash-guid>");
            return 1;
        }
        var walk = RandfuzzGdbWalk.BuildForCrash(id.Value);
        if (json)
        {
            Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(walk, new System.Text.Json.JsonSerializerOptions
            {
                WriteIndented = true,
                PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase,
            }));
            return walk.Error is null ? 0 : 2;
        }
        Console.WriteLine(walk.SummaryLine);
        if (walk.WalkPath is not null) Console.WriteLine("  walk: " + walk.WalkPath);
        if (walk.ControlledOffset is { } off)
            Console.WriteLine($"  CONTROL: {walk.ControlledRegister ?? "IP"} @ {off}");
        foreach (var line in walk.ScriptLines.Take(6))
            Console.WriteLine("  " + line);
        return walk.Error is null ? 0 : 2;
    }

    return Unknown($"gdb {args[0]}");
}

static int RunRop(string[] args)
{
    if (args.Length == 0 || args[0] is "-h" or "--help" or "help")
    {
        Console.WriteLine("""
            Usage:
              randall rop scan --exe <path> [--arch x64|x86] [--json]
              randall rop search --exe <path> --need <kind> [--badchars "00 0a"] [--json]
              randall rop sketch --exe <path> --goal auto|pivot|write|control|leak|canary [--badchars …] [--json]
              randall rop from-crash -i <crash-guid> [--goal auto] [--exe path] [--modules N] [--json]
              randall rop search -i <crash-guid> --need <kind> [--badchars …] [--json]
              randall rop show -i <crash-guid> [--json]
              randall rop badchars -i <crash-guid> [--json]

            ROP Studio — gadget catalog + constrained chain sketches for lab binaries.
            Prefer: randall scream walk -i <guid> for the full playbook.
            No shellcode / payloads. See docs/WINDBG_FUZZ_PKG.md.
            """);
        return 0;
    }

    var sub = args[0].ToLowerInvariant();
    if (sub is "-h" or "--help" or "help")
    {
        Console.WriteLine("Usage: randall rop scan|search|sketch|from-crash|show|badchars …");
        return 0;
    }

    string? exe = null;
    string? need = null;
    string? goal = "auto";
    string? arch = null;
    string? bad = null;
    Guid? crashId = null;
    var json = false;
    var maxModules = 3;
    for (var i = 1; i < args.Length; i++)
    {
        if (args[i] is "-h" or "--help" or "help")
        {
            Console.WriteLine($"Usage: randall rop {sub} …  (try: randall rop -h)");
            return 0;
        }
        if (args[i] is "--exe" or "-e" && i + 1 < args.Length) exe = args[++i];
        else if (args[i] is "--need" or "-n" && i + 1 < args.Length) need = args[++i];
        else if (args[i] is "--goal" or "-g" && i + 1 < args.Length) goal = args[++i];
        else if (args[i] is "--arch" && i + 1 < args.Length) arch = args[++i];
        else if (args[i] is "--badchars" or "--bad" && i + 1 < args.Length) bad = args[++i];
        else if (args[i] is "--modules" && i + 1 < args.Length && int.TryParse(args[i + 1], out var mm))
        {
            maxModules = mm;
            i++;
        }
        else if (args[i] is "-i" or "--id" or "--crash" && i + 1 < args.Length
                 && Guid.TryParse(args[i + 1], out var g))
        {
            crashId = g;
            i++;
        }
        else if (args[i] is "--json") json = true;
    }

    object report;
    if (sub is "from-crash" or "crash")
    {
        if (crashId is null)
        {
            Console.Error.WriteLine("Usage: randall rop from-crash -i <crash-guid> [--goal auto] [--exe path] [--modules N]");
            return 1;
        }

        report = RopStudio.FromCrash(crashId.Value, goal ?? "auto", bad, exeOverride: exe, maxModules: maxModules);
    }
    else if (sub is "show" or "status" or "sidecars")
    {
        if (crashId is null)
        {
            Console.Error.WriteLine("Usage: randall rop show -i <crash-guid>");
            return 1;
        }

        report = RopStudio.LoadSidecars(crashId.Value) ?? (object)new { error = "crash not found" };
    }
    else if (sub is "badchars" or "badchar" or "learn-badchars")
    {
        if (crashId is null)
        {
            Console.Error.WriteLine("Usage: randall rop badchars -i <crash-guid>");
            return 1;
        }

        report = RopBadCharLearner.LearnFromCrash(crashId.Value);
    }
    else if (sub is "search" && crashId is not null)
    {
        report = RopStudio.SearchFromCrash(crashId.Value, need ?? "ret", bad);
    }
    else
    {
        if (string.IsNullOrWhiteSpace(exe))
        {
            Console.Error.WriteLine("Usage: randall rop scan|search|sketch|from-crash|show|badchars …");
            return 1;
        }

        exe = ExecutableResolver.FindExisting(Path.GetFullPath(exe)) ?? Path.GetFullPath(exe);
        if (!File.Exists(exe))
        {
            Console.Error.WriteLine($"exe not found: {exe}");
            return 1;
        }

        report = sub switch
        {
            "scan" => RopGadgetScanner.Scan(exe, arch),
            "search" => RopStudio.Search(exe, need ?? "ret", bad, archHint: arch),
            "sketch" or "chain" => RopStudio.Sketch(exe, goal ?? "control", bad, archHint: arch),
            _ => null!,
        };
        if (report is null)
        {
            Console.Error.WriteLine($"Unknown rop subcommand: {sub}");
            return 1;
        }
    }

    if (json)
    {
        Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(report, new System.Text.Json.JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase,
        }));
        return 0;
    }

    switch (report)
    {
        case RopScanReportDto scan:
            Console.WriteLine(scan.SummaryLine);
            if (scan.Error is not null) Console.Error.WriteLine("  error: " + scan.Error);
            foreach (var g in scan.Gadgets.Take(24))
                Console.WriteLine($"  {g.Address}  [{g.Kind}]  {g.Instruction}  ({g.BytesHex})");
            if (scan.GadgetCount > 24)
                Console.WriteLine($"  … {scan.GadgetCount - 24} more (use --json)");
            if (scan.CachePath is not null)
                Console.WriteLine($"  cache: {scan.CachePath}");
            return scan.Error is null && scan.GadgetCount > 0 ? 0 : 2;
        case RopSearchReportDto search:
            Console.WriteLine(search.SummaryLine);
            foreach (var g in search.Hits)
                Console.WriteLine($"  {g.Address}  [{g.Kind}]  {g.Instruction}");
            return search.Hits.Count > 0 ? 0 : 2;
        case RopSketchReportDto sketch:
            Console.WriteLine(sketch.SummaryLine);
            foreach (var c in sketch.Constraints)
                Console.WriteLine($"  constraint: {c}");
            foreach (var s in sketch.Steps)
            {
                var sym = s.Gadget.Symbol is null ? "" : $" @{s.Gadget.Symbol}";
                Console.WriteLine($"  [{s.Index}] {s.Role}: {s.Gadget.Address}{sym}  {s.Gadget.Instruction} — {s.Why}");
            }
            if (sketch.ModulesScanned is { Count: > 0 })
                Console.WriteLine("  modules: " + string.Join(", ", sketch.ModulesScanned.Select(Path.GetFileName)));
            if (sketch.OutputPath is not null)
                Console.WriteLine($"  wrote: {sketch.OutputPath}");
            return sketch.Error is null && sketch.Steps.Count > 0 ? 0 : 2;
        case RopBadCharReportDto badchars:
            Console.WriteLine(badchars.SummaryLine);
            foreach (var r in badchars.Reasons ?? [])
                Console.WriteLine($"  · {r}");
            if (!string.IsNullOrWhiteSpace(badchars.BadCharsHex))
                Console.WriteLine($"  --badchars \"{badchars.BadCharsHex}\"");
            if (badchars.OutputPath is not null)
                Console.WriteLine($"  wrote: {badchars.OutputPath}");
            return badchars.Error is null ? 0 : 2;
        case RopSidecarsDto side:
            Console.WriteLine(side.SummaryLine);
            if (side.ScreamWalkPath is not null) Console.WriteLine("  scream:   " + side.ScreamWalkPath);
            if (side.StackLensPath is not null) Console.WriteLine("  stack:    " + side.StackLensPath);
            if (side.RopPath is not null) Console.WriteLine("  rop:      " + side.RopPath);
            if (side.WalkPath is not null) Console.WriteLine("  windbg:   " + side.WalkPath);
            if (side.GdbWalkPath is not null) Console.WriteLine("  gdb:      " + side.GdbWalkPath);
            if (side.BadCharsPath is not null) Console.WriteLine("  badchars: " + side.BadCharsPath);
            if (side.LadderPath is not null) Console.WriteLine("  ladder:   " + side.LadderPath);
            if (side.GuidePath is not null) Console.WriteLine("  guide:    " + side.GuidePath);
            if (side.StackLens?.PrimaryControl is { } pc)
                Console.WriteLine($"  CONTROL:  {pc.Where}" + (pc.InputOffset is { } po ? $" @ {po}" : ""));
            else if (side.Walk?.ControlledOffset is { } off)
                Console.WriteLine($"  CONTROL:  {side.Walk.ControlledRegister ?? "IP"} @ {off}");
            else if (side.ScreamWalk?.ControlledOffset is { } soff)
                Console.WriteLine($"  CONTROL:  {side.ScreamWalk.ControlledRegister ?? "IP"} @ {soff}");
            if (side.Sketch?.Steps.Count > 0)
                Console.WriteLine($"  sketch:   {side.Sketch.Steps.Count} step(s) · {side.Sketch.Goal}");
            if (side.ScreamWalk is { } sw)
                Console.WriteLine($"  playbook: {sw.Steps.Count} step(s) · goal {sw.GoalResolved}");
            return 0;
        default:
            return 1;
    }
}

static int RunWindbg(string[] args)
{
    if (args.Length == 0 || args[0] is "-h" or "--help" or "help")
    {
        Console.WriteLine("""
            Usage:
              randall windbg scripts
              randall windbg walk -i <crash-guid> [--json]

            RandfuzzDbg — WinDbg Preview walk scripts + JSON export (docs/WINDBG_FUZZ_PKG.md).
            """);
        return 0;
    }

    var sub = args[0].ToLowerInvariant();
    if (sub is "scripts" or "script" or "help-scripts")
    {
        Console.Write(RandfuzzDbgWalk.FormatScriptHelp());
        return 0;
    }

    if (sub is "walk" or "export")
    {
        Guid? id = null;
        var json = false;
        for (var i = 1; i < args.Length; i++)
        {
            if (args[i] is "-h" or "--help" or "help")
            {
                Console.WriteLine("""
                    Usage:
                      randall windbg walk -i <crash-guid> [--json]

                    Write *_windbg_walk.json + RandfuzzDbg script hints for the crash dump.
                    """);
                return 0;
            }
            if (args[i] is "-i" or "--id" or "--crash" && i + 1 < args.Length
                && Guid.TryParse(args[i + 1], out var g))
            {
                id = g;
                i++;
            }
            else if (args[i] is "--json") json = true;
        }

        if (id is null)
        {
            Console.Error.WriteLine("Usage: randall windbg walk -i <crash-guid>");
            return 1;
        }

        var walk = RandfuzzDbgWalk.BuildForCrash(id.Value);
        if (json)
        {
            Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(walk, new System.Text.Json.JsonSerializerOptions
            {
                WriteIndented = true,
                PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase,
            }));
            return walk.Error is null ? 0 : 2;
        }

        Console.WriteLine(walk.SummaryLine);
        if (walk.WalkPath is not null) Console.WriteLine($"  walk: {walk.WalkPath}");
        if (walk.RopPath is not null) Console.WriteLine($"  rop:  {walk.RopPath}");
        if (walk.DumpPath is not null) Console.WriteLine($"  dump: {walk.DumpPath}");
        Console.WriteLine("  script:");
        foreach (var line in walk.ScriptLines.Take(12))
            Console.WriteLine("    " + line);
        return walk.Error is null ? 0 : 2;
    }

    Console.Error.WriteLine("Usage: randall windbg scripts|walk …");
    return 1;
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
    string? token = null;
    var allowOpen = false;
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
        else if (args[i] is "--token" && i + 1 < args.Length)
        {
            token = args[++i];
        }
        else if (args[i] is "--allow-open")
        {
            allowOpen = true;
        }
    }

    if (!string.IsNullOrWhiteSpace(token))
        Environment.SetEnvironmentVariable(LabAccess.EnvToken, token.Trim());

    if (LabAccess.RequiresTokenForBind(bind) && !LabAccess.IsConfigured && !allowOpen)
    {
        Console.Error.WriteLine(
            $"Refusing LAN bind ({bind}) without a lab token. Set --token SECRET, export {LabAccess.EnvToken}, or pass --allow-open (lab only). See docs/LAB_AGENT.md.");
        return 2;
    }

    var serverProject = FindServerProjectPath();
    if (serverProject is null)
    {
        Console.Error.WriteLine("Could not locate Randall.Server.csproj.");
        return 1;
    }

    var urls = $"http://{bind}:{port}";
    Console.WriteLine($"Starting Randfuzz {label} at {urls}");
    if (LabAccess.IsNonLoopbackBind(bind))
    {
        Console.WriteLine($"LAN clients: http://<this-machine-ip>:{port}");
        if (!LabAccess.IsConfigured)
            Console.WriteLine(
                $"WARN: --allow-open on {bind} — APIs are unauthenticated. Prefer --token (docs/LAB_AGENT.md).");
        else
            Console.WriteLine($"Lab access token: required ({LabAccess.EnvToken} set)");
    }
    else if (LabAccess.IsConfigured)
    {
        Console.WriteLine($"Lab access token: required ({LabAccess.EnvToken} set)");
    }

    var psi = new ProcessStartInfo
    {
        FileName = "dotnet",
        Arguments = $"run --project \"{serverProject}\" --urls {urls}",
        UseShellExecute = false,
    };
    // Child process must see the token.
    if (LabAccess.IsConfigured)
        psi.Environment[LabAccess.EnvToken] = LabAccess.ConfiguredToken!;

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
              randall case catalog [--category C] [--search Q]   Browse the fuzzing recipe catalog
              randall case catalog --categories                  List catalog categories + counts
              randall case catalog --instantiate <id> [--name p] Create a project from a recipe
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
            "catalog" => CaseCatalog(rest),
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

static int CaseCatalog(string[] args)
{
    string? category = null, search = null, instantiate = null, name = null;
    var local = true;
    var showCats = false;
    for (var i = 0; i < args.Length; i++)
    {
        switch (args[i])
        {
            case "--category" or "-c" when i + 1 < args.Length: category = args[++i]; break;
            case "--search" or "-s" when i + 1 < args.Length: search = args[++i]; break;
            case "--instantiate" or "--create" when i + 1 < args.Length: instantiate = args[++i]; break;
            case "--name" or "-n" when i + 1 < args.Length: name = args[++i]; break;
            case "--public": local = false; break;
            case "--categories": showCats = true; break;
        }
    }

    if (instantiate is not null)
    {
        var r = RecipeCatalog.Instantiate(instantiate, name, local);
        Console.WriteLine(r.Message);
        if (r.Path is not null) Console.WriteLine(r.Path);
        return r.Ok ? 0 : 1;
    }

    if (showCats)
    {
        Console.WriteLine($"Recipe catalog — {RecipeCatalog.Count} recipes across categories:");
        foreach (var cat in RecipeCatalog.Categories())
            Console.WriteLine($"  {cat} ({RecipeCatalog.List(cat).Count})");
        return 0;
    }

    var entries = RecipeCatalog.List(category, search);
    Console.WriteLine($"Recipe catalog ({entries.Count}/{RecipeCatalog.Count})" +
        (category is not null ? $" · category={category}" : "") + (search is not null ? $" · search={search}" : "") + ":");
    foreach (var e in entries)
        Console.WriteLine($"  {e.Id,-16} [{e.Kind,-4}] {e.Category,-18} {e.Name}  — {string.Join(",", e.Tags)}");
    Console.WriteLine();
    Console.WriteLine("Create a project:  randall case catalog --instantiate <id> [--name <proj>] [--public]");
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

static int RunRecorders(string[] args)
{
    if (args.Length == 0 || args[0] is "-h" or "--help" or "help")
    {
        Console.WriteLine("""
            Usage:
              randall recorders stop

            Stops orphaned host captures left behind after a hard kill / disconnect:
              Procmon (/Terminate), DebugView, ProcDump, WPR (-cancel), pktmon stop,
              tshark/dumpcap kill, plus the agent remote Procmon slot.

            Normal fuzz end and UI/CLI Stop already tear down armed recorders via FuzzEngine.
            Use this when GUI tools or WPR/pktmon/tshark are still running afterward.
            """);
        return 0;
    }

    var sub = args[0].ToLowerInvariant();
    if (sub is not ("stop" or "stop-all" or "stopall"))
    {
        Console.Error.WriteLine("Usage: randall recorders stop");
        return 1;
    }

    var result = RecordingTeardown.StopHostCaptures();
    Console.WriteLine(result.Message);
    foreach (var item in result.Items)
    {
        var path = string.IsNullOrWhiteSpace(item.Path) ? "" : $" → {item.Path}";
        Console.WriteLine($"  {item.Name}{path}: {item.Status}");
    }

    return result.Ok ? 0 : 1;
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

/// <summary>Silent progress sink for `stalk bench` — records the stalking signal (frontier novelty + edges).</summary>
sealed class StalkBenchSink : Randall.Infrastructure.IFuzzProgressSink
{
    public int NovelInputs { get; private set; }
    public int MaxEdges { get; private set; }

    public void OnStarted(string project, string kind) { }
    public void OnIteration(Randall.Infrastructure.FuzzIterationEvent e)
    {
        if (e.NewCoverage) NovelInputs++;
        if (e.CoverageEdgeTotal > MaxEdges) MaxEdges = e.CoverageEdgeTotal;
    }
    public void OnCompleted(Randall.Core.FuzzRunResult result) { }
    public void OnStopped(string reason) { }
    public void OnError(string message) { }
}
