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
    "fuzz" => await RunFuzzAsync(args.Skip(1).ToArray()),
    "crashes" => ListCrashes(args.Skip(1).ToArray()),
    "replay" => ReplayCrash(args.Skip(1).ToArray()),
    "export" => NotImplemented("export"),
    _ => Unknown(args[0]),
};

static void PrintHelp()
{
    Console.WriteLine("""
        Randall — generation + coverage-guided fuzzing for Windows

        Usage:
          randall targets              List lab project profiles
          randall fuzz -c <project>    Fuzz vulnserver, notepad++, or cfpass
          randall fuzz -c <project> --dry-run
          randall crashes [-p name]    List saved crashes
          randall replay <crash.bin>   Re-send TCP payload or re-open file target
          randall serve [--port N]     Web UI + API
          randall legs                 Eight legs feature map
          randall version

        Lab projects (projects/*.yaml):
          vulnserver   TCP TRUN-style (classic vuln lab server)
          notepadpp    XML / text file parser (GUI)
          cfpass       Custom / strange binary formats

        Docs: https://github.com/jinverar/randall/blob/main/docs/TARGETS.md
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
    Console.WriteLine("Randall 0.2.0-alpha (lab targets)");
    return 0;
}

static int ListTargets(string[] args)
{
    var root = FindRepoRoot() ?? Directory.GetCurrentDirectory();
    var projectsDir = Path.Combine(root, "projects");
    foreach (var path in ProjectLoader.DiscoverProjects(projectsDir))
    {
        try
        {
            var p = ProjectLoader.Load(path);
            Console.WriteLine($"{p.Name,-12} [{p.Kind}] {p.Description}");
            Console.WriteLine($"             {path}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"{path} — error: {ex.Message}");
        }
    }
    return 0;
}

static async Task<int> RunFuzzAsync(string[] args)
{
    string? config = null;
    var dryRun = false;
    for (var i = 0; i < args.Length; i++)
    {
        if (args[i] is "-c" or "--config" && i + 1 < args.Length)
            config = args[++i];
        else if (args[i] is "--dry-run")
            dryRun = true;
    }

    if (config is null)
    {
        Console.Error.WriteLine("Usage: randall fuzz -c projects/vulnserver.yaml [--dry-run]");
        return 1;
    }

    var yamlPath = Path.GetFullPath(config);
    var project = ProjectLoader.Load(yamlPath);
    Console.WriteLine($"Fuzzing: {project.Name} ({project.Kind}) — {project.Description}");
    if (dryRun)
        Console.WriteLine("[dry-run mode]");

    var engine = new FuzzEngine();
    var result = await engine.RunAsync(project, yamlPath, dryRun);
    Console.WriteLine($"Done: {result.Iterations} iterations, {result.CrashesFound} crashes");
    return 0;
}

static int ListCrashes(string[] args)
{
    string? projectFilter = null;
    for (var i = 0; i < args.Length - 1; i++)
    {
        if (args[i] is "-p" or "--project")
            projectFilter = args[++i];
    }

    var root = FindRepoRoot() ?? Directory.GetCurrentDirectory();
    var store = new CrashStore(Path.Combine(root, "data", "crashes"));
    foreach (var c in store.List(projectFilter))
        Console.WriteLine($"{c.At:u} {c.Project} iter={c.Iteration} {c.Mutator} {c.InputPath}");
    return 0;
}

static int ReplayCrash(string[] args)
{
    if (args.Length == 0)
    {
        Console.Error.WriteLine("Usage: randall replay <path-to-crash.bin>");
        return 1;
    }
    var path = Path.GetFullPath(args[0]);
    if (!File.Exists(path))
    {
        Console.Error.WriteLine($"File not found: {path}");
        return 1;
    }
    Console.WriteLine($"Replay not fully wired — crash input saved at: {path}");
    Console.WriteLine("Re-run: randall fuzz -c projects/<target>.yaml and compare crash hash");
    return 0;
}

static int RunServe(string[] args)
{
    var port = 5000;
    for (var i = 0; i < args.Length - 1; i++)
    {
        if (args[i] is "--port" or "-p" && int.TryParse(args[i + 1], out var p))
            port = p;
    }

    var serverProject = FindServerProjectPath();
    if (serverProject is null)
    {
        Console.Error.WriteLine("Could not locate Randall.Server.csproj.");
        return 1;
    }

    Console.WriteLine($"Starting Randall web UI at http://localhost:{port}");
    var psi = new ProcessStartInfo
    {
        FileName = "dotnet",
        Arguments = $"run --project \"{serverProject}\" --urls http://localhost:{port}",
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

static string? FindRepoRoot()
{
    var dir = new DirectoryInfo(Directory.GetCurrentDirectory());
    while (dir is not null)
    {
        if (File.Exists(Path.Combine(dir.FullName, "Randall.sln")))
            return dir.FullName;
        dir = dir.Parent;
    }
    return null;
}

static int NotImplemented(string command)
{
    Console.Error.WriteLine($"{command} is not implemented yet — see docs/ARCHITECTURE.md");
    return 2;
}

static int Unknown(string command)
{
    Console.Error.WriteLine($"Unknown command: {command}");
    PrintHelp();
    return 1;
}
