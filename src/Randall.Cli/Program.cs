using System.Diagnostics;
using Randall.Contracts;

if (args.Length == 0 || args[0] is "-h" or "--help" or "help")
{
    PrintHelp();
    return 0;
}

return args[0].ToLowerInvariant() switch
{
    "legs" => PrintLegs(),
    "version" => PrintVersion(),
    "serve" => RunServe(args.Skip(1).ToArray()),
    "fuzz" => NotImplemented("fuzz"),
    "replay" => NotImplemented("replay"),
    "export" => NotImplemented("export"),
    _ => Unknown(args[0]),
};

static void PrintHelp()
{
    Console.WriteLine("""
        Randall — generation + coverage-guided fuzzing for Windows

        Usage:
          randall legs              List the eight legs (feature areas)
          randall serve [--port N]  Start web UI + API (default port 5000)
          randall fuzz -c project   Headless fuzz session (planned)
          randall replay <id>       Replay a saved crash input (planned)
          randall export <project>  Export portable project bundle (planned)
          randall version           Show version

        Docs: https://github.com/jinverar/randall/blob/main/docs/LEGS.md
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
    Console.WriteLine("Randall 0.1.0-alpha (scaffolding)");
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
        Console.Error.WriteLine("Could not locate Randall.Server.csproj. Run from the repo root or publish Randall.Server.");
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
