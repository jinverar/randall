using System.Diagnostics;
using System.Text;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>Leg 8 — Pack: build a portable standalone folder for air-gapped lab VMs.</summary>
public static class PortablePacker
{
    public static async Task<PackResultDto> PackAsync(string repoRoot, string outputDir, CancellationToken cancellationToken = default)
    {
        outputDir = Path.GetFullPath(outputDir);
        Directory.CreateDirectory(outputDir);

        var cliProject = Path.Combine(repoRoot, "src", "Randall.Cli", "Randall.Cli.csproj");
        var serverProject = Path.Combine(repoRoot, "src", "Randall.Server", "Randall.Server.csproj");
        if (!File.Exists(cliProject))
            throw new FileNotFoundException("Randall.Cli.csproj not found", cliProject);

        var cliOut = Path.Combine(outputDir, "cli");
        var serverOut = Path.Combine(outputDir, "server");
        Directory.CreateDirectory(cliOut);
        Directory.CreateDirectory(serverOut);

        await RunPublishAsync(cliProject, cliOut, cancellationToken);
        await RunPublishAsync(serverProject, serverOut, cancellationToken);

        var included = new List<string>();
        CopyTree(Path.Combine(repoRoot, "projects"), Path.Combine(outputDir, "projects"), included);
        CopyTree(Path.Combine(repoRoot, "plugins"), Path.Combine(outputDir, "plugins"), included, optional: true);
        CopyTree(Path.Combine(repoRoot, "campaigns"), Path.Combine(outputDir, "campaigns"), included, optional: true);
        CopyTree(Path.Combine(repoRoot, "docs"), Path.Combine(outputDir, "docs"), included, optional: true);
        CopyFile(Path.Combine(repoRoot, "README.md"), Path.Combine(outputDir, "README.md"), included);
        CopyFile(Path.Combine(repoRoot, "docs", "assets", "randall.png"), Path.Combine(outputDir, "randall.png"), included, optional: true);

        Directory.CreateDirectory(Path.Combine(outputDir, "data", "corpus"));
        Directory.CreateDirectory(Path.Combine(outputDir, "data", "crashes"));
        Directory.CreateDirectory(Path.Combine(outputDir, "targets"));

        var startCmd = """
            @echo off
            echo Randall portable lab
            echo   fuzz:   cli\Randall.Cli.exe fuzz -c projects\vulnserver.yaml
            echo   serve:  server\Randall.Server.exe --urls http://localhost:5000
            echo   proxy:  cli\Randall.Cli.exe proxy --listen 9998 --target 127.0.0.1:9999
            """;
        await File.WriteAllTextAsync(Path.Combine(outputDir, "start.cmd"), startCmd, cancellationToken);

        var size = Directory.EnumerateFiles(outputDir, "*", SearchOption.AllDirectories)
            .Sum(f => new FileInfo(f).Length);

        return new PackResultDto(outputDir, size, included.ToArray());
    }

    private static async Task RunPublishAsync(string csproj, string outDir, CancellationToken cancellationToken)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "dotnet",
            Arguments = $"publish \"{csproj}\" -c Release -r win-x64 --self-contained true " +
                        $"-p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o \"{outDir}\"",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        using var process = Process.Start(psi)
            ?? throw new InvalidOperationException("Failed to start dotnet publish");
        await process.WaitForExitAsync(cancellationToken);
        if (process.ExitCode != 0)
        {
            var err = await process.StandardError.ReadToEndAsync(cancellationToken);
            throw new InvalidOperationException($"dotnet publish failed: {err}");
        }
    }

    private static void CopyTree(string source, string dest, List<string> included, bool optional = false)
    {
        if (!Directory.Exists(source))
        {
            if (!optional)
                Directory.CreateDirectory(dest);
            return;
        }
        Directory.CreateDirectory(dest);
        foreach (var file in Directory.EnumerateFiles(source, "*", SearchOption.AllDirectories))
        {
            var rel = Path.GetRelativePath(source, file);
            var target = Path.Combine(dest, rel);
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            File.Copy(file, target, overwrite: true);
            included.Add(rel.Replace('\\', '/'));
        }
    }

    private static void CopyFile(string source, string dest, List<string> included, bool optional = false)
    {
        if (!File.Exists(source))
        {
            if (!optional)
                throw new FileNotFoundException(source);
            return;
        }
        Directory.CreateDirectory(Path.GetDirectoryName(dest)!);
        File.Copy(source, dest, overwrite: true);
        included.Add(Path.GetFileName(dest));
    }
}

public static class GhidraExporter
{
    public static void WriteArtifacts(string exportDir, TriageBundleDto bundle, IReadOnlyList<string>? edges = null)
    {
        var edgesPath = Path.Combine(exportDir, "coverage_edges.txt");
        if (edges is not null)
            File.WriteAllLines(edgesPath, edges);

        var script = """
            # Randall → Ghidra triage helper
            # Run in Ghidra Script Manager (Python)
            #
            # 1. Import crash_input.bin as a binary (or attach as a file artifact)
            # 2. Load coverage_edges.txt — each line is module:pc:size from DynamoRIO drcov
            # 3. Mark addresses in coverage_edges.txt as visited in your Dragon Dance workflow
            #
            # Dragon Dance: map drcov basic blocks to Ghidra addresses using the module load base.
            
            print("Randall triage bundle loaded.")
            print("Files: crash_input.bin, sample.drcov.log, coverage_edges.txt")
            """;
        File.WriteAllText(Path.Combine(exportDir, "ghidra_import.py"), script);

        var dd = $"""
            Dragon Dance / Ghidra workflow
            ==============================
            Crash ID: {bundle.CrashId}
            Project:  {bundle.Project}
            
            Files in this bundle:
              crash_input.bin     — reproducer input (send via replay or file open)
              sample.drcov.log    — DynamoRIO text coverage trace
              coverage_edges.txt  — parsed basic block keys (module:pc:size)
              ghidra_import.py    — Ghidra script stub
            
            Steps:
              1. Replay crash_input.bin against the target to confirm
              2. Import sample.drcov.log into Dragon Dance or parse coverage_edges.txt
              3. In Ghidra, run ghidra_import.py and navigate to first diverge block
            """;
        File.WriteAllText(Path.Combine(exportDir, "DRAGON_DANCE.txt"), dd);
    }
}
