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
            echo Randfuzz portable lab
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
    /// <summary>
    /// First-class Ghidra triage pack: real ColorizingService script + edges + modules.
    /// Dragon Dance notes explain binary-drcov (optional); Randfuzz primary path is our script.
    /// </summary>
    public static void WriteArtifacts(
        string exportDir,
        TriageBundleDto bundle,
        IReadOnlyList<string>? edges = null,
        IReadOnlyList<string>? baselineEdges = null,
        long? goToRva = null,
        string? divergeEdge = null)
    {
        Directory.CreateDirectory(exportDir);
        var edgeList = edges?.ToList() ?? [];
        var edgesPath = Path.Combine(exportDir, "coverage_edges.txt");
        File.WriteAllLines(edgesPath, edgeList);

        if (!string.IsNullOrWhiteSpace(bundle.DrcovPath) && File.Exists(bundle.DrcovPath))
            GhidraScriptBuilder.WriteModulesSidecar(exportDir, bundle.DrcovPath);

        var baseline = baselineEdges?.ToHashSet(StringComparer.OrdinalIgnoreCase) ?? [];
        var shared = edgeList.Where(baseline.Contains).ToList();
        var novel = edgeList.Where(e => !baseline.Contains(e)).ToList();

        var layers = new List<GhidraScriptBuilder.LayerSpec>();
        if (shared.Count > 0)
        {
            var (r, g, b) = GhidraScriptBuilder.BgrToRgb("0x00FFFF"); // baseline cyan
            layers.Add(new("baseline-shared", GhidraScriptBuilder.BlocksFromEdges(shared), r, g, b));
        }

        if (novel.Count > 0)
        {
            var (r, g, b) = GhidraScriptBuilder.BgrToRgb("0x0000FF"); // crash-path / novel red-ish in BGR→RGB
            layers.Add(new("crash-novel", GhidraScriptBuilder.BlocksFromEdges(novel), r, g, b));
        }
        else if (edgeList.Count > 0)
        {
            var (r, g, b) = GhidraScriptBuilder.BgrToRgb("0x00FF00");
            layers.Add(new("crash-coverage", GhidraScriptBuilder.BlocksFromEdges(edgeList), r, g, b));
        }

        var notes =
            $"Crash {bundle.CrashId} · project {bundle.Project}\n" +
            $"Edges {edgeList.Count} · shared-with-baseline {shared.Count} · novel {novel.Count}\n" +
            (divergeEdge is null ? "No diverge edge computed." : $"Focus edge: {divergeEdge}");

        var script = GhidraScriptBuilder.BuildColorScript(
            "Randfuzz crash triage → Ghidra",
            layers,
            goToRva,
            notes);
        File.WriteAllText(Path.Combine(exportDir, "ghidra_import.py"), script);

        // Also drop a copy of the generic importer for offline re-runs against coverage_edges.txt
        var generic = Path.Combine(CrashCatalog.FindRepoRoot() ?? exportDir, "tools", "ghidra", "RandfuzzImportEdges.py");
        if (File.Exists(generic))
            File.Copy(generic, Path.Combine(exportDir, "RandfuzzImportEdges.py"), overwrite: true);

        var dd = $"""
            Randfuzz Ghidra stalk (primary) + Dragon Dance (optional)
            ========================================================
            Crash ID: {bundle.CrashId}
            Project:  {bundle.Project}
            Focus RVA: {(goToRva is null ? "(none)" : $"0x{goToRva:x}")}
            Diverge edge: {divergeEdge ?? "(none)"}

            Files:
              crash_input.bin      — reproducer
              sample.drcov.log     — DynamoRIO TEXT coverage (-dump_text) when available
              coverage_edges.txt   — moduleId:0xstart:size
              modules.txt          — drcov module table (id → path)
              ghidra_import.py     — FIRST-CLASS Randfuzz Script Manager importer (paints BBs)
              RandfuzzImportEdges.py — generic edges importer (if shipped from tools/ghidra)

            === Primary path (Randfuzz → Ghidra) ===
              1. Open the crashing module binary in Ghidra CodeBrowser; finish analysis
              2. Window → Script Manager → run ghidra_import.py
              3. Cyan ≈ shared with baseline; red/novel ≈ crash-only path; plain ≈ missed
              4. Script jumps to focus RVA when known
              5. Also: randall stalk missed -p {bundle.Project}

            === Optional: Dragon Dance ===
              Dragon Dance imports BINARY drcov (drrun -t drcov WITHOUT -dump_text).
              Randfuzz fuzzing uses -dump_text so our parser + Ghidra scripts work.
              For Dragon Dance:
                drrun -t drcov -logdir OUT -- <target> <args>
                Install Dragon Dance extension → import the *.proc.log binary file
              Do NOT expect sample.drcov.log (text) to import cleanly into Dragon Dance.

            Docs: docs/HOWTO_STALK_IDA_GHIDRA.md · docs/GHIDRA_INTEGRATION.md
            """;
        File.WriteAllText(Path.Combine(exportDir, "DRAGON_DANCE.txt"), dd);
        File.WriteAllText(Path.Combine(exportDir, "GHIDRA_README.txt"), dd);
    }
}
