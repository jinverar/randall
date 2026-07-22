using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>Leg 8 — Pack: build a portable standalone folder for air-gapped lab VMs.</summary>
public static class PortablePacker
{
    /// <summary>
    /// Publish self-contained CLI + server into <paramref name="outputDir"/>.
    /// Default RID follows the host OS (win-x64 / linux-x64 / osx-*). Override with <paramref name="rid"/>.
    /// </summary>
    public static async Task<PackResultDto> PackAsync(
        string repoRoot,
        string outputDir,
        string? rid = null,
        CancellationToken cancellationToken = default)
    {
        outputDir = Path.GetFullPath(outputDir);
        Directory.CreateDirectory(outputDir);

        var cliProject = Path.Combine(repoRoot, "src", "Randall.Cli", "Randall.Cli.csproj");
        var serverProject = Path.Combine(repoRoot, "src", "Randall.Server", "Randall.Server.csproj");
        if (!File.Exists(cliProject))
            throw new FileNotFoundException("Randall.Cli.csproj not found", cliProject);

        rid ??= DefaultRid();
        var cliOut = Path.Combine(outputDir, "cli");
        var serverOut = Path.Combine(outputDir, "server");
        Directory.CreateDirectory(cliOut);
        Directory.CreateDirectory(serverOut);

        await RunPublishAsync(cliProject, cliOut, rid, cancellationToken);
        await RunPublishAsync(serverProject, serverOut, rid, cancellationToken);

        var included = new List<string>();
        CopyTree(Path.Combine(repoRoot, "projects"), Path.Combine(outputDir, "projects"), included);
        CopyTree(Path.Combine(repoRoot, "plugins"), Path.Combine(outputDir, "plugins"), included, optional: true);
        CopyTree(Path.Combine(repoRoot, "campaigns"), Path.Combine(outputDir, "campaigns"), included, optional: true);
        CopyTree(Path.Combine(repoRoot, "docs"), Path.Combine(outputDir, "docs"), included, optional: true);
        CopyFile(Path.Combine(repoRoot, "README.md"), Path.Combine(outputDir, "README.md"), included);
        CopyFile(Path.Combine(repoRoot, "docs", "assets", "randall.png"), Path.Combine(outputDir, "randall.png"), included, optional: true);
        CopyFile(Path.Combine(repoRoot, "docs", "RELEASE.md"), Path.Combine(outputDir, "RELEASE.md"), included, optional: true);

        Directory.CreateDirectory(Path.Combine(outputDir, "data", "corpus"));
        Directory.CreateDirectory(Path.Combine(outputDir, "data", "crashes"));
        Directory.CreateDirectory(Path.Combine(outputDir, "targets"));

        var isWindows = rid.StartsWith("win", StringComparison.OrdinalIgnoreCase);
        if (isWindows)
        {
            var startCmd = """
                @echo off
                echo Randfuzz portable lab
                echo   fuzz:   cli\Randall.Cli.exe fuzz -c projects\file-text.yaml
                echo   fuzz:   cli\Randall.Cli.exe fuzz -c projects\reeldeck.yaml
                echo   serve:  server\Randall.Server.exe --urls http://localhost:5000
                echo   proxy:  cli\Randall.Cli.exe proxy --listen 9998 --target 127.0.0.1:9999
                echo Build lab targets on this box first (scripts\build-all-lab-targets.ps1).
                """;
            await File.WriteAllTextAsync(Path.Combine(outputDir, "start.cmd"), startCmd, cancellationToken);
        }
        else
        {
            var startSh =
                "#!/usr/bin/env bash\n" +
                "set -euo pipefail\n" +
                $"echo \"Randfuzz portable lab ({rid})\"\n" +
                "echo \"  fuzz:  ./cli/Randall.Cli fuzz -c projects/file-text.yaml\"\n" +
                "echo \"  fuzz:  ./cli/Randall.Cli fuzz -c projects/reeldeck.yaml\"\n" +
                "echo \"  serve: ./server/Randall.Server --urls http://127.0.0.1:5000\"\n" +
                "echo \"Build lab targets: scripts/build-lab-targets.sh && scripts/build-file-text.sh\"\n";
            var shPath = Path.Combine(outputDir, "start.sh");
            await File.WriteAllTextAsync(shPath, startSh, cancellationToken);
            try
            {
#pragma warning disable CA1416 // Unix-only mode bits; guarded by non-Windows pack path
                File.SetUnixFileMode(shPath,
                    UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute |
                    UnixFileMode.GroupRead | UnixFileMode.GroupExecute |
                    UnixFileMode.OtherRead | UnixFileMode.OtherExecute);
#pragma warning restore CA1416
            }
            catch
            {
                /* Windows FS */
            }
        }

        var size = Directory.EnumerateFiles(outputDir, "*", SearchOption.AllDirectories)
            .Sum(f => new FileInfo(f).Length);

        return new PackResultDto(outputDir, size, included.ToArray());
    }

    public static string DefaultRid()
    {
        if (OperatingSystem.IsWindows())
            return "win-x64";
        if (OperatingSystem.IsMacOS())
            return RuntimeInformation.OSArchitecture == Architecture.Arm64 ? "osx-arm64" : "osx-x64";
        return RuntimeInformation.OSArchitecture == Architecture.Arm64 ? "linux-arm64" : "linux-x64";
    }

    private static async Task RunPublishAsync(string csproj, string outDir, string rid, CancellationToken cancellationToken)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "dotnet",
            Arguments = $"publish \"{csproj}\" -c Release -r {rid} --self-contained true " +
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

        IReadOnlyList<DrcovModuleRow> modules = [];
        if (!string.IsNullOrWhiteSpace(bundle.DrcovPath) && File.Exists(bundle.DrcovPath))
        {
            modules = DrcovParser.ParseModules(bundle.DrcovPath);
            GhidraScriptBuilder.WriteModulesSidecar(exportDir, modules);
        }

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

        var bookmarkRvas = GhidraScriptBuilder.BlocksFromEdges(novel.Take(16))
            .Select(b => b.Rva)
            .Distinct()
            .ToList();

        var script = GhidraScriptBuilder.BuildColorScript(
            "Randfuzz crash triage → Ghidra",
            layers,
            goToRva,
            notes,
            modules,
            bookmarkRvas);
        File.WriteAllText(Path.Combine(exportDir, "ghidra_import.py"), script);

        // Also drop a copy of the generic importer for offline re-runs against coverage_edges.txt
        var toolsDir = Path.Combine(CrashCatalog.FindRepoRoot() ?? exportDir, "tools", "ghidra");
        foreach (var name in new[] { "RandfuzzImportEdges.py", "RandfuzzImportLayers.py" })
        {
            var src = Path.Combine(toolsDir, name);
            if (File.Exists(src))
                File.Copy(src, Path.Combine(exportDir, name), overwrite: true);
        }

        var binaryLogs = Directory.Exists(exportDir)
            ? Directory.GetFiles(exportDir, "binary_*.log").Select(Path.GetFileName).Where(n => n is not null).ToList()
            : [];

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
              binary_*.log         — BINARY drcov for Dragon Dance (when captureBinaryDrcov / capture-binary)
              coverage_edges.txt   — moduleId:0xstart:size
              modules.txt          — id → path → start → end (preferred load addresses)
              ghidra_import.py     — FIRST-CLASS Randfuzz Script Manager importer (paints BBs + bookmarks)
              RandfuzzImportEdges.py — generic edges importer (if shipped from tools/ghidra)

            === Primary path (Randfuzz → Ghidra) ===
              1. Open the crashing module binary in Ghidra CodeBrowser; finish analysis
              2. Window → Script Manager → run ghidra_import.py
              3. Cyan ≈ shared with baseline; red/novel ≈ crash-only path; plain ≈ missed
              4. Script bookmarks + jumps to focus RVA when known
              5. Also: randall stalk missed -p {bundle.Project}

            === Optional: Dragon Dance ===
              Dragon Dance imports BINARY drcov (drrun -t drcov WITHOUT -dump_text).
              Randfuzz fuzzing uses -dump_text so our parser + Ghidra scripts work.
              Enable YAML fuzz.captureBinaryDrcov: true (file targets) or:
                randall stalk capture-binary -p {bundle.Project} -i crash_input.bin
              Then import binary_*.log / corpus/traces-binary/*.log in the Dragon Dance window.
              Do NOT expect sample.drcov.log (text) to import cleanly into Dragon Dance.
              Bundled binary logs here: {(binaryLogs.Count == 0 ? "(none yet)" : string.Join(", ", binaryLogs!))}

            Docs: docs/HOWTO_STALK_IDA_GHIDRA.md · docs/GHIDRA_INTEGRATION.md
            """;
        File.WriteAllText(Path.Combine(exportDir, "DRAGON_DANCE.txt"), dd);
        File.WriteAllText(Path.Combine(exportDir, "GHIDRA_README.txt"), dd);
    }
}
