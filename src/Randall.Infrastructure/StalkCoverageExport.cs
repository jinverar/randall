using System.Text;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>Dynapstalker-style IDA IDC + Ghidra color export from layered stalk campaigns.</summary>
public static class StalkCoverageExport
{
    public static StalkExportResultDto Export(StalkExportRequest request, string? repoRoot = null)
    {
        if (string.IsNullOrWhiteSpace(request.Project))
            throw new ArgumentException("project required");

        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var layers = StalkCampaignStore.ListLayers(request.Project, repoRoot)
            .Where(l => request.LayerIds.Count == 0 || request.LayerIds.Contains(l.Id, StringComparer.OrdinalIgnoreCase))
            .OrderBy(l => l.CreatedAt)
            .ToList();

        if (layers.Count == 0)
            throw new InvalidOperationException("No stalk layers to export — record a baseline first.");

        var outDir = string.IsNullOrWhiteSpace(request.OutputDir)
            ? Path.Combine(StalkCampaignStore.ProjectDir(request.Project, repoRoot), "export")
            : Path.GetFullPath(request.OutputDir);
        Directory.CreateDirectory(outDir);

        var format = (request.Format ?? "idc").Trim().ToLowerInvariant();
        return format switch
        {
            "ghidra" => ExportGhidra(request.Project, layers, outDir, repoRoot),
            "edges" => ExportEdges(request.Project, layers, outDir, repoRoot),
            _ => ExportIdc(request.Project, layers, outDir, repoRoot),
        };
    }

    private static StalkExportResultDto ExportIdc(
        string project,
        IReadOnlyList<StalkLayerDto> layers,
        string outDir,
        string repoRoot)
    {
        var files = new List<string>();
        var total = 0;
        // Oldest first — Dynapstalker: only recolor default/white blocks
        foreach (var layer in layers)
        {
            var edges = StalkCampaignStore.LoadEdges(project, layer.Id, repoRoot);
            total += edges.Count;
            var path = Path.Combine(outDir, $"{Sanitize(project)}_{Sanitize(layer.Tag)}_{layer.Id}.idc");
            var sb = new StringBuilder();
            sb.AppendLine("// Randfuzz stalk export — Dynapstalker-style IDC");
            sb.AppendLine($"// Project: {project}");
            sb.AppendLine($"// Layer: {layer.Tag} — {layer.Label}");
            sb.AppendLine($"// Color (IDA BGR hex): {layer.ColorHex}");
            sb.AppendLine($"// Blocks: {edges.Count}");
            sb.AppendLine("static main() {");
            sb.AppendLine("  auto ea, cur;");
            var color = ParseIdaColor(layer.ColorHex);
            foreach (var edge in edges.OrderBy(e => e))
            {
                var addr = EdgeAddress(edge);
                if (addr is null) continue;
                // Dynapstalker: only recolor default/white so earlier layers keep their color.
                sb.AppendLine($"  ea = {addr};");
                sb.AppendLine("  if (ea != BADADDR) {");
                sb.AppendLine("    cur = GetColor(ea, CIC_ITEM);");
                sb.AppendLine("    if (cur == 0xFFFFFFFF || cur == -1)");
                sb.AppendLine($"      SetColor(ea, CIC_ITEM, {color});");
                sb.AppendLine("  }");
            }

            sb.AppendLine("}");
            File.WriteAllText(path, sb.ToString());
            files.Add(path);
        }

        var readme = Path.Combine(outDir, "README_IDA.txt");
        File.WriteAllText(readme, """
            Randfuzz → IDA Pro color import (Dynapstalker workflow)
            =======================================================
            1. Open the target binary in IDA and wait for auto-analysis.
            2. File → Script file… — load the OLDEST *.idc first (baseline / yellow).
            3. Load later layers in order (fuzzed / green, fuzzier, crash).
            4. Scripts only paint still-white items — baseline yellow stays yellow.
            5. Remaining WHITE blocks = missed code (PDF lesson). Review those for
               string/memcpy / error paths, then revise the fuzzer.
            6. Jump (G) to interesting PCs from Stalking bugs / missed report.

            Colors are IDA BGR integers (e.g. 0x00FFFF ≈ yellow/cyan baseline,
            0x00FF00 ≈ green fuzzed — Randfuzz default layer colors).

            One-shot from a raw drcov log (PDF exercise):
              randall stalk dynapstalker drcov.log savant.exe out.idc --color 0x00ffff
            """);
        files.Add(readme);
        return new StalkExportResultDto("idc", outDir, total, files);
    }

    private static StalkExportResultDto ExportGhidra(
        string project,
        IReadOnlyList<StalkLayerDto> layers,
        string outDir,
        string repoRoot)
    {
        var files = new List<string>();
        var total = 0;
        var scriptPath = Path.Combine(outDir, $"{Sanitize(project)}_stalk_layers.py");
        var layerSpecs = new List<GhidraScriptBuilder.LayerSpec>();
        foreach (var layer in layers)
        {
            var edges = StalkCampaignStore.LoadEdges(project, layer.Id, repoRoot);
            total += edges.Count;
            var (r, g, b) = HexToRgb(layer.ColorHex);
            layerSpecs.Add(new(
                $"{layer.Tag}:{layer.Label}",
                GhidraScriptBuilder.BlocksFromEdges(edges),
                r, g, b));
        }

        // Prefer module table from newest text trace when present
        IReadOnlyList<DrcovModuleRow> modules = [];
        var corpusDir = Path.Combine(repoRoot, "data", "corpus", project);
        var textTraces = Path.Combine(corpusDir, "traces");
        if (Directory.Exists(textTraces))
        {
            var latest = Directory.EnumerateFiles(textTraces, "*.log")
                .Select(p => new FileInfo(p))
                .Where(f => f.Exists && f.Length > 0)
                .OrderByDescending(f => f.LastWriteTimeUtc)
                .Select(f => f.FullName)
                .FirstOrDefault();
            if (latest is not null)
                modules = DrcovParser.ParseModules(latest);
        }

        if (modules.Count > 0)
        {
            GhidraScriptBuilder.WriteModulesSidecar(outDir, modules);
            files.Add(Path.Combine(outDir, "modules.txt"));
        }

        var script = GhidraScriptBuilder.BuildColorScript(
            $"Randfuzz stalk layers — {project}",
            layerSpecs,
            notes: "Oldest layer first. Plain blocks ≈ missed. See docs/GHIDRA_INTEGRATION.md",
            modules: modules);
        File.WriteAllText(scriptPath, script);
        files.Add(scriptPath);

        var binaryCopied = BinaryDrcovCapture.CopySidecarsInto(corpusDir, outDir);
        foreach (var b in binaryCopied)
            files.Add(b);

        var readme = Path.Combine(outDir, "README_GHIDRA.txt");
        File.WriteAllText(readme, $$"""
            Randfuzz → Ghidra (first-class integration)
            ===========================================
            1. Import/open the target binary; finish analysis.
            2. Window → Script Manager → Run *_stalk_layers.py
            3. Oldest layer paints first; later layers only fill still-uncolored BBs.
            4. Plain / uncolored ≈ missed (Dynapstalker lesson).
            5. Crash packs: randall export -i <guid> → ghidra_import.py (novel vs baseline).
            6. Installable scripts: tools/ghidra/ (Script Manager → assign keybinding).
            7. Dragon Dance (optional): BINARY drcov only (no -dump_text).
               Enable fuzz.captureBinaryDrcov or: randall stalk capture-binary -p {{project}}
               Sidecars in this pack: {{(binaryCopied.Count == 0 ? "(none — run capture-binary)" : string.Join(", ", binaryCopied.Select(Path.GetFileName)))}}
               See docs/GHIDRA_INTEGRATION.md
            """);
        files.Add(readme);

        var ddNote = Path.Combine(outDir, "DRAGON_DANCE.txt");
        File.WriteAllText(ddNote, $$"""
            Dragon Dance (optional) — binary drcov only
            ===========================================
            Randfuzz primary path: *_stalk_layers.py (text edges / Script Manager).
            Dragon Dance wants: drrun -t drcov WITHOUT -dump_text → *.proc.log

            Auto-capture: fuzz.captureBinaryDrcov: true  →  data/corpus/{{project}}/traces-binary/
            One-shot:     randall stalk capture-binary -p {{project}} [-i seed.bin]
            Packed here:  {{(binaryCopied.Count == 0 ? "(none)" : string.Join(", ", binaryCopied.Select(Path.GetFileName)))}}

            Do NOT import sample.drcov.log / text stalk logs into Dragon Dance.
            """);
        files.Add(ddNote);

        // Bundle generic importers alongside the export for offline labs
        var tools = Path.Combine(repoRoot, "tools", "ghidra");
        foreach (var name in new[] { "RandfuzzImportEdges.py", "RandfuzzImportLayers.py" })
        {
            var src = Path.Combine(tools, name);
            if (!File.Exists(src)) continue;
            var dest = Path.Combine(outDir, name);
            File.Copy(src, dest, overwrite: true);
            files.Add(dest);
        }

        return new StalkExportResultDto("ghidra", outDir, total, files);
    }

    private static StalkExportResultDto ExportEdges(
        string project,
        IReadOnlyList<StalkLayerDto> layers,
        string outDir,
        string repoRoot)
    {
        var files = new List<string>();
        var total = 0;
        foreach (var layer in layers)
        {
            var edges = StalkCampaignStore.LoadEdges(project, layer.Id, repoRoot);
            total += edges.Count;
            var path = Path.Combine(outDir, $"{Sanitize(project)}_{Sanitize(layer.Tag)}_{layer.Id}.edges.txt");
            File.WriteAllLines(path, edges.OrderBy(e => e));
            files.Add(path);
        }

        return new StalkExportResultDto("edges", outDir, total, files);
    }

    private static string? EdgeAddress(string edge)
    {
        var parts = edge.Split(':');
        if (parts.Length < 2) return null;
        var addr = parts[1].Trim();
        if (!addr.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            addr = "0x" + addr;
        return addr;
    }

    private static long? EdgeRvaLong(string edge)
    {
        var addr = EdgeAddress(edge);
        if (addr is null) return null;
        var s = addr.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? addr[2..] : addr;
        return long.TryParse(s, System.Globalization.NumberStyles.HexNumber,
            System.Globalization.CultureInfo.InvariantCulture, out var v)
            ? v
            : null;
    }

    private static string ParseIdaColor(string colorHex)
    {
        var hex = colorHex.Trim();
        if (hex.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            return hex;
        return "0x" + hex;
    }

    private static (int R, int G, int B) HexToRgb(string colorHex)
    {
        // Stored as IDA BGR; convert to RGB for Ghidra/Java Color
        var hex = colorHex.Trim();
        if (hex.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            hex = hex[2..];
        if (!uint.TryParse(hex, System.Globalization.NumberStyles.HexNumber, null, out var bgr))
            return (0, 255, 255);
        var b = (int)((bgr >> 16) & 0xFF);
        var g = (int)((bgr >> 8) & 0xFF);
        var r = (int)(bgr & 0xFF);
        return (r, g, b);
    }

    private static string Sanitize(string name)
    {
        foreach (var c in Path.GetInvalidFileNameChars())
            name = name.Replace(c, '_');
        return name.Replace(' ', '_');
    }
}
