using System.Globalization;
using System.Text;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Dynapstalker-faithful helper: one drcov <c>-dump_text</c> log → IDA IDC or Ghidra Python
/// that color-codes hit basic blocks (only paints still-uncolored items). PDF exercise args:
/// log, process name, output script, optional color.
/// </summary>
public static class DynapstalkerExport
{
    public static StalkExportResultDto ExportIdc(
        string drcovPath,
        string processName,
        string outputIdcPath,
        string? colorHex = null) =>
        Export(drcovPath, processName, outputIdcPath, "idc", colorHex);

    public static StalkExportResultDto ExportGhidra(
        string drcovPath,
        string processName,
        string outputPyPath,
        string? colorHex = null) =>
        Export(drcovPath, processName, outputPyPath, "ghidra", colorHex);

    public static StalkExportResultDto Export(
        string drcovPath,
        string processName,
        string outputPath,
        string format,
        string? colorHex = null)
    {
        if (string.IsNullOrWhiteSpace(drcovPath) || !File.Exists(drcovPath))
            throw new FileNotFoundException("drcov log not found", drcovPath);
        if (string.IsNullOrWhiteSpace(processName))
            throw new ArgumentException("process name required (e.g. savant.exe)", nameof(processName));
        if (string.IsNullOrWhiteSpace(outputPath))
            throw new ArgumentException("output path required", nameof(outputPath));

        var fmt = ResolveFormat(format, outputPath);
        var edges = DrcovParser.ParseEdges(drcovPath, processName);
        if (edges.Count == 0)
            throw new InvalidOperationException(
                $"No BB edges matched process '{processName}' in {drcovPath}. " +
                "Confirm -dump_text was used and the module table contains that name.");

        var outPath = Path.GetFullPath(outputPath);
        Directory.CreateDirectory(Path.GetDirectoryName(outPath) ?? ".");

        return fmt == "ghidra"
            ? WriteGhidra(drcovPath, processName, outPath, edges, colorHex)
            : WriteIdc(drcovPath, processName, outPath, edges, colorHex);
    }

    private static string ResolveFormat(string? format, string outputPath)
    {
        var fmt = (format ?? "").Trim().ToLowerInvariant();
        if (fmt is "ghidra" or "py" or "python")
            return "ghidra";
        if (fmt is "idc" or "ida")
            return "idc";
        var ext = Path.GetExtension(outputPath);
        if (ext.Equals(".py", StringComparison.OrdinalIgnoreCase))
            return "ghidra";
        return "idc";
    }

    private static StalkExportResultDto WriteIdc(
        string drcovPath,
        string processName,
        string outPath,
        IReadOnlyList<string> edges,
        string? colorHex)
    {
        var color = NormalizeIdaColor(colorHex);
        var sb = new StringBuilder();
        sb.AppendLine("// Randfuzz Dynapstalker export (PDF / PaiMei-style) — IDA Pro");
        sb.AppendLine($"// Source: {drcovPath}");
        sb.AppendLine($"// Process filter: {processName}");
        sb.AppendLine($"// Color (IDA BGR): {color}");
        sb.AppendLine($"// Blocks: {edges.Count}");
        sb.AppendLine("// Load oldest scripts first. Only recolors default/white items.");
        sb.AppendLine("// Addresses are module-relative RVAs from drcov; rebase in IDA if needed.");
        sb.AppendLine("static main() {");
        sb.AppendLine("  auto ea, cur;");
        foreach (var edge in edges.OrderBy(e => e, StringComparer.OrdinalIgnoreCase))
        {
            var addr = EdgeAddress(edge);
            if (addr is null) continue;
            sb.AppendLine($"  ea = {addr};");
            sb.AppendLine("  if (ea != BADADDR) {");
            sb.AppendLine("    cur = GetColor(ea, CIC_ITEM);");
            sb.AppendLine("    if (cur == 0xFFFFFFFF || cur == -1)");
            sb.AppendLine($"      SetColor(ea, CIC_ITEM, {color});");
            sb.AppendLine("  }");
        }

        sb.AppendLine("}");
        File.WriteAllText(outPath, sb.ToString());
        WriteReadme(Path.GetDirectoryName(outPath)!);
        return new StalkExportResultDto("idc", outPath, edges.Count, [outPath]);
    }

    private static StalkExportResultDto WriteGhidra(
        string drcovPath,
        string processName,
        string outPath,
        IReadOnlyList<string> edges,
        string? colorHex)
    {
        var (r, g, b) = HexToRgb(colorHex);
        // Filter edges to modules matching process name when module table is present
        var modules = DrcovParser.ParseModules(drcovPath);
        HashSet<string>? allowIds = null;
        if (modules.Count > 0)
        {
            allowIds = modules
                .Where(m =>
                    m.Path.Contains(processName, StringComparison.OrdinalIgnoreCase) ||
                    Path.GetFileName(m.Path).Equals(processName, StringComparison.OrdinalIgnoreCase))
                .Select(m => m.Id)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            if (allowIds.Count == 0)
                allowIds = null;
        }

        var filtered = allowIds is null
            ? edges
            : edges.Where(e => allowIds.Contains(e.Split(':')[0])).ToList();
        var blocks = GhidraScriptBuilder.BlocksFromEdges(filtered);
        var script = GhidraScriptBuilder.BuildColorScript(
            $"Dynapstalker Ghidra — {processName}",
            [new GhidraScriptBuilder.LayerSpec(processName, blocks, r, g, b)],
            notes: $"Source: {drcovPath}\nProcess filter: {processName}");
        File.WriteAllText(outPath, script);
        WriteReadme(Path.GetDirectoryName(outPath)!);
        GhidraScriptBuilder.WriteModulesSidecar(Path.GetDirectoryName(outPath)!, drcovPath);
        return new StalkExportResultDto("ghidra", outPath, filtered.Count, [outPath]);
    }

    private static void WriteReadme(string dir)
    {
        var readme = Path.Combine(dir, "README_DYNAPSTALKER.txt");
        File.WriteAllText(readme, """
            Dynapstalker → IDA / Ghidra (Randfuzz)
            ======================================
            PDF exercise mapping:
              1. drrun -t drcov -dump_text -- <target>     (baseline, then fuzzed)
              2a. IDA:    randall stalk dynapstalker <log> <exe> out.idc --color 0x00ffff
              2b. Ghidra: randall stalk dynapstalker <log> <exe> out.py --format ghidra --color 0x00ffff
              3. Load OLDEST script first (yellow/cyan baseline), then green fuzzed.
              4. Scripts only paint still-uncolored items. Remaining plain = missed.
              5. Review missed near string/memcpy / error paths → revise fuzzer → remeasure.

            Ghidra tip: addresses are imageBase + drcov RVA. Open the matching module binary.
            Then: randall stalk missed -p <project>
            """);
    }

    private static string NormalizeIdaColor(string? colorHex)
    {
        if (string.IsNullOrWhiteSpace(colorHex))
            return "0x00FFFF";
        var hex = colorHex.Trim();
        if (!hex.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            hex = "0x" + hex;
        return hex;
    }

    private static (int R, int G, int B) HexToRgb(string? colorHex)
    {
        // Accept IDA BGR (0x00FFFF yellow) or RGB; default cyan/yellow-ish.
        var hex = (colorHex ?? "0x00FFFF").Trim();
        if (hex.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            hex = hex[2..];
        if (!uint.TryParse(hex, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var bgr))
            return (255, 255, 0);
        // Treat as IDA BGR (same as stalk layer colors)
        var b = (int)((bgr >> 16) & 0xFF);
        var g = (int)((bgr >> 8) & 0xFF);
        var r = (int)(bgr & 0xFF);
        return (r, g, b);
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
        return long.TryParse(s, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var v) ? v : null;
    }
}
