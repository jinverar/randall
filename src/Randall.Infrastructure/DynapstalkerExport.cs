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
        var sb = new StringBuilder();
        sb.AppendLine("# Randfuzz Dynapstalker export — Ghidra Python (Jython)");
        sb.AppendLine($"# Source: {drcovPath}");
        sb.AppendLine($"# Process filter: {processName}");
        sb.AppendLine($"# Color RGB: ({r}, {g}, {b})");
        sb.AppendLine($"# Blocks: {edges.Count}");
        sb.AppendLine("# Window → Script Manager → Run. Only paints addresses with no background yet.");
        sb.AppendLine("# drcov BB starts are module RVAs → added to the program image base.");
        sb.AppendLine("from ghidra.app.plugin.core.colorizer import ColorizingService");
        sb.AppendLine("from ghidra.program.model.address import AddressSet");
        sb.AppendLine("from java.awt import Color");
        sb.AppendLine();
        sb.AppendLine("service = state.getTool().getService(ColorizingService)");
        sb.AppendLine("if service is None:");
        sb.AppendLine("    raise Exception('ColorizingService not available — open CodeBrowser tool')");
        sb.AppendLine();
        sb.AppendLine($"color = Color({r}, {g}, {b})");
        sb.AppendLine("base = currentProgram.getImageBase()");
        sb.AppendLine("painted = 0");
        sb.AppendLine("skipped = 0");
        sb.AppendLine("rvas = [");
        foreach (var edge in edges.OrderBy(e => e, StringComparer.OrdinalIgnoreCase))
        {
            var rva = EdgeRvaLong(edge);
            if (rva is null) continue;
            sb.AppendLine($"    {rva},");
        }

        sb.AppendLine("]");
        sb.AppendLine("for rva in rvas:");
        sb.AppendLine("    addr = base.add(rva)");
        sb.AppendLine("    existing = service.getBackgroundColor(addr)");
        sb.AppendLine("    if existing is not None:");
        sb.AppendLine("        skipped += 1");
        sb.AppendLine("        continue");
        sb.AppendLine("    aset = AddressSet(addr)");
        sb.AppendLine("    service.setBackgroundColor(aset, color)");
        sb.AppendLine("    painted += 1");
        sb.AppendLine($"print('Dynapstalker Ghidra: painted %d, skipped(already colored) %d ({processName})' % (painted, skipped))");

        File.WriteAllText(outPath, sb.ToString());
        WriteReadme(Path.GetDirectoryName(outPath)!);
        return new StalkExportResultDto("ghidra", outPath, edges.Count, [outPath]);
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
