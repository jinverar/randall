using System.Text;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Dynapstalker-faithful helper: one drcov <c>-dump_text</c> log → one IDA IDC that color-codes
/// hit basic blocks (only paints still-white / default items). Matches the PDF exercise script
/// args: log, process name, output IDC, optional RGB/BGR color.
/// </summary>
public static class DynapstalkerExport
{
    public static StalkExportResultDto ExportIdc(
        string drcovPath,
        string processName,
        string outputIdcPath,
        string? colorHex = null)
    {
        if (string.IsNullOrWhiteSpace(drcovPath) || !File.Exists(drcovPath))
            throw new FileNotFoundException("drcov log not found", drcovPath);
        if (string.IsNullOrWhiteSpace(processName))
            throw new ArgumentException("process name required (e.g. savant.exe)", nameof(processName));
        if (string.IsNullOrWhiteSpace(outputIdcPath))
            throw new ArgumentException("output IDC path required", nameof(outputIdcPath));

        var color = NormalizeColor(colorHex);
        var edges = DrcovParser.ParseEdges(drcovPath, processName);
        if (edges.Count == 0)
            throw new InvalidOperationException(
                $"No BB edges matched process '{processName}' in {drcovPath}. " +
                "Confirm -dump_text was used and the module table contains that name.");

        var outPath = Path.GetFullPath(outputIdcPath);
        Directory.CreateDirectory(Path.GetDirectoryName(outPath) ?? ".");

        var sb = new StringBuilder();
        sb.AppendLine("// Randfuzz Dynapstalker export (PDF / PaiMei-style)");
        sb.AppendLine($"// Source: {drcovPath}");
        sb.AppendLine($"// Process filter: {processName}");
        sb.AppendLine($"// Color (IDA BGR): {color}");
        sb.AppendLine($"// Blocks: {edges.Count}");
        sb.AppendLine("// Load oldest scripts first. Only recolors default/white items.");
        sb.AppendLine("static main() {");
        sb.AppendLine("  auto ea, cur;");
        foreach (var edge in edges.OrderBy(e => e, StringComparer.OrdinalIgnoreCase))
        {
            var addr = EdgeAddress(edge);
            if (addr is null) continue;
            sb.AppendLine($"  ea = {addr};");
            sb.AppendLine("  if (ea != BADADDR) {");
            sb.AppendLine("    cur = GetColor(ea, CIC_ITEM);");
            // 0xFFFFFFFF = default white in IDA graph/listing for unset items
            sb.AppendLine("    if (cur == 0xFFFFFFFF || cur == -1)");
            sb.AppendLine($"      SetColor(ea, CIC_ITEM, {color});");
            sb.AppendLine("  }");
        }

        sb.AppendLine("}");
        File.WriteAllText(outPath, sb.ToString());

        var readme = Path.Combine(Path.GetDirectoryName(outPath)!, "README_DYNAPSTALKER.txt");
        File.WriteAllText(readme, """
            Dynapstalker → IDA Pro (Randfuzz)
            =================================
            PDF exercise mapping:
              1. drrun -t drcov -dump_text -- <target>     (baseline, then fuzzed)
              2. randall stalk dynapstalker <log> <exe> <out.idc> [--color 0x00ffff]
              3. IDA: File → Script file — load OLDEST IDC first (yellow baseline)
              4. Load fuzzed IDC second (green). White blocks = still missed.
              5. Review white blocks (string/memcpy / error paths) → revise fuzzer
              6. Re-measure; export a new color for the improved round.

            Then in Randfuzz:
              randall stalk missed -p <project>
              (optional) import a BB inventory for never-hit without IDA
            """);

        return new StalkExportResultDto("idc", outPath, edges.Count, [outPath, readme]);
    }

    private static string NormalizeColor(string? colorHex)
    {
        if (string.IsNullOrWhiteSpace(colorHex))
            return "0x00FFFF"; // PDF default yellow/cyan (IDA BGR)
        var hex = colorHex.Trim();
        if (!hex.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            hex = "0x" + hex;
        return hex;
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
}
