using System.Globalization;
using System.Text;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// First-class Randfuzz → Ghidra integration: generates Script Manager Python that paints
/// coverage (full BB ranges), preserves earlier colors, and can jump to first diverge.
/// Dragon Dance remains optional for binary drcov; this path uses our text edges.
/// </summary>
public static class GhidraScriptBuilder
{
    public sealed record BlockSpec(long Rva, int Size, string? ModuleId = null);

    public sealed record LayerSpec(
        string Name,
        IReadOnlyList<BlockSpec> Blocks,
        int R,
        int G,
        int B);

    public static string BuildColorScript(
        string title,
        IReadOnlyList<LayerSpec> layers,
        long? goToRva = null,
        string? notes = null)
    {
        var sb = new StringBuilder();
        sb.AppendLine("# -*- coding: utf-8 -*-");
        sb.AppendLine($"# {title}");
        sb.AppendLine("# Randfuzz Ghidra integration — run in CodeBrowser → Script Manager");
        sb.AppendLine("# Addresses: currentProgram.imageBase + drcov RVA; paints full BB size.");
        sb.AppendLine("# Only colors addresses that still have no background (oldest layer wins).");
        if (!string.IsNullOrWhiteSpace(notes))
        {
            foreach (var line in notes!.Split('\n'))
                sb.AppendLine("# " + line);
        }

        sb.AppendLine();
        sb.AppendLine("from ghidra.app.plugin.core.colorizer import ColorizingService");
        sb.AppendLine("from ghidra.program.model.address import AddressSet");
        sb.AppendLine("from java.awt import Color");
        sb.AppendLine();
        sb.AppendLine("service = state.getTool().getService(ColorizingService)");
        sb.AppendLine("if service is None:");
        sb.AppendLine("    raise Exception('ColorizingService unavailable — open the CodeBrowser tool')");
        sb.AppendLine();
        sb.AppendLine("base = currentProgram.getImageBase()");
        sb.AppendLine("listing = currentProgram.getListing()");
        sb.AppendLine();

        for (var i = 0; i < layers.Count; i++)
        {
            var layer = layers[i];
            sb.AppendLine($"# --- layer {i}: {Escape(layer.Name)} ({layer.Blocks.Count} blocks) ---");
            sb.AppendLine($"color_{i} = Color({layer.R}, {layer.G}, {layer.B})");
            sb.AppendLine($"painted_{i} = 0");
            sb.AppendLine($"skipped_{i} = 0");
            sb.AppendLine($"blocks_{i} = [");
            foreach (var b in layer.Blocks.OrderBy(x => x.Rva))
            {
                var size = Math.Max(1, b.Size);
                sb.AppendLine($"    ({b.Rva}, {size}),");
            }

            sb.AppendLine("]");
            sb.AppendLine($"for (rva, size) in blocks_{i}:");
            sb.AppendLine("    start = base.add(rva)");
            sb.AppendLine("    if service.getBackgroundColor(start) is not None:");
            sb.AppendLine($"        skipped_{i} += 1");
            sb.AppendLine("        continue");
            sb.AppendLine("    end = start.add(size - 1)");
            sb.AppendLine("    aset = AddressSet(start, end)");
            sb.AppendLine($"    service.setBackgroundColor(aset, color_{i})");
            sb.AppendLine($"    painted_{i} += 1");
            sb.AppendLine($"print('Randfuzz layer \"{Escape(layer.Name)}\": painted %d BBs, skipped %d' % (painted_{i}, skipped_{i}))");
            sb.AppendLine();
        }

        if (goToRva is not null)
        {
            sb.AppendLine($"# First diverge / focus RVA");
            sb.AppendLine($"focus = base.add({goToRva.Value})");
            sb.AppendLine("goTo(focus)");
            sb.AppendLine("print('Randfuzz: jumped to focus RVA 0x%x -> %s' % (" + goToRva.Value + ", focus))");
            sb.AppendLine();
        }

        sb.AppendLine("print('Randfuzz Ghidra import complete. Plain (uncolored) blocks ≈ missed.')");
        return sb.ToString();
    }

    public static IReadOnlyList<BlockSpec> BlocksFromEdges(IEnumerable<string> edges, string? moduleFilter = null)
    {
        HashSet<string>? allow = null;
        if (!string.IsNullOrWhiteSpace(moduleFilter))
            allow = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { moduleFilter! };

        var list = new List<BlockSpec>();
        foreach (var edge in edges)
        {
            var parts = edge.Split(':');
            if (parts.Length < 2) continue;
            var mod = parts[0];
            if (allow is not null && !allow.Contains(mod))
                continue;
            if (!TryParseHex(parts[1], out var rva))
                continue;
            var size = 1;
            if (parts.Length >= 3)
                int.TryParse(parts[2], NumberStyles.Integer, CultureInfo.InvariantCulture, out size);
            if (size <= 0) size = 1;
            list.Add(new BlockSpec(rva, size, mod));
        }

        return list;
    }

    public static (int R, int G, int B) BgrToRgb(string? colorHex, int fallbackR = 255, int fallbackG = 255, int fallbackB = 0)
    {
        var hex = (colorHex ?? "").Trim();
        if (hex.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            hex = hex[2..];
        if (!uint.TryParse(hex, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var bgr))
            return (fallbackR, fallbackG, fallbackB);
        var b = (int)((bgr >> 16) & 0xFF);
        var g = (int)((bgr >> 8) & 0xFF);
        var r = (int)(bgr & 0xFF);
        return (r, g, b);
    }

    public static void WriteModulesSidecar(string exportDir, string? drcovPath)
    {
        if (string.IsNullOrWhiteSpace(drcovPath) || !File.Exists(drcovPath))
            return;
        var modules = DrcovParser.ParseModules(drcovPath);
        if (modules.Count == 0)
            return;
        var path = Path.Combine(exportDir, "modules.txt");
        File.WriteAllLines(path, modules.Select(m => $"{m.Id}\t{m.Path}"));
    }

    private static bool TryParseHex(string raw, out long value)
    {
        value = 0;
        var s = raw.Trim();
        if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            s = s[2..];
        return long.TryParse(s, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out value);
    }

    private static string Escape(string s) => s.Replace("\\", "\\\\").Replace("\"", "\\\"");
}
