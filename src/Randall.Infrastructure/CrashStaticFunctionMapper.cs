using System.Globalization;
using System.Text.RegularExpressions;
using Randall.Contracts;
using Randall.Infrastructure.Rop;

namespace Randall.Infrastructure;

/// <summary>
/// Maps crash RIP/EIP (or fault PC) to a static function + offset.
/// Prefers <c>randall-analysis.json</c>; falls back to PE export / section heuristics.
/// </summary>
public static partial class CrashStaticFunctionMapper
{
    [GeneratedRegex(@"^(.+)\+0x([0-9a-fA-F]+)$", RegexOptions.CultureInvariant)]
    private static partial Regex ModuleOffsetPattern();

    public static string FormatOneLine(StaticFunctionMappingDto m) =>
        $"{m.FunctionName}{m.Offset} ({m.Source})";

    public static StaticFunctionMappingDto? TryMapFromCrash(
        string project,
        CrashAnalysisDto? analysis,
        CrashTriageDto? triage = null,
        string? repoRoot = null,
        string? exeOverride = null)
    {
        if (string.IsNullOrWhiteSpace(project))
            return null;

        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var rip = triage?.Rip ?? analysis?.Registers?.Rip;
        var fault = triage?.FaultAddress ?? analysis?.FaultAddress;
        var faultModule = triage?.FaultModule ?? analysis?.FaultModule;

        var pcSource = !string.IsNullOrWhiteSpace(rip) ? "rip" : "fault";
        var pc = !string.IsNullOrWhiteSpace(rip) ? rip : fault;
        if (string.IsNullOrWhiteSpace(pc))
            return null;

        if (!TryParseAddress(pc, out var pcVa))
            return null;

        var moduleRva = TryParseModuleRva(faultModule);
        if (moduleRva is null && TryParseAddress(faultModule, out var fmVa))
            moduleRva = fmVa;

        var doc = GhidraAnalysisBridge.TryLoad(project, repoRoot);
        if (doc is not null)
        {
            var ghidra = TryMapGhidra(doc, pcVa, moduleRva, pcSource, pc);
            if (ghidra is not null)
                return ghidra;
        }

        var rva = moduleRva ?? TryRvaFromPreferredBase(pcVa, exeOverride, repoRoot, project);
        if (rva is null)
            return null;

        var exe = ResolveExePath(project, analysis, repoRoot, exeOverride);
        return TryMapPeFallback(exe, rva.Value, pcSource, pc, FormatRva(rva.Value));
    }

    public static StaticFunctionMappingDto? TryMapFromDetail(
        CrashDetailDto detail,
        string? repoRoot = null,
        string? exeOverride = null) =>
        TryMapFromCrash(
            detail.Summary.Project,
            detail.Analysis,
            detail.Triage,
            repoRoot,
            exeOverride);

    private static StaticFunctionMappingDto? TryMapGhidra(
        RandallAnalysisDocument doc,
        ulong pcVa,
        ulong? moduleRva,
        string pcSource,
        string pcAddress)
    {
        if (!TryParseAddress(doc.ImageBase, out var imageBase))
            imageBase = 0;

        RandallAnalysisFunctionDto? best = null;
        ulong bestOffset = 0;
        var bestScore = int.MinValue;

        foreach (var fn in doc.Functions)
        {
            if (!TryParseAddress(fn.Address, out var fnVa))
                continue;

            var fnRva = fnVa >= imageBase ? fnVa - imageBase : fnVa;
            var size = (ulong)Math.Max(fn.Size, 1);
            ulong offset;
            var score = 0;

            if (moduleRva is ulong mrva &&
                mrva >= fnRva && mrva < fnRva + size)
            {
                offset = mrva - fnRva;
                score = 100;
            }
            else if (pcVa >= fnVa && pcVa < fnVa + size)
            {
                offset = pcVa - fnVa;
                score = 80;
            }
            else if (moduleRva is null &&
                     pcVa >= imageBase &&
                     pcVa - imageBase >= fnRva &&
                     pcVa - imageBase < fnRva + size)
            {
                offset = pcVa - imageBase - fnRva;
                score = 60;
            }
            else
            {
                continue;
            }

            if (score > bestScore || (score == bestScore && fnRva > (best is not null && TryParseAddress(best.Address, out var bva) && TryParseAddress(doc.ImageBase, out var ib2) ? (bva >= ib2 ? bva - ib2 : bva) : 0)))
            {
                bestScore = score;
                best = fn;
                bestOffset = offset;
            }
        }

        if (best is null)
            return null;

        return new StaticFunctionMappingDto(
            pcSource,
            pcAddress,
            best.Name,
            $"+0x{bestOffset:X}",
            "ghidra",
            moduleRva is ulong r ? FormatRva(r) : null,
            BuildInstructionHint(best),
            best.FuzzPriority > 0 ? best.FuzzPriority : null);
    }

    private static StaticFunctionMappingDto? TryMapPeFallback(
        string? exePath,
        ulong moduleRva,
        string pcSource,
        string pcAddress,
        string moduleRvaText)
    {
        if (string.IsNullOrWhiteSpace(exePath) || !File.Exists(exePath))
            return null;

        byte[] bytes;
        try
        {
            bytes = File.ReadAllBytes(exePath);
        }
        catch
        {
            return null;
        }

        if (bytes.Length >= 2 && bytes[0] == 0x7F && bytes[1] == (byte)'E')
            return TryMapElfSymbol(exePath, moduleRva, pcSource, pcAddress, moduleRvaText);

        var exports = PeExportTable.TryParse(bytes);
        var exportName = PeExportTable.Nearest(exports, (uint)moduleRva);
        if (exportName is not null)
        {
            var export = exports.LastOrDefault(e =>
                e.Name.Equals(exportName, StringComparison.OrdinalIgnoreCase) &&
                e.Rva <= moduleRva);
            var off = export is { Name: not null } ? moduleRva - export.Rva : 0UL;
            return new StaticFunctionMappingDto(
                pcSource,
                pcAddress,
                exportName,
                $"+0x{off:X}",
                "pe-export",
                moduleRvaText,
                "nearest PE export (no Ghidra map)");
        }

        var surface = BinarySurfaceMap.TryLoad(exePath, maxStrings: 512);
        var section = surface?.SectionAt(moduleRva);
        if (section is not null)
        {
            return new StaticFunctionMappingDto(
                pcSource,
                pcAddress,
                section,
                $"+0x{moduleRva:X}",
                "pe-section",
                moduleRvaText,
                $"in {section} section (export symbol unresolved)");
        }

        return null;
    }

    private static StaticFunctionMappingDto? TryMapElfSymbol(
        string exePath,
        ulong moduleRva,
        string pcSource,
        string pcAddress,
        string moduleRvaText)
    {
        var surface = BinarySurfaceMap.TryLoad(exePath, maxStrings: 512);
        var section = surface?.SectionAt(moduleRva);
        if (section is null)
            return null;

        return new StaticFunctionMappingDto(
            pcSource,
            pcAddress,
            section,
            $"+0x{moduleRva:X}",
            "elf-section",
            moduleRvaText,
            $"in {section} section (run ghidra-analyze for names)");
    }

    private static string? BuildInstructionHint(RandallAnalysisFunctionDto fn)
    {
        var parts = new List<string>();
        if (fn.DangerousCalls.Count > 0)
            parts.Add("calls " + string.Join(", ", fn.DangerousCalls.Take(3)));
        if (fn.InputReachable)
            parts.Add("input-reachable");
        if (fn.FuzzPriority >= 70)
            parts.Add($"fuzz-priority {fn.FuzzPriority}/100");
        return parts.Count == 0 ? null : string.Join(" · ", parts);
    }

    private static ulong? TryParseModuleRva(string? faultModule)
    {
        if (string.IsNullOrWhiteSpace(faultModule))
            return null;
        var m = ModuleOffsetPattern().Match(faultModule.Trim());
        if (!m.Success)
            return null;
        return ulong.TryParse(m.Groups[2].Value, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var rva)
            ? rva
            : null;
    }

    private static ulong? TryRvaFromPreferredBase(
        ulong pcVa,
        string? exeOverride,
        string repoRoot,
        string project)
    {
        var exe = ResolveExePath(project, null, repoRoot, exeOverride);
        if (string.IsNullOrWhiteSpace(exe) || !File.Exists(exe))
            return null;

        try
        {
            var bytes = File.ReadAllBytes(exe);
            var baseVa = PeExportTable.TryImageBase(bytes);
            if (baseVa is null or 0)
                return null;
            if (pcVa < baseVa.Value)
                return null;
            return pcVa - baseVa.Value;
        }
        catch
        {
            return null;
        }
    }

    private static string? ResolveExePath(
        string project,
        CrashAnalysisDto? analysis,
        string repoRoot,
        string? exeOverride)
    {
        if (!string.IsNullOrWhiteSpace(exeOverride) && File.Exists(exeOverride))
            return Path.GetFullPath(exeOverride);

        var partial = new CrashDetailDto(
            new CrashSummaryDto(
                Guid.Empty, project, 0, "", "", "", null, null, null, null, null, DateTimeOffset.MinValue),
            0, "", "", null, analysis, null);
        return RopStudio.ResolveCrashModules(partial, repoRoot, exeOverride, maxModules: 1).FirstOrDefault()
               ?? TryResolveProjectExe(project, repoRoot);
    }

    private static string? TryResolveProjectExe(string project, string repoRoot)
    {
        try
        {
            foreach (var path in ProjectLoader.DiscoverAll(repoRoot))
            {
                var cfg = ProjectLoader.Load(path);
                if (!cfg.Name.Equals(project, StringComparison.OrdinalIgnoreCase))
                    continue;
                var rel = cfg.Target.Executable.Replace('/', Path.DirectorySeparatorChar);
                var declared = Path.IsPathRooted(rel)
                    ? rel
                    : Path.GetFullPath(Path.Combine(repoRoot, "projects", rel));
                return ExecutableResolver.FindExisting(declared) ?? declared;
            }
        }
        catch
        {
            /* ignore */
        }

        return null;
    }

    internal static bool TryParseAddress(string? addr, out ulong value)
    {
        value = 0;
        if (string.IsNullOrWhiteSpace(addr))
            return false;
        var s = addr.Trim();
        if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            s = s[2..];
        return ulong.TryParse(s, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out value);
    }

    private static string FormatRva(ulong rva) => $"0x{rva:X}";
}
