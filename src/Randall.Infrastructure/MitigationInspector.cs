using System.Diagnostics;

namespace Randall.Infrastructure;

/// <summary>
/// checksec-style inspector for Linux ELF binaries — reports which exploit mitigations are compiled
/// in (NX/DEP, stack canary, PIE→ASLR, RELRO, FORTIFY). Uses <c>readelf</c> (binutils) so it works
/// without extra deps; returns a best-effort report if readelf is unavailable.
/// </summary>
public static class MitigationInspector
{
    public sealed record MitigationReport(
        bool Nx,
        bool Canary,
        bool Pie,
        string Relro,      // "full" | "partial" | "none"
        bool Fortify,
        string Tier,       // basic | nx | aslr | modern (best-effort)
        bool ReadelfUsed);

    public static MitigationReport Inspect(string exePath)
    {
        var lW = Readelf($"-lW \"{exePath}\"");
        var dW = Readelf($"-dW \"{exePath}\"");
        var hW = Readelf($"-hW \"{exePath}\"");
        var syms = Readelf($"--dyn-syms -W \"{exePath}\"");
        var used = lW is not null || dW is not null || hW is not null || syms is not null;

        // NX: a GNU_STACK segment marked executable (flag E) means NX is OFF.
        var gnuStackLine = FindLine(lW, "GNU_STACK");
        var nx = gnuStackLine is null || !SegmentFlagsHave(gnuStackLine, 'E');

        // PIE: shared-object type (DYN) with an interpreter → position-independent executable.
        var isDyn = hW is not null && hW.Contains("Type:", StringComparison.Ordinal) &&
                    hW.Contains("DYN", StringComparison.Ordinal);
        var hasInterp = lW is not null && lW.Contains("INTERP", StringComparison.Ordinal);
        var pie = isDyn && hasInterp;

        // RELRO: GNU_RELRO segment = partial; + BIND_NOW/FLAGS NOW = full.
        var hasRelro = lW is not null && lW.Contains("GNU_RELRO", StringComparison.Ordinal);
        var bindNow = dW is not null &&
                      (dW.Contains("BIND_NOW", StringComparison.Ordinal) ||
                       dW.Contains("NOW", StringComparison.Ordinal));
        var relro = !hasRelro ? "none" : (bindNow ? "full" : "partial");

        // Canary: dynamic symbol __stack_chk_fail.
        var canary = syms is not null && syms.Contains("__stack_chk_fail", StringComparison.Ordinal);

        // FORTIFY: presence of _chk fortified libc wrappers.
        var fortify = syms is not null &&
                      (syms.Contains("_chk", StringComparison.Ordinal));

        var tier = ClassifyTier(nx, canary, pie, relro, fortify);
        return new MitigationReport(nx, canary, pie, relro, fortify, tier, used);
    }

    private static string ClassifyTier(bool nx, bool canary, bool pie, string relro, bool fortify)
    {
        if (canary && nx && pie && relro == "full") return "modern";
        if (pie && nx) return "aslr";
        if (nx) return "nx";
        return "basic";
    }

    private static bool SegmentFlagsHave(string gnuStackLine, char flag)
    {
        // readelf -lW GNU_STACK line ends with flags like "RW " or "RWE".
        var idx = gnuStackLine.IndexOf("0x", StringComparison.Ordinal);
        return gnuStackLine.Contains(" " + flag, StringComparison.Ordinal) ||
               gnuStackLine.TrimEnd().EndsWith(flag.ToString(), StringComparison.Ordinal) ||
               gnuStackLine.Contains("RWE", StringComparison.Ordinal) && flag == 'E';
    }

    private static string? FindLine(string? text, string needle)
    {
        if (text is null) return null;
        foreach (var line in text.Split('\n'))
            if (line.Contains(needle, StringComparison.Ordinal))
                return line;
        return null;
    }

    private static string? Readelf(string args)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "readelf",
                Arguments = args,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            using var p = Process.Start(psi);
            if (p is null) return null;
            var outp = p.StandardOutput.ReadToEnd();
            p.StandardError.ReadToEnd();
            p.WaitForExit(8000);
            return string.IsNullOrWhiteSpace(outp) ? null : outp;
        }
        catch
        {
            return null;
        }
    }
}
