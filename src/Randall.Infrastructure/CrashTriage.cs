using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>Crash research taxonomy — classify dumps for triage (not exploit building).</summary>
public static class CrashTriage
{
    public static CrashTriageDto Classify(
        CrashAnalysisDto? analysis,
        CrashSidecarDto? sidecar,
        CrashSummaryDto? summary = null,
        byte[]? payload = null)
    {
        var codeHint = analysis?.ExceptionHint
            ?? sidecar?.ExceptionHint
            ?? WindowsExceptionHints.Describe(ParseExit(summary?.TargetExitCode))
            ?? (summary?.TargetExitCode is { } x ? $"exit {x}" : null)
            ?? "unknown";

        var fault = analysis?.FaultAddress;
        var rip = analysis?.Registers?.Rip;
        var rsp = analysis?.Registers?.Rsp;
        var module = analysis?.FaultModule;

        var crashClass = ClassifyClass(analysis?.ExceptionCode, codeHint, fault, rip);
        var ipControlled = LooksLikeIpControl(fault, rip, module);
        var stackSmashed = LooksLikeStackSmash(analysis?.ExceptionCode, codeHint, rsp, rip);
        var severity = ScoreSeverity(crashClass, ipControlled, stackSmashed, analysis?.Ok == true);
        var summaryText = BuildSummary(crashClass, severity, fault, module, ipControlled, stackSmashed);
        var clusterKey = BuildClusterKey(summary?.Project ?? "?", crashClass, fault, module);
        var (depth, depthNote) = FindPatternDepth(payload, rip, fault, rsp);

        return new CrashTriageDto(
            crashClass,
            severity,
            summaryText,
            ipControlled,
            stackSmashed,
            clusterKey,
            codeHint,
            fault,
            module,
            rip,
            rsp,
            depth,
            depthNote);
    }

    /// <summary>
    /// Research metric only: if RIP/fault/RSP dword appears in the crashing input (LE),
    /// report the byte offset — useful for "how deep" triage, not exploit building.
    /// </summary>
    public static (int? Depth, string? Note) FindPatternDepth(
        byte[]? payload,
        string? rip,
        string? fault,
        string? rsp)
    {
        if (payload is null || payload.Length == 0)
            return (null, null);

        foreach (var (label, addr) in new[] { ("RIP", rip), ("fault", fault), ("RSP", rsp) })
        {
            if (string.IsNullOrWhiteSpace(addr))
                continue;
            var needle = AddrToLittleEndianBytes(addr, 4);
            if (needle is null)
                continue;
            var idx = IndexOf(payload, needle);
            if (idx >= 0)
                return (idx, $"{label} dword found in input at offset {idx} (depth triage)");

            var needle8 = AddrToLittleEndianBytes(addr, 8);
            if (needle8 is null)
                continue;
            idx = IndexOf(payload, needle8);
            if (idx >= 0)
                return (idx, $"{label} qword found in input at offset {idx} (depth triage)");
        }

        return (null, null);
    }

    private static byte[]? AddrToLittleEndianBytes(string addr, int width)
    {
        var hex = addr.Trim();
        if (hex.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            hex = hex[2..];
        if (!ulong.TryParse(hex, System.Globalization.NumberStyles.HexNumber, null, out var value))
            return null;
        var bytes = BitConverter.GetBytes(value);
        return bytes.AsSpan(0, width).ToArray();
    }

    private static int IndexOf(byte[] haystack, byte[] needle)
    {
        for (var i = 0; i <= haystack.Length - needle.Length; i++)
        {
            var ok = true;
            for (var j = 0; j < needle.Length; j++)
            {
                if (haystack[i + j] != needle[j])
                {
                    ok = false;
                    break;
                }
            }
            if (ok) return i;
        }
        return -1;
    }

    public static string BuildClusterKey(string project, string crashClass, string? fault, string? module)
    {
        var pc = NormalizePc(fault) ?? "no-pc";
        var mod = string.IsNullOrWhiteSpace(module) ? "unk" : Path.GetFileName(module).ToLowerInvariant();
        return $"{project}:{crashClass}:{mod}:{pc}";
    }

    private static string ClassifyClass(string? exceptionCode, string hint, string? fault, string? rip)
    {
        var h = (hint ?? "").ToUpperInvariant();
        var code = (exceptionCode ?? "").ToUpperInvariant();

        if (h.Contains("STACK_BUFFER_OVERRUN") || code.Contains("C0000409"))
            return "stack_buffer_overrun";
        if (h.Contains("STACK_OVERFLOW") || code.Contains("C00000FD"))
            return "stack_overflow";
        if (h.Contains("ACCESS_VIOLATION") || code.Contains("C0000005"))
            return "access_violation";
        if (h.Contains("ILLEGAL_INSTRUCTION") || code.Contains("C000001D"))
            return "illegal_instruction";
        if (h.Contains("DIVIDE_BY_ZERO") || code.Contains("C0000094"))
            return "divide_by_zero";
        if (h.Contains("HANG") || h.Contains("TIMEOUT"))
            return "hang";
        if (string.IsNullOrWhiteSpace(fault) && string.IsNullOrWhiteSpace(rip) && h.StartsWith("EXIT"))
            return "clean_exit";
        return "other";
    }

    private static bool LooksLikeIpControl(string? fault, string? rip, string? module)
    {
        if (string.IsNullOrWhiteSpace(rip) && string.IsNullOrWhiteSpace(fault))
            return false;

        var pc = NormalizePc(rip) ?? NormalizePc(fault);
        if (pc is null)
            return false;

        // Classic research signal: EIP/RIP smashed to ASCII filler (e.g. 0x41414141 / mona overwrite)
        if (pc.Contains("41414141", StringComparison.OrdinalIgnoreCase) ||
            pc.StartsWith("414141", StringComparison.OrdinalIgnoreCase) ||
            pc.EndsWith("41414141", StringComparison.OrdinalIgnoreCase))
            return true;

        // Four repeated printable ASCII bytes in the low dword (AAAA / BBBB / …)
        if (LooksLikeAsciiDword(pc))
            return true;

        return false;
    }

    /// <summary>True when the low 32 bits look like four repeated ASCII bytes (e.g. 41414141).</summary>
    private static bool LooksLikeAsciiDword(string pcHex)
    {
        var h = pcHex;
        if (h.Length < 8)
            return false;
        var low = h[^8..];
        var b0 = low[..2];
        if (!(b0 == low[2..4] && b0 == low[4..6] && b0 == low[6..8]))
            return false;
        if (!byte.TryParse(b0, System.Globalization.NumberStyles.HexNumber, null, out var b))
            return false;
        return b is >= 0x20 and <= 0x7E;
    }

    private static bool LooksLikeStackSmash(string? exceptionCode, string hint, string? rsp, string? rip)
    {
        var h = (hint ?? "").ToUpperInvariant();
        var code = (exceptionCode ?? "").ToUpperInvariant();
        if (h.Contains("STACK_BUFFER_OVERRUN") || code.Contains("C0000409"))
            return true;
        if (h.Contains("STACK_OVERFLOW") || code.Contains("C00000FD"))
            return true;

        // RSP looking like a low / ascii pattern is a soft signal
        var sp = NormalizePc(rsp);
        if (sp is not null && (sp.StartsWith("4141", StringComparison.OrdinalIgnoreCase) ||
                               sp.StartsWith("00000000", StringComparison.OrdinalIgnoreCase)))
            return true;

        return false;
    }

    private static string ScoreSeverity(string crashClass, bool ipControlled, bool stackSmashed, bool analyzed)
    {
        if (ipControlled || crashClass is "stack_buffer_overrun" or "illegal_instruction")
            return "critical";
        if (stackSmashed || crashClass is "access_violation" or "stack_overflow")
            return "high";
        if (crashClass is "hang" or "divide_by_zero")
            return "medium";
        if (!analyzed)
            return "low";
        return "medium";
    }

    private static string BuildSummary(
        string crashClass,
        string severity,
        string? fault,
        string? module,
        bool ipControlled,
        bool stackSmashed)
    {
        var parts = new List<string> { crashClass.Replace('_', ' '), severity };
        if (!string.IsNullOrWhiteSpace(fault))
            parts.Add($"@ {fault}");
        if (!string.IsNullOrWhiteSpace(module))
            parts.Add($"in {Path.GetFileName(module)}");
        if (ipControlled)
            parts.Add("IP looks controlled / non-image");
        if (stackSmashed)
            parts.Add("stack smash signals");
        return string.Join(" · ", parts);
    }

    private static string? NormalizePc(string? addr)
    {
        if (string.IsNullOrWhiteSpace(addr))
            return null;
        var a = addr.Trim();
        if (a.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            a = a[2..];
        // Collapse to lower hex, keep last 8–16 chars for clustering stability under ASLR within session
        a = a.ToLowerInvariant();
        return a.Length > 12 ? a[^12..] : a;
    }

    private static int? ParseExit(string? exit)
    {
        if (string.IsNullOrWhiteSpace(exit))
            return null;
        if (int.TryParse(exit, out var i))
            return i;
        if (exit.StartsWith("0x", StringComparison.OrdinalIgnoreCase) &&
            int.TryParse(exit.AsSpan(2), System.Globalization.NumberStyles.HexNumber, null, out var h))
            return h;
        return null;
    }
}
