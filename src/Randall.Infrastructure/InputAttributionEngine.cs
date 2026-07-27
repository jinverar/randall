using System.Globalization;
using System.Text.RegularExpressions;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Research-only: correlate debugger registers with payload bytes and attribute mutation steps.
/// Does not invent exploit payloads — joins existing mutation lineage + CDB evidence.
/// </summary>
public static partial class InputAttributionEngine
{
    private static readonly string[] RegisterOrder =
    [
        "fault", "rip", "rax", "rcx", "rdx", "rbx", "rsi", "rdi", "rbp", "rsp",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    ];

    private static readonly HashSet<string> LengthMutators = new(StringComparer.OrdinalIgnoreCase)
    {
        "expand", "insert", "splice", "havoc", "framed", "interesting", "boundary",
    };

    private static readonly HashSet<string> BitMutators = new(StringComparer.OrdinalIgnoreCase)
    {
        "bitflip", "flip", "byte", "nibble",
    };

    public sealed record AttributionResult(
        IReadOnlyList<RegisterPayloadMatchDto> RegisterMatches,
        RegisterPayloadMatchDto? PrimaryMatch,
        int? PatternDepthBytes,
        string? PatternNote,
        string? SuspectedMutator,
        int? SuspectedMutatorStep,
        string Confidence,
        int AttributionScreamBonus,
        string Summary,
        string? Narrative);

    public static AttributionResult Analyze(
        byte[]? payload,
        DebuggerObservation? debugger,
        CrashTriageDto? triage,
        CrashSidecarDto? sidecar,
        IReadOnlyList<string> mutatorLineage)
    {
        var matches = FindRegisterMatches(payload, debugger, triage);
        var primary = PickPrimaryMatch(matches, debugger);
        var (depth, depthNote) = triage?.PatternDepthBytes is int d
            ? (triage.PatternDepthBytes, triage.PatternNote)
            : primary is not null
                ? (primary.PayloadOffset, primary.Note)
                : CrashTriage.FindPatternDepth(
                    payload,
                    debugger?.Rip ?? triage?.Rip,
                    debugger?.FaultAddress ?? triage?.FaultAddress,
                    triage?.Rsp,
                    debugger?.RegistersText);

        var (mutator, mutStep, mutNote) = AttributeMutatorStep(
            mutatorLineage, payload, primary, depth, debugger, sidecar);

        var confidence = ScoreConfidence(debugger, depth, mutatorLineage.Count, matches, primary);
        var bonus = ComputeAttributionBonus(debugger, confidence, primary, matches.Count);
        var narrative = BuildNarrative(
            sidecar, debugger, primary, depth, mutator, mutStep, mutNote, matches);
        var summary = BuildSummary(mutator, depth, primary, debugger, confidence, sidecar);

        return new AttributionResult(
            matches,
            primary,
            depth,
            depthNote ?? primary?.Note,
            mutator,
            mutStep,
            confidence,
            bonus,
            summary,
            narrative);
    }

    public static IReadOnlyList<RegisterPayloadMatchDto> FindRegisterMatches(
        byte[]? payload,
        DebuggerObservation? debugger,
        CrashTriageDto? triage)
    {
        if (payload is null || payload.Length == 0)
            return [];

        if (debugger?.RegisterMatches is { Count: > 0 })
        {
            // Re-filter cached matches — older dumps / pre-honesty observations may still claim NULLs.
            return debugger.RegisterMatches
                .Where(m => m.MatchKind == "ascii" || !IsExcludedFromRawInputAttribution(m.ValueHex))
                .ToList();
        }

        return FindRegisterMatchesFromText(
            payload,
            debugger?.RegistersText,
            debugger?.FaultAddress ?? triage?.FaultAddress,
            debugger?.Rip ?? triage?.Rip,
            triage?.Rsp);
    }

    public static IReadOnlyList<RegisterPayloadMatchDto> FindRegisterMatchesFromText(
        byte[] payload,
        string? registersText,
        string? faultAddress = null,
        string? rip = null,
        string? rsp = null)
    {
        var regs = ParseRegisters(registersText);
        if (regs.Count == 0 && faultAddress is null && rip is null && rsp is null)
            return [];

        if (!string.IsNullOrWhiteSpace(faultAddress))
            regs["fault"] = faultAddress;
        if (!string.IsNullOrWhiteSpace(rip))
            regs["rip"] = rip;
        if (!string.IsNullOrWhiteSpace(rsp))
            regs["rsp"] = rsp;

        var matches = new List<RegisterPayloadMatchDto>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var regName in RegisterOrder)
        {
            if (!regs.TryGetValue(regName, out var addr) || string.IsNullOrWhiteSpace(addr))
                continue;

            var match = MatchRegisterToPayload(regName, addr, payload);
            if (match is null)
                continue;

            var key = $"{match.Register}:{match.PayloadOffset}:{match.WidthBytes}";
            if (!seen.Add(key))
                continue;
            matches.Add(match);
        }

        return matches
            .OrderBy(m => RegisterPriority(m.Register))
            .ThenBy(m => m.PayloadOffset)
            .ToList();
    }

    public static Dictionary<string, string> ParseRegisters(string? regsText)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(regsText))
            return map;

        foreach (Match m in RegisterLine().Matches(regsText))
        {
            var name = m.Groups["reg"].Value.ToLowerInvariant();
            var val = NormalizeAddr(m.Groups["val"].Value);
            if (val is not null)
                map[name] = val;
        }

        return map;
    }

    public const string LowValueExclusionReason =
        "NULL/low value excluded from raw input-value attribution";

    public static bool IsExcludedFromRawInputAttribution(string? addr)
    {
        if (string.IsNullOrWhiteSpace(addr) || !TryParseUlong(addr, out var v))
            return false;
        var lo = v & 0xFFFFFFFFUL;
        if (lo is 0 or 1 or 2 or 4 or 8 or 16 or 0xFFFFFFFFUL)
            return true;
        if (v is 0 or 1 or 2 or 4 or 8 or 16)
            return true;
        return false;
    }

    public static bool IsStrongNonZeroPattern(string? addr)
    {
        if (string.IsNullOrWhiteSpace(addr) || IsExcludedFromRawInputAttribution(addr))
            return false;
        return LooksLikeAsciiPattern(addr);
    }

    /// <summary>All-ones dword/qword (−1 / 0xFF..FF) — correlation only, not proven control.</summary>
    public sealed record SentinelCorrelation(
        string Register,
        string ValueHex,
        int? PayloadOffset,
        int? WidthBytes);

    /// <summary>
    /// Find RCX/RAX/… holding <c>0xFFFFFFFF</c> / <c>0xFFFFFFFFFFFFFFFF</c>.
    /// Surfaces as Unverified correlation (boundary + −1 is an experiment hint, not R4).
    /// </summary>
    public static SentinelCorrelation? FindAllOnesSentinelCorrelation(string? registersText, byte[]? payload)
    {
        if (string.IsNullOrWhiteSpace(registersText))
            return null;

        foreach (var (name, val) in ParseRegisters(registersText))
        {
            if (!TryParseUlong(val, out var v))
                continue;
            var isDword = (v & 0xFFFFFFFFUL) == 0xFFFFFFFFUL && v <= 0xFFFFFFFFUL;
            var isQword = v == ulong.MaxValue;
            if (!isDword && !isQword)
                continue;

            int? offset = null;
            int width = isQword ? 8 : 4;
            if (payload is { Length: > 0 })
            {
                var needle = isQword
                    ? new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }
                    : new byte[] { 0xFF, 0xFF, 0xFF, 0xFF };
                var idx = IndexOf(payload, needle);
                if (idx >= 0)
                    offset = idx;
            }

            return new SentinelCorrelation(name.ToUpperInvariant(), NormalizeHex(val) ?? val, offset, width);
        }

        return null;
    }

    private static string? NormalizeHex(string addr)
    {
        if (!TryParseUlong(addr, out var v))
            return null;
        return "0x" + v.ToString("X");
    }

    public static RegisterPayloadMatchDto? MatchRegisterToPayload(string register, string addr, byte[] payload)
    {
        if (IsExcludedFromRawInputAttribution(addr))
            return null;

        if (LooksLikeAsciiPattern(addr))
        {
            var needle = AddrToLittleEndianBytes(addr, 4);
            if (needle is null)
                return null;
            var idx = IndexOf(payload, needle);
            if (idx >= 0)
            {
                return new RegisterPayloadMatchDto(
                    register.ToUpperInvariant(),
                    addr,
                    idx,
                    4,
                    "ascii",
                    $"{register.ToUpperInvariant()} ASCII dword found in input at +{idx}");
            }
        }

        foreach (var width in new[] { 4, 8 })
        {
            var needle = AddrToLittleEndianBytes(addr, width);
            if (needle is null)
                continue;
            var idx = IndexOf(payload, needle);
            if (idx >= 0)
            {
                return new RegisterPayloadMatchDto(
                    register.ToUpperInvariant(),
                    addr,
                    idx,
                    width,
                    width == 4 ? "dword" : "qword",
                    $"{register.ToUpperInvariant()} {(width == 4 ? "dword" : "qword")} found in input at +{idx}");
            }
        }

        return null;
    }

    internal static RegisterPayloadMatchDto? PickPrimaryMatch(
        IReadOnlyList<RegisterPayloadMatchDto> matches,
        DebuggerObservation? debugger)
    {
        if (matches.Count == 0)
            return null;

        if (!string.IsNullOrWhiteSpace(debugger?.PrimaryRegisterMatch))
        {
            var named = matches.FirstOrDefault(m =>
                m.Register.Equals(debugger.PrimaryRegisterMatch, StringComparison.OrdinalIgnoreCase));
            if (named is not null && !IsSyntheticRegister(named.Register))
                return named;
        }

        // Prefer GP registers that carry input-derived values over synthetic fault/rip aliases.
        return matches
            .OrderBy(m => IsSyntheticRegister(m.Register) ? 1 : 0)
            .ThenBy(m => RegisterPriority(m.Register))
            .ThenBy(m => m.MatchKind == "ascii" ? 0 : 1)
            .First();
    }

    private static bool IsSyntheticRegister(string register) =>
        register.Equals("FAULT", StringComparison.OrdinalIgnoreCase)
        || register.Equals("RIP", StringComparison.OrdinalIgnoreCase);

    private static (string? Mutator, int? Step, string? Note) AttributeMutatorStep(
        IReadOnlyList<string> chain,
        byte[]? payload,
        RegisterPayloadMatchDto? primary,
        int? depth,
        DebuggerObservation? debugger,
        CrashSidecarDto? sidecar)
    {
        if (chain.Count == 0)
            return (sidecar?.Mutator, null, null);

        if (chain.Count == 1)
            return (chain[0], 0, "sole mutator in lineage");

        var bestIdx = -1;
        var bestScore = int.MinValue;
        string? bestNote = null;

        for (var i = 0; i < chain.Count; i++)
        {
            var mut = chain[i];
            var score = 0;
            var notes = new List<string>();

            if (i == chain.Count - 1)
            {
                score += 1;
                notes.Add("last step");
            }

            if (primary?.MatchKind == "ascii")
            {
                if (ContainsToken(mut, LengthMutators))
                {
                    score += 4;
                    notes.Add("ASCII fault ↔ length/body mutator");
                }
            }
            else if (primary is not null)
            {
                if (ContainsToken(mut, LengthMutators) && depth is int off && payload is not null && off >= payload.Length / 3)
                {
                    score += 3;
                    notes.Add("integer fault at tail ↔ expand/insert");
                }

                if (ContainsToken(mut, BitMutators) && depth is int small && small < 16)
                {
                    score += 2;
                    notes.Add("early offset ↔ bitflip");
                }

                if (mut.Contains("interesting", StringComparison.OrdinalIgnoreCase)
                    || mut.Contains("boundary", StringComparison.OrdinalIgnoreCase))
                {
                    score += 2;
                    notes.Add("integer/boundary mutator");
                }
            }

            if (debugger?.Access == DebuggerAccessKind.Write
                && mut.Contains("expand", StringComparison.OrdinalIgnoreCase))
            {
                score += 2;
                notes.Add("write AV ↔ expand");
            }

            if (sidecar?.Mutator is not null
                && mut.Equals(sidecar.Mutator, StringComparison.OrdinalIgnoreCase)
                && i == chain.Count - 1)
            {
                score += 1;
            }

            if (score > bestScore)
            {
                bestScore = score;
                bestIdx = i;
                bestNote = notes.Count > 0 ? string.Join("; ", notes) : null;
            }
        }

        if (bestIdx >= 0 && bestScore >= 2)
            return (chain[bestIdx], bestIdx, bestNote);

        return (chain[^1], chain.Count - 1, "default: last mutator before crash");
    }

    private static string ScoreConfidence(
        DebuggerObservation? dbg,
        int? depth,
        int chainLen,
        IReadOnlyList<RegisterPayloadMatchDto> matches,
        RegisterPayloadMatchDto? primary)
    {
        var score = 0;
        if (dbg is { Ok: true }) score += 2;
        if (dbg?.SuspectedInputInfluence == "HIGH") score += 3;
        else if (dbg?.SuspectedInputInfluence == "MEDIUM") score += 1;
        if (dbg?.FaultAddressClass == DebuggerAddressClass.AsciiPattern) score += 2;
        if (depth is not null) score += 2;
        if (chainLen >= 2) score += 1;
        if (primary?.MatchKind == "ascii") score += 2;
        if (matches.Count >= 2) score += 1;
        if (dbg?.Access == DebuggerAccessKind.Write) score += 2;
        if (dbg?.FaultAddressClass == DebuggerAddressClass.Heapish) score += 1;
        if (dbg?.FaultAddressClass == DebuggerAddressClass.Freed) score += 1;

        return score switch
        {
            >= 8 => "HIGH",
            >= 4 => "MEDIUM",
            >= 1 => "LOW",
            _ => "UNKNOWN",
        };
    }

    private static int ComputeAttributionBonus(
        DebuggerObservation? dbg,
        string confidence,
        RegisterPayloadMatchDto? primary,
        int matchCount)
    {
        if (confidence is not ("HIGH" or "MEDIUM"))
            return 0;

        var bonus = confidence == "HIGH" ? 6 : 3;
        if (dbg?.Access == DebuggerAccessKind.Write) bonus += 4;
        if (dbg?.Access == DebuggerAccessKind.Execute) bonus += 3;
        if (primary?.MatchKind == "ascii") bonus += 4;
        if (dbg?.FaultAddressClass == DebuggerAddressClass.AsciiPattern) bonus += 3;
        if (dbg?.FaultAddressClass == DebuggerAddressClass.Heapish) bonus += 2;
        if (dbg?.FaultAddressClass == DebuggerAddressClass.Freed) bonus += 3;
        if (matchCount >= 2) bonus += 2;
        if (dbg?.SuspectedInputInfluence == "HIGH") bonus += 2;
        return Math.Clamp(bonus, 0, 18);
    }

    private static string BuildSummary(
        string? mutator,
        int? depth,
        RegisterPayloadMatchDto? primary,
        DebuggerObservation? dbg,
        string confidence,
        CrashSidecarDto? sidecar)
    {
        var parts = new List<string>();
        if (!string.IsNullOrWhiteSpace(sidecar?.Command))
            parts.Add($"field {sidecar.Command}");
        else if (depth is int d)
            parts.Add($"payload+{d}");

        if (primary is not null)
            parts.Add($"{primary.Register}={primary.ValueHex} @ +{primary.PayloadOffset}");
        else if (depth is int off)
            parts.Add($"pattern @ +{off}");

        var sinkLabel = FormatHonestSink(dbg);
        if (sinkLabel is not null)
            parts.Add(sinkLabel);
        else if (dbg?.FaultAddress is not null)
            parts.Add($"fault {dbg.FaultAddress}");

        if (dbg?.Access is DebuggerAccessKind.Write or DebuggerAccessKind.Execute)
            parts.Add($"{dbg.Access.ToString().ToLowerInvariant()} AV");

        if (dbg?.HeapSignal is not null)
            parts.Add(dbg.HeapSignal.ToLowerInvariant());

        if (!string.IsNullOrWhiteSpace(mutator))
            parts.Add($"via '{mutator}'");

        var body = parts.Count == 0 ? "insufficient evidence for attribution" : string.Join(" → ", parts);
        return $"[{confidence}] {body}";
    }

    public static string? BuildNarrative(
        CrashSidecarDto? sidecar,
        DebuggerObservation? dbg,
        RegisterPayloadMatchDto? primary,
        int? depth,
        string? mutator,
        int? mutStep,
        string? mutNote,
        IReadOnlyList<RegisterPayloadMatchDto> matches)
    {
        if (dbg is not { Ok: true } && primary is null && depth is null)
            return null;

        var sb = new System.Text.StringBuilder();
        var field = sidecar?.Command ?? (depth is int d ? $"payload+{d}" : "input field");
        sb.Append(field);

        if (primary is not null && !IsExcludedFromRawInputAttribution(primary.ValueHex))
            sb.Append($" → {primary.Register}={primary.ValueHex} (input+{primary.PayloadOffset}, {primary.MatchKind})");
        else if (primary is not null && IsExcludedFromRawInputAttribution(primary.ValueHex))
            sb.Append($" → {primary.Register}={primary.ValueHex} (null/low — not attributed as controlled pointer)");
        else if (depth is int off)
            sb.Append($" → controlled bytes at +{off}");

        var sink = FormatHonestSink(dbg);
        if (sink is not null)
        {
            var style = InferSinkStyle(dbg);
            sb.Append(style is not null ? $" → {style} at {sink}" : $" → sink {sink}");
        }

        if (dbg?.Access is DebuggerAccessKind.Write or DebuggerAccessKind.Read or DebuggerAccessKind.Execute)
            sb.Append($" → {dbg.Access.ToString().ToLowerInvariant()} AV");
        else if (dbg?.ExceptionHint is not null)
            sb.Append($" → {dbg.ExceptionHint}");

        if (dbg?.HeapSignal is not null)
            sb.Append($" → {dbg.HeapSignal.Replace('_', ' ').ToLowerInvariant()}");

        if (!string.IsNullOrWhiteSpace(mutator))
        {
            sb.Append(mutStep is int step && step >= 0
                ? $" (mutation step {step + 1}: {mutator}"
                : $" (mutator {mutator}");
            if (!string.IsNullOrWhiteSpace(mutNote))
                sb.Append($"; {mutNote}");
            sb.Append(')');
        }

        if (matches.Count > 1)
        {
            var extras = matches
                .Where(m => primary is null || m.Register != primary.Register || m.PayloadOffset != primary.PayloadOffset)
                .Take(3)
                .Select(m => $"{m.Register}@+{m.PayloadOffset}")
                .ToList();
            if (extras.Count > 0)
                sb.Append($" · also {string.Join(", ", extras)}");
        }

        return sb.ToString();
    }

    private static string? FormatHonestSink(DebuggerObservation? dbg)
    {
        if (dbg is null)
            return null;

        if (!string.IsNullOrWhiteSpace(dbg.FaultingFunction)
            && !ScreamInvestigator.IsGarbageSymbol(dbg.FaultingFunction, dbg.FaultingModule))
        {
            var mod = string.IsNullOrWhiteSpace(dbg.FaultingModule) || dbg.FaultingModule is "!" or "?"
                ? null
                : dbg.FaultingModule;
            return mod is null
                ? $"{dbg.FaultingFunction}{dbg.FunctionOffset ?? ""}"
                : $"{mod}!{dbg.FaultingFunction}{dbg.FunctionOffset ?? ""}";
        }

        return dbg.Rip ?? dbg.FaultAddress;
    }

    private static string? InferSinkStyle(DebuggerObservation? dbg)
    {
        if (dbg is null)
            return null;

        var fn = (dbg.FaultingFunction ?? "").ToLowerInvariant();
        var disasm = (dbg.DisasmNearRip ?? "").ToLowerInvariant();

        if (fn.Contains("memcpy") || fn.Contains("memmove") || disasm.Contains("memcpy"))
            return "length→memcpy-style copy";
        if (fn.Contains("strcpy") || fn.Contains("strcat") || fn.Contains("strncpy") || fn.Contains("wcscpy"))
            return "C-string copy";
        if (fn.Contains("read") || fn.Contains("recv") || fn.Contains("fread"))
            return "read/recv boundary";
        if (fn.Contains("write") || fn.Contains("send"))
            return "write/send path";
        if (dbg.Access == DebuggerAccessKind.Write
            && (dbg.FaultAddressClass is (DebuggerAddressClass.NullPage
                    or DebuggerAddressClass.NearNull
                    or DebuggerAddressClass.SmallOffset)
                || IsExcludedFromRawInputAttribution(dbg.FaultAddress))
            && !IsStrongNonZeroPattern(dbg.FaultAddress))
            return "null/invalid destination write";
        if (dbg.Access == DebuggerAccessKind.Write && IsStrongNonZeroPattern(dbg.FaultAddress))
            return "controlled write";
        if (dbg.Access == DebuggerAccessKind.Write)
            return "write violation";
        if (dbg.Access == DebuggerAccessKind.Read
            && dbg.FaultAddressClass is (DebuggerAddressClass.NullPage
                or DebuggerAddressClass.NearNull
                or DebuggerAddressClass.SmallOffset))
            return "null/invalid destination read";
        if (dbg.Access == DebuggerAccessKind.Read && IsStrongNonZeroPattern(dbg.FaultAddress))
            return "controlled read";
        if (dbg.Access == DebuggerAccessKind.Read)
            return "read violation";
        return null;
    }

    private static int RegisterPriority(string register) =>
        register.ToLowerInvariant() switch
        {
            "fault" => 0,
            "rip" => 1,
            "rax" => 2,
            "rcx" => 3,
            "rdx" => 4,
            "rsi" => 5,
            "rdi" => 6,
            _ => 10,
        };

    private static bool ContainsToken(string mutator, HashSet<string> tokens)
    {
        foreach (var t in tokens)
        {
            if (mutator.Contains(t, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    private static bool LooksLikeAsciiPattern(string addr)
    {
        if (!TryParseUlong(addr, out var v))
            return false;
        var b0 = (byte)(v & 0xFF);
        var b1 = (byte)((v >> 8) & 0xFF);
        var b2 = (byte)((v >> 16) & 0xFF);
        var b3 = (byte)((v >> 24) & 0xFF);
        static bool Printable(byte b) => b is >= 0x20 and <= 0x7e;
        return Printable(b0) && Printable(b1) && Printable(b2) && Printable(b3)
               && (b0 == b1 || b0 is 0x41 or 0x42);
    }

    internal static byte[]? AddrToLittleEndianBytes(string addr, int width)
    {
        if (!TryParseUlong(addr, out var value))
            return null;
        var bytes = BitConverter.GetBytes(value);
        return bytes.AsSpan(0, width).ToArray();
    }

    internal static int IndexOf(byte[] haystack, byte[] needle)
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

    private static bool TryParseUlong(string addr, out ulong v)
    {
        v = 0;
        var h = addr.Trim();
        if (h.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            h = h[2..];
        h = h.Replace("`", "", StringComparison.Ordinal);
        return ulong.TryParse(h, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out v);
    }

    private static string? NormalizeAddr(string addr)
    {
        var a = addr.Trim().Replace("`", "", StringComparison.Ordinal);
        if (a.Length == 0)
            return null;
        if (!a.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            a = "0x" + a;
        return a;
    }

    [GeneratedRegex(@"\b(?<reg>r[a-z]{2,3}|eip|rip|rsp|esp|rbp|ebp)\s*=\s*(?<val>[0-9A-Fa-fx`]+)",
        RegexOptions.IgnoreCase)]
    private static partial Regex RegisterLine();
}
