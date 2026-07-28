using System.Globalization;
using System.Text.RegularExpressions;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Static reconstruction of faulting x86/x64 memory operands from <c>u @rip</c> / disasm text
/// plus a register dump. Research-only — no TTD required.
/// Fixture-tested for forms like <c>mov dword ptr [rax-2Ch],ecx</c> (RAX=0x2C → EA=0).
/// </summary>
public static class EffectiveAddressReconstructor
{
    // Optional CDB prefix: address + optional opcode bytes (packed or spaced; linear — no ReDoS).
    private const string InsnPrefix =
        @"(?:[0-9a-fA-F`]{4,}\s+(?:(?:[0-9a-fA-F]{2}\s+)+|[0-9a-fA-F]{2,}\s+)?)?";

    // mov dword ptr [rax-2Ch],ecx
    // mov qword ptr [rbx+rcx*8+10h],rax
    // mov byte ptr [rsi],al
    // lea rax,[rip+1234h]
    private static readonly Regex MemWrite = new(
        @"^\s*" + InsnPrefix + @"(?<mnem>mov|add|sub|xor|or|and|xchg|lea)\s+"
        + @"(?:(?<width>byte|word|dword|qword)\s+ptr\s+)?"
        + @"\[(?<mem>[^\]]+)\]\s*,\s*(?<src>[^\s,;]+)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex MemRead = new(
        @"^\s*" + InsnPrefix + @"(?<mnem>mov|add|sub|xor|or|and|xchg|lea|cmp|test)\s+"
        + @"(?<dst>[^\s,\[]+)\s*,\s*"
        + @"(?:(?<width>byte|word|dword|qword)\s+ptr\s+)?"
        + @"\[(?<mem>[^\]]+)\]",
        RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.CultureInvariant);

    /// <summary>
    /// Reconstruct EA from a faulting instruction line + register dump.
    /// When <paramref name="faultAddress"/> is present, compares computed EA to it.
    /// </summary>
    public static EffectiveAddressDto Reconstruct(
        string? disasmOrInstruction,
        string? registersText,
        string? preferRip = null,
        DebuggerAccessKind access = DebuggerAccessKind.Unknown,
        string? faultAddress = null)
    {
        var insn = PickFaultInstruction(disasmOrInstruction, preferRip);
        if (string.IsNullOrWhiteSpace(insn))
        {
            return Unknown(
                instruction: null,
                mnemonic: null,
                honesty: nameof(ExploitClaimKind.Unverified),
                note: "UNKNOWN — no parseable faulting instruction in u @rip / disasm (symbol-path noise rejected).",
                access: access,
                faultAddress: faultAddress);
        }

        var write = MemWrite.Match(insn);
        if (write.Success)
            return BuildFromMatch(insn, write, isWrite: true, registersText, preferRip, access, faultAddress);

        var read = MemRead.Match(insn);
        if (read.Success)
            return BuildFromMatch(insn, read, isWrite: false, registersText, preferRip, access, faultAddress);

        // Instruction line is real but memory operand not decoded — show insn honestly, EA UNKNOWN.
        return Unknown(
            instruction: insn.Trim(),
            mnemonic: TryMnemonic(insn),
            honesty: nameof(ExploitClaimKind.Hypothesized),
            note: "UNKNOWN — instruction seen but memory operand not decoded (no symbol-path fallback).",
            access: access,
            faultAddress: faultAddress);
    }

    private static EffectiveAddressDto Unknown(
        string? instruction,
        string? mnemonic,
        string honesty,
        string note,
        DebuggerAccessKind access,
        string? faultAddress)
    {
        var faultHex = NormalizeAddressHex(faultAddress);
        return new EffectiveAddressDto(
            Ok: false,
            Instruction: instruction,
            Mnemonic: mnemonic,
            WidthLabel: "unknown",
            WidthBytes: null,
            BaseRegister: null,
            IndexRegister: null,
            Scale: 1,
            Displacement: 0,
            SourceRegister: null,
            DestinationRegister: null,
            EffectiveAddressHex: null,
            ValueHex: null,
            AccessKind: access == DebuggerAccessKind.Unknown ? null : access.ToString(),
            Honesty: honesty,
            Note: note,
            ReconstructionKind: "Static",
            Expression: null,
            MatchesFaultAddress: null,
            FaultAddressHex: faultHex);
    }

    private static EffectiveAddressDto BuildFromMatch(
        string insn,
        Match m,
        bool isWrite,
        string? registersText,
        string? preferRip,
        DebuggerAccessKind access,
        string? faultAddress)
    {
        var mnem = m.Groups["mnem"].Value.ToLowerInvariant();
        var widthLabel = m.Groups["width"].Success
            ? m.Groups["width"].Value.ToLowerInvariant()
            : "unknown";
        var widthBytes = WidthBytes(widthLabel);
        var mem = m.Groups["mem"].Value.Replace(" ", "", StringComparison.Ordinal);
        ParseMem(mem, out var baseReg, out var indexReg, out var scale, out var disp);

        string? src = null;
        string? dst = null;
        if (isWrite)
            src = NormalizeReg(m.Groups["src"].Value);
        else
            dst = NormalizeReg(m.Groups["dst"].Value);

        var regs = ParseRegisters(registersText);
        // Prefer dump RIP; fall back to preferRip / line address for RIP-relative.
        EnsureRip(regs, preferRip, insn);

        ulong? ea = null;
        string? eaNote = null;
        var isRipRel = string.Equals(baseReg, "rip", StringComparison.OrdinalIgnoreCase)
                       || string.Equals(baseReg, "eip", StringComparison.OrdinalIgnoreCase);

        if (isRipRel)
        {
            if (regs.TryGetValue("rip", out var ripVal))
            {
                var insnLen = TryInsnByteLength(insn);
                long eaSigned = unchecked((long)ripVal);
                if (insnLen is int len)
                {
                    eaSigned += len;
                }
                else
                {
                    eaNote = "RIP-relative: instruction length unknown — used RIP+disp (may be off by insn size)";
                }

                eaSigned += disp;
                ea = unchecked((ulong)eaSigned);
            }
            else
            {
                eaNote = "base rip missing from register dump";
            }
        }
        else if (baseReg is not null && regs.TryGetValue(CanonicalReg(baseReg), out var baseVal))
        {
            long eaSigned = unchecked((long)baseVal);
            if (indexReg is not null)
            {
                if (regs.TryGetValue(CanonicalReg(indexReg), out var indexVal))
                    eaSigned += unchecked((long)indexVal) * scale;
                else
                    eaNote = $"index {indexReg} missing from register dump";
            }

            eaSigned += disp;
            ea = unchecked((ulong)eaSigned);
        }
        else if (baseReg is null && indexReg is not null)
        {
            // [index*scale(+disp)]
            if (regs.TryGetValue(CanonicalReg(indexReg), out var indexVal))
            {
                long eaSigned = unchecked((long)indexVal) * scale + disp;
                ea = unchecked((ulong)eaSigned);
            }
            else
            {
                eaNote = $"index {indexReg} missing from register dump";
            }
        }
        else if (baseReg is null && indexReg is null)
        {
            ea = unchecked((ulong)disp);
        }
        else
        {
            eaNote = baseReg is null
                ? "no base register in operand"
                : $"base {baseReg} missing from register dump";
        }

        string? valueHex = null;
        if (src is not null && regs.TryGetValue(CanonicalReg(src), out var srcVal))
            valueHex = FormatHex(srcVal, widthBytes ?? 8);
        else if (dst is not null && regs.TryGetValue(CanonicalReg(dst), out var dstVal) && !isWrite)
            valueHex = FormatHex(dstVal, widthBytes ?? 8);

        var accessKind = access != DebuggerAccessKind.Unknown
            ? access.ToString()
            : isWrite ? nameof(DebuggerAccessKind.Write) : nameof(DebuggerAccessKind.Read);

        var expression = FormatExpression(baseReg, indexReg, scale, disp);
        var faultHex = NormalizeAddressHex(faultAddress);
        bool? matchesFault = null;
        if (ea is ulong computed && faultHex is not null)
        {
            var eaHex = NormalizeAddressHex($"0x{computed:X}");
            matchesFault = string.Equals(eaHex, faultHex, StringComparison.OrdinalIgnoreCase);
            if (matchesFault == false)
                eaNote = AppendNote(eaNote, $"computed EA 0x{computed:X} ≠ fault {faultHex}");
            else
                eaNote = AppendNote(eaNote, "matches debugger fault address");
        }

        var honesty = ea is not null
            ? nameof(ExploitClaimKind.Observed)
            : nameof(ExploitClaimKind.Hypothesized);

        var note = ea is not null
            ? $"EA = {expression}"
              + (eaNote is not null ? $" ({eaNote})" : "")
            : eaNote ?? "UNKNOWN — could not compute effective address.";

        return new EffectiveAddressDto(
            Ok: true,
            Instruction: insn.Trim(),
            Mnemonic: mnem,
            WidthLabel: widthLabel,
            WidthBytes: widthBytes,
            BaseRegister: baseReg,
            IndexRegister: indexReg,
            Scale: scale,
            Displacement: disp,
            SourceRegister: src,
            DestinationRegister: dst,
            EffectiveAddressHex: ea is ulong e ? $"0x{e:X}" : null,
            ValueHex: valueHex,
            AccessKind: accessKind,
            Honesty: honesty,
            Note: note,
            ReconstructionKind: "Static",
            Expression: expression,
            MatchesFaultAddress: matchesFault,
            FaultAddressHex: faultHex);
    }

    internal static void ParseMem(
        string mem,
        out string? baseReg,
        out string? indexReg,
        out int scale,
        out long disp)
    {
        baseReg = null;
        indexReg = null;
        scale = 1;
        disp = 0;
        var cleaned = mem.Trim().Replace(" ", "", StringComparison.Ordinal)
            .Replace("ptr", "", StringComparison.OrdinalIgnoreCase).Trim();

        // Peel trailing displacement first so "rax-2Ch" does not treat 2Ch as an index reg.
        var dispMatch = Regex.Match(
            cleaned,
            @"(?<disp>[+-](?:0x)?[0-9a-fA-F]+h?)$",
            RegexOptions.IgnoreCase);
        var head = cleaned;
        if (dispMatch.Success)
        {
            TryParseDisp(dispMatch.Groups["disp"].Value, out disp);
            head = cleaned[..dispMatch.Index];
        }
        else if (TryParseDisp(cleaned, out disp) && !Regex.IsMatch(cleaned, @"[a-z]", RegexOptions.IgnoreCase))
        {
            return; // displacement-only
        }

        if (string.IsNullOrEmpty(head))
            return;

        // Forms (after disp peel):
        //   base
        //   base+index
        //   base+index*scale
        //   index*scale
        var indexed = Regex.Match(
            head,
            @"^(?:(?<base>[a-z][a-z0-9]*)\+)?(?<index>[a-z][a-z0-9]*)\*(?<scale>[1248])$",
            RegexOptions.IgnoreCase);
        if (indexed.Success)
        {
            if (indexed.Groups["base"].Success)
                baseReg = NormalizeReg(indexed.Groups["base"].Value);
            indexReg = NormalizeReg(indexed.Groups["index"].Value);
            if (int.TryParse(indexed.Groups["scale"].Value, out var sc))
                scale = sc;
            return;
        }

        var basePlusIndex = Regex.Match(
            head,
            @"^(?<base>[a-z][a-z0-9]*)\+(?<index>[a-z][a-z0-9]*)$",
            RegexOptions.IgnoreCase);
        if (basePlusIndex.Success)
        {
            baseReg = NormalizeReg(basePlusIndex.Groups["base"].Value);
            indexReg = NormalizeReg(basePlusIndex.Groups["index"].Value);
            return;
        }

        var baseOnly = Regex.Match(head, @"^(?<base>[a-z][a-z0-9]*)$", RegexOptions.IgnoreCase);
        if (baseOnly.Success)
            baseReg = NormalizeReg(baseOnly.Groups["base"].Value);
    }

    private static bool TryParseDisp(string raw, out long disp)
    {
        disp = 0;
        var s = raw.Trim();
        if (string.IsNullOrEmpty(s))
            return false;
        var neg = s.StartsWith('-');
        var body = s.TrimStart('+', '-');
        var hexSuffix = body.EndsWith("h", StringComparison.OrdinalIgnoreCase);
        if (hexSuffix)
            body = body[..^1];
        if (body.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            body = body[2..];
            hexSuffix = true;
        }

        NumberStyles style = hexSuffix || body.Any(c => c is >= 'a' and <= 'f' or >= 'A' and <= 'F')
            ? NumberStyles.HexNumber
            : NumberStyles.Integer;
        if (!ulong.TryParse(body, style, CultureInfo.InvariantCulture, out var u))
        {
            // Intel displacements are hex even without suffix when letters present; retry hex.
            if (style != NumberStyles.HexNumber
                && ulong.TryParse(body, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out u))
            {
                disp = neg ? -unchecked((long)u) : unchecked((long)u);
                return true;
            }

            return false;
        }

        disp = neg ? -unchecked((long)u) : unchecked((long)u);
        return true;
    }

    internal static Dictionary<string, ulong> ParseRegisters(string? registersText)
    {
        var map = new Dictionary<string, ulong>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(registersText))
            return map;
        foreach (Match m in Regex.Matches(
                     registersText,
                     @"\b([re]?[abcd]x|[re]?[sd]i|[re]?[sb]p|r(?:8|9|1[0-5])|[re]?ip|eflags|rax|rbx|rcx|rdx|rsi|rdi|rbp|rsp|rip)\s*=\s*`?([0-9a-fA-F]+)`?",
                     RegexOptions.IgnoreCase))
        {
            var name = CanonicalReg(m.Groups[1].Value);
            var hex = m.Groups[2].Value.Replace("`", "", StringComparison.Ordinal);
            if (ulong.TryParse(hex, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var v))
                map[name] = v;
        }

        // Also accept "rax 0000000000000123" cdb columnar form
        foreach (Match m in Regex.Matches(
                     registersText,
                     @"\b([re]?[abcd]x|[re]?[sd]i|[re]?[sb]p|r(?:8|9|1[0-5])|rip)\s+([0-9a-fA-F]{4,16})\b",
                     RegexOptions.IgnoreCase))
        {
            var name = CanonicalReg(m.Groups[1].Value);
            if (map.ContainsKey(name))
                continue;
            if (ulong.TryParse(m.Groups[2].Value, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var v))
                map[name] = v;
        }

        return map;
    }

    private static void EnsureRip(Dictionary<string, ulong> regs, string? preferRip, string insn)
    {
        if (regs.ContainsKey("rip"))
            return;
        if (TryParseAddress(preferRip, out var fromPrefer))
        {
            regs["rip"] = fromPrefer;
            return;
        }

        // Leading address on a CDB u @rip line.
        var m = Regex.Match(insn.Trim(), @"^([0-9a-fA-F`]+)\s+");
        if (m.Success && TryParseAddress(m.Groups[1].Value, out var fromLine))
            regs["rip"] = fromLine;
    }

    /// <summary>Count opcode bytes between address and mnemonic on a CDB line (for RIP-relative).</summary>
    internal static int? TryInsnByteLength(string insn)
    {
        // 00007ff6`12340100 8948d4  mov ...
        // 00007ff6`12340100 48 89 48 d4  mov ...
        var m = Regex.Match(
            insn.Trim(),
            @"^[0-9a-fA-F`]+\s+((?:[0-9a-fA-F]{2}\s+)+|[0-9a-fA-F]{2,})\s+(?:mov|lea|add|sub|xor|or|and|xchg|cmp|test)\b",
            RegexOptions.IgnoreCase);
        if (!m.Success)
            return null;
        var bytes = m.Groups[1].Value.Replace(" ", "", StringComparison.Ordinal);
        if (bytes.Length < 2 || bytes.Length % 2 != 0)
            return null;
        if (!bytes.All(c => Uri.IsHexDigit(c)))
            return null;
        return bytes.Length / 2;
    }

    private static string CanonicalReg(string reg)
    {
        var r = NormalizeReg(reg) ?? reg.ToLowerInvariant();
        return r switch
        {
            "eax" or "ax" or "al" or "ah" => "rax",
            "ebx" or "bx" or "bl" or "bh" => "rbx",
            "ecx" or "cx" or "cl" or "ch" => "rcx",
            "edx" or "dx" or "dl" or "dh" => "rdx",
            "esi" or "si" or "sil" => "rsi",
            "edi" or "di" or "dil" => "rdi",
            "ebp" or "bp" or "bpl" => "rbp",
            "esp" or "sp" or "spl" => "rsp",
            "eip" => "rip",
            _ => r,
        };
    }

    private static string? NormalizeReg(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return null;
        var r = raw.Trim().TrimStart('%').ToLowerInvariant();
        // strip size casts
        if (r.StartsWith("dword", StringComparison.Ordinal) || r.StartsWith("qword", StringComparison.Ordinal))
            return null;
        return Regex.Replace(r, @"[^a-z0-9]", "");
    }

    private static int? WidthBytes(string label) => label switch
    {
        "byte" => 1,
        "word" => 2,
        "dword" => 4,
        "qword" => 8,
        _ => null,
    };

    private static string FormatHex(ulong value, int widthBytes)
    {
        var mask = widthBytes switch
        {
            1 => 0xFFUL,
            2 => 0xFFFFUL,
            4 => 0xFFFFFFFFUL,
            _ => ulong.MaxValue,
        };
        if (widthBytes is 1 or 2 or 4)
            value &= mask;
        return widthBytes switch
        {
            1 => $"0x{value:X2}",
            2 => $"0x{value:X4}",
            4 => $"0x{value:X8}",
            _ => $"0x{value:X}",
        };
    }

    private static string FormatExpression(string? baseReg, string? indexReg, int scale, long disp)
    {
        var parts = new List<string>();
        if (baseReg is not null)
            parts.Add(baseReg);
        if (indexReg is not null)
            parts.Add(scale == 1 ? indexReg : $"{indexReg}*{scale}");
        if (disp != 0 || parts.Count == 0)
        {
            var dispLabel = disp switch
            {
                0 => "0",
                > 0 and <= 9 => disp.ToString(CultureInfo.InvariantCulture),
                > 0 => $"0x{disp:X}",
                < 0 and >= -9 => $"({disp})",
                _ => $"(-0x{-disp:X})",
            };
            parts.Add(dispLabel);
        }

        return string.Join(" + ", parts);
    }

    private static string? TryMnemonic(string insn)
    {
        var m = Regex.Match(insn, @"\b(mov|add|sub|xor|lea|cmp|test|call|jmp|ret|xchg|or|and)\b", RegexOptions.IgnoreCase);
        return m.Success ? m.Groups[1].Value.ToLowerInvariant() : null;
    }

    /// <summary>
    /// Prefer marker/RIP-matched instruction lines; never accept symbol-path noise as the fault insn.
    /// </summary>
    private static string? PickFaultInstruction(string? text, string? preferRip)
    {
        var extracted = ScreamInvestigator.ExtractFaultInstructionLine(text, preferRip);
        if (!string.IsNullOrWhiteSpace(extracted) && !ScreamInvestigator.LooksLikeCdbNoise(extracted))
            return extracted;

        return FirstInstructionish(text);
    }

    private static string? FirstInstructionish(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
            return null;
        foreach (var line in text.Split('\n'))
        {
            var t = line.Trim();
            if (t.Length < 5 || ScreamInvestigator.LooksLikeCdbNoise(t))
                continue;
            if (ScreamInvestigator.LooksLikeInstructionLine(t))
                return t;
            // Bare fixture / stripped form: mov dword ptr [rax-2Ch],ecx
            if (Regex.IsMatch(
                    t,
                    @"^(?:[0-9a-fA-F`]+\s+(?:[0-9a-fA-F]{2}\s+)*)?(mov|add|sub|lea|cmp|xor|xchg|or|and|test)\b.+\[[^\]]+\]",
                    RegexOptions.IgnoreCase))
                return t;
        }

        return null;
    }

    internal static string? NormalizeAddressHex(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return null;
        if (!TryParseAddress(raw, out var v))
            return null;
        return $"0x{v:X}";
    }

    private static bool TryParseAddress(string? raw, out ulong value)
    {
        value = 0;
        if (string.IsNullOrWhiteSpace(raw))
            return false;
        var s = raw.Trim()
            .Replace("`", "", StringComparison.Ordinal)
            .Replace("0x", "", StringComparison.OrdinalIgnoreCase);
        return ulong.TryParse(s, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out value);
    }

    private static string AppendNote(string? existing, string add) =>
        string.IsNullOrWhiteSpace(existing) ? add : $"{existing}; {add}";
}
