using System.Globalization;
using System.Text.RegularExpressions;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Static reconstruction of faulting x86/x64 memory operands from <c>u @rip</c> / disasm text
/// plus a register dump. Research-only — no TTD required.
/// Fixture-tested for forms like <c>mov dword ptr [rax-2Ch],ecx</c>.
/// </summary>
public static class EffectiveAddressReconstructor
{
    // Optional CDB prefix: address + raw bytes before the mnemonic (packed or spaced).
    private const string InsnPrefix =
        @"(?:(?:[0-9a-fA-F`]+|\s|[0-9a-fA-F]{2})+?\s+)?";

    // mov dword ptr [rax-2Ch],ecx
    // mov qword ptr [rbx+rcx*8+10h],rax
    // mov byte ptr [rsi],al
    private static readonly Regex MemWrite = new(
        @"^\s*" + InsnPrefix + @"(?<mnem>mov|add|sub|xor|or|and|xchg|lea)\s+"
        + @"(?:(?<width>byte|word|dword|qword)\s+ptr\s+)?"
        + @"\[(?<mem>[^\]]+)\]\s*,\s*(?<src>[^\s,;]+)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex MemRead = new(
        @"^\s*" + InsnPrefix + @"(?<mnem>mov|add|sub|xor|or|and|xchg|lea|cmp|test)\s+"
        + @"(?<dst>[^\s,\[]+)\s*,\s*"
        + @"(?:(?<width>byte|word|dword|qword)\s+ptr\s+)?"
        + @"\[(?<mem>[^\]]+)\]",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex MemOp = new(
        @"^(?:(?<base>[a-z0-9]+))?"
        + @"(?:\+(?<index>[a-z0-9]+)(?:\*(?<scale>[1248]))?)?"
        + @"(?<disp>[+-](?:0x)?[0-9a-fA-Fh]+)?$"
        + @"|^(?<dispOnly>[+-]?(?:0x)?[0-9a-fA-Fh]+)$",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public static EffectiveAddressDto Reconstruct(
        string? disasmOrInstruction,
        string? registersText,
        string? preferRip = null,
        DebuggerAccessKind access = DebuggerAccessKind.Unknown)
    {
        var insn = ScreamInvestigator.ExtractFaultInstructionLine(disasmOrInstruction, preferRip)
                   ?? FirstInstructionish(disasmOrInstruction);
        if (string.IsNullOrWhiteSpace(insn))
        {
            return new EffectiveAddressDto(
                false, null, null, "unknown", null, null, null, 1, 0, null, null, null, null,
                access == DebuggerAccessKind.Unknown ? null : access.ToString(),
                nameof(ExploitClaimKind.Unverified),
                "No parseable faulting instruction in u @rip / disasm.",
                "Static");
        }

        var write = MemWrite.Match(insn);
        if (write.Success)
            return BuildFromMatch(insn, write, isWrite: true, registersText, access);

        var read = MemRead.Match(insn);
        if (read.Success)
            return BuildFromMatch(insn, read, isWrite: false, registersText, access);

        return new EffectiveAddressDto(
            false, insn.Trim(), TryMnemonic(insn), "unknown", null, null, null, 1, 0, null, null, null, null,
            access == DebuggerAccessKind.Unknown ? null : access.ToString(),
            nameof(ExploitClaimKind.Hypothesized),
            "Instruction seen but memory operand not decoded.",
            "Static");
    }

    private static EffectiveAddressDto BuildFromMatch(
        string insn,
        Match m,
        bool isWrite,
        string? registersText,
        DebuggerAccessKind access)
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
        ulong? ea = null;
        string? eaNote = null;
        if (baseReg is not null && regs.TryGetValue(CanonicalReg(baseReg), out var baseVal))
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

        var honesty = ea is not null
            ? nameof(ExploitClaimKind.Observed)
            : nameof(ExploitClaimKind.Hypothesized);

        var note = ea is not null
            ? $"EA = {(baseReg ?? "0")}"
              + (indexReg is not null ? $" + {indexReg}*{scale}" : "")
              + (disp != 0 ? $" + {disp:+#;-#;0}" : "")
              + (eaNote is not null ? $" ({eaNote})" : "")
            : eaNote ?? "Could not compute effective address.";

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
            ReconstructionKind: "Static");
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

        // base
        // base+index
        // base+index*scale
        // index*scale  (rare)
        var m = Regex.Match(
            head,
            @"^(?:(?<base>[a-z][a-z0-9]*))?(?:\+(?<index>[a-z][a-z0-9]*)(?:\*(?<scale>[1248]))?)?$",
            RegexOptions.IgnoreCase);
        if (!m.Success)
            return;
        if (m.Groups["base"].Success)
            baseReg = NormalizeReg(m.Groups["base"].Value);
        if (m.Groups["index"].Success)
            indexReg = NormalizeReg(m.Groups["index"].Value);
        if (m.Groups["scale"].Success && int.TryParse(m.Groups["scale"].Value, out var sc))
            scale = sc;
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

    private static string? TryMnemonic(string insn)
    {
        var m = Regex.Match(insn, @"\b(mov|add|sub|xor|lea|cmp|test|call|jmp|ret)\b", RegexOptions.IgnoreCase);
        return m.Success ? m.Groups[1].Value.ToLowerInvariant() : null;
    }

    private static string? FirstInstructionish(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
            return null;
        foreach (var line in text.Split('\n'))
        {
            var t = line.Trim();
            if (t.Length > 8 && Regex.IsMatch(t, @"\b(mov|add|sub|lea|cmp|xor)\b", RegexOptions.IgnoreCase))
                return t;
        }

        return null;
    }
}
