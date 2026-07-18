using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Minimal C-like IDL → ProtocolDefinition stub field map.
/// Not MIDL/NDR — typedef struct with fixed scalar / array fields only.
/// </summary>
public static class IdlStubMapper
{
    private static readonly Regex StructRx = new(
        @"typedef\s+struct\s*(?:\w+\s*)?\{\s*(.*?)\s*\}\s*(\w+)\s*;",
        RegexOptions.Singleline | RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex FieldRx = new(
        @"^\s*(?<type>[A-Za-z_][\w\s\*]*?)\s+(?<name>[A-Za-z_]\w*)\s*(?:\[(?<len>[^\]]+)\])?\s*;",
        RegexOptions.Multiline | RegexOptions.Compiled);

    public sealed record ParseResult(
        string StructName,
        ProtocolDefinition Definition,
        List<(string RelativeSeed, byte[] Bytes)> SeedFiles,
        IReadOnlyList<string> FieldSummary,
        IReadOnlyList<string> Notes);

    public static ParseResult Parse(string idl, string? protocolName = null, string? description = null)
    {
        if (string.IsNullOrWhiteSpace(idl))
            throw new ArgumentException("IDL text is empty");

        var cleaned = Regex.Replace(idl, @"/\*.*?\*/", " ", RegexOptions.Singleline);
        cleaned = Regex.Replace(cleaned, @"//.*?$", "", RegexOptions.Multiline);

        var m = StructRx.Match(cleaned);
        if (!m.Success)
            throw new ArgumentException(
                "No typedef struct { … } Name; found. Minimal IDL only — see docs/RPC_LAB.md.");

        var structName = m.Groups[2].Value.Trim();
        var body = m.Groups[1].Value;
        var name = Sanitize(protocolName ?? structName);
        var notes = new List<string>
        {
            "Minimal IDL: fixed scalars/arrays only — no pointers, unions, or full NDR.",
        };

        var blocks = new List<ProtocolBlockDefinition>();
        var seeds = new List<(string RelativeSeed, byte[] Bytes)>();
        var summary = new List<string>();

        // Best-effort: uint32 len; byte data[len]; → sized
        var sizedPair = Regex.Match(body,
            @"(?:uint32_t|ULONG|DWORD|unsigned\s+long|unsigned\s+int)\s+(\w+)\s*;\s*(?:byte|UCHAR|unsigned\s+char|char)\s+(\w+)\s*\[\s*\1\s*\]\s*;",
            RegexOptions.IgnoreCase | RegexOptions.Singleline);
        if (sizedPair.Success)
        {
            var lenName = sizedPair.Groups[1].Value;
            var dataName = sizedPair.Groups[2].Value;
            var seedRel = $"seeds/idl_{name}_{Sanitize(dataName)}.bin";
            var seedBytes = Encoding.ASCII.GetBytes("PAYLOAD");
            seeds.Add((seedRel, seedBytes));
            blocks.Add(new ProtocolBlockDefinition
            {
                Type = "sized",
                LengthName = lenName,
                LengthBytes = 4,
                LittleEndian = true,
                LengthMutable = true,
                Child = new ProtocolBlockDefinition
                {
                    Type = "bytes",
                    Name = dataName,
                    Mutable = true,
                    MinSize = 1,
                    MaxSize = 8192,
                    SeedFile = seedRel,
                },
            });
            summary.Add($"{lenName}+{dataName}: sized u32le → bytes");
            notes.Add($"Mapped length-prefixed pair {lenName}/{dataName} as sized.");
            body = body.Remove(sizedPair.Index, sizedPair.Length);
        }

        foreach (Match f in FieldRx.Matches(body))
        {
            var rawType = Regex.Replace(f.Groups["type"].Value.Trim(), @"\s+", " ");
            var fieldName = f.Groups["name"].Value;
            var lenTok = f.Groups["len"].Success ? f.Groups["len"].Value.Trim() : null;

            if (rawType.Contains('*', StringComparison.Ordinal))
            {
                notes.Add($"Skipped pointer field {fieldName} — not supported in minimal IDL.");
                continue;
            }

            if (!TryMapField(rawType, lenTok, fieldName, name, blocks, seeds, summary, notes))
                notes.Add($"Skipped unsupported type '{rawType}' on {fieldName}.");
        }

        if (blocks.Count == 0)
            throw new ArgumentException("No mappable fields in typedef struct.");

        return new ParseResult(
            structName,
            new ProtocolDefinition
            {
                Name = name,
                Description = description ?? $"IDL stub map from struct {structName}",
                Blocks = blocks,
            },
            seeds,
            summary,
            notes);
    }

    private static bool TryMapField(
        string rawType,
        string? lenTok,
        string fieldName,
        string protocolName,
        List<ProtocolBlockDefinition> blocks,
        List<(string RelativeSeed, byte[] Bytes)> seeds,
        List<string> summary,
        List<string> notes)
    {
        var t = rawType.ToLowerInvariant();

        if (lenTok is not null)
        {
            if (!int.TryParse(lenTok, NumberStyles.Integer, CultureInfo.InvariantCulture, out var n) || n <= 0)
                throw new ArgumentException($"Array length must be a positive integer (got [{lenTok}]).");

            var isWide = t is "wchar_t" or "wchar" or "olechar" || t.Contains("wchar", StringComparison.Ordinal);
            var byteLen = isWide ? n * 2 : n;
            byteLen = Math.Clamp(byteLen, 1, 65536);
            var seedRel = $"seeds/idl_{protocolName}_{Sanitize(fieldName)}.bin";
            byte[] seedBytes;
            if (isWide)
            {
                seedBytes = Encoding.Unicode.GetBytes(new string('A', Math.Max(1, n)));
                if (seedBytes.Length != byteLen)
                    Array.Resize(ref seedBytes, byteLen);
                notes.Add($"{fieldName}: wchar[{n}] → UTF-16LE bytes[{byteLen}] (YAML string is ASCII-only).");
            }
            else
            {
                seedBytes = Enumerable.Repeat((byte)'A', byteLen).ToArray();
            }

            seeds.Add((seedRel, seedBytes));
            blocks.Add(new ProtocolBlockDefinition
            {
                Type = "bytes",
                Name = fieldName,
                Mutable = true,
                MinSize = byteLen,
                MaxSize = Math.Max(byteLen * 4, 4096),
                SeedFile = seedRel,
            });
            summary.Add($"{fieldName}: bytes[{byteLen}]{(isWide ? " utf16" : "")}");
            return true;
        }

        string? intType = t switch
        {
            "uint16_t" or "int16_t" or "ushort" or "short" or "unsigned short" or "word" => "word",
            "uint32_t" or "int32_t" or "ulong" or "unsigned long" or "unsigned int" or "int"
                or "dword" or "long" => "dword",
            "uint64_t" or "int64_t" or "ulonglong" or "unsigned long long" or "qword" => "qword",
            _ => null,
        };

        if (intType is not null)
        {
            blocks.Add(new ProtocolBlockDefinition
            {
                Type = intType,
                Name = fieldName,
                Value = "0",
                Mutable = true,
                LittleEndian = true,
            });
            summary.Add($"{fieldName}: {intType} LE");
            return true;
        }

        // uint8 / byte scalar → 1-byte fuzzable buffer
        if (t is "uint8_t" or "int8_t" or "byte" or "uchar" or "unsigned char" or "char" or "boolean")
        {
            var seedRel = $"seeds/idl_{protocolName}_{Sanitize(fieldName)}.bin";
            seeds.Add((seedRel, [0x00]));
            blocks.Add(new ProtocolBlockDefinition
            {
                Type = "bytes",
                Name = fieldName,
                Mutable = true,
                MinSize = 1,
                MaxSize = 16,
                SeedFile = seedRel,
            });
            summary.Add($"{fieldName}: bytes[1]");
            return true;
        }

        if (t is "wchar_t" or "wchar")
            throw new ArgumentException("Bare wchar_t needs an array length, e.g. wchar_t name[32];");

        return false;
    }

    private static string Sanitize(string raw)
    {
        var s = Regex.Replace(raw.Trim().ToLowerInvariant(), @"[^a-z0-9_\-]+", "_").Trim('_');
        return string.IsNullOrEmpty(s) ? "idl_stub" : s;
    }
}
