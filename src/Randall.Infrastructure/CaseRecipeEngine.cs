using System.Globalization;
using System.Text;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// CyberChef-style case recipes inspired by Sulley blocks (static/string/delim)
/// and AFL seed/dictionary practice — build bytes, then mutate in the fuzzer.
/// </summary>
public static class CaseRecipeEngine
{
    public static IReadOnlyList<CaseOpDto> ListOps() =>
    [
        new("static", "Static text", "Literal UTF-8 — Sulley s_static (keep as-is in seed)", "text",
            ["value", "role"]),
        new("text", "Text / string", "UTF-8 string — Sulley s_string (good dictionary hint)", "text",
            ["value", "role"]),
        new("delim", "Delimiter", "Space, colon, slash, CRLF, … — Sulley s_delim", "text",
            ["value", "role"]),
        new("hex", "Hex bytes", "Raw bytes from hex (spaces/dashes ok)", "binary",
            ["value"]),
        new("repeat", "Repeat", "Repeat a byte/char N times (AAAA…)", "binary",
            ["value", "count"]),
        new("random", "Random bytes", "N cryptographically random bytes", "binary",
            ["count"]),
        new("interesting", "Interesting int", "AFL-style interesting 8/16/32-bit value", "binary",
            ["format", "value"]),
        new("null", "Null byte", "Single 0x00", "binary", []),
        new("crlf", "CRLF", "\\r\\n", "text", []),
        new("lf", "LF", "Single \\n", "text", []),
        new("base64", "Base64 decode", "Decode base64 into bytes", "binary",
            ["value"]),
        new("utf16", "UTF-16LE text", "Windows-style wide string (no NUL terminator)", "text",
            ["value", "role"]),
        new("quote", "Quoted string", "Wrap value in \"…\" (role applies to inner)", "text",
            ["value", "role"]),
        new("pad", "Pad / align", "Pad the next block to N bytes with 0x00 (or value)", "binary",
            ["count", "value"]),
        new("fill", "Fill range", "N bytes of a single value (0x00 / 0xFF / char)", "binary",
            ["count", "value"]),
        new("cyclic", "Cyclic pattern", "Unique pattern length N (depth triage)", "binary",
            ["count"]),
        new("len-prefix", "Length prefix", "u8/u16/u32 LE|BE of the following payload size", "binary",
            ["format"]),
    ];

    public static CasePreviewDto Preview(IReadOnlyList<CaseStepDto> steps)
    {
        var (bytes, hints, notes) = Render(steps);
        var previewLen = Math.Min(bytes.Length, 256);
        var hexPreview = ToHex(bytes.AsSpan(0, previewLen));
        if (bytes.Length > previewLen)
            hexPreview += " …";
        var ascii = ToAscii(bytes.AsSpan(0, previewLen));
        if (bytes.Length > previewLen)
            ascii += " …";
        return new CasePreviewDto(
            bytes.Length,
            hexPreview,
            ascii,
            Convert.ToHexString(bytes),
            hints,
            notes);
    }

    public static (byte[] Bytes, List<string> Hints, List<string> Notes) Render(IReadOnlyList<CaseStepDto> steps)
    {
        var parts = new List<byte[]>();
        var hints = new List<string>();
        var notes = new List<string>();
        var pendingLenFormat = (string?)null;
        var pendingPad = ((int Count, byte Fill)?)null;

        foreach (var step in steps)
        {
            var op = (step.Op ?? "").Trim().ToLowerInvariant();
            if (op is "len-prefix" or "length" or "size")
            {
                pendingLenFormat = string.IsNullOrWhiteSpace(step.Format) ? "u16le" : step.Format!;
                notes.Add($"Length prefix ({pendingLenFormat}) applies to the next block.");
                continue;
            }

            if (op is "pad" or "align")
            {
                var fill = ParsePadByte(step.Value);
                pendingPad = (Math.Clamp(step.Count ?? 16, 0, 1_000_000), fill);
                notes.Add($"Pad to {pendingPad.Value.Count} bytes applies to the next block.");
                continue;
            }

            var chunk = RenderStep(step);
            if (pendingLenFormat is not null)
            {
                parts.Add(EncodeLength(chunk.Length, pendingLenFormat));
                pendingLenFormat = null;
            }

            if (pendingPad is not null)
            {
                var (padTo, fill) = pendingPad.Value;
                if (chunk.Length < padTo)
                {
                    var padded = new byte[padTo];
                    Buffer.BlockCopy(chunk, 0, padded, 0, chunk.Length);
                    Array.Fill(padded, fill, chunk.Length, padTo - chunk.Length);
                    chunk = padded;
                }
                pendingPad = null;
            }

            parts.Add(chunk);

            var role = (step.Role ?? "fuzzable").Trim().ToLowerInvariant();
            if ((role is "fuzzable" or "string") &&
                (op is "text" or "string" or "delim" or "quote" or "utf16") &&
                !string.IsNullOrWhiteSpace(step.Value) &&
                step.Value!.Length is > 0 and < 200)
            {
                hints.Add(step.Value!);
            }
        }

        if (pendingLenFormat is not null)
            notes.Add("Warning: length-prefix had no following block.");
        if (pendingPad is not null)
            notes.Add("Warning: pad had no following block.");

        var total = parts.Sum(p => p.Length);
        var buf = new byte[total];
        var o = 0;
        foreach (var p in parts)
        {
            Buffer.BlockCopy(p, 0, buf, o, p.Length);
            o += p.Length;
        }

        if (hints.Count == 0)
            notes.Add("Tip: mark string/delim blocks as fuzzable to harvest dictionary tokens.");

        return (buf, hints.Distinct(StringComparer.Ordinal).ToList(), notes);
    }

    /// <summary>Turn raw seed bytes into a best-effort recipe (hex / text / CRLF split).</summary>
    public static CaseImportBytesDto SuggestFromBytes(byte[] bytes)
    {
        var previewLen = Math.Min(bytes.Length, 64);
        var steps = new List<CaseStepDto>();
        if (bytes.Length == 0)
            return new CaseImportBytesDto(0, "", "", steps);

        var asciiRatio = bytes.Count(b => b is >= 32 and <= 126 or 9 or 10 or 13) / (double)bytes.Length;
        if (asciiRatio >= 0.85)
        {
            var text = Encoding.UTF8.GetString(bytes);
            var parts = text.Split(["\r\n", "\n"], StringSplitOptions.None);
            for (var i = 0; i < parts.Length; i++)
            {
                if (parts[i].Length > 0)
                {
                    var looksStatic = parts[i] is "GET" or "POST" or "HTTP/1.0" or "HTTP/1.1" or
                                      "USER" or "PASS" or "QUIT" or "TRUN" or "GMON";
                    steps.Add(new CaseStepDto("text", parts[i], Role: looksStatic ? "static" : "fuzzable"));
                }
                if (i < parts.Length - 1)
                    steps.Add(new CaseStepDto(text.Contains("\r\n", StringComparison.Ordinal) ? "crlf" : "lf"));
            }
            if (steps.Count == 0)
                steps.Add(new CaseStepDto("text", text, Role: "fuzzable"));
        }
        else
        {
            // Chunk binary into hex blocks of ≤32 bytes for editability
            for (var i = 0; i < bytes.Length; i += 32)
            {
                var n = Math.Min(32, bytes.Length - i);
                steps.Add(new CaseStepDto("hex", Convert.ToHexString(bytes.AsSpan(i, n))));
            }
        }

        return new CaseImportBytesDto(
            bytes.Length,
            ToHex(bytes.AsSpan(0, previewLen)) + (bytes.Length > previewLen ? " …" : ""),
            ToAscii(bytes.AsSpan(0, previewLen)) + (bytes.Length > previewLen ? " …" : ""),
            steps);
    }

    public static CaseImportBytesDto Import(CaseImportBytesRequest request)
    {
        byte[] bytes;
        if (!string.IsNullOrWhiteSpace(request.Hex))
            bytes = ParseHex(request.Hex!);
        else if (!string.IsNullOrWhiteSpace(request.Base64))
            bytes = Convert.FromBase64String(request.Base64!.Trim());
        else if (request.Text is not null)
            bytes = Encoding.UTF8.GetBytes(Unescape(request.Text));
        else
            throw new ArgumentException("Provide hex, text, or base64");

        return SuggestFromBytes(bytes);
    }

    private static byte[] RenderStep(CaseStepDto step)
    {
        var op = (step.Op ?? "").Trim().ToLowerInvariant();
        return op switch
        {
            "static" or "text" or "string" or "delim" or "delimiter" =>
                Encoding.UTF8.GetBytes(Unescape(step.Value ?? "")),
            "quote" or "quoted" =>
                Encoding.UTF8.GetBytes("\"" + Unescape(step.Value ?? "") + "\""),
            "utf16" or "utf16le" or "wide" =>
                Encoding.Unicode.GetBytes(Unescape(step.Value ?? "")),
            "hex" or "bytes" => ParseHex(step.Value ?? ""),
            "repeat" => Repeat(step.Value ?? "A", step.Count ?? 100),
            "fill" => Repeat(step.Value ?? "0x00", step.Count ?? 16),
            "random" => RandomBytes(Math.Clamp(step.Count ?? 16, 0, 1_000_000)),
            "interesting" or "int" => Interesting(step.Format ?? "u32le", step.Value),
            "null" or "zero" => [0],
            "crlf" or "newline" => "\r\n"u8.ToArray(),
            "lf" => "\n"u8.ToArray(),
            "base64" or "b64" => Convert.FromBase64String((step.Value ?? "").Trim()),
            "cyclic" or "pattern" => Cyclic(Math.Clamp(step.Count ?? 100, 1, 1_000_000)),
            _ => throw new ArgumentException($"Unknown case op: {step.Op}"),
        };
    }

    private static byte ParsePadByte(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return 0;
        if (value.StartsWith("0x", StringComparison.OrdinalIgnoreCase) &&
            byte.TryParse(value.AsSpan(2), NumberStyles.HexNumber, null, out var b))
            return b;
        return (byte)value[0];
    }

    private static string Unescape(string s) =>
        s.Replace("\\r", "\r", StringComparison.Ordinal)
            .Replace("\\n", "\n", StringComparison.Ordinal)
            .Replace("\\t", "\t", StringComparison.Ordinal)
            .Replace("\\0", "\0", StringComparison.Ordinal)
            .Replace("\\\\", "\\", StringComparison.Ordinal);

    private static byte[] ParseHex(string value)
    {
        var hex = value.Replace(" ", "", StringComparison.Ordinal)
            .Replace("-", "", StringComparison.Ordinal)
            .Replace("0x", "", StringComparison.OrdinalIgnoreCase);
        if (hex.Length % 2 != 0)
            hex = "0" + hex;
        return Convert.FromHexString(hex);
    }

    private static byte[] Repeat(string value, int count)
    {
        count = Math.Clamp(count, 0, 1_000_000);
        byte unit;
        if (value.StartsWith("0x", StringComparison.OrdinalIgnoreCase) &&
            byte.TryParse(value.AsSpan(2), NumberStyles.HexNumber, null, out var b))
            unit = b;
        else if (value.Length == 0)
            unit = (byte)'A';
        else
            unit = (byte)value[0];

        var buf = new byte[count];
        Array.Fill(buf, unit);
        return buf;
    }

    private static byte[] RandomBytes(int count)
    {
        var buf = new byte[count];
        Random.Shared.NextBytes(buf);
        return buf;
    }

    private static readonly long[] InterestingValues =
    [
        0, 1, 0x7f, 0x80, 0xff, 0x100, 0x7fff, 0x8000, 0xffff,
        0x7fffffff, unchecked((int)0x80000000), unchecked((uint)0xffffffff),
        -1, -128, 127, 255, 1024, 4096, 65535,
    ];

    private static byte[] Interesting(string format, string? value)
    {
        long n;
        if (!string.IsNullOrWhiteSpace(value) &&
            (long.TryParse(value, out n) ||
             long.TryParse(value.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? value[2..] : value,
                 NumberStyles.HexNumber, null, out n)))
        {
            /* use parsed */
        }
        else
        {
            n = InterestingValues[Random.Shared.Next(InterestingValues.Length)];
        }

        format = format.Trim().ToLowerInvariant();
        return format switch
        {
            "u8" or "byte" => [(byte)n],
            "u16be" or "be16" => [(byte)(n >> 8), (byte)n],
            "u16le" or "le16" => [(byte)n, (byte)(n >> 8)],
            "u32be" or "be32" => [(byte)(n >> 24), (byte)(n >> 16), (byte)(n >> 8), (byte)n],
            _ => [(byte)n, (byte)(n >> 8), (byte)(n >> 16), (byte)(n >> 24)], // u32le
        };
    }

    private static byte[] EncodeLength(int length, string format) =>
        format.Trim().ToLowerInvariant() switch
        {
            "u8" => [(byte)length],
            "u16be" => [(byte)(length >> 8), (byte)length],
            "u16le" => [(byte)length, (byte)(length >> 8)],
            "u32be" => [(byte)(length >> 24), (byte)(length >> 16), (byte)(length >> 8), (byte)length],
            "u32le" => [(byte)length, (byte)(length >> 8), (byte)(length >> 16), (byte)(length >> 24)],
            _ => [(byte)length, (byte)(length >> 8)],
        };

    /// <summary>Simple unique alphabetic cycle (depth triage — not exploit tooling).</summary>
    private static byte[] Cyclic(int length)
    {
        var buf = new byte[length];
        for (var i = 0; i < length; i++)
        {
            var a = i / (26 * 26) % 26;
            var b = i / 26 % 26;
            var c = i % 26;
            // 3-char alphabet pattern: Aa0 style simplified to letters
            buf[i] = (byte)('A' + (a + b + c) % 26);
            if (i % 3 == 1) buf[i] = (byte)('a' + b);
            if (i % 3 == 2) buf[i] = (byte)('0' + c % 10);
        }
        return buf;
    }

    private static string ToHex(ReadOnlySpan<byte> bytes)
    {
        var sb = new StringBuilder(bytes.Length * 3);
        for (var i = 0; i < bytes.Length; i++)
        {
            if (i > 0) sb.Append(' ');
            sb.Append(bytes[i].ToString("X2"));
        }
        return sb.ToString();
    }

    private static string ToAscii(ReadOnlySpan<byte> bytes)
    {
        var chars = new char[bytes.Length];
        for (var i = 0; i < bytes.Length; i++)
        {
            var b = bytes[i];
            chars[i] = b is >= 32 and <= 126 ? (char)b : '.';
        }
        return new string(chars);
    }
}
