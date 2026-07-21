using System.Text;

namespace Randall.Infrastructure;

/// <summary>
/// Cyclic ("De Bruijn"/Metasploit-style) pattern generation and offset lookup — the classic
/// exploit-dev workflow popularized by Immunity Debugger's mona.py (pattern_create /
/// pattern_offset / findmsp). Generate a unique pattern, crash the target with it, then look up the
/// controlled register value to learn the exact byte offset that lands in EIP/RIP.
/// </summary>
public static class PatternTools
{
    private const string Upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private const string Lower = "abcdefghijklmnopqrstuvwxyz";
    private const string Digit = "0123456789";

    /// <summary>Max unique length of the 3-char cyclic pattern (26*26*10*3).</summary>
    public const int MaxUnique = 26 * 26 * 10 * 3;

    /// <summary>Metasploit-style cyclic pattern "Aa0Aa1Aa2…" truncated to <paramref name="length"/>.</summary>
    public static string Create(int length)
    {
        if (length <= 0) return "";
        var sb = new StringBuilder(Math.Min(length, MaxUnique));
        foreach (var a in Upper)
            foreach (var b in Lower)
                foreach (var c in Digit)
                {
                    if (sb.Length >= length) return sb.ToString(0, length);
                    sb.Append(a).Append(b).Append(c);
                }
        // length > MaxUnique: uniqueness can't be guaranteed; return what we have.
        return sb.ToString();
    }

    /// <summary>
    /// Finds the byte offset of <paramref name="query"/> in a cyclic pattern of
    /// <paramref name="patternLength"/>. Accepts an ASCII fragment ("Aa3A") or a register hex value
    /// ("0x6341326141..." / "41366441"), trying both endiannesses. Returns -1 if not found.
    /// </summary>
    public static int Offset(string query, int patternLength = MaxUnique)
    {
        if (string.IsNullOrWhiteSpace(query)) return -1;
        var full = Create(Math.Max(patternLength, 8));
        query = query.Trim();

        // 1) direct ASCII match
        var direct = full.IndexOf(query, StringComparison.Ordinal);
        if (direct >= 0) return direct;

        // 2) hex register value → bytes → ASCII (both byte orders)
        var bytes = TryParseHex(query);
        if (bytes is not null && bytes.Length > 0)
        {
            var asAscii = AsAscii(bytes);
            var o1 = asAscii is null ? -1 : full.IndexOf(asAscii, StringComparison.Ordinal);
            if (o1 >= 0) return o1;

            Array.Reverse(bytes); // little-endian register → in-memory order
            var rev = AsAscii(bytes);
            var o2 = rev is null ? -1 : full.IndexOf(rev, StringComparison.Ordinal);
            if (o2 >= 0) return o2;
        }

        return -1;
    }

    /// <summary>
    /// Find where a register/hex value appears inside the <em>actual crashing input</em>
    /// (skill-building: works even when the payload was not a pure cyclic pattern).
    /// Prefers an 8-byte LE window (x64) and only accepts printable ASCII matches to avoid
    /// random 4-byte collisions that look like fake offsets.
    /// </summary>
    public static int OffsetInBuffer(string query, ReadOnlySpan<byte> input)
    {
        if (string.IsNullOrWhiteSpace(query) || input.IsEmpty)
            return -1;

        query = query.Trim();
        var bytes = TryParseHex(query);
        if (bytes is null || bytes.Length == 0)
            return -1;

        // x64 register values → prefer 8 unique printable bytes (cyclic patterns are ASCII).
        foreach (var width in bytes.Length >= 8 ? new[] { 8, 4 } : new[] { 4 })
        {
            if (bytes.Length < width)
                continue;
            var slice = bytes.AsSpan(bytes.Length - width, width).ToArray();
            var le = (byte[])slice.Clone();
            Array.Reverse(le);
            if (IsPrintableAscii(le))
            {
                var offLe = IndexOf(input, le);
                if (offLe >= 0)
                    return offLe;
            }

            if (IsPrintableAscii(slice))
            {
                var offBe = IndexOf(input, slice);
                if (offBe >= 0)
                    return offBe;
            }

            // For width 4, skip non-printable — too many false positives for skill triage.
            if (width == 4)
                break;
        }

        return -1;
    }

    private static bool IsPrintableAscii(ReadOnlySpan<byte> bytes)
    {
        foreach (var b in bytes)
        {
            if (b is < 0x20 or > 0x7e)
                return false;
        }

        return bytes.Length > 0;
    }

    /// <summary>
    /// If <paramref name="input"/> contains a Metasploit-style cyclic run (≥ 12 bytes), return a
    /// recommended <c>--pattern-len</c> (the input length, clamped). Otherwise null.
    /// </summary>
    public static int? TryInferPatternLength(ReadOnlySpan<byte> input, int minRun = 12)
    {
        if (input.Length < minRun)
            return null;
        var ascii = Encoding.Latin1.GetString(input);
        var cyclic = Create(Math.Min(Math.Max(input.Length, minRun), MaxUnique));
        // Prefer the longest matching cyclic substring.
        for (var len = Math.Min(ascii.Length, cyclic.Length); len >= minRun; len--)
        {
            for (var i = 0; i + len <= ascii.Length; i++)
            {
                var slice = ascii.AsSpan(i, len);
                if (cyclic.AsSpan().IndexOf(slice) >= 0)
                    return Math.Clamp(input.Length, minRun, MaxUnique);
            }
        }

        return null;
    }

    private static int IndexOf(ReadOnlySpan<byte> haystack, ReadOnlySpan<byte> needle)
    {
        if (needle.IsEmpty || needle.Length > haystack.Length)
            return -1;
        for (var i = 0; i <= haystack.Length - needle.Length; i++)
        {
            if (haystack.Slice(i, needle.Length).SequenceEqual(needle))
                return i;
        }

        return -1;
    }

    private static byte[]? TryParseHex(string s)
    {
        s = s.Trim();
        if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) s = s[2..];
        s = s.TrimStart('0').Length == 0 && s.Length > 0 ? s : s; // keep as-is
        if (s.Length == 0 || s.Length % 2 != 0) return null;
        var bytes = new byte[s.Length / 2];
        for (var i = 0; i < bytes.Length; i++)
        {
            if (!byte.TryParse(s.AsSpan(i * 2, 2), System.Globalization.NumberStyles.HexNumber, null, out bytes[i]))
                return null;
        }
        return bytes;
    }

    private static string? AsAscii(byte[] bytes)
    {
        var sb = new StringBuilder(bytes.Length);
        foreach (var b in bytes)
        {
            if (b is < 0x20 or > 0x7e) return null; // non-printable → not a pattern fragment
            sb.Append((char)b);
        }
        return sb.ToString();
    }
}
