namespace Randall.Infrastructure.Mutators;

/// <summary>Shared byte-level mutation primitives (AFL/libFuzzer-style building blocks).</summary>
internal static class MutationOps
{
    public static byte[] BitFlip(byte[] buf, Random rng)
    {
        if (buf.Length == 0)
            return [(byte)rng.Next(256)];
        var i = rng.Next(buf.Length);
        buf[i] ^= (byte)(1 << rng.Next(8));
        return buf;
    }

    public static byte[] Arith(byte[] buf, Random rng)
    {
        if (buf.Length == 0)
            return buf;
        var i = rng.Next(buf.Length);
        var delta = rng.Next(-35, 36);
        buf[i] = (byte)(buf[i] + delta);
        return buf;
    }

    public static byte[] InterestingByte(byte[] buf, Random rng)
    {
        if (buf.Length == 0)
            buf = new byte[4];
        var i = rng.Next(buf.Length);
        ReadOnlySpan<byte> values = [0, 1, 0x7F, 0x80, 0xFF, 0xFE, 0x7E, 0x81];
        buf[i] = values[rng.Next(values.Length)];
        return buf;
    }

    public static byte[] InterestingIntegers(byte[] buf, Random rng)
    {
        if (buf.Length == 0)
            buf = new byte[8];

        if (buf.Length == 0)
            return [(byte)rng.Next(256)];

        var widths = new List<int>();
        if (buf.Length >= 1) widths.Add(1);
        if (buf.Length >= 2) widths.Add(2);
        if (buf.Length >= 4) widths.Add(4);
        var width = widths[rng.Next(widths.Count)];
        var maxOffset = buf.Length - width;
        var offset = maxOffset > 0 ? rng.Next(maxOffset + 1) : 0;

        uint[] interesting =
        [
            0, 1, 2, 0x7F, 0x80, 0xFF, 0xFE, 0x7E, 0x81,
            0x7FFF, 0x8000, 0xFFFF, 0xFFFE,
            0x7FFFFFFF, 0x80000000, 0xFFFFFFFE, 0xFFFFFFFF,
        ];

        var pick = interesting[rng.Next(interesting.Length)];
        WriteUInt(buf, offset, width, pick, littleEndian: rng.NextDouble() < 0.85);
        return buf;
    }

    public static byte[] Truncate(byte[] buf, Random rng)
    {
        if (buf.Length <= 1)
            return buf;
        var len = rng.Next(1, buf.Length);
        return buf.AsSpan(0, len).ToArray();
    }

    public static byte[] Expand(byte[] buf, Random rng)
    {
        var extra = rng.Next(16, 512);
        var result = new byte[buf.Length + extra];
        buf.CopyTo(result, 0);
        for (var i = buf.Length; i < result.Length; i++)
            result[i] = (byte)(rng.NextDouble() < 0.5 ? 'A' : 0);
        return result;
    }

    public static byte[] InsertRandom(byte[] buf, Random rng)
    {
        var extra = rng.Next(4, 128);
        var result = new byte[buf.Length + extra];
        buf.CopyTo(result, 0);
        rng.NextBytes(result.AsSpan(buf.Length));
        return result;
    }

    public static byte[] DictionaryInsert(byte[] buf, ReadOnlyMemory<byte> token, Random rng)
    {
        var t = token.Span;
        if (t.Length == 0)
            return buf;
        var pos = buf.Length > 0 ? rng.Next(buf.Length) : 0;
        var result = new byte[buf.Length + t.Length];
        buf.AsSpan(0, pos).CopyTo(result);
        t.CopyTo(result.AsSpan(pos));
        buf.AsSpan(pos).CopyTo(result.AsSpan(pos + t.Length));
        return result;
    }

    public static byte[] DictionaryOverwrite(byte[] buf, ReadOnlyMemory<byte> token, Random rng)
    {
        var t = token.Span;
        if (t.Length == 0 || buf.Length == 0)
            return buf;
        var pos = rng.Next(buf.Length);
        var copyLen = Math.Min(t.Length, buf.Length - pos);
        t[..copyLen].CopyTo(buf.AsSpan(pos));
        return buf;
    }

    public static byte[] Splice(byte[] a, byte[] b, Random rng)
    {
        if (a.Length == 0) return b.ToArray();
        if (b.Length == 0) return a.ToArray();
        // Next(min, maxExclusive) requires max > min — length-1 seeds must not throw.
        var splitA = a.Length == 1 ? 1 : rng.Next(1, a.Length);
        var splitB = rng.Next(0, b.Length);
        var result = new byte[splitA + (b.Length - splitB)];
        a.AsSpan(0, splitA).CopyTo(result);
        b.AsSpan(splitB).CopyTo(result.AsSpan(splitA));
        return result;
    }

    /// <summary>Duplicate a random slice of the seed (AFL-style chunk repeat).</summary>
    public static byte[] DuplicateChunk(byte[] buf, Random rng)
    {
        if (buf.Length == 0)
            return buf;
        var start = rng.Next(buf.Length);
        var len = rng.Next(1, Math.Min(64, buf.Length - start) + 1);
        var times = rng.Next(2, 8);
        var chunk = buf.AsSpan(start, len);
        var result = new byte[buf.Length + chunk.Length * (times - 1)];
        var o = 0;
        buf.AsSpan(0, start + len).CopyTo(result);
        o = start + len;
        for (var t = 1; t < times; t++)
        {
            chunk.CopyTo(result.AsSpan(o));
            o += chunk.Length;
        }
        buf.AsSpan(start + len).CopyTo(result.AsSpan(o));
        return result;
    }

    /// <summary>Swap two random spans inside the seed (local shuffle).</summary>
    public static byte[] ShuffleSpans(byte[] buf, Random rng)
    {
        if (buf.Length < 4)
            return BitFlip(buf.ToArray(), rng);
        var a = rng.Next(buf.Length - 1);
        var b = rng.Next(buf.Length - 1);
        if (a == b) b = (b + 1) % buf.Length;
        if (a > b) (a, b) = (b, a);
        var len = Math.Min(rng.Next(1, 8), Math.Min(b - a, buf.Length - b));
        if (len <= 0)
            return buf;
        for (var i = 0; i < len; i++)
            (buf[a + i], buf[b + i]) = (buf[b + i], buf[a + i]);
        return buf;
    }

    public static byte[] DeleteRange(byte[] buf, Random rng)
    {
        if (buf.Length <= 1)
            return buf;
        var start = rng.Next(buf.Length);
        var maxLen = buf.Length - start;
        var len = rng.Next(1, Math.Min(64, maxLen) + 1);
        var result = new byte[buf.Length - len];
        buf.AsSpan(0, start).CopyTo(result);
        buf.AsSpan(start + len).CopyTo(result.AsSpan(start));
        return result;
    }

    public static byte[] InsertAtOffset(byte[] buf, Random rng, int? maxInsert = null)
    {
        var insertLen = rng.Next(1, Math.Min(maxInsert ?? 128, 256) + 1);
        var pos = buf.Length > 0 ? rng.Next(buf.Length + 1) : 0;
        var result = new byte[buf.Length + insertLen];
        buf.AsSpan(0, pos).CopyTo(result);
        rng.NextBytes(result.AsSpan(pos, insertLen));
        buf.AsSpan(pos).CopyTo(result.AsSpan(pos + insertLen));
        return result;
    }

    public static byte[] ReplaceChunk(byte[] buf, Random rng)
    {
        if (buf.Length == 0)
            return [(byte)rng.Next(256)];
        var start = rng.Next(buf.Length);
        var len = rng.Next(1, Math.Min(64, buf.Length - start) + 1);
        rng.NextBytes(buf.AsSpan(start, len));
        return buf;
    }

    public static byte[] ZeroRange(byte[] buf, Random rng)
    {
        if (buf.Length == 0)
            return buf;
        var start = rng.Next(buf.Length);
        var len = rng.Next(1, Math.Min(64, buf.Length - start) + 1);
        buf.AsSpan(start, len).Clear();
        return buf;
    }

    public static byte[] FillRange(byte[] buf, Random rng)
    {
        if (buf.Length == 0)
            return buf;
        var start = rng.Next(buf.Length);
        var len = rng.Next(1, Math.Min(64, buf.Length - start) + 1);
        var fill = (byte)rng.Next(256);
        buf.AsSpan(start, len).Fill(fill);
        return buf;
    }

    public static byte[] CloneChunk(byte[] buf, Random rng)
    {
        if (buf.Length == 0)
            return buf;
        var start = rng.Next(buf.Length);
        var len = rng.Next(1, Math.Min(64, buf.Length - start) + 1);
        var chunk = buf.AsSpan(start, len);
        var insertAt = rng.Next(buf.Length + 1);
        var result = new byte[buf.Length + len];
        buf.AsSpan(0, insertAt).CopyTo(result);
        chunk.CopyTo(result.AsSpan(insertAt));
        buf.AsSpan(insertAt).CopyTo(result.AsSpan(insertAt + len));
        return result;
    }

    public static byte[] MoveChunk(byte[] buf, Random rng)
    {
        if (buf.Length < 2)
            return buf;
        var start = rng.Next(buf.Length);
        var len = rng.Next(1, Math.Min(32, buf.Length - start) + 1);
        var chunk = buf.AsSpan(start, len).ToArray();
        var without = DeleteRangeAt(buf, start, len);
        var insertAt = without.Length > 0 ? rng.Next(without.Length + 1) : 0;
        var result = new byte[without.Length + chunk.Length];
        without.AsSpan(0, insertAt).CopyTo(result);
        chunk.CopyTo(result.AsSpan(insertAt));
        without.AsSpan(insertAt).CopyTo(result.AsSpan(insertAt + chunk.Length));
        return result;
    }

    public static byte[] SwapRecords(byte[] buf, Random rng)
    {
        if (buf.Length < 4)
            return ShuffleSpans(buf.ToArray(), rng);
        var mid = buf.Length / 2;
        var aLen = rng.Next(1, Math.Min(mid, 64) + 1);
        var bStart = mid + rng.Next(0, Math.Max(1, buf.Length - mid - 1));
        var bLen = Math.Min(aLen, buf.Length - bStart);
        if (bLen <= 0)
            return buf;
        var result = buf.ToArray();
        for (var i = 0; i < bLen; i++)
            (result[i], result[bStart + i]) = (result[bStart + i], result[i]);
        return result;
    }

    public static byte[] RepeatRecord(byte[] buf, Random rng) => DuplicateChunk(buf, rng);

    public static byte[] LengthenNearField(byte[] buf, Random rng)
    {
        if (buf.Length < 4)
            return Expand(buf, rng);
        // Treat first 2–4 bytes as a length-ish field and inflate nearby body.
        var width = buf.Length >= 4 && rng.NextDouble() < 0.5 ? 4 : 2;
        var bodyStart = width;
        var extra = rng.Next(4, 128);
        var result = new byte[buf.Length + extra];
        buf.AsSpan(0, bodyStart).CopyTo(result);
        buf.AsSpan(bodyStart).CopyTo(result.AsSpan(bodyStart));
        rng.NextBytes(result.AsSpan(buf.Length));
        // Optionally bump the length field (little-endian).
        if (rng.NextDouble() < 0.7)
        {
            uint cur = width == 2
                ? (uint)(result[0] | (result[1] << 8))
                : (uint)(result[0] | (result[1] << 8) | (result[2] << 16) | (result[3] << 24));
            cur = unchecked(cur + (uint)extra);
            if (width == 2)
            {
                result[0] = (byte)cur;
                result[1] = (byte)(cur >> 8);
            }
            else
            {
                result[0] = (byte)cur;
                result[1] = (byte)(cur >> 8);
                result[2] = (byte)(cur >> 16);
                result[3] = (byte)(cur >> 24);
            }
        }
        return result;
    }

    public static byte[] ShortenNearField(byte[] buf, Random rng)
    {
        if (buf.Length <= 4)
            return Truncate(buf, rng);
        var keep = rng.Next(2, buf.Length);
        return buf.AsSpan(0, keep).ToArray();
    }

    private static byte[] DeleteRangeAt(byte[] buf, int start, int len)
    {
        var result = new byte[buf.Length - len];
        buf.AsSpan(0, start).CopyTo(result);
        buf.AsSpan(start + len).CopyTo(result.AsSpan(start));
        return result;
    }

    public static byte[] Havoc(byte[] input, Random rng, int depth)
    {
        var buf = input.ToArray();
        var rounds = rng.Next(2, Math.Max(3, depth + 1));
        ReadOnlySpan<Func<byte[], Random, byte[]>> ops =
        [
            BitFlip, Arith, InterestingByte, Truncate, Expand, InsertRandom,
            DuplicateChunk, ShuffleSpans, DeleteRange,
            static (b, r) => InsertAtOffset(b, r),
            ReplaceChunk, ZeroRange, CloneChunk, FillRange,
        ];

        for (var i = 0; i < rounds; i++)
        {
            var op = ops[rng.Next(ops.Length)];
            buf = op(buf, rng);
            if (buf.Length == 0)
                buf = [(byte)rng.Next(256)];
        }
        return buf;
    }

    private static void WriteUInt(byte[] buf, int offset, int width, uint value, bool littleEndian)
    {
        switch (width)
        {
            case 1:
                buf[offset] = (byte)value;
                break;
            case 2:
                if (littleEndian)
                {
                    buf[offset] = (byte)value;
                    buf[offset + 1] = (byte)(value >> 8);
                }
                else
                {
                    buf[offset] = (byte)(value >> 8);
                    buf[offset + 1] = (byte)value;
                }
                break;
            case 4:
                if (littleEndian)
                {
                    buf[offset] = (byte)value;
                    buf[offset + 1] = (byte)(value >> 8);
                    buf[offset + 2] = (byte)(value >> 16);
                    buf[offset + 3] = (byte)(value >> 24);
                }
                else
                {
                    buf[offset] = (byte)(value >> 24);
                    buf[offset + 1] = (byte)(value >> 16);
                    buf[offset + 2] = (byte)(value >> 8);
                    buf[offset + 3] = (byte)value;
                }
                break;
            default:
            {
                // uint is 4 bytes; never slice past either buffer.
                var space = Math.Max(0, buf.Length - offset);
                var n = Math.Min(4, space);
                if (n <= 0)
                    return;
                if (littleEndian)
                    BitConverter.TryWriteBytes(buf.AsSpan(offset, n), value);
                else
                {
                    var bytes = BitConverter.GetBytes(value);
                    if (BitConverter.IsLittleEndian)
                        Array.Reverse(bytes);
                    bytes.AsSpan(0, n).CopyTo(buf.AsSpan(offset, n));
                }
                break;
            }
        }
    }
}
