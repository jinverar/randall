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

        var widths = new List<int>();
        if (buf.Length >= 1) widths.Add(1);
        if (buf.Length >= 2) widths.Add(2);
        if (buf.Length >= 4) widths.Add(4);
        if (buf.Length >= 8) widths.Add(8);
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
        var splitA = rng.Next(1, a.Length);
        var splitB = rng.Next(0, b.Length);
        var result = new byte[splitA + (b.Length - splitB)];
        a.AsSpan(0, splitA).CopyTo(result);
        b.AsSpan(splitB).CopyTo(result.AsSpan(splitA));
        return result;
    }

    public static byte[] Havoc(byte[] input, Random rng, int depth)
    {
        var buf = input.ToArray();
        var rounds = rng.Next(2, Math.Max(3, depth + 1));
        ReadOnlySpan<Func<byte[], Random, byte[]>> ops =
        [
            BitFlip, Arith, InterestingByte, Truncate, Expand, InsertRandom,
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
                if (littleEndian)
                    BitConverter.TryWriteBytes(buf.AsSpan(offset, Math.Min(8, buf.Length - offset)), value);
                else
                {
                    var bytes = BitConverter.GetBytes(value);
                    if (BitConverter.IsLittleEndian)
                        Array.Reverse(bytes);
                    bytes.AsSpan(0, Math.Min(8, buf.Length - offset)).CopyTo(buf.AsSpan(offset));
                }
                break;
        }
    }
}
