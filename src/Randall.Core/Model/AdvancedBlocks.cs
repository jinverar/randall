namespace Randall.Core.Model;

using System.Text;

/// <summary>Signed or unsigned fixed-width integer (Peach Number / Boofuzz Word family).</summary>
public sealed class NumberBlock : IBlockNode
{
    public required string Name { get; init; }
    public int Width { get; init; } = 4;
    public bool LittleEndian { get; init; } = true;
    public bool Signed { get; init; }
    public bool Mutable { get; init; } = true;
    public long DefaultValue { get; init; }

    public int Render(Span<byte> buffer, int offset, RenderContext ctx)
    {
        Write(buffer[offset..], DefaultValue);
        return Width;
    }

    public void CollectFields(int baseOffset, List<FieldRegion> fields, RenderContext ctx)
    {
        var kind = Signed ? $"int{Width * 8}" : $"uint{Width * 8}";
        if (Width is 1) kind = Signed ? "int8" : "uint8";
        else if (Width is 2) kind = Signed ? "int16" : "uint16";
        else if (Width is 4) kind = Signed ? "int32" : "uint32";
        else if (Width is 8) kind = Signed ? "int64" : "uint64";
        fields.Add(new FieldRegion(Name, baseOffset, Width, Mutable, kind, LittleEndian));
    }

    private void Write(Span<byte> dest, long value)
    {
        ulong u = Signed ? unchecked((ulong)value) : (ulong)value;
        for (var i = 0; i < Width; i++)
        {
            var shift = LittleEndian ? 8 * i : 8 * (Width - 1 - i);
            dest[i] = (byte)(u >> shift);
        }
    }
}

/// <summary>Enum — constrained choice among named integer values.</summary>
public sealed class EnumBlock : IBlockNode
{
    public required string Name { get; init; }
    public int Width { get; init; } = 4;
    public bool LittleEndian { get; init; } = true;
    public bool Mutable { get; init; } = true;
    public required IReadOnlyList<ulong> Values { get; init; }
    public ulong DefaultValue { get; init; }

    public int Render(Span<byte> buffer, int offset, RenderContext ctx)
    {
        var pick = Values.Count == 0
            ? DefaultValue
            : Values[ctx.ChoiceIndex.HasValue
                ? ctx.ChoiceIndex.Value % Values.Count
                : ctx.Rng.Next(Values.Count)];
        Write(buffer[offset..], pick);
        return Width;
    }

    public void CollectFields(int baseOffset, List<FieldRegion> fields, RenderContext ctx) =>
        fields.Add(new FieldRegion(Name, baseOffset, Width, Mutable, "enum", LittleEndian));

    private void Write(Span<byte> dest, ulong value)
    {
        for (var i = 0; i < Width; i++)
        {
            var shift = LittleEndian ? 8 * i : 8 * (Width - 1 - i);
            dest[i] = (byte)(value >> shift);
        }
    }
}

/// <summary>Bitfield / flags packed into a fixed-width integer.</summary>
public sealed class FlagsBlock : IBlockNode
{
    public required string Name { get; init; }
    public int Width { get; init; } = 4;
    public bool LittleEndian { get; init; } = true;
    public bool Mutable { get; init; } = true;
    public ulong DefaultValue { get; init; }
    /// <summary>Optional named flag bits (name → bit mask). Used for mutate hints.</summary>
    public IReadOnlyDictionary<string, ulong> FlagBits { get; init; } =
        new Dictionary<string, ulong>();

    public int Render(Span<byte> buffer, int offset, RenderContext ctx)
    {
        Write(buffer[offset..], DefaultValue);
        return Width;
    }

    public void CollectFields(int baseOffset, List<FieldRegion> fields, RenderContext ctx) =>
        fields.Add(new FieldRegion(Name, baseOffset, Width, Mutable, "flags", LittleEndian));

    private void Write(Span<byte> dest, ulong value)
    {
        for (var i = 0; i < Width; i++)
        {
            var shift = LittleEndian ? 8 * i : 8 * (Width - 1 - i);
            dest[i] = (byte)(value >> shift);
        }
    }
}

/// <summary>Repeat / array — emit child N times (count fixed or from field hint).</summary>
public sealed class RepeatBlock : IBlockNode
{
    public required string Name { get; init; }
    public required IBlockNode Child { get; init; }
    public int Count { get; init; } = 1;
    public int MinCount { get; init; } = 0;
    public int MaxCount { get; init; } = 16;
    public bool CountMutable { get; init; } = true;

    public int Render(Span<byte> buffer, int offset, RenderContext ctx)
    {
        var n = Count;
        if (CountMutable && MaxCount > MinCount)
            n = ctx.Rng.Next(MinCount, Math.Max(MinCount + 1, MaxCount + 1));
        n = Math.Clamp(n, 0, 256);
        var pos = offset;
        for (var i = 0; i < n; i++)
            pos += Child.Render(buffer, pos, ctx);
        return pos - offset;
    }

    public void CollectFields(int baseOffset, List<FieldRegion> fields, RenderContext ctx)
    {
        // Expose the first instance fields; count is structural.
        var measureBuf = new byte[65536];
        var one = Child.Render(measureBuf, 0, ctx);
        fields.Add(new FieldRegion(Name + ".count", baseOffset, 0, CountMutable, "repeat-count"));
        Child.CollectFields(baseOffset, fields, ctx);
        _ = one;
    }
}

/// <summary>Alignment / padding to a byte boundary.</summary>
public sealed class PaddingBlock : IBlockNode
{
    public int Align { get; init; } = 4;
    public byte PadByte { get; init; }
    public string? Name { get; init; }

    public int Render(Span<byte> buffer, int offset, RenderContext ctx)
    {
        if (Align <= 1)
            return 0;
        var rem = offset % Align;
        if (rem == 0)
            return 0;
        var pad = Align - rem;
        buffer.Slice(offset, pad).Fill(PadByte);
        return pad;
    }

    public void CollectFields(int baseOffset, List<FieldRegion> fields, RenderContext ctx)
    {
        if (!string.IsNullOrWhiteSpace(Name))
            fields.Add(new FieldRegion(Name!, baseOffset, 0, false, "padding"));
    }
}

/// <summary>
/// Switch / choice among child blocks (Peach Choice). Renders one selected child.
/// </summary>
public sealed class SwitchBlock : IBlockNode
{
    public required string Name { get; init; }
    public required IReadOnlyList<(string Key, IBlockNode Node)> Cases { get; init; }
    public bool Mutable { get; init; } = true;

    public int Render(Span<byte> buffer, int offset, RenderContext ctx)
    {
        if (Cases.Count == 0)
            return 0;
        var idx = ctx.ChoiceIndex.HasValue
            ? ctx.ChoiceIndex.Value % Cases.Count
            : ctx.Rng.Next(Cases.Count);
        return Cases[idx].Node.Render(buffer, offset, ctx);
    }

    public void CollectFields(int baseOffset, List<FieldRegion> fields, RenderContext ctx)
    {
        fields.Add(new FieldRegion(Name, baseOffset, 0, Mutable, "switch"));
        if (Cases.Count > 0)
            Cases[0].Node.CollectFields(baseOffset, fields, ctx);
    }
}

/// <summary>
/// Conditional block — when predicate is unmet, emits nothing.
/// Predicate is a simple equality on a previously rendered enum/flags field name (best-effort).
/// TODO: full expression language (Peach when=).
/// </summary>
public sealed class ConditionalBlock : IBlockNode
{
    public required string WhenField { get; init; }
    public required string WhenEquals { get; init; }
    public required IBlockNode Child { get; init; }
    /// <summary>When true (default), always render — stub until field-value table is threaded.</summary>
    public bool AlwaysRenderStub { get; init; } = true;

    public int Render(Span<byte> buffer, int offset, RenderContext ctx)
    {
        // TODO: evaluate WhenField against rendered so-far buffer / seed table.
        if (AlwaysRenderStub)
            return Child.Render(buffer, offset, ctx);
        return 0;
    }

    public void CollectFields(int baseOffset, List<FieldRegion> fields, RenderContext ctx) =>
        Child.CollectFields(baseOffset, fields, ctx);
}

/// <summary>
/// Offset / relativeOffset placeholder — reserves space; patched in Finalize when possible.
/// TODO: full back-patch of absolute/relative offsets after layout.
/// </summary>
public sealed class OffsetBlock : IBlockNode
{
    public required string Name { get; init; }
    public int Width { get; init; } = 4;
    public bool LittleEndian { get; init; } = true;
    public bool Relative { get; init; }
    public string? TargetField { get; init; }
    public bool Mutable { get; init; } = true;
    public ulong DefaultValue { get; init; }

    public int Render(Span<byte> buffer, int offset, RenderContext ctx)
    {
        Write(buffer[offset..], DefaultValue);
        return Width;
    }

    public void CollectFields(int baseOffset, List<FieldRegion> fields, RenderContext ctx) =>
        fields.Add(new FieldRegion(Name, baseOffset, Width, Mutable,
            Relative ? "relativeOffset" : "offset", LittleEndian));

    private void Write(Span<byte> dest, ulong value)
    {
        for (var i = 0; i < Width; i++)
        {
            var shift = LittleEndian ? 8 * i : 8 * (Width - 1 - i);
            dest[i] = (byte)(value >> shift);
        }
    }
}

/// <summary>Blob from hex string default (handy for magic / fixed headers).</summary>
public sealed class HexStaticBlock : IBlockNode
{
    private readonly byte[] _bytes;

    public HexStaticBlock(string hex)
    {
        hex = hex.Replace(" ", "").Replace("-", "").Replace("0x", "", StringComparison.OrdinalIgnoreCase);
        _bytes = Convert.FromHexString(hex.Length % 2 == 0 ? hex : "0" + hex);
    }

    public int Render(Span<byte> buffer, int offset, RenderContext ctx)
    {
        _bytes.CopyTo(buffer[offset..]);
        return _bytes.Length;
    }

    public void CollectFields(int baseOffset, List<FieldRegion> fields, RenderContext ctx) { }
}

/// <summary>Helper: ASCII/UTF-8 static with optional hex: prefix.</summary>
public static class StaticValueParser
{
    public static byte[] Parse(string? value)
    {
        if (string.IsNullOrEmpty(value))
            return [];
        if (value.StartsWith("hex:", StringComparison.OrdinalIgnoreCase))
        {
            var hex = value[4..].Replace(" ", "").Replace("-", "");
            return Convert.FromHexString(hex.Length % 2 == 0 ? hex : "0" + hex);
        }
        return Encoding.ASCII.GetBytes(value);
    }
}
