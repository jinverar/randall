namespace Randall.Core.Model;

using System.Text;

public sealed record FieldRegion(
    string Name,
    int Offset,
    int Length,
    bool Mutable,
    string Kind = "bytes",
    bool LittleEndian = true);

public interface IBlockNode
{
    int Render(Span<byte> buffer, int offset, RenderContext ctx);
    void CollectFields(int baseOffset, List<FieldRegion> fields, RenderContext ctx);
}

public sealed class RenderContext
{
    public required IReadOnlyDictionary<string, byte[]> Seeds { get; init; }
    public Random Rng { get; } = Random.Shared;
    /// <summary>Deterministic choice index for exhaustive / choices blocks.</summary>
    public int? ChoiceIndex { get; init; }
}

public sealed class StaticBlock(string value, Encoding? encoding = null) : IBlockNode
{
    private readonly byte[] _bytes = (encoding ?? Encoding.ASCII).GetBytes(value);

    public int Render(Span<byte> buffer, int offset, RenderContext ctx)
    {
        _bytes.CopyTo(buffer[offset..]);
        return _bytes.Length;
    }

    public void CollectFields(int baseOffset, List<FieldRegion> fields, RenderContext ctx) { }
}

/// <summary>Boofuzz Delim — fixed separator, optionally mutable.</summary>
public sealed class DelimBlock(string value, string name, bool mutable) : IBlockNode
{
    private readonly byte[] _bytes = Encoding.ASCII.GetBytes(value);

    public int Render(Span<byte> buffer, int offset, RenderContext ctx)
    {
        _bytes.CopyTo(buffer[offset..]);
        return _bytes.Length;
    }

    public void CollectFields(int baseOffset, List<FieldRegion> fields, RenderContext ctx)
    {
        if (mutable)
            fields.Add(new FieldRegion(name, baseOffset, _bytes.Length, true, "delim"));
    }
}

/// <summary>Boofuzz String — mutable ASCII/UTF-8 text field.</summary>
public sealed class StringBlock : IBlockNode
{
    public required string Name { get; init; }
    public bool Mutable { get; init; } = true;
    public string DefaultValue { get; init; } = "";
    public int MinSize { get; init; } = 0;
    public int MaxSize { get; init; } = 4096;
    public string? SeedFile { get; init; }

    public int Render(Span<byte> buffer, int offset, RenderContext ctx)
    {
        var data = ResolveBytes(ctx);
        data.CopyTo(buffer[offset..]);
        return data.Length;
    }

    public void CollectFields(int baseOffset, List<FieldRegion> fields, RenderContext ctx)
    {
        var len = ResolveBytes(ctx).Length;
        fields.Add(new FieldRegion(Name, baseOffset, len, Mutable, "string"));
    }

    private byte[] ResolveBytes(RenderContext ctx)
    {
        if (SeedFile is not null && ctx.Seeds.TryGetValue(SeedFile, out var seed))
            return seed;
        if (!string.IsNullOrEmpty(DefaultValue))
            return Encoding.ASCII.GetBytes(DefaultValue);
        var size = ctx.Rng.Next(MinSize, Math.Max(MinSize + 1, MaxSize + 1));
        var buf = new byte[size];
        ctx.Rng.NextBytes(buf);
        return buf;
    }
}

/// <summary>Boofuzz Word/DWord/QWord — fixed-width integer field.</summary>
public sealed class IntegerBlock : IBlockNode
{
    public required string Name { get; init; }
    public int Width { get; init; } = 4;
    public bool LittleEndian { get; init; } = true;
    public bool Mutable { get; init; } = true;
    public ulong DefaultValue { get; init; }

    public int Render(Span<byte> buffer, int offset, RenderContext ctx)
    {
        WriteInteger(buffer[offset..], DefaultValue);
        return Width;
    }

    public void CollectFields(int baseOffset, List<FieldRegion> fields, RenderContext ctx)
    {
        var kind = Width switch { 2 => "word", 8 => "qword", _ => "dword" };
        fields.Add(new FieldRegion(Name, baseOffset, Width, Mutable, kind, LittleEndian));
    }

    private void WriteInteger(Span<byte> dest, ulong value)
    {
        if (Width == 2)
        {
            var v = (ushort)value;
            if (LittleEndian) { dest[0] = (byte)v; dest[1] = (byte)(v >> 8); }
            else { dest[0] = (byte)(v >> 8); dest[1] = (byte)v; }
        }
        else if (Width == 8)
        {
            if (LittleEndian)
                for (var i = 0; i < 8; i++)
                    dest[i] = (byte)(value >> (8 * i));
            else
                for (var i = 0; i < 8; i++)
                    dest[7 - i] = (byte)(value >> (8 * i));
        }
        else
        {
            var v = (uint)value;
            if (LittleEndian)
            {
                dest[0] = (byte)v; dest[1] = (byte)(v >> 8);
                dest[2] = (byte)(v >> 16); dest[3] = (byte)(v >> 24);
            }
            else
            {
                dest[0] = (byte)(v >> 24); dest[1] = (byte)(v >> 16);
                dest[2] = (byte)(v >> 8); dest[3] = (byte)v;
            }
        }
    }
}

/// <summary>Boofuzz Group — pick one of several static values.</summary>
public sealed class ChoiceBlock : IBlockNode
{
    public required string Name { get; init; }
    public required IReadOnlyList<byte[]> Values { get; init; }
    public bool Mutable { get; init; } = true;

    public int Render(Span<byte> buffer, int offset, RenderContext ctx)
    {
        if (Values.Count == 0)
            return 0;
        var idx = ctx.ChoiceIndex.HasValue
            ? ctx.ChoiceIndex.Value % Values.Count
            : ctx.Rng.Next(Values.Count);
        var pick = Values[idx];
        pick.CopyTo(buffer[offset..]);
        return pick.Length;
    }

    public void CollectFields(int baseOffset, List<FieldRegion> fields, RenderContext ctx)
    {
        if (!Mutable || Values.Count == 0)
            return;
        var maxLen = Values.Max(v => v.Length);
        fields.Add(new FieldRegion(Name, baseOffset, maxLen, true, "choices"));
    }
}

public sealed class BytesBlock : IBlockNode
{
    public required string Name { get; init; }
    public bool Mutable { get; init; } = true;
    public int MinSize { get; init; } = 1;
    public int MaxSize { get; init; } = 4096;
    public string? SeedFile { get; init; }
    public byte[]? DefaultValue { get; init; }

    public int Render(Span<byte> buffer, int offset, RenderContext ctx)
    {
        var data = ResolveBytes(ctx);
        data.CopyTo(buffer[offset..]);
        return data.Length;
    }

    public void CollectFields(int baseOffset, List<FieldRegion> fields, RenderContext ctx)
    {
        var len = ResolveBytes(ctx).Length;
        fields.Add(new FieldRegion(Name, baseOffset, len, Mutable));
    }

    private byte[] ResolveBytes(RenderContext ctx)
    {
        if (SeedFile is not null && ctx.Seeds.TryGetValue(SeedFile, out var seed))
            return seed;
        if (DefaultValue is not null)
            return DefaultValue;
        var size = ctx.Rng.Next(MinSize, Math.Max(MinSize + 1, MaxSize + 1));
        var buf = new byte[size];
        ctx.Rng.NextBytes(buf);
        return buf;
    }
}

/// <summary>Length prefix (2 or 4 byte) + payload — classic off-by-one target.</summary>
public sealed class LengthPrefixedBlock : IBlockNode
{
    public required string LengthName { get; init; }
    public required IBlockNode Payload { get; init; }
    public int LengthBytes { get; init; } = 4;
    public bool LittleEndian { get; init; } = true;
    public bool LengthMutable { get; init; } = true;

    public int Render(Span<byte> buffer, int offset, RenderContext ctx)
    {
        var payloadBuf = new byte[65536];
        var payloadLen = Payload.Render(payloadBuf, 0, ctx);
        WriteLength(buffer[offset..], payloadLen);
        payloadBuf.AsSpan(0, payloadLen).CopyTo(buffer[(offset + LengthBytes)..]);
        return LengthBytes + payloadLen;
    }

    public void CollectFields(int baseOffset, List<FieldRegion> fields, RenderContext ctx)
    {
        fields.Add(new FieldRegion(LengthName, baseOffset, LengthBytes, LengthMutable, "length", LittleEndian));
        Payload.CollectFields(baseOffset + LengthBytes, fields, ctx);
    }

    private void WriteLength(Span<byte> dest, int value)
    {
        if (LengthBytes == 2)
        {
            var v = (ushort)Math.Clamp(value, 0, ushort.MaxValue);
            if (LittleEndian) { dest[0] = (byte)v; dest[1] = (byte)(v >> 8); }
            else { dest[0] = (byte)(v >> 8); dest[1] = (byte)v; }
        }
        else
        {
            var v = (uint)value;
            if (LittleEndian)
            {
                dest[0] = (byte)v; dest[1] = (byte)(v >> 8);
                dest[2] = (byte)(v >> 16); dest[3] = (byte)(v >> 24);
            }
            else
            {
                dest[0] = (byte)(v >> 24); dest[1] = (byte)(v >> 16);
                dest[2] = (byte)(v >> 8); dest[3] = (byte)v;
            }
        }
    }
}

public sealed class GroupBlock(IReadOnlyList<IBlockNode> children) : IBlockNode
{
    public int Render(Span<byte> buffer, int offset, RenderContext ctx)
    {
        var pos = offset;
        foreach (var child in children)
            pos += child.Render(buffer, pos, ctx);
        return pos - offset;
    }

    public void CollectFields(int baseOffset, List<FieldRegion> fields, RenderContext ctx)
    {
        var pos = baseOffset;
        foreach (var child in children)
        {
            child.CollectFields(pos, fields, ctx);
            pos += Measure(child, ctx);
        }
    }

    private static int Measure(IBlockNode node, RenderContext ctx)
    {
        var buf = new byte[65536];
        return node.Render(buf, 0, ctx);
    }
}

public sealed class ChecksumBlock : IBlockNode
{
    public required string Name { get; init; }
    public int LengthBytes { get; init; } = 4;
    public bool LittleEndian { get; init; } = true;
    public bool Mutable { get; init; } = true;

    public int Render(Span<byte> buffer, int offset, RenderContext ctx)
    {
        if (offset <= 0)
        {
            buffer[offset..(offset + LengthBytes)].Clear();
            return LengthBytes;
        }
        var crc = Crc32.Compute(buffer[..offset]);
        WriteChecksum(buffer[offset..], crc);
        return LengthBytes;
    }

    public void CollectFields(int baseOffset, List<FieldRegion> fields, RenderContext ctx)
    {
        fields.Add(new FieldRegion(Name, baseOffset, LengthBytes, Mutable, "checksum", LittleEndian));
    }

    private void WriteChecksum(Span<byte> dest, uint crc)
    {
        if (LengthBytes == 4)
            Crc32.Write(dest, crc, LittleEndian);
        else if (LengthBytes == 2)
        {
            var v = (ushort)crc;
            if (LittleEndian) { dest[0] = (byte)v; dest[1] = (byte)(v >> 8); }
            else { dest[0] = (byte)(v >> 8); dest[1] = (byte)v; }
        }
    }
}

public sealed record DerivedFieldSpec(
    string Name,
    string Kind,
    int Offset,
    int Length,
    bool LittleEndian,
    bool Trailing);

public sealed class BlockModel : IProtocolModel
{
    private readonly IBlockNode _root;
    private readonly int _bufferSize;
    private readonly List<DerivedFieldSpec> _derived = [];
    private readonly bool _trailingCrc32;

    public BlockModel(string name, IBlockNode root, int bufferSize = 65536, bool trailingCrc32 = false)
    {
        Name = name;
        _root = root;
        _bufferSize = bufferSize;
        _trailingCrc32 = trailingCrc32;
    }

    public string Name { get; }

    public void RegisterDerivedFields(IReadOnlyDictionary<string, byte[]> seeds)
    {
        _derived.Clear();
        var msg = Render(seeds);
        foreach (var f in GetFields(seeds))
        {
            if (f.Kind is "checksum" or "length")
            {
                _derived.Add(new DerivedFieldSpec(
                    f.Name, f.Kind, f.Offset, f.Length, f.LittleEndian,
                    Trailing: f.Kind == "checksum" && f.Offset + f.Length == msg.Length));
            }
        }
        if (_trailingCrc32 && msg.Length >= 4 &&
            !_derived.Any(d => d.Trailing && d.Kind == "checksum"))
        {
            _derived.Add(new DerivedFieldSpec(
                "trailing_crc32", "checksum", msg.Length - 4, 4, true, Trailing: true));
        }
    }

    public byte[] FinalizeMessage(byte[] message, bool syncLengthFields = false)
    {
        var result = message;
        foreach (var spec in _derived.Where(d => d.Kind == "length").OrderBy(d => d.Offset))
        {
            if (!syncLengthFields)
                continue;
            var payloadLen = result.Length - (spec.Offset + spec.Length);
            WriteLengthAt(result, spec.Offset, spec.Length, spec.LittleEndian, (uint)Math.Max(0, payloadLen));
        }

        foreach (var spec in _derived.Where(d => d.Kind == "checksum"))
        {
            var coverLen = spec.Trailing
                ? Math.Max(0, result.Length - spec.Length)
                : Math.Max(0, spec.Offset);
            if (coverLen <= 0 || spec.Offset + spec.Length > result.Length)
                continue;
            var crc = Crc32.Compute(result.AsSpan(0, coverLen));
            WriteChecksumAt(result, spec.Offset, spec.Length, spec.LittleEndian, crc);
        }
        return result;
    }

    private static void WriteLengthAt(byte[] buf, int offset, int width, bool le, uint value)
    {
        if (width == 2)
        {
            var v = (ushort)value;
            if (le) { buf[offset] = (byte)v; buf[offset + 1] = (byte)(v >> 8); }
            else { buf[offset] = (byte)(v >> 8); buf[offset + 1] = (byte)v; }
        }
        else if (width >= 4)
        {
            if (le)
            {
                buf[offset] = (byte)value; buf[offset + 1] = (byte)(value >> 8);
                buf[offset + 2] = (byte)(value >> 16); buf[offset + 3] = (byte)(value >> 24);
            }
            else
            {
                buf[offset] = (byte)(value >> 24); buf[offset + 1] = (byte)(value >> 16);
                buf[offset + 2] = (byte)(value >> 8); buf[offset + 3] = (byte)value;
            }
        }
    }

    private static void WriteChecksumAt(byte[] buf, int offset, int length, bool le, uint crc)
    {
        if (length == 4)
            Crc32.Write(buf.AsSpan(offset, 4), crc, le);
        else if (length == 2)
        {
            var v = (ushort)crc;
            if (le) { buf[offset] = (byte)v; buf[offset + 1] = (byte)(v >> 8); }
            else { buf[offset] = (byte)(v >> 8); buf[offset + 1] = (byte)v; }
        }
    }

    public byte[] Render() => Render(new Dictionary<string, byte[]>());

    public byte[] Render(IReadOnlyDictionary<string, byte[]> seeds)
    {
        var ctx = new RenderContext { Seeds = seeds };
        var buffer = new byte[_bufferSize];
        var len = _root.Render(buffer, 0, ctx);
        return buffer[..len];
    }

    public IReadOnlyList<FieldRegion> GetFields(IReadOnlyDictionary<string, byte[]>? seeds = null)
    {
        var ctx = new RenderContext { Seeds = seeds ?? new Dictionary<string, byte[]>() };
        var fields = new List<FieldRegion>();
        _root.CollectFields(0, fields, ctx);
        return fields;
    }

    public IReadOnlyList<FieldRegion> GetMutableFields(IReadOnlyDictionary<string, byte[]>? seeds = null) =>
        GetFields(seeds).Where(f => f.Mutable).ToList();

    public byte[] PatchField(byte[] message, FieldRegion field, byte[] newValue)
    {
        if (string.IsNullOrEmpty(field.Name))
            return message;

        var before = message.AsSpan(0, field.Offset);
        var after = field.Offset + field.Length <= message.Length
            ? message.AsSpan(field.Offset + field.Length)
            : ReadOnlySpan<byte>.Empty;
        var result = new byte[before.Length + newValue.Length + after.Length];
        before.CopyTo(result);
        newValue.CopyTo(result.AsSpan(before.Length));
        after.CopyTo(result.AsSpan(before.Length + newValue.Length));
        return result;
    }

    public byte[] PatchField(byte[] message, string fieldName, byte[] newValue)
    {
        var match = GetFields().FirstOrDefault(f => f.Name.Equals(fieldName, StringComparison.OrdinalIgnoreCase));
        if (match is null || string.IsNullOrEmpty(match.Name))
            return message;
        return PatchField(message, match, newValue);
    }

    byte[] IProtocolModel.Render() => Render();
}
