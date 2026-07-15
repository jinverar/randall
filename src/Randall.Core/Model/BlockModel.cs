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

public sealed class BlockModel : IProtocolModel
{
    private readonly IBlockNode _root;
    private readonly int _bufferSize;

    public BlockModel(string name, IBlockNode root, int bufferSize = 65536)
    {
        Name = name;
        _root = root;
        _bufferSize = bufferSize;
    }

    public string Name { get; }

    public byte[] Render() => Render(new Dictionary<string, byte[]>());

    public byte[] Render(IReadOnlyDictionary<string, byte[]> seeds)
    {
        var ctx = new RenderContext { Seeds = seeds };
        var buffer = new byte[_bufferSize];
        var len = _root.Render(buffer, 0, ctx);
        return buffer[..len];
    }

    public IReadOnlyList<FieldRegion> GetFields()
    {
        var ctx = new RenderContext { Seeds = new Dictionary<string, byte[]>() };
        var fields = new List<FieldRegion>();
        _root.CollectFields(0, fields, ctx);
        return fields;
    }

    public IReadOnlyList<FieldRegion> GetMutableFields() =>
        GetFields().Where(f => f.Mutable).ToList();

    public byte[] PatchField(byte[] message, string fieldName, byte[] newValue)
    {
        var match = GetFields().FirstOrDefault(f => f.Name.Equals(fieldName, StringComparison.OrdinalIgnoreCase));
        if (match is null || string.IsNullOrEmpty(match.Name))
            return message;
        var field = match;

        var before = message.AsSpan(0, field.Offset);
        var after = message.AsSpan(field.Offset + field.Length);
        var result = new byte[before.Length + newValue.Length + after.Length];
        before.CopyTo(result);
        newValue.CopyTo(result.AsSpan(before.Length));
        after.CopyTo(result.AsSpan(before.Length + newValue.Length));
        return result;
    }

    byte[] IProtocolModel.Render() => Render();
}
