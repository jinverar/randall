using System.Security.Cryptography;
using System.Text;
using Randall.Core;

namespace Randall.Infrastructure.Mutators;

public static class BuiltInMutators
{
    public static IReadOnlyList<IMutator> Create(IEnumerable<string> names, int? seed = null)
    {
        var rng = seed.HasValue ? new Random(seed.Value) : Random.Shared;
        var list = new List<IMutator>();
        foreach (var name in names)
        {
            var n = name.Trim().ToLowerInvariant();
            IMutator? m = n switch
            {
                "bitflip" => new BitFlipMutator(rng),
                "expand" => new ExpandMutator(rng),
                "truncate" => new TruncateMutator(rng),
                "boundary" => new BoundaryMutator(rng),
                "insert" => new InsertBlobMutator(rng),
                _ => null,
            };
            if (m is not null)
                list.Add(m);
        }
        if (list.Count == 0)
            list.Add(new BitFlipMutator(rng));
        return list;
    }
}

internal sealed class BitFlipMutator(Random rng) : IMutator
{
    public string Name => "bitflip";
    public ReadOnlyMemory<byte> Mutate(ReadOnlyMemory<byte> input)
    {
        if (input.Length == 0)
            return new byte[] { (byte)rng.Next(256) };
        var buf = input.ToArray();
        var i = rng.Next(buf.Length);
        buf[i] ^= (byte)(1 << rng.Next(8));
        return buf;
    }
}

internal sealed class ExpandMutator(Random rng) : IMutator
{
    public string Name => "expand";
    public ReadOnlyMemory<byte> Mutate(ReadOnlyMemory<byte> input)
    {
        var repeat = rng.Next(64, 4096);
        var buf = new byte[input.Length + repeat];
        input.CopyTo(buf);
        for (var i = input.Length; i < buf.Length; i++)
            buf[i] = (byte)'A';
        return buf;
    }
}

internal sealed class TruncateMutator(Random rng) : IMutator
{
    public string Name => "truncate";
    public ReadOnlyMemory<byte> Mutate(ReadOnlyMemory<byte> input)
    {
        if (input.Length <= 1)
            return input;
        var len = rng.Next(1, input.Length);
        return input.Slice(0, len).ToArray();
    }
}

internal sealed class BoundaryMutator(Random rng) : IMutator
{
    public string Name => "boundary";
    public ReadOnlyMemory<byte> Mutate(ReadOnlyMemory<byte> input)
    {
        var buf = input.Length > 0 ? input.ToArray() : new byte[4];
        var i = rng.Next(buf.Length);
        var values = new byte[] { 0, 1, 0x7F, 0x80, 0xFF, 0xFE };
        buf[i] = values[rng.Next(values.Length)];
        return buf;
    }
}

internal sealed class InsertBlobMutator(Random rng) : IMutator
{
    public string Name => "insert";
    public ReadOnlyMemory<byte> Mutate(ReadOnlyMemory<byte> input)
    {
        var blobLen = rng.Next(8, 256);
        var buf = new byte[input.Length + blobLen];
        input.CopyTo(buf);
        rng.NextBytes(buf.AsSpan(input.Length));
        return buf;
    }
}

public static class InputHash
{
    public static string StackHash(ReadOnlyMemory<byte> input)
    {
        var hash = SHA256.HashData(input.Span);
        return Convert.ToHexString(hash)[..16];
    }
}
