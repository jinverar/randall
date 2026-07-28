using System.Security.Cryptography;
using System.Text;
using Randall.Contracts;
using Randall.Core;

namespace Randall.Infrastructure.Mutators;

public static class BuiltInMutators
{
    public static IReadOnlyList<IMutator> Create(
        IEnumerable<string> names,
        int? seed = null,
        MutationContext? context = null)
    {
        var rng = seed.HasValue ? new Random(seed.Value) : Random.Shared;
        context ??= new MutationContext();
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
                "havoc" => new HavocMutator(rng, context.HavocDepth),
                "interesting" or "ints" => new InterestingMutator(rng),
                "dictionary" or "dict" => new DictionaryMutator(rng, context.DictionaryTokens),
                "arith" => new ArithMutator(rng),
                "duplicate" or "dup" => new DuplicateMutator(rng),
                "shuffle" => new ShuffleMutator(rng),
                "cyclic" or "pattern" => new CyclicMutator(rng),
                "delete-range" or "delete" or "delete_range" => new ChunkOpMutator("delete-range", rng, MutationOps.DeleteRange),
                "insert-at-offset" or "insert-at" or "insert_at_offset" => new ChunkOpMutator("insert-at-offset", rng, (b, r) => MutationOps.InsertAtOffset(b, r)),
                "replace-chunk" or "replace" or "replace_chunk" => new ChunkOpMutator("replace-chunk", rng, MutationOps.ReplaceChunk),
                "zero-range" or "zero" or "zero_range" => new ChunkOpMutator("zero-range", rng, MutationOps.ZeroRange),
                "fill-range" or "fill" or "fill_range" => new ChunkOpMutator("fill-range", rng, MutationOps.FillRange),
                "clone-chunk" or "clone" or "clone_chunk" => new ChunkOpMutator("clone-chunk", rng, MutationOps.CloneChunk),
                "move-chunk" or "move" or "move_chunk" => new ChunkOpMutator("move-chunk", rng, MutationOps.MoveChunk),
                "swap-records" or "swap" or "swap_records" => new ChunkOpMutator("swap-records", rng, MutationOps.SwapRecords),
                "repeat-record" or "repeat" or "repeat_record" => new ChunkOpMutator("repeat-record", rng, MutationOps.RepeatRecord),
                "lengthen-near-field" or "lengthen" => new ChunkOpMutator("lengthen-near-field", rng, MutationOps.LengthenNearField),
                "shorten-near-field" or "shorten" => new ChunkOpMutator("shorten-near-field", rng, MutationOps.ShortenNearField),
                "dictionary-at-field" or "dict-at-field" => new DictionaryMutator(rng, context.DictionaryTokens),
                "splice" when context.PickAlternateSeed is not null =>
                    new SpliceMutator(rng, context.PickAlternateSeed),
                _ => null,
            };
            if (m is not null)
                list.Add(m);
        }
        if (list.Count == 0)
            list.Add(new BitFlipMutator(rng));
        return list;
    }

    public static IReadOnlyList<byte[]> BuildDictionaryTokens(
        ProjectConfig project,
        string yamlPath)
    {
        var tokens = new List<byte[]>();
        foreach (var entry in project.Dictionary)
        {
            if (string.IsNullOrWhiteSpace(entry))
                continue;
            tokens.Add(DecodeDictionaryEntry(entry));
        }

        if (!string.IsNullOrWhiteSpace(project.DictionaryFile))
        {
            try
            {
                var path = ProjectLoader.ResolvePath(yamlPath, project.DictionaryFile);
                foreach (var line in File.ReadLines(path))
                {
                    if (string.IsNullOrWhiteSpace(line) || line.StartsWith('#'))
                        continue;
                    tokens.Add(DecodeDictionaryEntry(line));
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Warning: dictionary file skipped: {ex.Message}");
            }
        }

        return tokens;
    }

    private static byte[] DecodeDictionaryEntry(string entry)
    {
        if (entry.StartsWith("hex:", StringComparison.OrdinalIgnoreCase))
        {
            var hex = entry[4..].Replace(" ", "").Replace("-", "");
            return Convert.FromHexString(hex);
        }
        return System.Text.Encoding.UTF8.GetBytes(entry
            .Replace("\\r", "\r", StringComparison.Ordinal)
            .Replace("\\n", "\n", StringComparison.Ordinal)
            .Replace("\\t", "\t", StringComparison.Ordinal)
            .Replace("\\0", "\0", StringComparison.Ordinal));
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

internal sealed class ChunkOpMutator(
    string name,
    Random rng,
    Func<byte[], Random, byte[]> op) : IMutator
{
    public string Name => name;
    public ReadOnlyMemory<byte> Mutate(ReadOnlyMemory<byte> input) =>
        op(input.ToArray(), rng);
}

/// <summary>
/// Exploit-dev practice mutator — replace/expand the payload with a Metasploit-style cyclic
/// pattern so a crash can be turned into "RIP/saved-return at offset N".
/// </summary>
internal sealed class CyclicMutator(Random rng) : IMutator
{
    public string Name => "cyclic";
    public ReadOnlyMemory<byte> Mutate(ReadOnlyMemory<byte> input)
    {
        // Prefer overflow-sized patterns for stack-smash labs (64–800), keep unique range.
        var len = rng.Next(64, 801);
        if (input.Length > len)
            len = Math.Min(input.Length + rng.Next(32, 200), PatternTools.MaxUnique);
        return Encoding.ASCII.GetBytes(PatternTools.Create(len));
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
