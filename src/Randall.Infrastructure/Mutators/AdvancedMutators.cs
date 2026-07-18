using Randall.Core;

namespace Randall.Infrastructure.Mutators;

public sealed class MutationContext
{
    public IReadOnlyList<byte[]> DictionaryTokens { get; init; } = [];
    public Func<byte[]>? PickAlternateSeed { get; init; }
    public int HavocDepth { get; init; } = 6;
}

internal sealed class HavocMutator(Random rng, int depth) : IMutator
{
    public string Name => "havoc";
    public ReadOnlyMemory<byte> Mutate(ReadOnlyMemory<byte> input) =>
        MutationOps.Havoc(input.ToArray(), rng, depth);
}

internal sealed class InterestingMutator(Random rng) : IMutator
{
    public string Name => "interesting";
    public ReadOnlyMemory<byte> Mutate(ReadOnlyMemory<byte> input) =>
        MutationOps.InterestingIntegers(input.ToArray(), rng);
}

internal sealed class DictionaryMutator(Random rng, IReadOnlyList<byte[]> tokens) : IMutator
{
    public string Name => "dictionary";
    public ReadOnlyMemory<byte> Mutate(ReadOnlyMemory<byte> input)
    {
        if (tokens.Count == 0)
            return MutationOps.InterestingByte(input.ToArray(), rng);
        var token = tokens[rng.Next(tokens.Count)];
        return rng.NextDouble() < 0.5
            ? MutationOps.DictionaryOverwrite(input.ToArray(), token, rng)
            : MutationOps.DictionaryInsert(input.ToArray(), token, rng);
    }
}

internal sealed class SpliceMutator(Random rng, Func<byte[]> pickAlternate) : IMutator
{
    public string Name => "splice";
    public ReadOnlyMemory<byte> Mutate(ReadOnlyMemory<byte> input)
    {
        var other = pickAlternate();
        return MutationOps.Splice(input.ToArray(), other, rng);
    }
}

internal sealed class ArithMutator(Random rng) : IMutator
{
    public string Name => "arith";
    public ReadOnlyMemory<byte> Mutate(ReadOnlyMemory<byte> input) =>
        MutationOps.Arith(input.ToArray(), rng);
}

internal sealed class DuplicateMutator(Random rng) : IMutator
{
    public string Name => "duplicate";
    public ReadOnlyMemory<byte> Mutate(ReadOnlyMemory<byte> input) =>
        MutationOps.DuplicateChunk(input.ToArray(), rng);
}

internal sealed class ShuffleMutator(Random rng) : IMutator
{
    public string Name => "shuffle";
    public ReadOnlyMemory<byte> Mutate(ReadOnlyMemory<byte> input) =>
        MutationOps.ShuffleSpans(input.ToArray(), rng);
}
