namespace Randall.Infrastructure;

public static class LineageChainBuilder
{
    public static IReadOnlyList<string> BuildFromParent(
        string? parentInputHash,
        IReadOnlyDictionary<string, IReadOnlyList<string>> lineageByHash,
        IReadOnlyList<string> mutatorChain)
    {
        var current = mutatorChain
            .Where(n => !string.IsNullOrWhiteSpace(n)
                        && !n.StartsWith("joker:", StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (string.IsNullOrWhiteSpace(parentInputHash)
            || !lineageByHash.TryGetValue(parentInputHash, out var parentChain)
            || parentChain.Count == 0)
            return current;

        var merged = parentChain.ToList();
        foreach (var name in current)
        {
            if (merged.Count > 0 && merged[^1].Equals(name, StringComparison.OrdinalIgnoreCase))
                continue;
            merged.Add(name);
        }

        return merged;
    }
}
