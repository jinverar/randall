namespace Randall.Core.Model;

/// <summary>
/// How length fields are rewritten after mutation (Peach-style dependency policy).
/// </summary>
public enum LengthPolicy
{
    /// <summary>Rewrite length to match actual payload size (valid framing).</summary>
    Valid,
    /// <summary>Leave the mutated length bytes alone.</summary>
    Mutate,
    /// <summary>Same as Mutate — do not resync (alias for clarity vs Valid).</summary>
    Independent,
    /// <summary>Write actual length ± 1.</summary>
    OffByOne,
    /// <summary>Write actual length truncated/wrapped to field width.</summary>
    Wrap,
    /// <summary>Write actual length + configured delta.</summary>
    ActualPlusDelta,
    /// <summary>Keep the pre-mutation length value (stale vs body).</summary>
    Stale,
    /// <summary>Force length field to zero.</summary>
    Zero,
}

/// <summary>
/// How checksum / CRC fields are rewritten after mutation.
/// </summary>
public enum ChecksumPolicy
{
    Valid,
    Mutate,
    Independent,
    OffByOne,
    Wrap,
    ActualPlusDelta,
    Stale,
    Zero,
}

public static class DependencyPolicyParser
{
    public static LengthPolicy ParseLength(string? value, bool syncLengthFieldsFallback)
    {
        if (string.IsNullOrWhiteSpace(value))
            return syncLengthFieldsFallback ? LengthPolicy.Valid : LengthPolicy.Independent;
        return value.Trim().ToLowerInvariant() switch
        {
            "valid" or "sync" or "fix" => LengthPolicy.Valid,
            "mutate" => LengthPolicy.Mutate,
            "independent" or "off" or "none" or "preserve" => LengthPolicy.Independent,
            "off-by-one" or "offbyone" or "obo" => LengthPolicy.OffByOne,
            "wrap" => LengthPolicy.Wrap,
            "actualplusdelta" or "actual-plus-delta" or "delta" => LengthPolicy.ActualPlusDelta,
            "stale" => LengthPolicy.Stale,
            "zero" => LengthPolicy.Zero,
            _ => syncLengthFieldsFallback ? LengthPolicy.Valid : LengthPolicy.Independent,
        };
    }

    public static ChecksumPolicy ParseChecksum(string? value, bool defaultValid = true)
    {
        if (string.IsNullOrWhiteSpace(value))
            return defaultValid ? ChecksumPolicy.Valid : ChecksumPolicy.Independent;
        return value.Trim().ToLowerInvariant() switch
        {
            "valid" or "sync" or "fix" => ChecksumPolicy.Valid,
            "mutate" => ChecksumPolicy.Mutate,
            "independent" or "off" or "none" or "preserve" => ChecksumPolicy.Independent,
            "off-by-one" or "offbyone" or "obo" => ChecksumPolicy.OffByOne,
            "wrap" => ChecksumPolicy.Wrap,
            "actualplusdelta" or "actual-plus-delta" or "delta" => ChecksumPolicy.ActualPlusDelta,
            "stale" => ChecksumPolicy.Stale,
            "zero" => ChecksumPolicy.Zero,
            _ => defaultValid ? ChecksumPolicy.Valid : ChecksumPolicy.Independent,
        };
    }
}
