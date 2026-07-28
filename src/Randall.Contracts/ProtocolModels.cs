namespace Randall.Contracts;

public sealed class ProtocolDefinition
{
    public string Name { get; set; } = "";
    public string Description { get; set; } = "";
    public bool TrailingCrc32 { get; set; }
    public List<ProtocolBlockDefinition> Blocks { get; set; } = [];
}

public sealed class ProtocolBlockDefinition
{
    public string Type { get; set; } = "static";
    public string? Name { get; set; }
    public string? Value { get; set; }
    public bool Mutable { get; set; } = true;
    public int MinSize { get; set; } = 1;
    public int MaxSize { get; set; } = 4096;
    public string? SeedFile { get; set; }
    public List<string> Values { get; set; } = [];
    /// <summary>Numeric enum / flag members (decimal or 0x hex).</summary>
    public List<string> EnumValues { get; set; } = [];
    /// <summary>Named flag bits: name → mask (0x01, 0x02, …).</summary>
    public Dictionary<string, string> Flags { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public List<ProtocolBlockDefinition>? Children { get; set; }
    public ProtocolBlockDefinition? Child { get; set; }
    /// <summary>Switch cases: key → nested block.</summary>
    public List<ProtocolSwitchCase>? Cases { get; set; }
    public string? LengthName { get; set; }
    public int LengthBytes { get; set; } = 4;
    /// <summary>Integer / enum / flags / offset width in bytes (1/2/4/8).</summary>
    public int Width { get; set; }
    public bool LittleEndian { get; set; } = true;
    public bool LengthMutable { get; set; } = true;
    public bool Signed { get; set; }
    public string? Algorithm { get; set; }
    public bool SyncLength { get; set; }
    /// <summary>Repeat count (fixed) or max when CountMutable.</summary>
    public int Count { get; set; } = 1;
    public int MinCount { get; set; }
    public int MaxCount { get; set; } = 8;
    public bool CountMutable { get; set; } = true;
    public int Align { get; set; } = 4;
    public string? PadByte { get; set; }
    /// <summary>Conditional: field name, or Peach-style <c>field == value</c> / <c>!=</c>.</summary>
    public string? When { get; set; }
    public string? WhenEquals { get; set; }
    public bool Relative { get; set; }
    public string? TargetField { get; set; }
    /// <summary>Checksum cover start: named field whose offset begins the CRC range.</summary>
    public string? CoverFrom { get; set; }
    /// <summary>Per-block length policy override (valid|mutate|independent|off-by-one|wrap|actualPlusDelta|stale|zero).</summary>
    public string? LengthPolicy { get; set; }
    /// <summary>Per-block checksum policy override.</summary>
    public string? ChecksumPolicy { get; set; }
}

public sealed class ProtocolSwitchCase
{
    public string Key { get; set; } = "";
    public ProtocolBlockDefinition? Block { get; set; }
    public List<ProtocolBlockDefinition>? Children { get; set; }
}

public sealed record ProtocolSummaryDto(
    string Name,
    string Description,
    string Path,
    IReadOnlyList<ProtocolFieldDto> Fields);

public sealed record ProtocolFieldDto(
    string Name,
    int Offset,
    int Length,
    bool Mutable,
    string Type);
