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
    public List<ProtocolBlockDefinition>? Children { get; set; }
    public ProtocolBlockDefinition? Child { get; set; }
    public string? LengthName { get; set; }
    public int LengthBytes { get; set; } = 4;
    public bool LittleEndian { get; set; } = true;
    public bool LengthMutable { get; set; } = true;
    public string? Algorithm { get; set; }
    public bool SyncLength { get; set; }
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
