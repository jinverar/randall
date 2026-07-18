namespace Randall.Contracts;

public sealed record DocIndexEntryDto(string Path, string Title, string Group);

public sealed record DocContentDto(string Path, string Title, string Markdown);
