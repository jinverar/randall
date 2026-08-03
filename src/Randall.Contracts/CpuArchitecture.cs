namespace Randall.Contracts;

/// <summary>
/// CPU bitness labels persisted on crash analysis / register snapshots / debugger observations.
/// Values are uppercase (<c>X86</c> / <c>X64</c>) so UI and CDB paths can branch without guessing.
/// </summary>
public static class CpuArchitecture
{
    public const string X86 = "X86";
    public const string X64 = "X64";
    public const string Unknown = "Unknown";

    public static bool IsX86(string? architecture) =>
        architecture is not null
        && (architecture.Equals(X86, StringComparison.OrdinalIgnoreCase)
            || architecture.Equals("x86", StringComparison.OrdinalIgnoreCase)
            || architecture.Equals("i386", StringComparison.OrdinalIgnoreCase)
            || architecture.Equals("wow64", StringComparison.OrdinalIgnoreCase)
            || architecture.Equals("ia32", StringComparison.OrdinalIgnoreCase));

    public static bool IsX64(string? architecture) =>
        architecture is not null
        && (architecture.Equals(X64, StringComparison.OrdinalIgnoreCase)
            || architecture.Equals("x64", StringComparison.OrdinalIgnoreCase)
            || architecture.Equals("amd64", StringComparison.OrdinalIgnoreCase)
            || architecture.Equals("x86-64", StringComparison.OrdinalIgnoreCase)
            || architecture.Equals("x86_64", StringComparison.OrdinalIgnoreCase));

    public static string Normalize(string? architecture) =>
        IsX86(architecture) ? X86
        : IsX64(architecture) ? X64
        : string.IsNullOrWhiteSpace(architecture) ? Unknown : architecture.Trim().ToUpperInvariant();
}
