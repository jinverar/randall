using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Map internal x64-shaped register keys (Rip/RAX DTO fields, CanonicalReg) to UI/CDB labels
/// for the crash architecture. Values stay in the same DTO fields; only names change.
/// </summary>
public static class RegisterDisplayNames
{
    private static readonly Dictionary<string, string> X64ToX86 = new(StringComparer.OrdinalIgnoreCase)
    {
        ["RIP"] = "EIP",
        ["RSP"] = "ESP",
        ["RBP"] = "EBP",
        ["RAX"] = "EAX",
        ["RBX"] = "EBX",
        ["RCX"] = "ECX",
        ["RDX"] = "EDX",
        ["RSI"] = "ESI",
        ["RDI"] = "EDI",
        ["R8"] = "R8D",
        ["R9"] = "R9D",
        ["R10"] = "R10D",
        ["R11"] = "R11D",
        ["R12"] = "R12D",
        ["R13"] = "R13D",
        ["R14"] = "R14D",
        ["R15"] = "R15D",
    };

    private static readonly Dictionary<string, string> X86ToX64 = new(StringComparer.OrdinalIgnoreCase)
    {
        ["EIP"] = "RIP",
        ["ESP"] = "RSP",
        ["EBP"] = "RBP",
        ["EAX"] = "RAX",
        ["EBX"] = "RBX",
        ["ECX"] = "RCX",
        ["EDX"] = "RDX",
        ["ESI"] = "RSI",
        ["EDI"] = "RDI",
    };

    public static string ForArch(string? register, string? architecture)
    {
        if (string.IsNullOrWhiteSpace(register))
            return register ?? "";
        var key = register.Trim().ToUpperInvariant();
        if (CpuArchitecture.IsX86(architecture))
            return X64ToX86.TryGetValue(key, out var x86) ? x86 : key;
        if (CpuArchitecture.IsX64(architecture) && X86ToX64.TryGetValue(key, out var x64))
            return x64;
        return key;
    }

    /// <summary>Ordered (label, value) rows for the Registers grid from a snapshot DTO.</summary>
    public static IReadOnlyList<(string Label, string? Value)> SnapshotRows(
        RegisterSnapshotDto? regs,
        string? architecture = null)
    {
        if (regs is null)
            return [];
        var arch = architecture ?? regs.Architecture;
        return
        [
            (ForArch("RIP", arch), regs.Rip),
            (ForArch("RSP", arch), regs.Rsp),
            (ForArch("RBP", arch), regs.Rbp),
            (ForArch("RAX", arch), regs.Rax),
            (ForArch("RBX", arch), regs.Rbx),
            (ForArch("RCX", arch), regs.Rcx),
            (ForArch("RDX", arch), regs.Rdx),
        ];
    }
}
