using System.Buffers.Binary;
using System.Text.RegularExpressions;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Detect target/crash CPU architecture from PE machine, ELF class, WOW64 flag,
/// minidump CONTEXT size/flags, or register-dump text (eip vs rip).
/// </summary>
public static partial class CpuArchitectureDetector
{
    public const ushort ImageFileMachineI386 = 0x014C;
    public const ushort ImageFileMachineAmd64 = 0x8664;
    public const ushort ImageFileMachineArm64 = 0xAA64;

    private const uint ContextI386 = 0x00010000;
    private const uint ContextAmd64 = 0x00100000;

    /// <summary>PE machine / ELF EI_CLASS from an on-disk image.</summary>
    public static string? FromExecutable(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            return null;

        try
        {
            using var fs = File.OpenRead(path);
            Span<byte> hdr = stackalloc byte[64];
            var n = fs.Read(hdr);
            if (n < 5)
                return null;

            // ELF: EI_CLASS at offset 4 — 1=32-bit, 2=64-bit
            if (hdr[0] == 0x7F && hdr[1] == (byte)'E' && hdr[2] == (byte)'L' && hdr[3] == (byte)'F')
                return hdr[4] == 1 ? CpuArchitecture.X86 : CpuArchitecture.X64;

            // PE
            if (hdr[0] != (byte)'M' || hdr[1] != (byte)'Z' || n < 0x40)
                return null;
            var peOff = BinaryPrimitives.ReadInt32LittleEndian(hdr[0x3C..]);
            if (peOff <= 0 || peOff > 0x100000)
                return null;
            fs.Seek(peOff, SeekOrigin.Begin);
            Span<byte> pe = stackalloc byte[6];
            if (fs.Read(pe) < 6)
                return null;
            if (BinaryPrimitives.ReadUInt32LittleEndian(pe) != 0x00004550)
                return null;
            var machine = BinaryPrimitives.ReadUInt16LittleEndian(pe[4..]);
            return machine switch
            {
                ImageFileMachineI386 => CpuArchitecture.X86,
                ImageFileMachineAmd64 => CpuArchitecture.X64,
                ImageFileMachineArm64 => CpuArchitecture.X64, // treat as 64-bit register surface
                _ => null,
            };
        }
        catch
        {
            return null;
        }
    }

    public static string FromWow64(bool wow64) =>
        wow64 ? CpuArchitecture.X86 : CpuArchitecture.X64;

    /// <summary>Minidump exception-stream CONTEXT blob size / ContextFlags.</summary>
    public static string? FromContextBlob(uint dataSize, uint contextFlags)
    {
        if ((contextFlags & ContextI386) != 0 && (contextFlags & ContextAmd64) == 0)
            return CpuArchitecture.X86;
        if ((contextFlags & ContextAmd64) != 0)
            return CpuArchitecture.X64;

        // WOW64 CONTEXT is 716 bytes; AMD64 CONTEXT is typically ≥0x4D0 (1232).
        if (dataSize is > 0 and <= 800)
            return CpuArchitecture.X86;
        if (dataSize >= 1000)
            return CpuArchitecture.X64;
        return null;
    }

    /// <summary>CDB / gdb register dump: prefer explicit eip/esp over rip/rsp.</summary>
    public static string? FromRegistersText(string? registersText)
    {
        if (string.IsNullOrWhiteSpace(registersText))
            return null;

        var hasEip = EipToken().IsMatch(registersText);
        var hasRip = RipToken().IsMatch(registersText);
        var hasEsp = EspToken().IsMatch(registersText);
        var hasRsp = RspToken().IsMatch(registersText);

        if (hasEip && !hasRip)
            return CpuArchitecture.X86;
        if (hasRip && !hasEip)
            return CpuArchitecture.X64;
        if (hasEsp && !hasRsp)
            return CpuArchitecture.X86;
        if (hasRsp && !hasEsp)
            return CpuArchitecture.X64;
        return null;
    }

    public static string? FromRegisterSnapshot(RegisterSnapshotDto? regs)
    {
        if (regs is null)
            return null;
        if (!string.IsNullOrWhiteSpace(regs.Architecture))
            return CpuArchitecture.Normalize(regs.Architecture);
        return null;
    }

    /// <summary>
    /// Resolve with priority: explicit → WOW64 → PE/ELF → context blob → register text → default X64.
    /// </summary>
    public static string Resolve(
        string? explicitArch = null,
        bool? wow64 = null,
        string? executablePath = null,
        uint? contextDataSize = null,
        uint? contextFlags = null,
        string? registersText = null,
        RegisterSnapshotDto? registers = null,
        string? defaultArch = CpuArchitecture.X64)
    {
        if (!string.IsNullOrWhiteSpace(explicitArch) && !CpuArchitecture.Normalize(explicitArch).Equals(CpuArchitecture.Unknown, StringComparison.Ordinal))
            return CpuArchitecture.Normalize(explicitArch);

        if (registers?.Architecture is { Length: > 0 } regArch
            && !CpuArchitecture.Normalize(regArch).Equals(CpuArchitecture.Unknown, StringComparison.Ordinal))
            return CpuArchitecture.Normalize(regArch);

        if (wow64 is true)
            return CpuArchitecture.X86;
        if (wow64 is false)
            return CpuArchitecture.X64;

        var fromExe = FromExecutable(executablePath);
        if (fromExe is not null)
            return fromExe;

        if (contextDataSize is uint size)
        {
            var fromCtx = FromContextBlob(size, contextFlags ?? 0);
            if (fromCtx is not null)
                return fromCtx;
        }

        var fromText = FromRegistersText(registersText);
        if (fromText is not null)
            return fromText;

        return defaultArch ?? CpuArchitecture.X64;
    }

    [GeneratedRegex(@"\beip\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex EipToken();

    [GeneratedRegex(@"\brip\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex RipToken();

    [GeneratedRegex(@"\besp\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex EspToken();

    [GeneratedRegex(@"\brsp\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex RspToken();
}
