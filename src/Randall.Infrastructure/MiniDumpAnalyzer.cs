using System.Runtime.InteropServices;
using System.Text;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>Extract exception + register context from Windows minidumps (dbghelp).</summary>
public static class MiniDumpAnalyzer
{
    private const uint ExceptionStream = 6;
    private const uint ModuleListStream = 4;

    public static CrashAnalysisDto Analyze(string? dumpPath)
    {
        if (string.IsNullOrWhiteSpace(dumpPath) || !File.Exists(dumpPath))
        {
            return new CrashAnalysisDto(
                false, dumpPath, null, null, null, null, null, [], "minidump not found");
        }

        try
        {
            var bytes = File.ReadAllBytes(dumpPath);
            var handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            try
            {
                var basePtr = handle.AddrOfPinnedObject();
                if (!MiniDumpReadDumpStream(basePtr, ExceptionStream, out _, out var streamPtr, out var streamSize) ||
                    streamPtr == IntPtr.Zero || streamSize < (uint)Marshal.SizeOf<MiniDumpExceptionStream>())
                {
                    return new CrashAnalysisDto(
                        false, dumpPath, null, null, null, null, null, [], "no exception stream in dump");
                }

                var exStream = Marshal.PtrToStructure<MiniDumpExceptionStream>(streamPtr);
                var code = exStream.Exception.ExceptionCode;
                var address = exStream.Exception.ExceptionAddress;
                var hint = WindowsExceptionHints.DescribeCode(code);

                RegisterSnapshotDto? regs = null;
                string? arch = null;
                if (exStream.ThreadContext.DataSize > 0 &&
                    TryReadContext(bytes, exStream.ThreadContext.Rva, exStream.ThreadContext.DataSize,
                        out regs, out arch))
                {
                    // regs + arch populated
                }

                var modules = ReadModuleList(basePtr, bytes);
                var moduleNames = modules.Select(m => m.Name).ToList();
                var faultModule = ResolveModule(modules, address);

                return new CrashAnalysisDto(
                    true,
                    dumpPath,
                    $"0x{code:X8}",
                    hint,
                    $"0x{address:X}",
                    faultModule,
                    regs,
                    moduleNames,
                    null,
                    Architecture: arch);
            }
            finally
            {
                handle.Free();
            }
        }
        catch (Exception ex)
        {
            return new CrashAnalysisDto(
                false, dumpPath, null, null, null, null, null, [], ex.Message);
        }
    }

    private static string Hex(ulong value) => $"0x{value:X}";
    private static string Hex32(uint value) => $"0x{value:X}";

    private static string? ResolveModule(IReadOnlyList<(ulong Base, string Name)> modules, ulong address)
    {
        foreach (var (b, name) in modules)
        {
            if (address >= b && address < b + 0x10000000)
                return $"{name}+0x{address - b:X}";
        }
        return null;
    }

    private static List<(ulong Base, string Name)> ReadModuleList(IntPtr basePtr, byte[] dump)
    {
        var list = new List<(ulong, string)>();
        if (!MiniDumpReadDumpStream(basePtr, ModuleListStream, out _, out var streamPtr, out var streamSize) ||
            streamPtr == IntPtr.Zero)
            return list;

        var count = (int)Marshal.ReadInt32(streamPtr);
        var offset = 4;
        for (var i = 0; i < count && offset + 108 < streamSize; i++)
        {
            var baseOfDll = (ulong)Marshal.ReadInt64(streamPtr, offset + 8);
            var nameRva = Marshal.ReadInt32(streamPtr, offset + 0x30);
            var name = ReadUtf8AtRva(dump, nameRva);
            if (!string.IsNullOrWhiteSpace(name))
                list.Add((baseOfDll, name));
            offset += 108;
        }
        return list;
    }

    private static string ReadUtf8AtRva(byte[] dump, int rva)
    {
        if (rva <= 0 || rva >= dump.Length)
            return "";
        var end = rva;
        while (end < dump.Length && dump[end] != 0)
            end++;
        return Encoding.UTF8.GetString(dump, rva, end - rva);
    }

    /// <summary>
    /// Read AMD64 or WOW64/x86 CONTEXT from the exception stream.
    /// Values are stored in the x64-shaped <see cref="RegisterSnapshotDto"/> fields; <c>Architecture</c> tells the UI which labels to use.
    /// </summary>
    internal static bool TryReadContext(
        byte[] dump,
        uint rva,
        uint dataSize,
        out RegisterSnapshotDto? regs,
        out string? architecture)
    {
        regs = null;
        architecture = null;
        if (rva == 0 || rva + Math.Min(dataSize, 32) > dump.Length)
            return false;

        var flagsAt0 = BitConverter.ToUInt32(dump, (int)rva);
        var flagsAt30 = rva + 0x34 <= dump.Length
            ? BitConverter.ToUInt32(dump, (int)rva + 0x30)
            : 0u;
        architecture = CpuArchitectureDetector.FromContextBlob(dataSize, flagsAt0 != 0 ? flagsAt0 : flagsAt30);

        var preferX86 = CpuArchitecture.IsX86(architecture)
                        || (dataSize is > 0 and <= 800)
                        || ((flagsAt0 & 0x00010000) != 0 && (flagsAt0 & 0x00100000) == 0);

        if (preferX86 && TryReadX86Context(dump, rva, dataSize, out regs))
        {
            architecture = CpuArchitecture.X86;
            return true;
        }

        if (TryReadAmd64Context(dump, rva, dataSize, out regs))
        {
            architecture ??= CpuArchitecture.X64;
            return true;
        }

        // Last resort: try the other layout if the preferred path failed.
        if (!preferX86 && TryReadX86Context(dump, rva, dataSize, out regs))
        {
            architecture = CpuArchitecture.X86;
            return true;
        }

        return false;
    }

    private static bool TryReadAmd64Context(byte[] dump, uint rva, uint dataSize, out RegisterSnapshotDto? regs)
    {
        regs = null;
        // Need at least through Rip (0xF8 + 8).
        if (rva + 0x100 > dump.Length)
            return false;
        if (dataSize is > 0 and < 0x100)
            return false;

        var handle = GCHandle.Alloc(dump, GCHandleType.Pinned);
        try
        {
            var ptr = handle.AddrOfPinnedObject() + (int)rva;
            var ctx = Marshal.PtrToStructure<Amd64Context>(ptr);
            if (ctx.ContextFlags == 0 && ctx.Rip == 0 && ctx.Rsp == 0)
                return false;

            regs = new RegisterSnapshotDto(
                Hex(ctx.Rip), Hex(ctx.Rsp), Hex(ctx.Rbp),
                Hex(ctx.Rax), Hex(ctx.Rbx), Hex(ctx.Rcx), Hex(ctx.Rdx),
                Architecture: CpuArchitecture.X64);
            return true;
        }
        finally
        {
            handle.Free();
        }
    }

    private static bool TryReadX86Context(byte[] dump, uint rva, uint dataSize, out RegisterSnapshotDto? regs)
    {
        regs = null;
        // WOW64/x86 CONTEXT: Eip@0xB8, Esp@0xC4 — need at least 0xC8 bytes.
        if (rva + 0xC8 > dump.Length)
            return false;
        if (dataSize is > 0 and < 0xC8)
            return false;

        var off = (int)rva;
        var contextFlags = BitConverter.ToUInt32(dump, off);
        // Reject obvious AMD64 blobs (ContextFlags live at +0x30).
        var amd64Flags = BitConverter.ToUInt32(dump, off + 0x30);
        if ((amd64Flags & 0x00100000) != 0 && (contextFlags & 0x00010000) == 0 && dataSize >= 1000)
            return false;

        uint ReadU32(int at) => BitConverter.ToUInt32(dump, off + at);
        var eip = ReadU32(0xB8);
        var esp = ReadU32(0xC4);
        var ebp = ReadU32(0xB4);
        var eax = ReadU32(0xB0);
        var ebx = ReadU32(0xA4);
        var ecx = ReadU32(0xAC);
        var edx = ReadU32(0xA8);

        if (eip == 0 && esp == 0 && ebp == 0 && eax == 0 && contextFlags == 0)
            return false;

        regs = new RegisterSnapshotDto(
            Hex32(eip), Hex32(esp), Hex32(ebp),
            Hex32(eax), Hex32(ebx), Hex32(ecx), Hex32(edx),
            Architecture: CpuArchitecture.X86);
        return true;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MiniDumpExceptionStream
    {
        public uint ThreadId;
        public uint Alignment;
        public MiniDumpException Exception;
        public MiniDumpLocationDescriptor ThreadContext;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MiniDumpException
    {
        public uint ExceptionCode;
        public uint ExceptionFlags;
        public ulong ExceptionRecord;
        public ulong ExceptionAddress;
        public uint NumberParameters;
        public uint __alignment;
        public ulong ExceptionInformation0;
        public ulong ExceptionInformation1;
        public ulong ExceptionInformation2;
        public ulong ExceptionInformation3;
        public ulong ExceptionInformation4;
        public ulong ExceptionInformation5;
        public ulong ExceptionInformation6;
        public ulong ExceptionInformation7;
        public ulong ExceptionInformation8;
        public ulong ExceptionInformation9;
        public ulong ExceptionInformation10;
        public ulong ExceptionInformation11;
        public ulong ExceptionInformation12;
        public ulong ExceptionInformation13;
        public ulong ExceptionInformation14;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MiniDumpLocationDescriptor
    {
        public uint DataSize;
        public uint Rva;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Amd64Context
    {
        public ulong P1Home;
        public ulong P2Home;
        public ulong P3Home;
        public ulong P4Home;
        public ulong P5Home;
        public ulong P6Home;
        public uint ContextFlags;
        public uint MxCsr;
        public ushort SegCs;
        public ushort SegDs;
        public ushort SegEs;
        public ushort SegFs;
        public ushort SegGs;
        public ushort SegSs;
        public uint EFlags;
        public ulong Dr0;
        public ulong Dr1;
        public ulong Dr2;
        public ulong Dr3;
        public ulong Dr6;
        public ulong Dr7;
        public ulong Rax;
        public ulong Rcx;
        public ulong Rdx;
        public ulong Rbx;
        public ulong Rsp;
        public ulong Rbp;
        public ulong Rsi;
        public ulong Rdi;
        public ulong R8;
        public ulong R9;
        public ulong R10;
        public ulong R11;
        public ulong R12;
        public ulong R13;
        public ulong R14;
        public ulong R15;
        public ulong Rip;
    }

    [DllImport("dbghelp.dll", SetLastError = true)]
    private static extern bool MiniDumpReadDumpStream(
        IntPtr BaseOfDump,
        uint StreamNumber,
        out IntPtr dir,
        out IntPtr streamPointer,
        out uint streamSize);
}
