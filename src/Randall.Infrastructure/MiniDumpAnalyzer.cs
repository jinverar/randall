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
                false, dumpPath, null, null, null, null, null, [], [], "minidump not found");
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
                        false, dumpPath, null, null, null, null, null, [], [], "no exception stream in dump");
                }

                var exStream = Marshal.PtrToStructure<MiniDumpExceptionStream>(streamPtr);
                var code = exStream.Exception.ExceptionCode;
                var address = exStream.Exception.ExceptionAddress;
                var hint = WindowsExceptionHints.Describe(unchecked((int)code)) ??
                           $"0x{code:X8}";

                RegisterSnapshotDto? regs = null;
                if (exStream.ThreadContext.DataSize > 0 &&
                    TryReadContext(bytes, exStream.ThreadContext.Rva, out var ctx))
                {
                    regs = new RegisterSnapshotDto(
                        ctx.Rip, ctx.Rsp, ctx.Rbp, ctx.Rax, ctx.Rbx, ctx.Rcx, ctx.Rdx);
                }

                var modules = ReadModuleList(basePtr, bytes);
                var faultModule = ResolveModule(modules, address);

                return new CrashAnalysisDto(
                    true,
                    dumpPath,
                    $"0x{code:X8}",
                    hint,
                    $"0x{address:X}",
                    faultModule,
                    regs,
                    modules.Take(12).ToList(),
                    HotEdgesFromModules(modules),
                    null);
            }
            finally
            {
                handle.Free();
            }
        }
        catch (Exception ex)
        {
            return new CrashAnalysisDto(
                false, dumpPath, null, null, null, null, null, [], [], ex.Message);
        }
    }

    private static List<string> HotEdgesFromModules(IReadOnlyList<string> modules) => modules;

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

    private static bool TryReadContext(byte[] dump, uint rva, out Amd64Context ctx)
    {
        ctx = default;
        if (rva + 0x100 > dump.Length)
            return false;

        var handle = GCHandle.Alloc(dump, GCHandleType.Pinned);
        try
        {
            var ptr = handle.AddrOfPinnedObject() + (int)rva;
            ctx = Marshal.PtrToStructure<Amd64Context>(ptr);
            return ctx.ContextFlags != 0;
        }
        finally
        {
            handle.Free();
        }
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
