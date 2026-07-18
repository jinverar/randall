using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Phase D v0 memory lens — human-readable fault/region/UAF/link hints from a minidump
/// (and optional live PID via VirtualQueryEx).
/// </summary>
public static class MemoryLensAnalyzer
{
    private const uint ExceptionStream = 6;
    private const uint ModuleListStream = 4;
    private const uint Memory64ListStream = 9;

    private static readonly (uint Pattern, string Name, string Hint)[] FillPatterns =
    [
        (0xFEEEFEEE, "FEEEFEEE", "MSVC heap free-fill — probable use-after-free"),
        (0xDDDDDDDD, "DDDDDDDD", "MSVC debug free / guard fill — freed or uninitialized"),
        (0xCDCDCDCD, "CDCDCDCD", "MSVC debug alloc fill — uninitialized heap"),
        (0xBAADF00D, "BAADF00D", "LocalAlloc / debug poison"),
        (0xABABABAB, "ABABABAB", "Heap tail guard / no-man's-land"),
        (0xCCCCCCCC, "CCCCCCCC", "MSVC uninitialized stack (x86 debug)"),
        (0xDEADBEEF, "DEADBEEF", "Common poison / freed marker"),
    ];

    public static MemoryLensReportDto AnalyzeDump(string? dumpPath, CrashAnalysisDto? analysis = null, int? pid = null)
    {
        analysis ??= string.IsNullOrWhiteSpace(dumpPath) ? null : MiniDumpAnalyzer.Analyze(dumpPath);
        if (string.IsNullOrWhiteSpace(dumpPath) || !File.Exists(dumpPath))
        {
            if (analysis is { Ok: true })
                return FromAnalysisOnly(analysis, dumpPath, pid);
            return Fail(dumpPath, pid, "minidump not found");
        }

        try
        {
            var bytes = File.ReadAllBytes(dumpPath);
            var handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            try
            {
                var basePtr = handle.AddrOfPinnedObject();
                var fault = ExtractFault(basePtr, bytes, analysis);
                var modules = ReadModules(basePtr, bytes);
                var regions = BuildModuleRegions(modules);
                var patternHits = new List<MemoryLensPatternHitDto>();
                var linkHints = new List<MemoryLensLinkHintDto>();

                CollectAddressPatterns(fault.FaultAddress, "fault address", patternHits);
                if (analysis?.Registers is { } regs)
                {
                    CollectAddressPatterns(regs.Rip, "RIP", patternHits);
                    CollectAddressPatterns(regs.Rsp, "RSP", patternHits);
                    CollectAddressPatterns(regs.Rax, "RAX", patternHits);
                    CollectAddressPatterns(regs.Rbx, "RBX", patternHits);
                    CollectAddressPatterns(regs.Rcx, "RCX", patternHits);
                    CollectAddressPatterns(regs.Rdx, "RDX", patternHits);
                    MaybeLinkPair("RAX/RBX", regs.Rax, regs.Rbx, linkHints);
                    MaybeLinkPair("RCX/RDX", regs.Rcx, regs.Rdx, linkHints);
                }

                MemoryLensNeighborhoodDto? neighborhood = null;
                if (TryParseUlong(fault.FaultAddress, out var faultVa) && faultVa != 0)
                {
                    neighborhood = TryReadNeighborhood(bytes, basePtr, faultVa, patternHits);
                    if (pid is int livePid)
                        MergeLiveRegions(livePid, faultVa, regions);
                }

                var summary = BuildSummary(fault, patternHits, linkHints, neighborhood, regions);
                var confidence = patternHits.Any(p => p.Confidence == "high") ? "high"
                    : patternHits.Count > 0 || linkHints.Count > 0 ? "guess"
                    : fault.FaultAddress is not null ? "medium"
                    : "low";

                var report = new MemoryLensReportDto(
                    true, dumpPath, pid, confidence, summary, fault, regions,
                    patternHits, linkHints, neighborhood, null,
                    HeapBackend: "patterns");
                return HeapCdbLens.Enrich(report, dumpPath);
            }
            finally
            {
                handle.Free();
            }
        }
        catch (Exception ex)
        {
            return Fail(dumpPath, pid, ex.Message);
        }
    }

    public static MemoryLensReportDto AnalyzeLivePid(int pid)
    {
        try
        {
            var regions = QueryLiveRegions(pid, max: 40);
            var summary = new List<string>
            {
                $"Live inspect PID {pid} — {regions.Count} regions sampled (VirtualQueryEx).",
                "No crash dump attached; start a fuzz run or attach scream for fault-centered lens.",
            };
            return new MemoryLensReportDto(
                true, null, pid, "medium", summary, null, regions, [], [], null, null);
        }
        catch (Exception ex)
        {
            return Fail(null, pid, ex.Message);
        }
    }

    private static MemoryLensReportDto FromAnalysisOnly(CrashAnalysisDto analysis, string? dumpPath, int? pid)
    {
        var fault = new MemoryLensFaultDto(
            analysis.ExceptionCode, analysis.ExceptionHint, analysis.FaultAddress,
            null, analysis.FaultModule);
        var hits = new List<MemoryLensPatternHitDto>();
        CollectAddressPatterns(analysis.FaultAddress, "fault address", hits);
        if (analysis.Registers is { } regs)
        {
            CollectAddressPatterns(regs.Rip, "RIP", hits);
            CollectAddressPatterns(regs.Rax, "RAX", hits);
        }

        var summary = BuildSummary(fault, hits, [], null, []);
        return new MemoryLensReportDto(
            true, dumpPath, pid, hits.Count > 0 ? "guess" : "low", summary, fault,
            [], hits, [], null, "dump bytes unavailable — analysis-only lens");
    }

    private static MemoryLensFaultDto ExtractFault(IntPtr basePtr, byte[] dump, CrashAnalysisDto? analysis)
    {
        string? code = analysis?.ExceptionCode;
        string? hint = analysis?.ExceptionHint;
        string? address = analysis?.FaultAddress;
        string? module = analysis?.FaultModule;
        string? access = null;

        if (MiniDumpReadDumpStream(basePtr, ExceptionStream, out _, out var streamPtr, out var streamSize) &&
            streamPtr != IntPtr.Zero &&
            streamSize >= (uint)Marshal.SizeOf<MiniDumpExceptionStream>())
        {
            var exStream = Marshal.PtrToStructure<MiniDumpExceptionStream>(streamPtr);
            code ??= $"0x{exStream.Exception.ExceptionCode:X8}";
            hint ??= WindowsExceptionHints.DescribeCode(exStream.Exception.ExceptionCode);
            address ??= $"0x{exStream.Exception.ExceptionAddress:X}";
            if (exStream.Exception.NumberParameters >= 2 &&
                exStream.Exception.ExceptionCode == 0xC0000005)
            {
                access = exStream.Exception.ExceptionInformation0 switch
                {
                    0 => "read",
                    1 => "write",
                    8 => "execute",
                    _ => $"access({exStream.Exception.ExceptionInformation0})",
                };
                // Prefer ExceptionInformation[1] as the faulting VA for AVs
                if (exStream.Exception.ExceptionInformation1 != 0)
                    address = $"0x{exStream.Exception.ExceptionInformation1:X}";
            }
        }

        return new MemoryLensFaultDto(code, hint, address, access, module);
    }

    private static void CollectAddressPatterns(string? hex, string where, List<MemoryLensPatternHitDto> hits)
    {
        if (!TryParseUlong(hex, out var value) || value == 0)
            return;

        foreach (var (pattern, name, hint) in FillPatterns)
        {
            if (MatchesFill(value, pattern))
            {
                hits.Add(new MemoryLensPatternHitDto(
                    where, $"0x{value:X}", name, hint,
                    pattern is 0xFEEEFEEE or 0xDDDDDDDD ? "high" : "guess"));
            }
        }

        // NULL-ish / low canonical
        if (value < 0x10000)
        {
            hits.Add(new MemoryLensPatternHitDto(
                where, $"0x{value:X}", "low-address",
                "Near-NULL pointer — null deref or corrupted pointer", "medium"));
        }
    }

    private static bool MatchesFill(ulong value, uint pattern)
    {
        var p = pattern;
        var loft = ((ulong)p << 32) | p;
        if (value == loft || value == p)
            return true;
        // repeating pattern in either dword
        if ((uint)value == p || (uint)(value >> 32) == p)
            return true;
        return false;
    }

    private static void MaybeLinkPair(string where, string? a, string? b, List<MemoryLensLinkHintDto> hints)
    {
        if (!TryParseUlong(a, out var flink) || !TryParseUlong(b, out var blink))
            return;
        if (flink < 0x10000 || blink < 0x10000)
            return;
        // Heuristic: both look like user-mode pointers and are distinct
        if (flink == blink)
        {
            hints.Add(new MemoryLensLinkHintDto(
                where, $"0x{flink:X}", $"0x{blink:X}",
                "Flink==Blink — empty list or corrupted unlink candidate", "guess"));
            return;
        }

        if (IsUserPointer(flink) && IsUserPointer(blink))
        {
            hints.Add(new MemoryLensLinkHintDto(
                where, $"0x{flink:X}", $"0x{blink:X}",
                "Register pair looks like LIST_ENTRY Flink/Blink candidates (best-effort)",
                "guess"));
        }
    }

    private static bool IsUserPointer(ulong v) =>
        v >= 0x10000 && v < 0x00007FFFFFFFFFFFUL;

    private static MemoryLensNeighborhoodDto? TryReadNeighborhood(
        byte[] dump, IntPtr basePtr, ulong faultVa, List<MemoryLensPatternHitDto> hits)
    {
        if (!MiniDumpReadDumpStream(basePtr, Memory64ListStream, out _, out var streamPtr, out var streamSize) ||
            streamPtr == IntPtr.Zero || streamSize < 16)
            return null;

        var numberOfRanges = (ulong)Marshal.ReadInt64(streamPtr, 0);
        var baseRva = (ulong)Marshal.ReadInt64(streamPtr, 8);
        if (numberOfRanges == 0 || numberOfRanges > 1_000_000)
            return null;

        var descSize = 16; // StartOfMemoryRange + DataSize
        var header = 16;
        ulong cursorRva = baseRva;
        for (ulong i = 0; i < numberOfRanges; i++)
        {
            var descOff = header + (int)(i * (ulong)descSize);
            if (descOff + descSize > streamSize)
                break;
            var start = (ulong)Marshal.ReadInt64(streamPtr, descOff);
            var size = (ulong)Marshal.ReadInt64(streamPtr, descOff + 8);
            if (size == 0 || size > int.MaxValue)
            {
                cursorRva += size;
                continue;
            }

            if (faultVa >= start && faultVa < start + size)
            {
                var offsetInRange = faultVa - start;
                var want = 64;
                var takeStart = offsetInRange > 32 ? offsetInRange - 32 : 0UL;
                var fileOff = (long)(cursorRva + takeStart);
                var take = (int)Math.Min((ulong)want, size - takeStart);
                if (fileOff < 0 || fileOff + take > dump.Length)
                    return null;

                var slice = dump.AsSpan((int)fileOff, take).ToArray();
                ScanSlicePatterns(slice, start + takeStart, hits);
                return new MemoryLensNeighborhoodDto(
                    $"0x{start + takeStart:X}",
                    take,
                    ToHex(slice),
                    ToAscii(slice),
                    AnnotateSlice(slice, start + takeStart));
            }

            cursorRva += size;
        }

        return null;
    }

    private static void ScanSlicePatterns(byte[] slice, ulong baseVa, List<MemoryLensPatternHitDto> hits)
    {
        for (var i = 0; i + 4 <= slice.Length; i += 4)
        {
            var dword = BitConverter.ToUInt32(slice, i);
            foreach (var (pattern, name, hint) in FillPatterns)
            {
                if (dword != pattern) continue;
                hits.Add(new MemoryLensPatternHitDto(
                    $"memory+0x{i:X} (@0x{baseVa + (ulong)i:X})",
                    $"0x{dword:X8}", name, hint,
                    pattern is 0xFEEEFEEE or 0xDDDDDDDD ? "high" : "guess"));
                break;
            }
        }
    }

    private static List<string> AnnotateSlice(byte[] slice, ulong baseVa)
    {
        var notes = new List<string>();
        for (var i = 0; i + 4 <= slice.Length; i += 4)
        {
            var dword = BitConverter.ToUInt32(slice, i);
            foreach (var (pattern, name, hint) in FillPatterns)
            {
                if (dword == pattern)
                    notes.Add($"+0x{i:X}: {name} — {hint}");
            }
        }

        if (notes.Count == 0)
            notes.Add("No known free-fill dwords in this window.");
        return notes;
    }

    private static List<(ulong Base, ulong Size, string Name)> ReadModules(IntPtr basePtr, byte[] dump)
    {
        var list = new List<(ulong, ulong, string)>();
        if (!MiniDumpReadDumpStream(basePtr, ModuleListStream, out _, out var streamPtr, out var streamSize) ||
            streamPtr == IntPtr.Zero)
            return list;

        var count = Marshal.ReadInt32(streamPtr);
        var offset = 4;
        for (var i = 0; i < count && offset + 108 < streamSize; i++)
        {
            var sizeOfImage = (uint)Marshal.ReadInt32(streamPtr, offset + 0); // actually first fields differ — use base + name
            var baseOfDll = (ulong)Marshal.ReadInt64(streamPtr, offset + 8);
            var nameRva = Marshal.ReadInt32(streamPtr, offset + 0x30);
            // SizeOfImage is at +0x18 in MINIDUMP_MODULE
            var imageSize = (uint)Marshal.ReadInt32(streamPtr, offset + 0x18);
            var name = ReadUtf8AtRva(dump, nameRva);
            if (!string.IsNullOrWhiteSpace(name))
                list.Add((baseOfDll, imageSize == 0 ? 0x100000UL : imageSize, Path.GetFileName(name)));
            offset += 108;
            _ = sizeOfImage;
        }

        return list;
    }

    private static List<MemoryLensRegionDto> BuildModuleRegions(IReadOnlyList<(ulong Base, ulong Size, string Name)> modules) =>
        modules.Take(24).Select(m => new MemoryLensRegionDto(
            $"0x{m.Base:X}",
            $"0x{m.Size:X}",
            "IMAGE",
            "image",
            m.Name)).ToList();

    private static void MergeLiveRegions(int pid, ulong faultVa, List<MemoryLensRegionDto> regions)
    {
        try
        {
            foreach (var r in QueryLiveRegions(pid, max: 12, around: faultVa))
            {
                if (!regions.Any(x => x.BaseAddress == r.BaseAddress))
                    regions.Insert(0, r);
            }
        }
        catch
        {
            /* optional */
        }
    }

    private static List<MemoryLensRegionDto> QueryLiveRegions(int pid, int max, ulong? around = null)
    {
        var list = new List<MemoryLensRegionDto>();
        var h = OpenProcess(0x0410 /* QUERY_INFORMATION | VM_READ */, false, pid);
        if (h == IntPtr.Zero)
            return list;

        try
        {
            ulong addr = 0;
            while (list.Count < max && addr < 0x00007FFFFFFFFFFFUL)
            {
                var result = VirtualQueryEx(h, (IntPtr)addr, out var mbi, (UIntPtr)Marshal.SizeOf<MemoryBasicInformation>());
                if (result == UIntPtr.Zero)
                    break;
                var size = (ulong)mbi.RegionSize.ToUInt64();
                if (size == 0) break;

                var baseAddr = (ulong)mbi.BaseAddress.ToInt64();
                var include = around is null ||
                              (around.Value >= baseAddr && around.Value < baseAddr + size) ||
                              list.Count < 8;
                if (include && mbi.State == 0x1000 /* MEM_COMMIT */)
                {
                    list.Add(new MemoryLensRegionDto(
                        $"0x{baseAddr:X}",
                        $"0x{size:X}",
                        ProtectLabel(mbi.Protect),
                        KindLabel(mbi.Type),
                        null));
                }

                var next = baseAddr + size;
                if (next <= addr) break;
                addr = next;
            }
        }
        finally
        {
            CloseHandle(h);
        }

        return list;
    }

    private static string ProtectLabel(uint p) => p switch
    {
        0x01 => "---",
        0x02 => "R--",
        0x04 => "R-X",
        0x08 => "RWX?",
        0x10 => "---c",
        0x20 => "R--c",
        0x40 => "RW-",
        0x80 => "RWX",
        _ => $"0x{p:X}",
    };

    private static string KindLabel(uint t) => t switch
    {
        0x1000000 => "image",
        0x40000 => "mapped",
        0x20000 => "private",
        _ => "region",
    };

    private static List<string> BuildSummary(
        MemoryLensFaultDto fault,
        List<MemoryLensPatternHitDto> patterns,
        List<MemoryLensLinkHintDto> links,
        MemoryLensNeighborhoodDto? neighborhood,
        List<MemoryLensRegionDto> regions)
    {
        var lines = new List<string>();
        if (fault.FaultAddress is not null)
        {
            lines.Add(
                $"Crash: {fault.ExceptionHint ?? "exception"} {fault.AccessType ?? ""} @ {fault.FaultAddress}"
                    .Replace("  ", " ").Trim());
        }
        else
        {
            lines.Add("Crash: fault address unavailable");
        }

        if (fault.FaultModule is not null)
            lines.Add($"Module: {fault.FaultModule}");

        var uaf = patterns.FirstOrDefault(p =>
            p.PatternName is "FEEEFEEE" or "DDDDDDDD" or "CDCDCDCD");
        if (uaf is not null)
            lines.Add($"Hint: {uaf.Hint} (seen in {uaf.Where})");
        else if (patterns.Count > 0)
            lines.Add($"Hint: {patterns[0].Hint}");

        if (links.Count > 0)
            lines.Add($"Link/unlink: {links[0].Note}");

        if (neighborhood is not null)
            lines.Add($"Neighborhood: {neighborhood.Length} bytes around fault mapped from dump.");
        else
            lines.Add("Neighborhood: not in Memory64 ranges (dump may be light / truncated).");

        if (regions.Count > 0)
            lines.Add($"Regions: {regions.Count} image/VM entries listed below.");

        return lines;
    }

    private static MemoryLensReportDto Fail(string? dump, int? pid, string error) =>
        new(false, dump, pid, "unavailable", [$"Memory lens failed: {error}"], null, [], [], [], null, error);

    private static bool TryParseUlong(string? hex, out ulong value)
    {
        value = 0;
        if (string.IsNullOrWhiteSpace(hex))
            return false;
        var s = hex.Trim();
        if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            s = s[2..];
        return ulong.TryParse(s, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out value);
    }

    private static string ReadUtf8AtRva(byte[] dump, int rva)
    {
        if (rva <= 0 || rva >= dump.Length) return "";
        var end = rva;
        while (end < dump.Length && dump[end] != 0) end++;
        return Encoding.UTF8.GetString(dump, rva, end - rva);
    }

    private static string ToHex(byte[] data)
    {
        var sb = new StringBuilder(data.Length * 3);
        for (var i = 0; i < data.Length; i++)
        {
            if (i > 0) sb.Append(i % 16 == 0 ? '\n' : ' ');
            sb.Append(data[i].ToString("X2"));
        }

        return sb.ToString();
    }

    private static string ToAscii(byte[] data)
    {
        var chars = data.Select(b => b is >= 32 and < 127 ? (char)b : '.').ToArray();
        return new string(chars);
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
    private struct MemoryBasicInformation
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public UIntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    [DllImport("dbghelp.dll", SetLastError = true)]
    private static extern bool MiniDumpReadDumpStream(
        IntPtr BaseOfDump, uint StreamNumber, out IntPtr dir, out IntPtr streamPointer, out uint streamSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern UIntPtr VirtualQueryEx(
        IntPtr hProcess, IntPtr lpAddress, out MemoryBasicInformation lpBuffer, UIntPtr dwLength);
}
