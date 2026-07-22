using System.Buffers.Binary;
using System.Text;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Lightweight PE/ELF surface map for stalk-guided RE: sections, imports, and strings.
/// Not a disassembler — enough to label missed blocks near interesting surfaces.
/// </summary>
public sealed class BinarySurfaceMap
{
    public string Path { get; init; } = "";
    public string Format { get; init; } = "unknown";
    public ulong ImageBase { get; init; }
    public IReadOnlyList<BinarySectionDto> Sections { get; init; } = [];
    public IReadOnlyList<BinaryImportDto> Imports { get; init; } = [];
    public IReadOnlyList<BinaryStringDto> Strings { get; init; } = [];

    private List<(ulong Rva, ulong Size, string Name)> _secRanges = [];
    private List<(ulong Rva, string Text)> _stringIndex = [];
    private List<(ulong Rva, string Label)> _importIndex = [];

    public static BinarySurfaceMap? TryLoad(string? binaryPath, int maxStrings = 2500)
    {
        if (string.IsNullOrWhiteSpace(binaryPath) || !File.Exists(binaryPath))
            return null;
        try
        {
            var bytes = File.ReadAllBytes(binaryPath);
            if (bytes.Length < 64)
                return null;
            if (bytes[0] == (byte)'M' && bytes[1] == (byte)'Z')
                return ParsePe(binaryPath, bytes, maxStrings);
            if (bytes.Length >= 4 && bytes[0] == 0x7F && bytes[1] == (byte)'E' &&
                bytes[2] == (byte)'L' && bytes[3] == (byte)'F')
                return ParseElf(binaryPath, bytes, maxStrings);
            return new BinarySurfaceMap
            {
                Path = binaryPath,
                Format = "unknown",
            };
        }
        catch (IOException)
        {
            return null;
        }
        catch (UnauthorizedAccessException)
        {
            return null;
        }
    }

    public string? SectionAt(ulong rva)
    {
        foreach (var (start, size, name) in _secRanges)
        {
            if (rva >= start && rva < start + Math.Max(1UL, size))
                return name;
        }
        return null;
    }

    public IReadOnlyList<string> NearbyStrings(ulong rva, ulong window = 0x400, int limit = 6)
    {
        var list = new List<(ulong Dist, string Text)>();
        foreach (var (sr, text) in _stringIndex)
        {
            var dist = sr > rva ? sr - rva : rva - sr;
            if (dist <= window)
                list.Add((dist, text));
        }
        return list.OrderBy(x => x.Dist).Take(limit).Select(x => x.Text).ToList();
    }

    public IReadOnlyList<string> NearbyImports(ulong rva, ulong window = 0x300, int limit = 6)
    {
        var list = new List<(ulong Dist, string Label)>();
        foreach (var (ir, label) in _importIndex)
        {
            var dist = ir > rva ? ir - rva : rva - ir;
            if (dist <= window)
                list.Add((dist, label));
        }
        return list.OrderBy(x => x.Dist).Take(limit).Select(x => x.Label).ToList();
    }

    public static bool IsInterestingImport(string function)
    {
        if (string.IsNullOrWhiteSpace(function))
            return false;
        var f = function.Trim();
        foreach (var tip in InterestingImportNeedles)
        {
            if (f.Contains(tip, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    public static bool LooksDangerousString(string text)
    {
        if (string.IsNullOrWhiteSpace(text) || text.Length < 3)
            return false;
        foreach (var tip in DangerousStringNeedles)
        {
            if (text.Contains(tip, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    private static readonly string[] InterestingImportNeedles =
    [
        "memcpy", "memmove", "memset", "strcpy", "strncpy", "strcat", "strncat",
        "sprintf", "vsprintf", "snprintf", "gets", "scanf", "sscanf",
        "recv", "recvfrom", "WSARecv", "ReadFile", "WriteFile", "DeviceIoControl",
        "MultiByteToWideChar", "WideCharToMultiByte", "lstrcpy", "lstrcat",
        "wcscpy", "wcscat", "CopyMemory", "RtlCopyMemory", "VirtualAlloc",
        "HeapAlloc", "malloc", "realloc", "free", "strcpy_s", "wcscpy_s",
    ];

    private static readonly string[] DangerousStringNeedles =
    [
        "password", "passwd", "secret", "admin", "root", "overflow",
        "buffer", "strcpy", "memcpy", "format", "%s", "%n",
        "error", "invalid", "denied", "unauthorized", "overflow",
        "Content-Length", "Authorization", "Cookie", "TRUN", "GMON",
    ];

    private static BinarySurfaceMap ParsePe(string path, byte[] bytes, int maxStrings)
    {
        var eLfanew = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(0x3C));
        if (eLfanew <= 0 || eLfanew + 0x18 >= bytes.Length)
            return new BinarySurfaceMap { Path = path, Format = "pe" };

        if (bytes[eLfanew] != (byte)'P' || bytes[eLfanew + 1] != (byte)'E')
            return new BinarySurfaceMap { Path = path, Format = "pe" };

        var coff = eLfanew + 4;
        var numSections = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(coff + 2));
        var optSize = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(coff + 16));
        var opt = coff + 20;
        if (opt + optSize > bytes.Length)
            return new BinarySurfaceMap { Path = path, Format = "pe" };

        var magic = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(opt));
        var pe32Plus = magic == 0x20B;
        ulong imageBase = pe32Plus
            ? BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan(opt + 24))
            : BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(opt + 28));

        var ddOff = pe32Plus ? opt + 112 : opt + 96;
        uint importRva = 0, importSize = 0;
        if (ddOff + 16 <= bytes.Length)
        {
            importRva = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(ddOff + 8));
            importSize = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(ddOff + 12));
        }

        var secTable = opt + optSize;
        var sections = new List<BinarySectionDto>();
        var ranges = new List<(ulong Rva, ulong Size, string Name, uint RawPtr, uint RawSize)>();
        for (var i = 0; i < numSections; i++)
        {
            var off = secTable + i * 40;
            if (off + 40 > bytes.Length) break;
            var name = ReadAsciiZ(bytes, off, 8);
            var vSize = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(off + 8));
            var vAddr = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(off + 12));
            var rawSize = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(off + 16));
            var rawPtr = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(off + 20));
            var chars = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(off + 36));
            sections.Add(new BinarySectionDto(
                name,
                $"0x{vAddr:x}",
                $"0x{vSize:x}",
                DescribePeChars(chars)));
            ranges.Add((vAddr, Math.Max(vSize, 1u), name, rawPtr, rawSize));
        }

        var imports = ParsePeImports(bytes, ranges, importRva, importSize, pe32Plus);
        var strings = ScanStrings(bytes, ranges, maxStrings);

        var map = new BinarySurfaceMap
        {
            Path = path,
            Format = "pe",
            ImageBase = imageBase,
            Sections = sections,
            Imports = imports,
            Strings = strings,
            _secRanges = ranges.Select(r => (r.Rva, r.Size, r.Name)).ToList(),
            _stringIndex = strings.Select(s => (ParseHex(s.Rva), s.Text)).ToList(),
            _importIndex = imports
                .Where(i => i.ThunkRva is not null)
                .Select(i => (ParseHex(i.ThunkRva!), $"{i.Library}!{i.Function}"))
                .ToList(),
        };
        return map;
    }

    private static List<BinaryImportDto> ParsePeImports(
        byte[] bytes,
        List<(ulong Rva, ulong Size, string Name, uint RawPtr, uint RawSize)> ranges,
        uint importRva,
        uint importSize,
        bool pe32Plus)
    {
        var list = new List<BinaryImportDto>();
        if (importRva == 0)
            return list;
        _ = importSize;

        var fileOff = RvaToFile(ranges, importRva);
        if (fileOff is null)
            return list;

        var off = fileOff.Value;
        // IMAGE_IMPORT_DESCRIPTOR is 20 bytes
        for (var n = 0; n < 512; n++)
        {
            var desc = off + n * 20;
            if (desc + 20 > bytes.Length) break;
            var oft = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(desc));
            var nameRva = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(desc + 12));
            var ft = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(desc + 16));
            if (oft == 0 && nameRva == 0 && ft == 0)
                break;

            var libOff = RvaToFile(ranges, nameRva);
            var lib = libOff is null ? "?" : ReadAsciiZ(bytes, libOff.Value, 260);
            var thunkRva = oft != 0 ? oft : ft;
            var thunkFile = RvaToFile(ranges, thunkRva);
            if (thunkFile is null) continue;

            var isPlus = pe32Plus;
            var entrySize = isPlus ? 8 : 4;
            for (var t = 0; t < 1024; t++)
            {
                var te = thunkFile.Value + t * entrySize;
                if (te + entrySize > bytes.Length) break;
                ulong entry = isPlus
                    ? BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan(te))
                    : BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(te));
                if (entry == 0) break;

                string func;
                var ordinalBit = isPlus ? (1UL << 63) : (1UL << 31);
                if ((entry & ordinalBit) != 0)
                {
                    func = $"#{entry & 0xFFFF}";
                }
                else
                {
                    var hintRva = (uint)(entry & 0x7FFFFFFF);
                    var hintFile = RvaToFile(ranges, hintRva);
                    func = hintFile is null ? "?" : ReadAsciiZ(bytes, hintFile.Value + 2, 256);
                }

                var thisThunkRva = thunkRva + (uint)(t * entrySize);
                list.Add(new BinaryImportDto(
                    lib,
                    func,
                    $"0x{thisThunkRva:x}",
                    IsInterestingImport(func)));
                if (list.Count >= 800)
                    return list;
            }
        }

        return list;
    }

    private static BinarySurfaceMap ParseElf(string path, byte[] bytes, int maxStrings)
    {
        var is64 = bytes[4] == 2;
        var little = bytes[5] != 2;
        if (!little)
            return new BinarySurfaceMap { Path = path, Format = "elf" }; // big-endian rare; skip

        var shOff = is64
            ? BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan(40))
            : BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(32));
        var shEntSize = is64
            ? BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(58))
            : BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(46));
        var shNum = is64
            ? BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(60))
            : BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(48));
        var shStrNdx = is64
            ? BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(62))
            : BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(50));

        if (shOff == 0 || shEntSize == 0 || shNum == 0)
            return new BinarySurfaceMap { Path = path, Format = "elf" };

        var sections = new List<BinarySectionDto>();
        var ranges = new List<(ulong Rva, ulong Size, string Name, uint RawPtr, uint RawSize)>();
        string[] names = new string[shNum];

        // First pass: locate string table
        byte[]? shStr = null;
        if (shStrNdx < shNum)
        {
            var soff = (long)shOff + shStrNdx * shEntSize;
            if (soff + shEntSize <= bytes.Length)
            {
                var strOff = is64
                    ? BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan((int)soff + 24))
                    : BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan((int)soff + 16));
                var strSize = is64
                    ? BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan((int)soff + 32))
                    : BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan((int)soff + 20));
                if (strOff + strSize <= (ulong)bytes.Length)
                {
                    shStr = new byte[strSize];
                    Array.Copy(bytes, (long)strOff, shStr, 0, (int)strSize);
                }
            }
        }

        for (var i = 0; i < shNum; i++)
        {
            var soff = (long)shOff + i * shEntSize;
            if (soff + shEntSize > bytes.Length) break;
            var nameOff = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan((int)soff));
            var name = shStr is null ? $"sec{i}" : ReadAsciiZ(shStr, (int)nameOff, 64);
            names[i] = name;

            ulong addr, size, offset;
            if (is64)
            {
                addr = BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan((int)soff + 16));
                offset = BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan((int)soff + 24));
                size = BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan((int)soff + 32));
            }
            else
            {
                addr = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan((int)soff + 12));
                offset = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan((int)soff + 16));
                size = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan((int)soff + 20));
            }

            if (size == 0 || string.IsNullOrEmpty(name) || name.StartsWith('.'))
            {
                // still keep named loadable-ish sections
            }

            if (size > 0 && offset + size <= (ulong)bytes.Length &&
                (name.StartsWith(".text", StringComparison.Ordinal) ||
                 name.StartsWith(".rodata", StringComparison.Ordinal) ||
                 name.StartsWith(".data", StringComparison.Ordinal) ||
                 name.StartsWith(".bss", StringComparison.Ordinal) ||
                 name is ".dynstr" or ".dynsym" or ".plt" or ".got" or ".got.plt"))
            {
                sections.Add(new BinarySectionDto(name, $"0x{addr:x}", $"0x{size:x}", "elf"));
                ranges.Add((addr, size, name, (uint)offset, (uint)size));
            }
        }

        // DT_NEEDED libs from dynamic + dynstr if present
        var imports = ParseElfNeeded(bytes, is64, ranges);
        var strings = ScanStrings(bytes, ranges, maxStrings);

        return new BinarySurfaceMap
        {
            Path = path,
            Format = "elf",
            ImageBase = 0,
            Sections = sections,
            Imports = imports,
            Strings = strings,
            _secRanges = ranges.Select(r => (r.Rva, r.Size, r.Name)).ToList(),
            _stringIndex = strings.Select(s => (ParseHex(s.Rva), s.Text)).ToList(),
            _importIndex = imports
                .Where(i => i.ThunkRva is not null)
                .Select(i => (ParseHex(i.ThunkRva!), $"{i.Library}!{i.Function}"))
                .ToList(),
        };
    }

    private static List<BinaryImportDto> ParseElfNeeded(
        byte[] bytes,
        bool is64,
        List<(ulong Rva, ulong Size, string Name, uint RawPtr, uint RawSize)> ranges)
    {
        var list = new List<BinaryImportDto>();
        var dynstr = ranges.FirstOrDefault(r => r.Name == ".dynstr");
        var dynamic = ranges.FirstOrDefault(r => r.Name == ".dynamic");
        if (dynstr.Name is null || dynamic.Name is null)
        {
            // Still expose libc-style hints from string scan later
            return list;
        }

        var ent = is64 ? 16 : 8;
        for (uint i = 0; i + ent <= dynamic.RawSize && list.Count < 64; i += (uint)ent)
        {
            var off = (int)(dynamic.RawPtr + i);
            long tag;
            ulong val;
            if (is64)
            {
                tag = BinaryPrimitives.ReadInt64LittleEndian(bytes.AsSpan(off));
                val = BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan(off + 8));
            }
            else
            {
                tag = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(off));
                val = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(off + 4));
            }
            if (tag == 0) break;
            if (tag != 1) continue; // DT_NEEDED
            if (val >= dynstr.RawSize) continue;
            var lib = ReadAsciiZ(bytes, (int)(dynstr.RawPtr + val), 256);
            list.Add(new BinaryImportDto(lib, "(needed)", null, false));
        }

        // Also scrape dynstr for interesting function names (exported/imported symbols mixed)
        var dyn = ScanAsciiInRange(bytes, dynstr.RawPtr, dynstr.RawSize, 4, 200);
        foreach (var (fileOff, text) in dyn)
        {
            if (!IsInterestingImport(text)) continue;
            var rva = dynstr.Rva + (ulong)(fileOff - (int)dynstr.RawPtr);
            list.Add(new BinaryImportDto("dynstr", text, $"0x{rva:x}", true));
            if (list.Count >= 200) break;
        }

        return list;
    }

    private static List<BinaryStringDto> ScanStrings(
        byte[] bytes,
        List<(ulong Rva, ulong Size, string Name, uint RawPtr, uint RawSize)> ranges,
        int maxStrings)
    {
        var list = new List<BinaryStringDto>();
        foreach (var sec in ranges)
        {
            if (sec.RawSize == 0 || sec.RawPtr + sec.RawSize > bytes.Length)
                continue;
            // Prefer data-ish sections for strings
            var name = sec.Name;
            var prefer = name.Contains("data", StringComparison.OrdinalIgnoreCase) ||
                         name.Contains("rdata", StringComparison.OrdinalIgnoreCase) ||
                         name.Contains("rodata", StringComparison.OrdinalIgnoreCase) ||
                         name.Contains("rsrc", StringComparison.OrdinalIgnoreCase);
            if (!prefer && !name.Contains("text", StringComparison.OrdinalIgnoreCase))
                continue;

            var minLen = prefer ? 4 : 6;
            foreach (var (fileOff, text) in ScanAsciiInRange(bytes, sec.RawPtr, sec.RawSize, minLen, maxStrings))
            {
                var rva = sec.Rva + (ulong)(fileOff - (int)sec.RawPtr);
                list.Add(new BinaryStringDto($"0x{rva:x}", text, name));
                if (list.Count >= maxStrings)
                    return list;
            }

            // Light UTF-16LE pass on data sections
            if (prefer)
            {
                foreach (var (fileOff, text) in ScanUtf16InRange(bytes, sec.RawPtr, sec.RawSize, 4, 200))
                {
                    var rva = sec.Rva + (ulong)(fileOff - (int)sec.RawPtr);
                    list.Add(new BinaryStringDto($"0x{rva:x}", text, name));
                    if (list.Count >= maxStrings)
                        return list;
                }
            }
        }
        return list;
    }

    private static IEnumerable<(int FileOff, string Text)> ScanAsciiInRange(
        byte[] bytes, uint start, uint size, int minLen, int limit)
    {
        var end = (int)Math.Min(bytes.Length, start + size);
        var i = (int)start;
        var n = 0;
        while (i < end && n < limit)
        {
            while (i < end && (bytes[i] < 0x20 || bytes[i] > 0x7E))
                i++;
            var s = i;
            while (i < end && bytes[i] >= 0x20 && bytes[i] <= 0x7E)
                i++;
            var len = i - s;
            if (len >= minLen)
            {
                var text = Encoding.ASCII.GetString(bytes, s, Math.Min(len, 120));
                yield return (s, text);
                n++;
            }
            i++;
        }
    }

    private static IEnumerable<(int FileOff, string Text)> ScanUtf16InRange(
        byte[] bytes, uint start, uint size, int minChars, int limit)
    {
        var end = (int)Math.Min(bytes.Length, start + size) - 1;
        var i = (int)start;
        var n = 0;
        while (i < end && n < limit)
        {
            var s = i;
            var chars = 0;
            while (i + 1 < end && bytes[i] >= 0x20 && bytes[i] <= 0x7E && bytes[i + 1] == 0)
            {
                chars++;
                i += 2;
            }
            if (chars >= minChars)
            {
                var sb = new StringBuilder(chars);
                for (var c = 0; c < Math.Min(chars, 80); c++)
                    sb.Append((char)bytes[s + c * 2]);
                yield return (s, sb.ToString());
                n++;
            }
            else
            {
                i += 2;
            }
        }
    }

    private static int? RvaToFile(
        List<(ulong Rva, ulong Size, string Name, uint RawPtr, uint RawSize)> ranges,
        ulong rva)
    {
        foreach (var sec in ranges)
        {
            var span = Math.Max(sec.Size, sec.RawSize);
            if (rva >= sec.Rva && rva < sec.Rva + span)
            {
                var delta = rva - sec.Rva;
                if (delta >= sec.RawSize) return null;
                return (int)(sec.RawPtr + delta);
            }
        }
        return null;
    }

    private static string ReadAsciiZ(byte[] bytes, int offset, int max)
    {
        if (offset < 0 || offset >= bytes.Length)
            return "";
        var end = Math.Min(bytes.Length, offset + max);
        var i = offset;
        while (i < end && bytes[i] != 0)
            i++;
        return Encoding.ASCII.GetString(bytes, offset, i - offset);
    }

    private static string DescribePeChars(uint c)
    {
        var parts = new List<string>();
        if ((c & 0x20) != 0) parts.Add("code");
        if ((c & 0x40) != 0) parts.Add("id");
        if ((c & 0x80) != 0) parts.Add("ud");
        if ((c & 0x20000000) != 0) parts.Add("x");
        if ((c & 0x40000000) != 0) parts.Add("r");
        if ((c & 0x80000000) != 0) parts.Add("w");
        return parts.Count == 0 ? $"0x{c:x}" : string.Join(',', parts);
    }

    private static ulong ParseHex(string hex)
    {
        var s = hex.Trim();
        if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            s = s[2..];
        return ulong.TryParse(s, System.Globalization.NumberStyles.HexNumber,
            System.Globalization.CultureInfo.InvariantCulture, out var v)
            ? v
            : 0;
    }
}
