using System.Security.Cryptography;
using System.Text;
using Randall.Contracts;

namespace Randall.Infrastructure.Rop;

/// <summary>
/// ROP Studio gadget harvest for PE/ELF lab binaries. Catalog only — no payloads.
/// See docs/WINDBG_FUZZ_PKG.md.
/// </summary>
public static class RopGadgetScanner
{
    public static string CacheDir(string? repoRoot = null) =>
        Path.Combine(repoRoot ?? CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory(),
            "data", "rop");

    public static RopScanReportDto Scan(
        string modulePath,
        string? archHint = null,
        int maxGadgets = 800,
        string? repoRoot = null,
        bool writeCache = true)
    {
        if (string.IsNullOrWhiteSpace(modulePath) || !File.Exists(modulePath))
            return Fail(modulePath, "module not found");

        try
        {
            var bytes = File.ReadAllBytes(modulePath);
            var sha = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
            var (arch, regions) = BinaryImage.LoadExecutableRegions(bytes, archHint);
            if (regions.Count == 0)
                return Fail(modulePath, "no executable sections found (need PE/ELF)");

            var gadgets = new List<RopGadgetDto>();
            var exeBytes = 0;
            foreach (var region in regions)
            {
                exeBytes += region.Data.Length;
                ScanRegion(modulePath, arch, region, gadgets, maxGadgets);
                if (gadgets.Count >= maxGadgets) break;
            }

            gadgets = Dedup(gadgets).Take(maxGadgets).ToList();
            string? cachePath = null;
            if (writeCache)
            {
                cachePath = Path.Combine(CacheDir(repoRoot), sha + ".gadgets.json");
                Directory.CreateDirectory(Path.GetDirectoryName(cachePath)!);
                File.WriteAllText(cachePath, System.Text.Json.JsonSerializer.Serialize(
                    new RopScanReportDto(modulePath, arch, sha, exeBytes, gadgets.Count, gadgets,
                        $"rop-scan: {gadgets.Count} gadget(s) · {arch} · {Path.GetFileName(modulePath)}",
                        cachePath.Replace('\\', '/')),
                    new System.Text.Json.JsonSerializerOptions
                    {
                        WriteIndented = true,
                        PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase,
                    }));
            }

            return new RopScanReportDto(
                modulePath.Replace('\\', '/'),
                arch,
                sha,
                exeBytes,
                gadgets.Count,
                gadgets,
                $"rop-scan: {gadgets.Count} gadget(s) · {arch} · {Path.GetFileName(modulePath)}",
                cachePath?.Replace('\\', '/'));
        }
        catch (Exception ex)
        {
            return Fail(modulePath, ex.Message);
        }
    }

    private static void ScanRegion(
        string modulePath,
        string arch,
        BinaryImage.ExecRegion region,
        List<RopGadgetDto> gadgets,
        int maxGadgets)
    {
        var data = region.Data;
        var baseVa = region.VirtualAddress;
        var mod = Path.GetFileName(modulePath);

        // Always index RETs — anchors for short gadgets ending in ret.
        for (var i = 0; i < data.Length && gadgets.Count < maxGadgets; i++)
        {
            if (data[i] != 0xC3) continue; // ret
            AddNear(gadgets, arch, mod, baseVa, data, i, maxGadgets);
        }

        // Non-ret control transfers of interest.
        for (var i = 0; i + 1 < data.Length && gadgets.Count < maxGadgets; i++)
        {
            // jmp reg / call reg (FF E0..E7 / FF D0..D7)
            if (data[i] == 0xFF && data[i + 1] is >= 0xE0 and <= 0xE7)
            {
                var reg = RegName(arch, data[i + 1] - 0xE0);
                Add(gadgets, baseVa + (ulong)i, $"jmp-{reg}", data.AsSpan(i, 2),
                    $"jmp {reg}", mod, ["jmp", "reg", "pivot-ish"]);
            }
            else if (data[i] == 0xFF && data[i + 1] is >= 0xD0 and <= 0xD7)
            {
                var reg = RegName(arch, data[i + 1] - 0xD0);
                Add(gadgets, baseVa + (ulong)i, $"call-{reg}", data.AsSpan(i, 2),
                    $"call {reg}", mod, ["call", "reg"]);
            }
        }
    }

    private static void AddNear(
        List<RopGadgetDto> gadgets,
        string arch,
        string mod,
        ulong baseVa,
        byte[] data,
        int retIndex,
        int maxGadgets)
    {
        // ret alone
        Add(gadgets, baseVa + (ulong)retIndex, "ret", data.AsSpan(retIndex, 1), "ret", mod, ["ret"]);

        // Look back up to 8 bytes for short gadgets ending at this ret.
        for (var back = 1; back <= 8 && retIndex - back >= 0 && gadgets.Count < maxGadgets; back++)
        {
            var start = retIndex - back;
            var span = data.AsSpan(start, back + 1);
            var decoded = TryDecode(arch, span);
            if (decoded is null) continue;
            Add(gadgets, baseVa + (ulong)start, decoded.Value.Kind, span,
                decoded.Value.Insn, mod, decoded.Value.Tags);
        }
    }

    private static (string Kind, string Insn, string[] Tags)? TryDecode(string arch, ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length < 2 || bytes[^1] != 0xC3) return null;

        // leave; ret
        if (bytes.Length == 2 && bytes[0] == 0xC9)
            return ("leave-ret", "leave; ret", ["leave", "ret", "pivot"]);

        // pop r32/r64; ret  (58..5F) — on x64 without REX these are still the classic encodings
        if (bytes.Length == 2 && bytes[0] is >= 0x58 and <= 0x5F)
        {
            var reg = RegName(arch, bytes[0] - 0x58);
            return ($"pop-{reg}", $"pop {reg}; ret", ["pop", reg, "ret"]);
        }

        // x64: 41 58..5F = pop r8..r15; ret
        if (arch == "x64" && bytes.Length == 3 && bytes[0] == 0x41 && bytes[1] is >= 0x58 and <= 0x5F)
        {
            var reg = "r" + (8 + (bytes[1] - 0x58));
            return ($"pop-{reg}", $"pop {reg}; ret", ["pop", reg, "ret"]);
        }

        // pop; pop; ret
        if (bytes.Length == 3 && bytes[0] is >= 0x58 and <= 0x5F && bytes[1] is >= 0x58 and <= 0x5F)
        {
            var a = RegName(arch, bytes[0] - 0x58);
            var b = RegName(arch, bytes[1] - 0x58);
            return ("pop-pop-ret", $"pop {a}; pop {b}; ret", ["pop", "seh", "ret"]);
        }

        // xchg esp/rsp, eax/rax ; ret — 94 C3 or 48 94 C3
        if (bytes.Length == 2 && bytes[0] == 0x94)
            return ("xchg-sp", arch == "x86" ? "xchg eax, esp; ret" : "xchg eax, esp; ret",
                ["xchg", "pivot", "sp"]);
        if (arch == "x64" && bytes.Length == 3 && bytes[0] == 0x48 && bytes[1] == 0x94)
            return ("xchg-sp", "xchg rax, rsp; ret", ["xchg", "pivot", "sp"]);

        // add esp/rsp, imm8; ret — 83 C4 ib C3
        if (bytes.Length == 4 && bytes[0] == 0x83 && bytes[1] == 0xC4)
        {
            var imm = bytes[2];
            return ("add-sp", $"add {(arch == "x86" ? "esp" : "esp")}, 0x{imm:x2}; ret",
                ["add", "sp", "pivot", "ret"]);
        }

        if (arch == "x64" && bytes.Length == 5 && bytes[0] == 0x48 && bytes[1] == 0x83 && bytes[2] == 0xC4)
        {
            var imm = bytes[3];
            return ("add-sp", $"add rsp, 0x{imm:x2}; ret", ["add", "sp", "pivot", "ret"]);
        }

        return null;
    }

    private static string RegName(string arch, int idx) => arch == "x86"
        ? idx switch
        {
            0 => "eax", 1 => "ecx", 2 => "edx", 3 => "ebx",
            4 => "esp", 5 => "ebp", 6 => "esi", 7 => "edi",
            _ => "r?",
        }
        : idx switch
        {
            0 => "rax", 1 => "rcx", 2 => "rdx", 3 => "rbx",
            4 => "rsp", 5 => "rbp", 6 => "rsi", 7 => "rdi",
            _ => "r?",
        };

    private static void Add(
        List<RopGadgetDto> gadgets,
        ulong va,
        string kind,
        ReadOnlySpan<byte> bytes,
        string insn,
        string mod,
        IReadOnlyList<string> tags)
    {
        gadgets.Add(new RopGadgetDto(
            "0x" + va.ToString("x"),
            kind,
            Convert.ToHexString(bytes).ToLowerInvariant(),
            insn,
            mod,
            bytes.Length,
            tags.ToList()));
    }

    private static List<RopGadgetDto> Dedup(List<RopGadgetDto> gadgets) =>
        gadgets
            .GroupBy(g => g.Address + "|" + g.Kind, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.First())
            .OrderBy(g => g.Address, StringComparer.OrdinalIgnoreCase)
            .ToList();

    private static RopScanReportDto Fail(string path, string error) =>
        new(path, "unknown", "", 0, 0, [], "rop-scan failed: " + error, Error: error);
}

/// <summary>Minimal PE/ELF executable-section loader for gadget harvest.</summary>
internal static class BinaryImage
{
    public sealed record ExecRegion(ulong VirtualAddress, byte[] Data);

    public static (string Arch, List<ExecRegion> Regions) LoadExecutableRegions(
        byte[] bytes, string? archHint)
    {
        if (bytes.Length >= 2 && bytes[0] == 0x4D && bytes[1] == 0x5A)
            return LoadPe(bytes, archHint);
        if (bytes.Length >= 4 && bytes[0] == 0x7F && bytes[1] == (byte)'E' && bytes[2] == (byte)'L' && bytes[3] == (byte)'F')
            return LoadElf(bytes, archHint);
        return ("unknown", []);
    }

    private static (string Arch, List<ExecRegion> Regions) LoadPe(byte[] bytes, string? archHint)
    {
        var regions = new List<ExecRegion>();
        if (bytes.Length < 0x40) return ("unknown", regions);
        var eLfanew = BitConverter.ToInt32(bytes, 0x3C);
        if (eLfanew <= 0 || eLfanew + 0x18 >= bytes.Length) return ("unknown", regions);
        if (BitConverter.ToUInt32(bytes, eLfanew) != 0x00004550) return ("unknown", regions); // PE\0\0

        var magic = BitConverter.ToUInt16(bytes, eLfanew + 0x18);
        var isPe32Plus = magic == 0x20B;
        var arch = archHint is "x86" or "x64"
            ? archHint
            : isPe32Plus ? "x64" : "x86";

        var sizeOfOptional = BitConverter.ToUInt16(bytes, eLfanew + 0x14);
        var sectionOff = eLfanew + 0x18 + sizeOfOptional;
        var numberOfSections = BitConverter.ToUInt16(bytes, eLfanew + 0x6);
        for (var s = 0; s < numberOfSections; s++)
        {
            var off = sectionOff + s * 40;
            if (off + 40 > bytes.Length) break;
            var characteristics = BitConverter.ToUInt32(bytes, off + 36);
            const uint IMAGE_SCN_MEM_EXECUTE = 0x20000000;
            const uint IMAGE_SCN_CNT_CODE = 0x00000020;
            if ((characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE)) == 0)
                continue;

            var va = BitConverter.ToUInt32(bytes, off + 12);
            var rawSize = BitConverter.ToInt32(bytes, off + 16);
            var rawPtr = BitConverter.ToInt32(bytes, off + 20);
            if (rawPtr <= 0 || rawSize <= 0 || rawPtr + rawSize > bytes.Length) continue;
            var slice = new byte[rawSize];
            Buffer.BlockCopy(bytes, rawPtr, slice, 0, rawSize);
            // Prefer ImageBase + VA when available
            ulong imageBase = isPe32Plus
                ? BitConverter.ToUInt64(bytes, eLfanew + 0x18 + 0x18)
                : BitConverter.ToUInt32(bytes, eLfanew + 0x18 + 0x1C);
            regions.Add(new ExecRegion(imageBase + va, slice));
        }

        return (arch, regions);
    }

    private static (string Arch, List<ExecRegion> Regions) LoadElf(byte[] bytes, string? archHint)
    {
        var regions = new List<ExecRegion>();
        if (bytes.Length < 52) return ("unknown", regions);
        var is64 = bytes[4] == 2;
        var arch = archHint is "x86" or "x64"
            ? archHint
            : is64 ? "x64" : "x86";
        var endian = bytes[5]; // 1=LE
        if (endian != 1) return (arch, regions); // only LE

        if (is64)
        {
            if (bytes.Length < 64) return (arch, regions);
            var ePhOff = BitConverter.ToInt64(bytes, 32);
            var ePhEntSize = BitConverter.ToUInt16(bytes, 54);
            var ePhNum = BitConverter.ToUInt16(bytes, 56);
            for (var i = 0; i < ePhNum; i++)
            {
                var off = (int)(ePhOff + i * ePhEntSize);
                if (off + 56 > bytes.Length) break;
                var pType = BitConverter.ToUInt32(bytes, off);
                if (pType != 1) continue; // PT_LOAD
                var pFlags = BitConverter.ToUInt32(bytes, off + 4);
                if ((pFlags & 1) == 0) continue; // PF_X
                var pOffset = BitConverter.ToInt64(bytes, off + 8);
                var pVaddr = BitConverter.ToUInt64(bytes, off + 16);
                var pFilesz = BitConverter.ToInt64(bytes, off + 32);
                if (pOffset < 0 || pFilesz <= 0 || pOffset + pFilesz > bytes.Length) continue;
                var slice = new byte[pFilesz];
                Buffer.BlockCopy(bytes, (int)pOffset, slice, 0, (int)pFilesz);
                regions.Add(new ExecRegion(pVaddr, slice));
            }
        }
        else
        {
            var ePhOff = BitConverter.ToInt32(bytes, 28);
            var ePhEntSize = BitConverter.ToUInt16(bytes, 42);
            var ePhNum = BitConverter.ToUInt16(bytes, 44);
            for (var i = 0; i < ePhNum; i++)
            {
                var off = ePhOff + i * ePhEntSize;
                if (off + 32 > bytes.Length) break;
                var pType = BitConverter.ToUInt32(bytes, off);
                if (pType != 1) continue;
                var pOffset = BitConverter.ToInt32(bytes, off + 4);
                var pVaddr = BitConverter.ToUInt32(bytes, off + 8);
                var pFilesz = BitConverter.ToInt32(bytes, off + 16);
                var pFlags = BitConverter.ToUInt32(bytes, off + 24);
                if ((pFlags & 1) == 0) continue;
                if (pOffset < 0 || pFilesz <= 0 || pOffset + pFilesz > bytes.Length) continue;
                var slice = new byte[pFilesz];
                Buffer.BlockCopy(bytes, pOffset, slice, 0, pFilesz);
                regions.Add(new ExecRegion(pVaddr, slice));
            }
        }

        return (arch, regions);
    }
}
