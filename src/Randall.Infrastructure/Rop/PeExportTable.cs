using System.Text;

namespace Randall.Infrastructure.Rop;

/// <summary>Parse PE export directory for nearest-symbol gadget tags (lab naming — not PDB).</summary>
public static class PeExportTable
{
    public sealed record Export(uint Rva, string Name);

    public static IReadOnlyList<Export> TryParse(byte[] bytes)
    {
        try
        {
            if (bytes.Length < 0x40 || bytes[0] != 0x4D || bytes[1] != 0x5A)
                return [];
            var eLfanew = BitConverter.ToInt32(bytes, 0x3C);
            if (eLfanew <= 0 || eLfanew + 0x18 >= bytes.Length) return [];
            if (BitConverter.ToUInt32(bytes, eLfanew) != 0x00004550) return [];

            var magic = BitConverter.ToUInt16(bytes, eLfanew + 0x18);
            var isPe32Plus = magic == 0x20B;
            var sizeOfOptional = BitConverter.ToUInt16(bytes, eLfanew + 0x14);
            var dataDirOff = eLfanew + 0x18 + (isPe32Plus ? 112 : 96);
            if (dataDirOff + 8 > bytes.Length) return [];

            var exportRva = BitConverter.ToUInt32(bytes, dataDirOff);
            var exportSize = BitConverter.ToUInt32(bytes, dataDirOff + 4);
            if (exportRva == 0 || exportSize == 0) return [];

            var exportOff = (int)RvaToOffset(bytes, eLfanew, sizeOfOptional, exportRva);
            if (exportOff < 0 || exportOff + 40 > bytes.Length) return [];

            var numberOfNames = BitConverter.ToUInt32(bytes, exportOff + 24);
            var addressOfFunctions = BitConverter.ToUInt32(bytes, exportOff + 28);
            var addressOfNames = BitConverter.ToUInt32(bytes, exportOff + 32);
            var addressOfOrdinals = BitConverter.ToUInt32(bytes, exportOff + 36);
            if (numberOfNames == 0 || numberOfNames > 50_000) return [];

            var funcsOff = (int)RvaToOffset(bytes, eLfanew, sizeOfOptional, addressOfFunctions);
            var namesOff = (int)RvaToOffset(bytes, eLfanew, sizeOfOptional, addressOfNames);
            var ordsOff = (int)RvaToOffset(bytes, eLfanew, sizeOfOptional, addressOfOrdinals);
            if (funcsOff < 0 || namesOff < 0 || ordsOff < 0) return [];

            var list = new List<Export>((int)Math.Min(numberOfNames, 4096));
            var limit = (int)Math.Min(numberOfNames, 4096);
            for (var i = 0; i < limit; i++)
            {
                var nameRva = BitConverter.ToUInt32(bytes, namesOff + i * 4);
                var nameFile = (int)RvaToOffset(bytes, eLfanew, sizeOfOptional, nameRva);
                if (nameFile < 0 || nameFile >= bytes.Length) continue;
                var name = ReadAsciiZ(bytes, nameFile, 96);
                if (string.IsNullOrWhiteSpace(name)) continue;

                var ordinal = BitConverter.ToUInt16(bytes, ordsOff + i * 2);
                var funcRva = BitConverter.ToUInt32(bytes, funcsOff + ordinal * 4);
                if (funcRva == 0) continue;
                // Skip forwarders (RVA inside export directory)
                if (funcRva >= exportRva && funcRva < exportRva + exportSize) continue;

                list.Add(new Export(funcRva, name));
            }

            return list
                .GroupBy(e => e.Rva)
                .Select(g => g.First())
                .OrderBy(e => e.Rva)
                .ToList();
        }
        catch
        {
            return [];
        }
    }

    public static string? Nearest(IReadOnlyList<Export> exports, uint rva, uint maxDelta = 0x800)
    {
        if (exports.Count == 0) return null;
        Export? best = null;
        foreach (var e in exports)
        {
            if (e.Rva > rva) break;
            if (rva - e.Rva <= maxDelta)
                best = e;
        }

        return best?.Name;
    }

    public static ulong? TryImageBase(byte[] bytes)
    {
        try
        {
            if (bytes.Length < 0x40 || bytes[0] != 0x4D || bytes[1] != 0x5A) return null;
            var eLfanew = BitConverter.ToInt32(bytes, 0x3C);
            if (eLfanew <= 0 || eLfanew + 0x18 >= bytes.Length) return null;
            var magic = BitConverter.ToUInt16(bytes, eLfanew + 0x18);
            return magic == 0x20B
                ? BitConverter.ToUInt64(bytes, eLfanew + 0x18 + 0x18)
                : BitConverter.ToUInt32(bytes, eLfanew + 0x18 + 0x1C);
        }
        catch
        {
            return null;
        }
    }

    private static long RvaToOffset(byte[] bytes, int eLfanew, ushort sizeOfOptional, uint rva)
    {
        var sectionOff = eLfanew + 0x18 + sizeOfOptional;
        var numberOfSections = BitConverter.ToUInt16(bytes, eLfanew + 0x6);
        for (var s = 0; s < numberOfSections; s++)
        {
            var off = sectionOff + s * 40;
            if (off + 40 > bytes.Length) break;
            var va = BitConverter.ToUInt32(bytes, off + 12);
            var rawSize = BitConverter.ToInt32(bytes, off + 16);
            var rawPtr = BitConverter.ToInt32(bytes, off + 20);
            var virtSize = BitConverter.ToInt32(bytes, off + 8);
            var span = Math.Max(rawSize, virtSize);
            if (span <= 0) continue;
            if (rva >= va && rva < va + (uint)span)
                return rawPtr + (long)(rva - va);
        }

        return -1;
    }

    private static string ReadAsciiZ(byte[] bytes, int off, int max)
    {
        var end = off;
        var lim = Math.Min(bytes.Length, off + max);
        while (end < lim && bytes[end] != 0) end++;
        return Encoding.ASCII.GetString(bytes, off, end - off);
    }
}
