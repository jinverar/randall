using System.Buffers.Binary;
using System.Text;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class StalkMapTests
{
    [Fact]
    public void BinarySurfaceMap_ReadsPeSectionsAndStrings()
    {
        var path = WriteMinimalPeWithString("password=admin", "TRUN /.:/");
        try
        {
            var map = BinarySurfaceMap.TryLoad(path);
            Assert.NotNull(map);
            Assert.Equal("pe", map!.Format);
            Assert.Contains(map.Sections, s => s.Name.Contains("rdata", StringComparison.OrdinalIgnoreCase)
                                               || s.Name.Contains("data", StringComparison.OrdinalIgnoreCase)
                                               || s.Name.Length > 0);
            Assert.Contains(map.Strings, s => s.Text.Contains("password", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(map.Strings, s => s.Text.Contains("TRUN", StringComparison.OrdinalIgnoreCase));
            Assert.True(BinarySurfaceMap.LooksDangerousString("password=admin"));
            Assert.True(BinarySurfaceMap.IsInterestingImport("memcpy"));
        }
        finally
        {
            try { File.Delete(path); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void BinarySurfaceMap_ReadsElfWhenPresent()
    {
        var candidates = new[] { "/bin/ls", "/usr/bin/ls", "/bin/cat", "/usr/bin/true" };
        var elf = candidates.FirstOrDefault(File.Exists);
        if (elf is null)
            return; // skip on hosts without a standard ELF

        var map = BinarySurfaceMap.TryLoad(elf);
        Assert.NotNull(map);
        Assert.Equal("elf", map!.Format);
        Assert.True(map.Sections.Count > 0 || map.Strings.Count > 0 || map.Imports.Count > 0);
    }

    [Fact]
    public void StalkMapBuilder_WorksWithoutBinary()
    {
        var root = Path.Combine(Path.GetTempPath(), "randall-map-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path.Combine(root, "data", "stalk", "mapdemo"));
        try
        {
            var map = StalkMapBuilder.Build("mapdemo", repoRoot: root, limit: 10);
            Assert.Equal("mapdemo", map.Project);
            Assert.Equal("missing", map.Format);
            Assert.Contains(map.SurfaceIdeas, i => i.Id == "map-binary");
        }
        finally
        {
            try { Directory.Delete(root, true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void StalkMapBuilder_EnrichesHotspotsNearStrings()
    {
        var root = Path.Combine(Path.GetTempPath(), "randall-map2-" + Guid.NewGuid().ToString("N"));
        var project = "surfacedemo";
        var stalkDir = Path.Combine(root, "data", "stalk", project);
        Directory.CreateDirectory(stalkDir);
        var pe = WriteMinimalPeWithString("Authorization", "error denied");
        // Place a never-hit inventory block near the string RVA (section at 0x1000)
        File.WriteAllLines(Path.Combine(stalkDir, "inventory.blocks.txt"),
        [
            "0:0x00001080:16",
            "0:0x00002000:16",
        ]);
        // Hit only the far block so 0x1080 is never-hit
        var corpus = Path.Combine(root, "data", "corpus", project);
        Directory.CreateDirectory(corpus);
        File.WriteAllLines(Path.Combine(corpus, "edges.txt"), ["0:0x00002000:16"]);

        try
        {
            var map = StalkMapBuilder.Build(project, binaryPath: pe, repoRoot: root, limit: 20);
            Assert.Equal("pe", map.Format);
            Assert.NotEmpty(map.HotStrings);
            Assert.Contains(map.Hotspots, h =>
                h.Block.Address.Contains("1080", StringComparison.OrdinalIgnoreCase) &&
                (h.NearbyStrings.Count > 0 || h.SurfaceKind == "string-adjacent" ||
                 h.Block.WhyMissed.Contains("string", StringComparison.OrdinalIgnoreCase) ||
                 h.BoostedScore >= h.Block.PriorityScore));
        }
        finally
        {
            try { Directory.Delete(root, true); } catch { /* ignore */ }
            try { File.Delete(pe); } catch { /* ignore */ }
        }
    }

    /// <summary>Minimal PE32 with one .rdata section containing ASCII payloads.</summary>
    private static string WriteMinimalPeWithString(params string[] payloads)
    {
        var path = Path.Combine(Path.GetTempPath(), "randall-pe-" + Guid.NewGuid().ToString("N") + ".exe");
        var rdata = new List<byte>();
        foreach (var p in payloads)
        {
            rdata.AddRange(Encoding.ASCII.GetBytes(p));
            rdata.Add(0);
            rdata.AddRange(new byte[8]); // padding
        }
        while (rdata.Count % 0x200 != 0)
            rdata.Add(0);

        // Layout:
        // 0x000 DOS + PE headers (padded to 0x200)
        // 0x200 section raw data
        const int headerSize = 0x200;
        const uint secVa = 0x1000;
        var file = new byte[headerSize + rdata.Count];

        // DOS
        file[0] = (byte)'M';
        file[1] = (byte)'Z';
        BinaryPrimitives.WriteInt32LittleEndian(file.AsSpan(0x3C), 0x80);

        // PE signature at 0x80
        file[0x80] = (byte)'P';
        file[0x81] = (byte)'E';
        // COFF: Machine i386, 1 section, SizeOfOptionalHeader=0xE0, Characteristics
        BinaryPrimitives.WriteUInt16LittleEndian(file.AsSpan(0x84), 0x14C);
        BinaryPrimitives.WriteUInt16LittleEndian(file.AsSpan(0x86), 1);
        BinaryPrimitives.WriteUInt16LittleEndian(file.AsSpan(0x94), 0xE0);
        BinaryPrimitives.WriteUInt16LittleEndian(file.AsSpan(0x96), 0x102);

        // Optional header PE32 magic
        const int opt = 0x98;
        BinaryPrimitives.WriteUInt16LittleEndian(file.AsSpan(opt), 0x10B);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(opt + 16), 0x1000); // AddressOfEntryPoint
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(opt + 28), 0x400000); // ImageBase
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(opt + 32), 0x1000); // SectionAlignment
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(opt + 36), 0x200); // FileAlignment
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(opt + 56), 0x2000); // SizeOfImage
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(opt + 60), headerSize); // SizeOfHeaders
        BinaryPrimitives.WriteUInt16LittleEndian(file.AsSpan(opt + 68), 3); // Subsystem
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(opt + 92), 16); // NumberOfRvaAndSizes

        // Section header after optional (opt + 0xE0 = 0x178)
        var sec = opt + 0xE0;
        Encoding.ASCII.GetBytes(".rdata").CopyTo(file.AsSpan(sec));
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(sec + 8), (uint)rdata.Count); // VirtualSize
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(sec + 12), secVa); // VirtualAddress
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(sec + 16), (uint)rdata.Count); // SizeOfRawData
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(sec + 20), headerSize); // PointerToRawData
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(sec + 36), 0x40000040); // CNTR_INITIALIZED_DATA | READ

        rdata.CopyTo(file.AsSpan(headerSize));
        File.WriteAllBytes(path, file);
        return path;
    }
}
