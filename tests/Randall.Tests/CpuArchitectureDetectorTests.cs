using System.Buffers.Binary;
using Randall.Contracts;
using Randall.Infrastructure;
using Xunit;

namespace Randall.Tests;

public class CpuArchitectureDetectorTests
{
    private static string WriteTinyPe(ushort machine)
    {
        var path = Path.Combine(Path.GetTempPath(), $"randall_pe_{machine:X}_{Guid.NewGuid():N}.exe");
        var file = new byte[0x100];
        file[0] = (byte)'M';
        file[1] = (byte)'Z';
        const int peOff = 0x80;
        BinaryPrimitives.WriteInt32LittleEndian(file.AsSpan(0x3C), peOff);
        BinaryPrimitives.WriteUInt32LittleEndian(file.AsSpan(peOff), 0x00004550);
        BinaryPrimitives.WriteUInt16LittleEndian(file.AsSpan(peOff + 4), machine);
        File.WriteAllBytes(path, file);
        return path;
    }

    [Fact]
    public void FromExecutable_ReadsPeMachine_I386()
    {
        var path = WriteTinyPe(0x014C);
        try
        {
            Assert.Equal(CpuArchitecture.X86, CpuArchitectureDetector.FromExecutable(path));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void FromExecutable_ReadsPeMachine_Amd64()
    {
        var path = WriteTinyPe(0x8664);
        try
        {
            Assert.Equal(CpuArchitecture.X64, CpuArchitectureDetector.FromExecutable(path));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void FromExecutable_ReadsElfClass()
    {
        var elf32 = Path.Combine(Path.GetTempPath(), $"randall_elf32_{Guid.NewGuid():N}");
        var elf64 = Path.Combine(Path.GetTempPath(), $"randall_elf64_{Guid.NewGuid():N}");
        try
        {
            File.WriteAllBytes(elf32, [0x7F, (byte)'E', (byte)'L', (byte)'F', 1, 1, 1, 0]);
            File.WriteAllBytes(elf64, [0x7F, (byte)'E', (byte)'L', (byte)'F', 2, 1, 1, 0]);
            Assert.Equal(CpuArchitecture.X86, CpuArchitectureDetector.FromExecutable(elf32));
            Assert.Equal(CpuArchitecture.X64, CpuArchitectureDetector.FromExecutable(elf64));
        }
        finally
        {
            File.Delete(elf32);
            File.Delete(elf64);
        }
    }

    [Theory]
    [InlineData(true, CpuArchitecture.X86)]
    [InlineData(false, CpuArchitecture.X64)]
    public void FromWow64_MapsBitness(bool wow64, string expected) =>
        Assert.Equal(expected, CpuArchitectureDetector.FromWow64(wow64));

    [Theory]
    [InlineData(716u, 0x00010007u, CpuArchitecture.X86)]
    [InlineData(1232u, 0x00100007u, CpuArchitecture.X64)]
    [InlineData(500u, 0u, CpuArchitecture.X86)]
    [InlineData(1232u, 0u, CpuArchitecture.X64)]
    public void FromContextBlob_UsesSizeAndFlags(uint size, uint flags, string expected) =>
        Assert.Equal(expected, CpuArchitectureDetector.FromContextBlob(size, flags));

    [Theory]
    [InlineData("eax=00000001 eip=00401000 esp=0012ff00", CpuArchitecture.X86)]
    [InlineData("rax=0000000000000001 rip=00007ff612340100 rsp=000000000012ff00", CpuArchitecture.X64)]
    [InlineData("eip 00401000", CpuArchitecture.X86)]
    public void FromRegistersText_PrefersExplicitIp(string text, string expected) =>
        Assert.Equal(expected, CpuArchitectureDetector.FromRegistersText(text));

    [Fact]
    public void Resolve_PrefersWow64OverDefault() =>
        Assert.Equal(CpuArchitecture.X86, CpuArchitectureDetector.Resolve(wow64: true));

    [Fact]
    public void Resolve_PrefersExplicitArchitecture() =>
        Assert.Equal(
            CpuArchitecture.X86,
            CpuArchitectureDetector.Resolve(explicitArch: "x86", wow64: false));
}

public class RegisterDisplayNamesTests
{
    [Theory]
    [InlineData("RIP", CpuArchitecture.X86, "EIP")]
    [InlineData("RSP", CpuArchitecture.X86, "ESP")]
    [InlineData("RAX", CpuArchitecture.X86, "EAX")]
    [InlineData("RIP", CpuArchitecture.X64, "RIP")]
    [InlineData("EAX", CpuArchitecture.X64, "RAX")]
    [InlineData("eip", CpuArchitecture.X86, "EIP")]
    public void ForArch_MapsLabels(string input, string arch, string expected) =>
        Assert.Equal(expected, RegisterDisplayNames.ForArch(input, arch));

    [Fact]
    public void SnapshotRows_X86_UsesEipLabels()
    {
        var regs = new RegisterSnapshotDto(
            "0x401000", "0x12FF00", "0x12FE00",
            "0x1", "0x2", "0x3", "0x4",
            Architecture: CpuArchitecture.X86);
        var rows = RegisterDisplayNames.SnapshotRows(regs);
        Assert.Equal("EIP", rows[0].Label);
        Assert.Equal("ESP", rows[1].Label);
        Assert.Equal("EBP", rows[2].Label);
        Assert.Equal("EAX", rows[3].Label);
        Assert.Equal("0x401000", rows[0].Value);
    }

    [Fact]
    public void SnapshotRows_X64_KeepsRipLabels()
    {
        var regs = new RegisterSnapshotDto(
            "0x7ff612340100", "0x7ffd1000", null, "0x2C", null, null, null,
            Architecture: CpuArchitecture.X64);
        var rows = RegisterDisplayNames.SnapshotRows(regs);
        Assert.Equal("RIP", rows[0].Label);
        Assert.Equal("RSP", rows[1].Label);
        Assert.Equal("RAX", rows[3].Label);
    }

    [Fact]
    public void MiniDumpAnalyzer_TryReadContext_X86Context()
    {
        // Minimal WOW64 CONTEXT with Eip/Esp/Eax filled.
        var ctx = new byte[716];
        BinaryPrimitives.WriteUInt32LittleEndian(ctx.AsSpan(0), 0x00010007); // CONTEXT_i386 | FULL
        BinaryPrimitives.WriteUInt32LittleEndian(ctx.AsSpan(0xB0), 0x41414141); // Eax
        BinaryPrimitives.WriteUInt32LittleEndian(ctx.AsSpan(0xB8), 0x00401000); // Eip
        BinaryPrimitives.WriteUInt32LittleEndian(ctx.AsSpan(0xC4), 0x0012FF00); // Esp
        BinaryPrimitives.WriteUInt32LittleEndian(ctx.AsSpan(0xB4), 0x0012FE00); // Ebp

        var dump = new byte[ctx.Length + 64];
        const uint rva = 32;
        ctx.CopyTo(dump, (int)rva);

        Assert.True(MiniDumpAnalyzer.TryReadContext(dump, rva, (uint)ctx.Length, out var regs, out var arch));
        Assert.Equal(CpuArchitecture.X86, arch);
        Assert.NotNull(regs);
        Assert.Equal("0x401000", regs!.Rip);
        Assert.Equal("0x12FF00", regs.Rsp);
        Assert.Equal("0x41414141", regs.Rax);
        Assert.Equal(CpuArchitecture.X86, regs.Architecture);
    }
}

public class CdbX86ScriptTests
{
    [Fact]
    public void StandardCrash_X86_UsesEipAndDdEsp()
    {
        var script = CdbScriptBuilder.BuildInline(
            CdbProbePlan.StandardCrash,
            new CdbScriptOptions { Architecture = CpuArchitecture.X86 });
        Assert.Contains(".effmach x86", script, StringComparison.Ordinal);
        Assert.Contains("u @eip L1", script, StringComparison.Ordinal);
        Assert.Contains("ln @eip", script, StringComparison.Ordinal);
        Assert.Contains("dd @esp L40", script, StringComparison.Ordinal);
        Assert.DoesNotContain("u @rip L1", script, StringComparison.Ordinal);
        Assert.DoesNotContain("dq @rsp", script, StringComparison.Ordinal);
    }

    [Fact]
    public void StandardCrash_Default_KeepsRipProbes()
    {
        var script = CdbScriptBuilder.BuildInline(CdbProbePlan.StandardCrash);
        Assert.Contains("u @rip L1", script, StringComparison.Ordinal);
        Assert.Contains("dq @rsp L40", script, StringComparison.Ordinal);
        Assert.DoesNotContain("@eip", script, StringComparison.Ordinal);
        Assert.DoesNotContain(".effmach", script, StringComparison.Ordinal);
    }
}
