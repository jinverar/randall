using Randall.Core.Model;
using Randall.Infrastructure;
using Randall.Infrastructure.Mutators;
using Xunit;

namespace Randall.Tests;

public class FileFuzzMaturityTests
{
    [Theory]
    [InlineData(0, false)]
    [InlineData(1, false)]
    [InlineData(unchecked((int)0xC0000005), true)]
    [InlineData(139, true)]
    [InlineData(-1, false)]
    [InlineData(-2, true)]
    public void IsCrashExitCode_OnlyCrashShaped(int code, bool expected) =>
        Assert.Equal(expected, TargetRunner.IsCrashExitCode(code));

    [Fact]
    public void ClassifyFileExit_ToolRejectIsNotCrash()
    {
        var (crashed, detail) = FileFuzzExecution.ClassifyFileExit(1, null);
        Assert.False(crashed);
        Assert.Contains("tool-reject", detail);
    }

    [Fact]
    public void ClassifyFileExit_SanitizerIsCrash()
    {
        var stderr = "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1";
        var (crashed, detail) = FileFuzzExecution.ClassifyFileExit(1, stderr);
        Assert.True(crashed);
        Assert.Contains("sanitizer", detail, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task TempFile_FlushCloseUniqueNoReuse()
    {
        var dir = Path.Combine(Path.GetTempPath(), "randall-filefuzz-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var a = Path.Combine(dir, $"fuzz_{Guid.NewGuid():N}.bin");
            var b = Path.Combine(dir, $"fuzz_{Guid.NewGuid():N}.bin");
            Assert.NotEqual(a, b);
            await FileFuzzExecution.WriteTempFileAsync(a, [1, 2, 3], CancellationToken.None);
            await FileFuzzExecution.WriteTempFileAsync(b, [4, 5, 6], CancellationToken.None);
            Assert.Equal(new byte[] { 1, 2, 3 }, await File.ReadAllBytesAsync(a));
            Assert.Equal(new byte[] { 4, 5, 6 }, await File.ReadAllBytesAsync(b));
            await Assert.ThrowsAsync<IOException>(async () =>
                await FileFuzzExecution.WriteTempFileAsync(a, [9], CancellationToken.None));
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void ChunkMutators_RegisteredAndChangeInput()
    {
        var names = new[]
        {
            "delete-range", "insert-at-offset", "replace-chunk", "zero-range", "fill-range",
            "clone-chunk", "move-chunk", "swap-records", "repeat-record",
            "lengthen-near-field", "shorten-near-field",
        };
        var mutators = BuiltInMutators.Create(names, seed: 42);
        Assert.Equal(names.Length, mutators.Count);
        var input = Enumerable.Range(0, 64).Select(i => (byte)i).ToArray();
        foreach (var m in mutators)
        {
            var outp = m.Mutate(input).ToArray();
            Assert.NotNull(outp);
            Assert.True(outp.Length > 0 || m.Name.Contains("delete") || m.Name.Contains("shorten"));
        }
    }

    [Fact]
    public void LengthPolicy_ValidRewritesSizedField()
    {
        var model = new BlockModel("t", new LengthPrefixedBlock
        {
            LengthName = "len",
            LengthBytes = 4,
            LittleEndian = true,
            LengthMutable = true,
            Payload = new BytesBlock { Name = "body", DefaultValue = [1, 2, 3, 4], Mutable = true },
        });
        var seeds = new Dictionary<string, byte[]>();
        model.RegisterDerivedFields(seeds);
        var msg = model.Render(seeds);
        // Corrupt length
        msg[0] = 0xFF;
        msg[1] = 0xFF;
        var fixedMsg = model.FinalizeMessage(msg, LengthPolicy.Valid, ChecksumPolicy.Independent);
        Assert.Equal(4, fixedMsg[0]); // little-endian payload length
        Assert.Equal(0, fixedMsg[1]);
    }

    [Fact]
    public void LengthPolicy_ZeroClearsLength()
    {
        var model = new BlockModel("t", new LengthPrefixedBlock
        {
            LengthName = "len",
            LengthBytes = 4,
            LittleEndian = true,
            Payload = new BytesBlock { Name = "body", DefaultValue = [9, 9], Mutable = true },
        });
        model.RegisterDerivedFields(new Dictionary<string, byte[]>());
        var msg = model.Render(new Dictionary<string, byte[]>());
        var z = model.FinalizeMessage(msg, LengthPolicy.Zero, ChecksumPolicy.Independent);
        Assert.Equal(0, z[0]);
        Assert.Equal(0, z[1]);
        Assert.Equal(0, z[2]);
        Assert.Equal(0, z[3]);
    }

    [Fact]
    public void AdvancedBlocks_EnumFlagsSwitchRepeat_ParseAndRender()
    {
        var yaml = """
            name: adv
            blocks:
              - type: group
                children:
                  - type: enum
                    name: kind
                    width: 1
                    enumValues: ["1", "2", "3"]
                    value: "2"
                  - type: flags
                    name: fl
                    width: 1
                    value: "0x05"
                    flags: { A: "0x01", B: "0x04" }
                  - type: switch
                    name: body
                    cases:
                      - key: a
                        block: { type: static, value: "AA" }
                      - key: b
                        block: { type: static, value: "BB" }
                  - type: padding
                    align: 4
                  - type: array
                    name: items
                    count: 2
                    countMutable: false
                    child: { type: uint8, name: x, value: "7" }
            """;
        var path = Path.Combine(Path.GetTempPath(), "randall-proto-" + Guid.NewGuid().ToString("N") + ".yaml");
        File.WriteAllText(path, yaml);
        try
        {
            // ProtocolLoader.Load needs project yaml + relative — use absolute via fake project dir
            var proj = Path.Combine(Path.GetDirectoryName(path)!, "proj.yaml");
            File.WriteAllText(proj, "name: t\nkind: file\n");
            var model = ProtocolLoader.Load(proj, Path.GetFileName(path));
            var bytes = model.Render();
            Assert.True(bytes.Length >= 2);
            var fields = model.GetFields();
            Assert.Contains(fields, f => f.Kind == "enum");
            Assert.Contains(fields, f => f.Kind == "flags");
        }
        finally
        {
            try { File.Delete(path); } catch { /* ignore */ }
            try { File.Delete(Path.Combine(Path.GetDirectoryName(path)!, "proj.yaml")); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void RecipeCatalog_QualityLabelsPresent()
    {
        var pdf = RecipeCatalog.Get("file-pdf");
        Assert.NotNull(pdf);
        Assert.Equal(RecipeCatalog.RecipeQuality.MagicOnly, pdf!.Entry.Quality);

        var png = RecipeCatalog.Get("file-png");
        Assert.NotNull(png);
        Assert.Equal(RecipeCatalog.RecipeQuality.MinimalValid, png!.Entry.Quality);
        Assert.True(png.SeedLength > 16);
    }

    [Fact]
    public void CorpusMinimizer_KeepsAtLeastOne()
    {
        var dir = Path.Combine(Path.GetTempPath(), "randall-cmin-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            File.WriteAllBytes(Path.Combine(dir, "a.bin"), [1, 2, 3]);
            File.WriteAllBytes(Path.Combine(dir, "b.bin"), [1, 2, 3]);
            File.WriteAllBytes(Path.Combine(dir, "c.bin"), [9, 9, 9]);
            var outDir = dir + "_min";
            var r = CorpusMinimizer.Minimize(dir, outDir, dryRun: false);
            Assert.True(r.Ok);
            Assert.True(r.KeptCount >= 1);
            Assert.True(r.KeptCount <= r.InputCount);
            Assert.True(Directory.Exists(outDir));
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { /* ignore */ }
            try { Directory.Delete(dir + "_min", true); } catch { /* ignore */ }
        }
    }

    [Fact]
    public void DependencyPolicyParser_Tokens()
    {
        Assert.Equal(LengthPolicy.OffByOne, DependencyPolicyParser.ParseLength("off-by-one", false));
        Assert.Equal(ChecksumPolicy.Stale, DependencyPolicyParser.ParseChecksum("stale"));
        Assert.Equal(LengthPolicy.Valid, DependencyPolicyParser.ParseLength(null, syncLengthFieldsFallback: true));
        Assert.Equal(LengthPolicy.Independent, DependencyPolicyParser.ParseLength(null, syncLengthFieldsFallback: false));
    }
}
