using Randall.Contracts;
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
        Assert.Equal(RecipeCatalog.RecipeQuality.StructuredModel, pdf!.Entry.Quality);

        var png = RecipeCatalog.Get("file-png");
        Assert.NotNull(png);
        Assert.Equal(RecipeCatalog.RecipeQuality.StructuredModel, png!.Entry.Quality);
        Assert.True(png.SeedLength > 16);

        var zip = RecipeCatalog.Get("file-zip");
        Assert.NotNull(zip);
        Assert.Equal(RecipeCatalog.RecipeQuality.StructuredModel, zip!.Entry.Quality);

        var pe = RecipeCatalog.Get("file-pe");
        Assert.NotNull(pe);
        Assert.Equal(RecipeCatalog.RecipeQuality.StructuredModel, pe!.Entry.Quality);

        var tlv = RecipeCatalog.Get("file-tlv");
        Assert.NotNull(tlv);
        Assert.Equal(RecipeCatalog.RecipeQuality.GrammarBacked, tlv!.Entry.Quality);
    }

    [Fact]
    public void When_SkipsChildUnlessPredicateMatches()
    {
        var root = new GroupBlock([
            new IntegerBlock { Name = "kind", Width = 1, DefaultValue = 1, Mutable = true },
            new ConditionalBlock
            {
                WhenField = "kind == 2",
                WhenEquals = "",
                Child = new StaticBlock("YES"),
            },
            new ConditionalBlock
            {
                WhenField = "kind",
                WhenEquals = "1",
                Child = new StaticBlock("OK"),
            },
        ]);
        var model = new BlockModel("when-t", root);
        var bytes = model.Render();
        Assert.Equal(new byte[] { 1, (byte)'O', (byte)'K' }, bytes);
    }

    [Fact]
    public void Offset_BackPatchesAbsoluteAndRelativeAfterLayout()
    {
        var root = new GroupBlock([
            new GroupBlock([
                new IntegerBlock { Name = "marker", Width = 4, DefaultValue = 0x11223344, LittleEndian = true },
            ], "target"),
            new BytesBlock { Name = "pad", DefaultValue = [9, 9], Mutable = false },
            new OffsetBlock
            {
                Name = "abs_off",
                Width = 4,
                LittleEndian = true,
                Relative = false,
                TargetField = "target",
                DefaultValue = 0xFFFFFFFF,
            },
            new OffsetBlock
            {
                Name = "rel_off",
                Width = 4,
                LittleEndian = true,
                Relative = true,
                TargetField = "target",
                DefaultValue = 0xFFFFFFFF,
            },
        ]);
        var model = new BlockModel("off-t", root);
        var bytes = model.Render();
        // target @ 0, pad 2B, abs @ 6 → 0, rel @ 10 → 0 - (10+4) = negative → clamped 0
        Assert.Equal(0, BitConverter.ToInt32(bytes, 6));
        Assert.Equal(0, BitConverter.ToInt32(bytes, 10));

        // Relative to a later field: put offset before target via second model
        var root2 = new GroupBlock([
            new OffsetBlock
            {
                Name = "ptr",
                Width = 4,
                LittleEndian = true,
                Relative = false,
                TargetField = "body",
                DefaultValue = 0,
            },
            new BytesBlock { Name = "gap", DefaultValue = [1, 2, 3, 4], Mutable = false },
            new IntegerBlock { Name = "body", Width = 2, DefaultValue = 0xABCD, LittleEndian = true },
        ]);
        var b2 = new BlockModel("off2", root2).Render();
        Assert.Equal(8, BitConverter.ToInt32(b2, 0)); // body starts at 4+4=8
    }

    [Fact]
    public void StructuredPng_GenerateRoundTrip_SignatureAndIhdr()
    {
        var repo = FindRepoRoot();
        var proj = Path.Combine(repo, "projects", "file-text.yaml");
        var model = ProtocolLoader.Load(proj, "protocols/png_structured.yaml");
        var bytes = model.Render();
        Assert.True(bytes.Length > 33);
        Assert.Equal(new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A }, bytes[..8]);
        // IHDR length = 13 BE
        Assert.Equal(13, (bytes[8] << 24) | (bytes[9] << 16) | (bytes[10] << 8) | bytes[11]);
        Assert.Equal("IHDR", System.Text.Encoding.ASCII.GetString(bytes, 12, 4));
        // color_type default 2 → no PLTE; IDAT type present
        Assert.True(IndexOf(bytes, "IDAT"u8) >= 0);
        Assert.True(IndexOf(bytes, "IEND"u8) >= 0);
        var fields = model.GetFields();
        Assert.Contains(fields, f => f.Name == "color_type");
        Assert.DoesNotContain(fields, f => f.Name == "plte_len");
    }

    [Fact]
    public void StructuredZip_GenerateRoundTrip_OffsetBackPatch()
    {
        var repo = FindRepoRoot();
        var proj = Path.Combine(repo, "projects", "file-text.yaml");
        var model = ProtocolLoader.Load(proj, "protocols/zip_structured.yaml");
        var bytes = model.Render();
        Assert.True(bytes.Length > 60);
        Assert.Equal(0x04034b50u, BitConverter.ToUInt32(bytes, 0));
        var fields = model.GetFields();
        var localOff = fields.First(f => f.Name == "local_header_offset");
        var cdOff = fields.First(f => f.Name == "eocd_cd_offset");
        Assert.Equal(0, BitConverter.ToInt32(bytes, localOff.Offset));
        var cdStart = fields.First(f => f.Name == "cd_sig").Offset;
        Assert.Equal(cdStart, BitConverter.ToInt32(bytes, cdOff.Offset));
        Assert.Equal(0x06054b50u, BitConverter.ToUInt32(bytes, fields.First(f => f.Name == "eocd_sig").Offset));
    }

    [Fact]
    public void StructuredPe_GenerateRoundTrip_MzAndPeSignature()
    {
        var repo = FindRepoRoot();
        var proj = Path.Combine(repo, "projects", "file-text.yaml");
        var model = ProtocolLoader.Load(proj, "protocols/pe_structured.yaml");
        var bytes = model.Render();
        Assert.True(bytes.Length > 128);
        Assert.Equal((byte)'M', bytes[0]);
        Assert.Equal((byte)'Z', bytes[1]);
        var eLfanew = BitConverter.ToInt32(bytes, 0x3C);
        Assert.True(eLfanew > 0 && eLfanew < bytes.Length - 4);
        Assert.Equal(0x00004550u, BitConverter.ToUInt32(bytes, eLfanew));
        var fields = model.GetFields();
        Assert.Contains(fields, f => f.Name == "e_lfanew");
        Assert.Contains(fields, f => f.Name == "pointer_to_raw_data");
        var rawPtr = fields.First(f => f.Name == "pointer_to_raw_data");
        var rawOff = BitConverter.ToInt32(bytes, rawPtr.Offset);
        Assert.Equal(fields.First(f => f.Name == "text_blob").Offset, rawOff);
    }

    [Fact]
    public void StructuredPdf_GenerateRoundTrip_HeaderXrefStartxref()
    {
        var repo = FindRepoRoot();
        var proj = Path.Combine(repo, "projects", "file-text.yaml");
        var model = ProtocolLoader.Load(proj, "protocols/pdf_structured.yaml");
        var bytes = model.Render();
        var text = System.Text.Encoding.ASCII.GetString(bytes);
        Assert.StartsWith("%PDF-1.4", text);
        Assert.Contains("xref", text);
        Assert.Contains("startxref", text);
        Assert.Contains("%%EOF", text);
        var fields = model.GetFields();
        var start = fields.First(f => f.Name == "startxref_off");
        Assert.Equal("asciiOffset", start.Kind);
        var xrefIdx = text.IndexOf("xref\n", StringComparison.Ordinal);
        Assert.True(xrefIdx >= 0);
        var ascii = System.Text.Encoding.ASCII.GetString(bytes, start.Offset, start.Length);
        Assert.Equal(xrefIdx, int.Parse(ascii));
    }

    [Fact]
    public void TlvGrammar_GenerateRoundTrip_MagicAndSwitch()
    {
        var repo = FindRepoRoot();
        var proj = Path.Combine(repo, "projects", "file-text.yaml");
        var model = ProtocolLoader.Load(proj, "protocols/tlv_grammar.yaml");
        var bytes = model.Render();
        Assert.True(bytes.Length >= 6);
        Assert.Equal("TLV1", System.Text.Encoding.ASCII.GetString(bytes, 0, 4));
        var fields = model.GetFields();
        Assert.Contains(fields, f => f.Kind == "switch" || f.Name == "tlv_body");
        Assert.Contains(fields, f => f.Name == "tlv_type" || f.Kind == "enum");
    }

    [Fact]
    public void AsciiOffset_BackPatchesDecimalDigits()
    {
        var root = new GroupBlock([
            new BytesBlock { Name = "pad", DefaultValue = [1, 2, 3, 4, 5], Mutable = false },
            new GroupBlock([
                new StaticBlock("XREF"),
            ], "xref"),
            new OffsetBlock
            {
                Name = "sx",
                Width = 8,
                AsciiDecimal = true,
                TargetField = "xref",
                DefaultValue = 0,
            },
        ]);
        var bytes = new BlockModel("ascii-off", root).Render();
        var ascii = System.Text.Encoding.ASCII.GetString(bytes, 9, 8);
        Assert.Equal("00000005", ascii);
    }

    [Fact]
    public void CoverageBackendResolver_Tokens()
    {
        var p = new Randall.Contracts.ProjectConfig();
        p.Coverage.Backend = "semantic";
        var r = CoverageBackendResolver.Resolve(p);
        Assert.Equal(CoverageBackendResolver.Semantic, r.Effective);
        Assert.True(r.SemanticOnly);

        p.Coverage.Backend = "sancov";
        r = CoverageBackendResolver.Resolve(p);
        Assert.True(r.PreferSancovIngest);
        Assert.True(CoverageBackendResolver.ShouldIngestSancov(p));
    }

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            if (File.Exists(Path.Combine(dir.FullName, "Randall.sln")))
                return dir.FullName;
            dir = dir.Parent;
        }
        throw new InvalidOperationException("Repo root not found");
    }

    private static int IndexOf(byte[] haystack, ReadOnlySpan<byte> needle)
    {
        for (var i = 0; i <= haystack.Length - needle.Length; i++)
        {
            if (haystack.AsSpan(i, needle.Length).SequenceEqual(needle))
                return i;
        }
        return -1;
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
    public void PngDemo_ProfileAndSeeds_Present()
    {
        var repo = FindRepoRoot();
        Assert.True(File.Exists(Path.Combine(repo, "projects", "png-demo.yaml")));
        Assert.True(File.Exists(Path.Combine(repo, "projects", "png-demo-harness.yaml")));
        Assert.True(File.Exists(Path.Combine(repo, "projects", "dictionaries", "png-demo.txt")));
        Assert.True(File.Exists(Path.Combine(repo, "projects", "seeds", "png_demo_minimal.png")));
        Assert.True(File.Exists(Path.Combine(repo, "projects", "seeds", "png_demo_fuzzboom.png")));
        Assert.True(File.Exists(Path.Combine(repo, "projects", "seeds", "png_demo_reject.bin")));
        Assert.True(File.Exists(Path.Combine(repo, "targets", "png-demo", "png_parse.c")));
        Assert.Contains("Competitive demo: png-demo",
            File.ReadAllText(Path.Combine(repo, "docs", "FILE_FUZZING.md")),
            StringComparison.Ordinal);
    }

    [Fact]
    public void PngDemo_StructuredModel_LoadsAgainstProfile()
    {
        var repo = FindRepoRoot();
        var proj = Path.Combine(repo, "projects", "png-demo.yaml");
        var model = ProtocolLoader.Load(proj, "protocols/png_structured.yaml");
        var bytes = model.Render();
        Assert.Equal(new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A }, bytes[..8]);
    }

    [Fact]
    public void PngDemo_NativeBinary_RejectNotCrash_AndBoomIsCrashShaped()
    {
        var repo = FindRepoRoot();
        var exe = Path.Combine(repo, "targets", "png-demo", "app.exe");
        if (!File.Exists(exe))
            exe = Path.Combine(repo, "targets", "png-demo", "app");
        if (!File.Exists(exe))
            exe = Path.Combine(repo, "targets", "png-demo", "png-demo.exe");
        if (!File.Exists(exe))
            exe = Path.Combine(repo, "targets", "png-demo", "png-demo");
        if (!File.Exists(exe))
            return; // binary optional in CI — build scripts cover the grind path

        var reject = Path.Combine(repo, "projects", "seeds", "png_demo_reject.bin");
        var boom = Path.Combine(repo, "projects", "seeds", "png_demo_fuzzboom.png");
        var ok = Path.Combine(repo, "projects", "seeds", "png_demo_minimal.png");

        var rejectCode = RunNative(exe, reject);
        Assert.False(TargetRunner.IsCrashExitCode(rejectCode));
        var (rejectCrash, rejectDetail) = FileFuzzExecution.ClassifyFileExit(rejectCode, null);
        Assert.False(rejectCrash);
        Assert.Contains("tool-reject", rejectDetail);

        var okCode = RunNative(exe, ok);
        Assert.Equal(0, okCode);
        Assert.False(TargetRunner.IsCrashExitCode(okCode));

        var boomCode = RunNative(exe, boom);
        Assert.True(TargetRunner.IsCrashExitCode(boomCode));
        var (boomCrash, _) = FileFuzzExecution.ClassifyFileExit(boomCode, null);
        Assert.True(boomCrash);
    }

    [Fact]
    public void PngDemo_ResearchPipeline_EvidenceAndRootCausePersist()
    {
        var dir = Path.Combine(Path.GetTempPath(), "randall-png-demo-research-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var id = Guid.NewGuid();
            const string project = "png-demo";
            var payload = File.ReadAllBytes(
                Path.Combine(FindRepoRoot(), "projects", "seeds", "png_demo_fuzzboom.png"));
            var sidecar = new CrashSidecarDto(
                id, "run-png", 1, project, "FUZZ", "dictionary",
                ["dictionary", "replace-chunk"], null, "seed", ["png_demo_fuzzboom.png"],
                "deadbeef", Path.Combine(dir, "boom.png"), payload.Length,
                unchecked((int)0xC0000409), "STATUS_STACK_BUFFER_OVERRUN", "abort", null, 1, 10, "native",
                null, null, null, null,
                new TransportSnapshotDto("file", "", 0, false),
                new FuzzSnapshotDto(true, false, "projects/png-demo.yaml"),
                DateTimeOffset.UtcNow,
                null,
                new OracleScore(70, [new OracleScoreTerm("crash", 60, "AV")], "+60 crash"));
            File.WriteAllBytes(sidecar.InputPath!, payload);

            var triage = CrashTriage.Classify(null, sidecar, null, payload);
            var root = RootCauseEngine.PersistForCrash(dir, id, project, sidecar, triage, null, null, null, sidecar.RandallScore);
            var evidence = EvidenceFactBuilder.PersistForCrash(dir, id, project, sidecar, triage, null, null,
                oracleScore: sidecar.RandallScore);
            Assert.True(root.Ok);
            Assert.True(evidence.Ok);
            Assert.True(File.Exists(RootCauseEngine.PathFor(dir, id)));
            Assert.True(File.Exists(EvidenceFactBuilder.PathFor(dir, id)));
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { /* ignore */ }
        }
    }

    private static int RunNative(string exe, string input)
    {
        using var p = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
        {
            FileName = exe,
            Arguments = $"\"{input}\"",
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardError = true,
            RedirectStandardOutput = true,
        }) ?? throw new InvalidOperationException("failed to start " + exe);
        p.WaitForExit(5000);
        return p.ExitCode;
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
