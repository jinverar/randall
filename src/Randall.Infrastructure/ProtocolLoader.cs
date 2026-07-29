using System.IO.Compression;
using System.Text;
using Randall.Contracts;
using Randall.Core;
using Randall.Core.Model;
using Randall.Infrastructure.Mutators;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace Randall.Infrastructure;

public static class ProtocolLoader
{
    private static readonly IDeserializer Deserializer = new DeserializerBuilder()
        .WithNamingConvention(CamelCaseNamingConvention.Instance)
        .IgnoreUnmatchedProperties()
        .Build();

    public static BlockModel Load(string projectYamlPath, string protocolRelativePath)
    {
        var full = ProjectLoader.ResolvePath(projectYamlPath, protocolRelativePath);
        if (!File.Exists(full))
            throw new FileNotFoundException($"Protocol not found: {full}");
        var def = Deserializer.Deserialize<ProtocolDefinition>(File.ReadAllText(full))
            ?? throw new InvalidOperationException($"Failed to parse protocol: {full}");
        def.Name = string.IsNullOrWhiteSpace(def.Name)
            ? Path.GetFileNameWithoutExtension(full)
            : def.Name;
        var root = BuildNode(def.Blocks);
        var model = new BlockModel(def.Name, root, trailingCrc32: def.TrailingCrc32);
        try
        {
            var seeds = LoadProtocolSeeds(projectYamlPath, protocolRelativePath);
            model.RegisterDerivedFields(seeds);
        }
        catch { model.RegisterDerivedFields(new Dictionary<string, byte[]>()); }
        return model;
    }

    public static IEnumerable<string> Discover(string protocolsDir)
    {
        var dir = Path.GetFullPath(protocolsDir);
        if (!Directory.Exists(dir))
            yield break;
        foreach (var f in Directory.EnumerateFiles(dir, "*.yaml"))
            yield return f;
        foreach (var f in Directory.EnumerateFiles(dir, "*.yml"))
            yield return f;
    }

    public static ProtocolSummaryDto Describe(string protocolPath, string projectYamlPath)
    {
        var full = ProjectLoader.ResolvePath(projectYamlPath, protocolPath);
        var def = Deserializer.Deserialize<ProtocolDefinition>(File.ReadAllText(full))!;
        var model = Load(projectYamlPath, protocolPath);
        var seeds = LoadProtocolSeeds(projectYamlPath, protocolPath);
        model.Render(seeds);
        var fields = model.GetFields().Select(f => new ProtocolFieldDto(
            f.Name,
            f.Offset,
            f.Length,
            f.Mutable,
            f.Kind)).ToList();
        return new ProtocolSummaryDto(model.Name, def.Description, protocolPath, fields);
    }

    public static IReadOnlyDictionary<string, byte[]> LoadProtocolSeeds(string projectYamlPath, string protocolRelativePath)
    {
        var full = ProjectLoader.ResolvePath(projectYamlPath, protocolRelativePath);
        var def = Deserializer.Deserialize<ProtocolDefinition>(File.ReadAllText(full))!;
        var dict = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
        CollectSeedFiles(def.Blocks, projectYamlPath, dict);
        return dict;
    }

    private static void CollectSeedFiles(
        IEnumerable<ProtocolBlockDefinition> blocks,
        string projectYamlPath,
        Dictionary<string, byte[]> dict)
    {
        foreach (var b in blocks)
        {
            if (!string.IsNullOrWhiteSpace(b.SeedFile) && !dict.ContainsKey(b.SeedFile))
            {
                try
                {
                    dict[b.SeedFile] = ProjectLoader.LoadSeed(projectYamlPath, b.SeedFile);
                }
                catch { /* optional seed */ }
            }
            if (b.Children is not null)
                CollectSeedFiles(b.Children, projectYamlPath, dict);
            if (b.Child is not null)
                CollectSeedFiles([b.Child], projectYamlPath, dict);
            if (b.Cases is not null)
            {
                foreach (var c in b.Cases)
                {
                    if (c.Block is not null)
                        CollectSeedFiles([c.Block], projectYamlPath, dict);
                    if (c.Children is not null)
                        CollectSeedFiles(c.Children, projectYamlPath, dict);
                }
            }
        }
    }

    private static IBlockNode BuildNode(IReadOnlyList<ProtocolBlockDefinition> blocks)
    {
        if (blocks.Count == 1)
            return BuildBlock(blocks[0]);
        return new GroupBlock(blocks.Select(BuildBlock).ToList());
    }

    private static IBlockNode BuildBlock(ProtocolBlockDefinition def) =>
        def.Type.ToLowerInvariant() switch
        {
            "static" when (def.Value ?? "").StartsWith("hex:", StringComparison.OrdinalIgnoreCase)
                => new HexStaticBlock(def.Value![4..]),
            "static" or "hex" => string.IsNullOrEmpty(def.Value)
                ? new StaticBlock("")
                : def.Type.Equals("hex", StringComparison.OrdinalIgnoreCase)
                    ? new HexStaticBlock(def.Value!)
                    : new StaticBlock(def.Value!),
            "delim" => new DelimBlock(def.Value ?? " ", def.Name ?? "delim", def.Mutable),
            "string" => new StringBlock
            {
                Name = def.Name ?? "string",
                Mutable = def.Mutable,
                DefaultValue = def.Value ?? "",
                MinSize = def.MinSize,
                MaxSize = def.MaxSize,
                SeedFile = def.SeedFile,
            },
            "uint8" or "byte" => MakeNumber(def, 1, signed: false),
            "int8" => MakeNumber(def, 1, signed: true),
            "uint16" or "word" => MakeNumber(def, ResolveWidth(def, 2), signed: false),
            "int16" => MakeNumber(def, ResolveWidth(def, 2), signed: true),
            "uint32" or "dword" or "uint" => MakeNumber(def, ResolveWidth(def, 4), signed: false),
            "int32" or "int" => MakeNumber(def, ResolveWidth(def, 4), signed: true),
            "uint64" or "qword" => MakeNumber(def, ResolveWidth(def, 8), signed: false),
            "int64" => MakeNumber(def, ResolveWidth(def, 8), signed: true),
            "enum" => new EnumBlock
            {
                Name = def.Name ?? "enum",
                Width = ResolveWidth(def, def.LengthBytes is 1 or 2 or 4 or 8 ? def.LengthBytes : 4),
                LittleEndian = def.LittleEndian,
                Mutable = def.Mutable,
                Values = ParseEnumValues(def),
                DefaultValue = ParseIntegerDefault(def.Value, ResolveWidth(def, 4)),
            },
            "flags" or "bitfield" => new FlagsBlock
            {
                Name = def.Name ?? "flags",
                Width = ResolveWidth(def, def.LengthBytes is 1 or 2 or 4 or 8 ? def.LengthBytes : 4),
                LittleEndian = def.LittleEndian,
                Mutable = def.Mutable,
                DefaultValue = ParseIntegerDefault(def.Value, ResolveWidth(def, 4)),
                FlagBits = def.Flags.ToDictionary(
                    kv => kv.Key,
                    kv => ParseIntegerDefault(kv.Value, 8),
                    StringComparer.OrdinalIgnoreCase),
            },
            "choices" or "group_values" => new ChoiceBlock
            {
                Name = def.Name ?? "choice",
                Mutable = def.Mutable,
                Values = (def.Values.Count > 0 ? def.Values : [def.Value ?? ""])
                    .Select(StaticValueParser.Parse)
                    .ToList(),
            },
            "switch" or "choice" => BuildSwitch(def),
            "bytes" or "data" or "payload" => new BytesBlock
            {
                Name = def.Name ?? "payload",
                Mutable = def.Mutable,
                MinSize = def.MinSize,
                MaxSize = def.MaxSize,
                SeedFile = def.SeedFile,
                DefaultValue = string.IsNullOrWhiteSpace(def.Value)
                    ? null
                    : StaticValueParser.Parse(def.Value),
            },
            "group" or "block" or "container" => new GroupBlock(
                (def.Children ?? []).Select(BuildBlock).ToList(), def.Name),
            "array" or "repeat" => new RepeatBlock
            {
                Name = def.Name ?? "array",
                Child = BuildSizedPayload(def),
                Count = Math.Max(1, def.Count),
                MinCount = def.MinCount,
                MaxCount = def.MaxCount > 0 ? def.MaxCount : Math.Max(def.Count, 8),
                CountMutable = def.CountMutable,
            },
            "padding" or "align" => new PaddingBlock
            {
                Align = def.Align > 0 ? def.Align : 4,
                PadByte = ParsePadByte(def.PadByte),
                Name = def.Name,
            },
            "offset" or "relativeoffset" => new OffsetBlock
            {
                Name = def.Name ?? "offset",
                Width = ResolveWidth(def, def.LengthBytes is 2 or 4 or 8 ? def.LengthBytes : 4),
                LittleEndian = def.LittleEndian,
                Relative = def.Relative || def.Type.Equals("relativeoffset", StringComparison.OrdinalIgnoreCase),
                TargetField = def.TargetField,
                Mutable = def.Mutable,
                DefaultValue = ParseIntegerDefault(def.Value, 4),
                AsciiDecimal = def.Ascii || def.AsciiDecimal,
            },
            "when" or "conditional" => new ConditionalBlock
            {
                WhenField = def.When ?? def.Name ?? "",
                WhenEquals = def.WhenEquals ?? "",
                Child = BuildSizedPayload(def),
                AlwaysRenderStub = false,
            },
            "sized" or "length" or "lengthprefix" => new LengthPrefixedBlock
            {
                LengthName = def.LengthName ?? def.Name ?? "length",
                LengthBytes = def.LengthBytes is 2 or 4 ? def.LengthBytes : 4,
                LittleEndian = def.LittleEndian,
                LengthMutable = def.LengthMutable,
                Payload = BuildSizedPayload(def),
            },
            "checksum" or "crc" or "crc32" => new ChecksumBlock
            {
                Name = def.Name ?? "checksum",
                LengthBytes = def.LengthBytes is 2 or 4 ? def.LengthBytes : 4,
                LittleEndian = def.LittleEndian,
                Mutable = def.Mutable,
                CoverFrom = def.CoverFrom,
            },
            // Unknown types: preserve as static so YAML still loads (competitive catalog won't hard-fail).
            _ => new StaticBlock(def.Value ?? ""),
        };

    private static IBlockNode MakeNumber(ProtocolBlockDefinition def, int width, bool signed) =>
        signed
            ? new NumberBlock
            {
                Name = def.Name ?? "int",
                Width = width,
                LittleEndian = def.LittleEndian,
                Signed = true,
                Mutable = def.Mutable,
                DefaultValue = unchecked((long)ParseIntegerDefault(def.Value, width)),
            }
            : new IntegerBlock
            {
                Name = def.Name ?? "uint",
                Width = width,
                LittleEndian = def.LittleEndian,
                Mutable = def.Mutable,
                DefaultValue = ParseIntegerDefault(def.Value, width),
            };

    private static int ResolveWidth(ProtocolBlockDefinition def, int fallback)
    {
        if (def.Width is 1 or 2 or 4 or 8)
            return def.Width;
        return fallback;
    }

    private static IReadOnlyList<ulong> ParseEnumValues(ProtocolBlockDefinition def)
    {
        var list = new List<ulong>();
        foreach (var v in def.EnumValues.Concat(def.Values))
        {
            if (string.IsNullOrWhiteSpace(v))
                continue;
            // Allow "NAME=0x01" or bare number.
            var s = v;
            var eq = s.IndexOf('=');
            if (eq >= 0)
                s = s[(eq + 1)..];
            list.Add(ParseIntegerDefault(s.Trim(), 8));
        }
        if (list.Count == 0 && !string.IsNullOrWhiteSpace(def.Value))
            list.Add(ParseIntegerDefault(def.Value, 8));
        return list;
    }

    private static byte ParsePadByte(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return 0;
        if (value.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            return Convert.ToByte(value, 16);
        return byte.TryParse(value, out var b) ? b : (byte)0;
    }

    private static IBlockNode BuildSwitch(ProtocolBlockDefinition def)
    {
        var cases = new List<(string Key, IBlockNode Node)>();
        if (def.Cases is { Count: > 0 })
        {
            foreach (var c in def.Cases)
            {
                IBlockNode node;
                if (c.Block is not null)
                    node = BuildBlock(c.Block);
                else if (c.Children is { Count: > 0 })
                    node = BuildNode(c.Children);
                else
                    node = new StaticBlock("");
                cases.Add((c.Key, node));
            }
        }
        else if (def.Children is { Count: > 0 })
        {
            for (var i = 0; i < def.Children.Count; i++)
                cases.Add((i.ToString(), BuildBlock(def.Children[i])));
        }

        return new SwitchBlock
        {
            Name = def.Name ?? "switch",
            Mutable = def.Mutable,
            Cases = cases,
        };
    }

    private static ulong ParseIntegerDefault(string? value, int width)
    {
        if (string.IsNullOrWhiteSpace(value))
            return 0;
        value = value.Trim();
        if (value.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            return Convert.ToUInt64(value, 16);
        return ulong.Parse(value);
    }

    private static IBlockNode BuildSizedPayload(ProtocolBlockDefinition def)
    {
        if (def.Child is not null)
            return BuildBlock(def.Child);
        if (def.Children is { Count: > 0 })
            return BuildNode(def.Children);
        throw new InvalidOperationException($"{def.Type} block requires child or children");
    }
}

public static class ModelFuzzer
{
    public static byte[] BuildPayload(
        BlockModel model,
        IReadOnlyDictionary<string, byte[]> seeds,
        IMutator mutator,
        Random rng,
        bool syncLengthFields = false,
        int havocDepth = 6) =>
        BuildPayload(model, seeds, mutator, rng, syncLengthFields, havocDepth, targetField: null, syncNbssLength: false);

    public static byte[] BuildPayload(
        BlockModel model,
        IReadOnlyDictionary<string, byte[]> seeds,
        IMutator mutator,
        Random rng,
        bool syncLengthFields,
        int havocDepth,
        FieldRegion? targetField) =>
        BuildPayload(model, seeds, mutator, rng, syncLengthFields, havocDepth, targetField, syncNbssLength: false);

    public static byte[] BuildPayload(
        BlockModel model,
        IReadOnlyDictionary<string, byte[]> seeds,
        IMutator mutator,
        Random rng,
        bool syncLengthFields,
        int havocDepth,
        FieldRegion? targetField,
        bool syncNbssLength) =>
        BuildPayload(
            model, seeds, mutator, rng, havocDepth, targetField, syncNbssLength,
            DependencyPolicyParser.ParseLength(null, syncLengthFields),
            DependencyPolicyParser.ParseChecksum(null),
            lengthDelta: 0,
            checksumDelta: 0);

    public static byte[] BuildPayload(
        BlockModel model,
        IReadOnlyDictionary<string, byte[]> seeds,
        IMutator mutator,
        Random rng,
        FuzzConfig fuzz,
        FieldRegion? targetField = null)
    {
        var (lenPol, crcPol, lenDelta, crcDelta) = FuzzDependencyPolicies.Resolve(fuzz);
        return BuildPayload(
            model, seeds, mutator, rng, fuzz.HavocDepth, targetField, fuzz.SyncNbssLength,
            lenPol, crcPol, lenDelta, crcDelta);
    }

    public static byte[] BuildPayload(
        BlockModel model,
        IReadOnlyDictionary<string, byte[]> seeds,
        IMutator mutator,
        Random rng,
        int havocDepth,
        FieldRegion? targetField,
        bool syncNbssLength,
        LengthPolicy lengthPolicy,
        ChecksumPolicy checksumPolicy,
        int lengthDelta = 0,
        int checksumDelta = 0)
    {
        var baseline = model.Render(seeds);
        var mutable = model.GetMutableFields(seeds);
        if (mutable.Count == 0)
            return MaybeSyncNbss(
                model.FinalizeMessage(baseline, lengthPolicy, checksumPolicy, lengthDelta, checksumDelta),
                syncNbssLength, fieldName: null);

        var lengthFields = mutable.Where(f => f.Kind == "length").ToList();
        IReadOnlyList<FieldRegion> pool = targetField is not null
            ? [targetField]
            : lengthFields.Count > 0 && rng.NextDouble() < 0.25
                ? lengthFields
                : mutable;

        var field = targetField ?? pool[rng.Next(pool.Count)];
        if (field.Offset + field.Length > baseline.Length && field.Kind is not "string" and not "choices")
            return MaybeSyncNbss(
                model.FinalizeMessage(baseline, lengthPolicy, checksumPolicy, lengthDelta, checksumDelta),
                syncNbssLength, field.Name);

        var slice = field.Offset + field.Length <= baseline.Length
            ? baseline.AsSpan(field.Offset, field.Length).ToArray()
            : Array.Empty<byte>();
        byte[] mutated;
        if (IsIntegerKind(field.Kind))
            mutated = MutateIntegerField(slice, field, rng);
        else if (field.Kind == "length")
            mutated = MutateLengthField(slice, field, baseline, rng);
        else if (mutator.Name == "havoc" ||
                 mutator.Name is not ("expand" or "insert") &&
                 field.Kind is "bytes" or "string" && rng.NextDouble() < 0.15)
            mutated = MutationOps.Havoc(slice, rng, havocDepth);
        else
            mutated = mutator.Mutate(slice).ToArray();

        var patched = model.PatchField(baseline, field, mutated);
        var finalized = model.FinalizeMessage(patched, lengthPolicy, checksumPolicy, lengthDelta, checksumDelta);
        return MaybeSyncNbss(finalized, syncNbssLength, field.Name);
    }

    private static bool IsIntegerKind(string kind) =>
        kind is "word" or "dword" or "qword" or "enum" or "flags"
            or "uint8" or "uint16" or "uint32" or "uint64"
            or "int8" or "int16" or "int32" or "int64"
            or "offset" or "relativeOffset";

    private static byte[] MaybeSyncNbss(byte[] message, bool syncNbssLength, string? fieldName)
    {
        if (!syncNbssLength || NbssFraming.IsNbssLengthField(fieldName))
            return message;
        return NbssFraming.TrySyncLength(message);
    }

    private static byte[] MutateIntegerField(byte[] bytes, FieldRegion field, Random rng)
    {
        var current = ReadInteger(bytes, field.Length, field.LittleEndian);
        var choices = new List<ulong>
        {
            0, 1, current,
            current > 0 ? current - 1 : 0,
            current + 1,
        };
        if (field.Length == 2)
        {
            choices.Add(ushort.MaxValue);
            choices.Add(ushort.MaxValue - 1);
        }
        else if (field.Length == 4)
        {
            choices.Add(uint.MaxValue);
            choices.Add(uint.MaxValue - 1);
        }
        else
        {
            choices.Add(ulong.MaxValue);
            choices.Add(ulong.MaxValue - 1);
        }
        var pick = choices[rng.Next(choices.Count)];
        return WriteInteger(pick, field.Length, field.LittleEndian);
    }

    private static ulong ReadInteger(ReadOnlySpan<byte> bytes, int width, bool littleEndian)
    {
        if (bytes.Length < width || width <= 0)
            return 0;
        if (width == 1)
            return bytes[0];
        if (width == 2)
            return littleEndian
                ? (ulong)(bytes[0] | (bytes[1] << 8))
                : (ulong)((bytes[0] << 8) | bytes[1]);
        if (width == 8)
        {
            ulong v = 0;
            if (littleEndian)
                for (var i = 0; i < 8; i++)
                    v |= (ulong)bytes[i] << (8 * i);
            else
                for (var i = 0; i < 8; i++)
                    v |= (ulong)bytes[i] << (8 * (7 - i));
            return v;
        }
        // Default: 4-byte integer fields.
        if (bytes.Length < 4)
            return bytes.Length > 0 ? bytes[0] : 0UL;
        return littleEndian
            ? (ulong)(bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24))
            : (ulong)((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]);
    }

    private static byte[] WriteInteger(ulong value, int width, bool littleEndian)
    {
        if (width <= 0)
            return [];
        var buf = new byte[width];
        if (width == 1)
        {
            buf[0] = (byte)value;
            return buf;
        }
        if (width == 2)
        {
            var v = (ushort)value;
            if (littleEndian) { buf[0] = (byte)v; buf[1] = (byte)(v >> 8); }
            else { buf[0] = (byte)(v >> 8); buf[1] = (byte)v; }
        }
        else if (width == 8)
        {
            if (littleEndian)
                for (var i = 0; i < 8; i++)
                    buf[i] = (byte)(value >> (8 * i));
            else
                for (var i = 0; i < 8; i++)
                    buf[7 - i] = (byte)(value >> (8 * i));
        }
        else
        {
            var v = (uint)value;
            if (width < 4)
            {
                buf[0] = (byte)v;
                return buf;
            }
            if (littleEndian)
            {
                buf[0] = (byte)v; buf[1] = (byte)(v >> 8);
                buf[2] = (byte)(v >> 16); buf[3] = (byte)(v >> 24);
            }
            else
            {
                buf[0] = (byte)(v >> 24); buf[1] = (byte)(v >> 16);
                buf[2] = (byte)(v >> 8); buf[3] = (byte)v;
            }
        }
        return buf;
    }

    private static byte[] MutateLengthField(
        byte[] lengthBytes,
        FieldRegion field,
        byte[] baseline,
        Random rng)
    {
        var current = ReadLength(lengthBytes, field.Length, field.LittleEndian);
        var payloadLen = baseline.Length - (field.Offset + field.Length);
        var choices = new List<uint>
        {
            0,
            1,
            current,
            current > 0 ? current - 1 : 0,
            current + 1,
            (uint)Math.Max(0, payloadLen),
            (uint)Math.Max(0, payloadLen + 1),
            payloadLen > 0 ? (uint)(payloadLen - 1) : 0,
        };
        if (field.Length == 2)
        {
            choices.Add(ushort.MaxValue);
            choices.Add(ushort.MaxValue - 1);
        }
        else
        {
            choices.Add(uint.MaxValue);
            choices.Add(uint.MaxValue - 1);
        }

        var pick = choices[rng.Next(choices.Count)];
        return WriteLength(pick, field.Length, field.LittleEndian);
    }

    private static uint ReadLength(ReadOnlySpan<byte> bytes, int width, bool littleEndian)
    {
        if (bytes.Length < width || width <= 0)
            return 0;
        if (width == 1)
            return bytes[0];
        if (width == 2)
            return littleEndian
                ? (uint)(bytes[0] | (bytes[1] << 8))
                : (uint)((bytes[0] << 8) | bytes[1]);
        if (bytes.Length < 4)
            return bytes.Length > 0 ? bytes[0] : 0u;
        return littleEndian
            ? (uint)(bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24))
            : (uint)((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]);
    }

    private static byte[] WriteLength(uint value, int width, bool littleEndian)
    {
        if (width <= 0)
            return [];
        var buf = new byte[width];
        if (width == 1)
        {
            buf[0] = (byte)value;
            return buf;
        }
        if (width == 2)
        {
            var v = (ushort)value;
            if (littleEndian) { buf[0] = (byte)v; buf[1] = (byte)(v >> 8); }
            else { buf[0] = (byte)(v >> 8); buf[1] = (byte)v; }
        }
        else
        {
            if (width < 4)
            {
                buf[0] = (byte)value;
                return buf;
            }
            if (littleEndian)
            {
                buf[0] = (byte)value; buf[1] = (byte)(value >> 8);
                buf[2] = (byte)(value >> 16); buf[3] = (byte)(value >> 24);
            }
            else
            {
                buf[0] = (byte)(value >> 24); buf[1] = (byte)(value >> 16);
                buf[2] = (byte)(value >> 8); buf[3] = (byte)value;
            }
        }
        return buf;
    }

    public static string FieldLabel(IReadOnlyList<FieldRegion> fields, int offset)
    {
        foreach (var f in fields)
        {
            if (offset >= f.Offset && offset < f.Offset + f.Length)
                return f.Name;
        }
        return "static";
    }
}

public static class ProjectBundle
{
    public static string Export(string projectYamlPath, string? outputPath = null)
    {
        projectYamlPath = Path.GetFullPath(projectYamlPath);
        var project = ProjectLoader.Load(projectYamlPath);
        var projectRoot = ProjectLoader.ResolveProjectRoot(projectYamlPath);
        var repoRoot = CrashCatalog.FindRepoRoot() ?? projectRoot;
        outputPath ??= Path.Combine(repoRoot, "bundles", $"{project.Name}.zip");
        outputPath = Path.GetFullPath(outputPath);
        Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);

        if (File.Exists(outputPath))
            File.Delete(outputPath);

        var staging = Path.Combine(Path.GetTempPath(), $"randall_bundle_{Guid.NewGuid():N}");
        try
        {
            Directory.CreateDirectory(staging);
            var bundleRoot = Path.Combine(staging, project.Name);
            Directory.CreateDirectory(bundleRoot);

            CopyFile(projectYamlPath, Path.Combine(bundleRoot, Path.GetFileName(projectYamlPath)));
            CopyTree(projectRoot, bundleRoot, project);
            CopyOptionalDir(projectRoot, bundleRoot, "protocols");
            CopyOptionalDir(projectRoot, bundleRoot, "seeds");
            CopyOptionalDir(projectRoot, bundleRoot, "plugins");

            ZipFile.CreateFromDirectory(bundleRoot, outputPath);
            return outputPath;
        }
        finally
        {
            try { Directory.Delete(staging, recursive: true); } catch { /* ignore */ }
        }
    }

    public static string Import(string zipPath, string? outputDir = null)
    {
        zipPath = Path.GetFullPath(zipPath);
        if (!File.Exists(zipPath))
            throw new FileNotFoundException($"Bundle not found: {zipPath}");

        var repoRoot = CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        outputDir ??= Path.Combine(
            repoRoot,
            "bundles",
            "imported",
            Path.GetFileNameWithoutExtension(zipPath));
        outputDir = Path.GetFullPath(outputDir);
        Directory.CreateDirectory(outputDir);
        ZipFile.ExtractToDirectory(zipPath, outputDir, overwriteFiles: true);
        return outputDir;
    }

    private static void CopyFile(string src, string dest)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(dest)!);
        File.Copy(src, dest, overwrite: true);
    }

    private static void CopyTree(string projectRoot, string bundleRoot, ProjectConfig project)
    {
        foreach (var seed in project.Seeds)
            CopyRel(projectRoot, bundleRoot, seed);
        if (!string.IsNullOrWhiteSpace(project.Model))
            CopyRel(projectRoot, bundleRoot, project.Model);
        foreach (var cmd in project.SessionCommands)
        {
            if (cmd.Seed is not null)
                CopyRel(projectRoot, bundleRoot, cmd.Seed);
            if (!string.IsNullOrWhiteSpace(cmd.Model))
                CopyRel(projectRoot, bundleRoot, cmd.Model);
        }
        if (!string.IsNullOrWhiteSpace(project.Target.Executable))
            CopyRel(projectRoot, bundleRoot, project.Target.Executable);
    }

    private static void CopyOptionalDir(string projectRoot, string bundleRoot, string dirName)
    {
        var src = Path.Combine(projectRoot, dirName);
        if (!Directory.Exists(src))
            return;
        CopyDirectory(src, Path.Combine(bundleRoot, dirName));
    }

    private static void CopyDirectory(string sourceDir, string destDir)
    {
        Directory.CreateDirectory(destDir);
        foreach (var file in Directory.EnumerateFiles(sourceDir, "*", SearchOption.AllDirectories))
        {
            var rel = Path.GetRelativePath(sourceDir, file);
            var dest = Path.Combine(destDir, rel);
            Directory.CreateDirectory(Path.GetDirectoryName(dest)!);
            File.Copy(file, dest, overwrite: true);
        }
    }

    private static void CopyRel(string projectRoot, string bundleRoot, string relative)
    {
        var src = Path.GetFullPath(Path.Combine(projectRoot, relative));
        if (!File.Exists(src))
            return;
        var dest = Path.Combine(bundleRoot, relative);
        Directory.CreateDirectory(Path.GetDirectoryName(dest)!);
        File.Copy(src, dest, overwrite: true);
    }
}
