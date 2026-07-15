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
            "static" => new StaticBlock(def.Value ?? ""),
            "string" => new StaticBlock(def.Value ?? ""),
            "bytes" or "data" or "payload" => new BytesBlock
            {
                Name = def.Name ?? "payload",
                Mutable = def.Mutable,
                MinSize = def.MinSize,
                MaxSize = def.MaxSize,
                SeedFile = def.SeedFile,
            },
            "group" => new GroupBlock((def.Children ?? []).Select(BuildBlock).ToList()),
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
            },
            _ => new StaticBlock(def.Value ?? ""),
        };

    private static IBlockNode BuildSizedPayload(ProtocolBlockDefinition def)
    {
        if (def.Child is not null)
            return BuildBlock(def.Child);
        if (def.Children is { Count: > 0 })
            return BuildNode(def.Children);
        throw new InvalidOperationException("sized block requires child or children");
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
        int havocDepth = 6)
    {
        var baseline = model.Render(seeds);
        var mutable = model.GetMutableFields();
        if (mutable.Count == 0)
            return model.FinalizeMessage(baseline, syncLengthFields);

        var lengthFields = mutable.Where(f => f.Kind == "length").ToList();
        IReadOnlyList<FieldRegion> pool = lengthFields.Count > 0 && rng.NextDouble() < 0.25
            ? lengthFields
            : mutable;

        var field = pool[rng.Next(pool.Count)];
        if (field.Offset + field.Length > baseline.Length)
            return model.FinalizeMessage(baseline, syncLengthFields);

        var slice = baseline.AsSpan(field.Offset, field.Length).ToArray();
        byte[] mutated;
        if (field.Kind == "length")
            mutated = MutateLengthField(slice, field, baseline, rng);
        else if (mutator.Name == "havoc" || (field.Kind == "bytes" && rng.NextDouble() < 0.15))
            mutated = MutationOps.Havoc(slice, rng, havocDepth);
        else
            mutated = mutator.Mutate(slice).ToArray();

        var patched = model.PatchField(baseline, field.Name, mutated);
        return model.FinalizeMessage(patched, syncLengthFields);
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
        if (width == 2)
            return littleEndian
                ? (uint)(bytes[0] | (bytes[1] << 8))
                : (uint)((bytes[0] << 8) | bytes[1]);
        return littleEndian
            ? (uint)(bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24))
            : (uint)((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]);
    }

    private static byte[] WriteLength(uint value, int width, bool littleEndian)
    {
        var buf = new byte[width];
        if (width == 2)
        {
            var v = (ushort)value;
            if (littleEndian) { buf[0] = (byte)v; buf[1] = (byte)(v >> 8); }
            else { buf[0] = (byte)(v >> 8); buf[1] = (byte)v; }
        }
        else
        {
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
