using System.Text;
using System.Text.RegularExpressions;
using Randall.Contracts;
using Randall.Infrastructure.Mutators;

namespace Randall.Infrastructure;

public static class CaseRecipeStore
{
    public static readonly string[] AllMutators =
    [
        "bitflip", "expand", "truncate", "boundary", "insert",
        "havoc", "interesting", "dictionary", "splice", "arith",
        "duplicate", "shuffle",
    ];

    public static CaseProjectProfileDto? GetProfile(string projectName, string? repoRoot = null)
    {
        repoRoot ??= CrashCatalog.FindRepoRoot();
        if (repoRoot is null)
            return null;

        var target = CrashCatalog.ListTargets(repoRoot)
            .FirstOrDefault(t => t.Name.Equals(projectName, StringComparison.OrdinalIgnoreCase));
        if (target is null || !File.Exists(target.ConfigPath))
            return null;

        var project = ProjectLoader.Load(target.ConfigPath);
        var hasExe = !string.IsNullOrWhiteSpace(project.Target.Executable) &&
                     File.Exists(ProjectLoader.ResolvePath(target.ConfigPath, project.Target.Executable));

        var seeds = ListSeeds(project, target.ConfigPath);
        var dictTokens = BuiltInMutators.BuildDictionaryTokens(project, target.ConfigPath)
            .Select(FormatToken)
            .Take(40)
            .ToList();

        var tip = hasExe
            ? "Local binary will be started (longLived) or spawned per case."
            : project.Kind is "tcp" or "udp"
                ? $"Remote service mode — fuzz {project.Transport.Host}:{project.Transport.Port} (no local exe). Start the service yourself or on another host."
                : "Configure target.executable or transport.host/port in the project YAML.";

        return new CaseProjectProfileDto(
            project.Name,
            project.Kind,
            project.Transport.Host,
            project.Transport.Port,
            hasExe,
            string.IsNullOrWhiteSpace(project.Target.Executable)
                ? null
                : ProjectLoader.ResolvePath(target.ConfigPath, project.Target.Executable),
            project.Target.LongLived,
            project.Mutators,
            AllMutators,
            seeds,
            dictTokens,
            dictTokens.Count,
            target.ConfigPath,
            tip,
            project.Description);
    }

    public static IReadOnlyList<CaseSeedInfoDto> ListSeeds(ProjectConfig project, string configPath)
    {
        var projectDir = Path.GetDirectoryName(configPath)!;
        var seedsDir = Path.Combine(projectDir, "seeds");
        var yamlSeeds = new HashSet<string>(
            project.Seeds.Select(s => Path.GetFileName(s.Replace('\\', '/'))),
            StringComparer.OrdinalIgnoreCase);

        var files = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var rel in project.Seeds)
        {
            try
            {
                var full = ProjectLoader.ResolvePath(configPath, rel);
                if (File.Exists(full))
                    files[Path.GetFileName(full)] = full;
            }
            catch { /* skip */ }
        }

        if (Directory.Exists(seedsDir))
        {
            foreach (var full in Directory.EnumerateFiles(seedsDir))
                files[Path.GetFileName(full)] = full;
        }

        return files
            .OrderBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
            .Take(80)
            .Select(kv =>
            {
                var bytes = File.ReadAllBytes(kv.Value);
                var n = Math.Min(bytes.Length, 64);
                return new CaseSeedInfoDto(
                    kv.Key,
                    $"seeds/{kv.Key}",
                    bytes.Length,
                    Convert.ToHexString(bytes.AsSpan(0, n)) + (bytes.Length > n ? "…" : ""),
                    AsciiPreview(bytes.AsSpan(0, n)),
                    yamlSeeds.Contains(kv.Key));
            })
            .ToList();
    }

    public static CaseImportBytesDto? LoadSeed(string projectName, string fileName, string? repoRoot = null)
    {
        var profile = GetProfile(projectName, repoRoot)
                      ?? throw new ArgumentException($"Unknown project: {projectName}");
        var safe = Path.GetFileName(fileName);
        var path = Path.Combine(Path.GetDirectoryName(profile.ConfigPath)!, "seeds", safe);
        if (!File.Exists(path))
            throw new FileNotFoundException($"Seed not found: {safe}");

        var bytes = File.ReadAllBytes(path);
        return CaseRecipeEngine.SuggestFromBytes(bytes);
    }

    public static CaseSaveResultDto SaveSeed(CaseSaveSeedRequest request, string? repoRoot = null)
    {
        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var profile = GetProfile(request.Project, repoRoot)
                      ?? throw new ArgumentException($"Unknown project: {request.Project}");

        var (bytes, hints, _) = CaseRecipeEngine.Render(request.Steps);
        if (bytes.Length == 0)
            return new CaseSaveResultDto(false, "Recipe produced 0 bytes", null, 0);

        var fileName = string.IsNullOrWhiteSpace(request.FileName)
            ? $"case_{DateTime.UtcNow:yyyyMMdd_HHmmss}.bin"
            : Path.GetFileName(request.FileName);
        if (!Path.HasExtension(fileName))
            fileName += ".bin";

        var projectDir = Path.GetDirectoryName(profile.ConfigPath)!;
        var seedsDir = Path.Combine(projectDir, "seeds");
        Directory.CreateDirectory(seedsDir);
        var path = Path.Combine(seedsDir, fileName);
        File.WriteAllBytes(path, bytes);

        TryEnsureSeedInYaml(profile.ConfigPath, $"seeds/{fileName}");

        if (request.AlsoAddDictionaryHints && hints.Count > 0)
            SaveDict(new CaseSaveDictRequest(request.Project, hints, true), repoRoot);

        return new CaseSaveResultDto(true,
            $"Saved seed ({bytes.Length} bytes) — appears under seeds/ for project '{request.Project}'" +
            (request.AlsoAddDictionaryHints && hints.Count > 0 ? $" + {hints.Count} dict hint(s)" : ""),
            path,
            bytes.Length);
    }

    public static CaseSaveResultDto SaveDict(CaseSaveDictRequest request, string? repoRoot = null)
    {
        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var profile = GetProfile(request.Project, repoRoot)
                      ?? throw new ArgumentException($"Unknown project: {request.Project}");

        var project = ProjectLoader.Load(profile.ConfigPath);
        var projectDir = Path.GetDirectoryName(profile.ConfigPath)!;
        var dictRel = !string.IsNullOrWhiteSpace(project.DictionaryFile)
            ? project.DictionaryFile!.Replace('\\', '/')
            : $"dictionaries/{SanitizeName(request.Project)}.txt";
        if (!dictRel.Contains('/', StringComparison.Ordinal) && !dictRel.Contains('\\', StringComparison.Ordinal))
            dictRel = "dictionaries/" + dictRel;

        var path = ProjectLoader.ResolvePath(profile.ConfigPath, dictRel);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);

        var lines = new List<string>();
        if (request.AppendToFile && File.Exists(path))
            lines.AddRange(File.ReadAllLines(path));

        var existing = new HashSet<string>(lines, StringComparer.Ordinal);
        var added = 0;
        foreach (var token in request.Tokens)
        {
            if (string.IsNullOrWhiteSpace(token) || !existing.Add(token))
                continue;
            lines.Add(token);
            added++;
        }

        File.WriteAllLines(path, lines);
        TryEnsureDictFileInYaml(profile.ConfigPath, dictRel);
        TryEnsureMutatorInYaml(profile.ConfigPath, "dictionary");

        return new CaseSaveResultDto(true,
            added == 0 ? "Dictionary unchanged (duplicates)" : $"Added {added} token(s) → {path}",
            path,
            added);
    }

    public static CaseSaveResultDto SetMutators(CaseMutatorsRequest request, string? repoRoot = null)
    {
        var profile = GetProfile(request.Project, repoRoot)
                      ?? throw new ArgumentException($"Unknown project: {request.Project}");

        var chosen = request.Mutators
            .Select(m => m.Trim().ToLowerInvariant())
            .Where(m => AllMutators.Contains(m))
            .Distinct()
            .ToList();
        if (chosen.Count == 0)
            chosen.Add("bitflip");

        var yaml = File.ReadAllText(profile.ConfigPath);
        var block = "mutators:\n" + string.Join("\n", chosen.Select(m => $"  - {m}")) + "\n";
        // Match "mutators:" plus following "- item" lines (do not let \s* eat the first newline
        // or list items are left behind and glue onto the last new entry).
        var mutatorsPattern = new Regex(
            @"^mutators:[ \t]*\r?\n(?:[ \t]+-[^\r\n]*\r?\n?)*",
            RegexOptions.Multiline);
        if (mutatorsPattern.IsMatch(yaml))
            yaml = mutatorsPattern.Replace(yaml, block, 1);
        else
            yaml = yaml.TrimEnd() + "\n\n" + block;

        File.WriteAllText(profile.ConfigPath, yaml);
        return new CaseSaveResultDto(true,
            $"Mutators updated: {string.Join(", ", chosen)}",
            profile.ConfigPath,
            chosen.Count);
    }

    /// <summary>
    /// Create a new project YAML under projects/ or projects/local/.
    /// The <c>name:</c> field becomes the Target profile label in the UI.
    /// </summary>
    public static CaseSaveResultDto CreateProject(CaseNewProjectRequest request, string? repoRoot = null)
    {
        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var name = SanitizeName(request.Name);
        if (string.IsNullOrWhiteSpace(name))
            throw new ArgumentException("Project name required (letters, digits, dash, underscore)");

        var kind = (request.Kind ?? "tcp").Trim().ToLowerInvariant();
        if (kind is not ("tcp" or "udp" or "file"))
            throw new ArgumentException("kind must be tcp, udp, or file");

        var folder = request.LocalFolder
            ? Path.Combine(repoRoot, "projects", "local")
            : Path.Combine(repoRoot, "projects");
        Directory.CreateDirectory(folder);
        Directory.CreateDirectory(Path.Combine(folder, "seeds"));
        Directory.CreateDirectory(Path.Combine(folder, "dictionaries"));

        var yamlPath = Path.Combine(folder, $"{name}.yaml");
        if (File.Exists(yamlPath))
            throw new InvalidOperationException($"Project already exists: {yamlPath}");

        var desc = string.IsNullOrWhiteSpace(request.Description)
            ? $"Custom {kind} target — edit seeds and mutators"
            : request.Description!.Trim();
        var host = string.IsNullOrWhiteSpace(request.Host) ? "127.0.0.1" : request.Host!.Trim();
        var port = request.Port is > 0 and < 65536 ? request.Port.Value : kind == "udp" ? 69 : 80;

        var ext = NormalizeExtension(request.Extension, kind);
        var fileFormat = (request.FileFormat ?? "file-blank").Trim().ToLowerInvariant();
        var yaml = kind switch
        {
            "file" => BuildFileYaml(name, desc, request.Executable, ext),
            "udp" => BuildUdpYaml(name, desc, host, port),
            _ => BuildTcpYaml(name, desc, host, port, request.Executable),
        };

        File.WriteAllText(yamlPath, yaml);
        try
        {
            ProjectLoader.Load(yamlPath);
        }
        catch (Exception ex)
        {
            File.Delete(yamlPath);
            throw new InvalidOperationException($"Generated YAML failed to load: {ex.Message}", ex);
        }

        var seedName = $"{name}_seed{ext}";
        var seedPath = Path.Combine(folder, "seeds", seedName);
        File.WriteAllBytes(seedPath, kind == "file"
            ? BuildFileStarterSeed(fileFormat)
            : Encoding.ASCII.GetBytes("PING\r\n"));

        // Point YAML seed entry at the actual extension
        if (kind == "file")
        {
            var text = File.ReadAllText(yamlPath);
            text = text.Replace($"seeds/{name}_seed.bin", $"seeds/{seedName}", StringComparison.Ordinal);
            File.WriteAllText(yamlPath, text);
        }

        File.WriteAllText(Path.Combine(folder, "dictionaries", $"{name}.txt"),
            "# Tokens for dictionary mutator — one per line\n# hex:DEADBEEF for raw bytes\n");

        return new CaseSaveResultDto(true,
            $"Created '{name}' — it now appears in Fuzz → Campaign → Target profile as \"{name}\". " +
            "Build a seed below, then switch to Campaign and Start.",
            yamlPath,
            yaml.Length);
    }

    private static string NormalizeExtension(string? extension, string kind)
    {
        if (kind != "file")
            return ".bin";
        var e = (extension ?? ".bin").Trim();
        if (string.IsNullOrEmpty(e))
            e = ".bin";
        if (!e.StartsWith('.'))
            e = "." + e;
        e = Regex.Replace(e, @"[^a-zA-Z0-9._\-]", "");
        return string.IsNullOrEmpty(e) ? ".bin" : e.ToLowerInvariant();
    }

    private static byte[] BuildFileStarterSeed(string fileFormat) =>
        fileFormat switch
        {
            "file-xml" or "xml" => Encoding.UTF8.GetBytes(
                "<?xml version=\"1.0\"?>\n<root>\n  <item id=\"1\">seed</item>\n</root>\n"),
            "file-framed" or "framed" =>
            [
                // magic DE AD BE EF + u16le length + "payload"
                0xDE, 0xAD, 0xBE, 0xEF, 0x07, 0x00,
                (byte)'p', (byte)'a', (byte)'y', (byte)'l', (byte)'o', (byte)'a', (byte)'d',
            ],
            "file-magic" or "magic" => Encoding.ASCII.GetBytes("CUST\x00\x00\x00\x08CUSTOM!!"),
            _ => Encoding.UTF8.GetBytes("RANDFUZZ_CUSTOM_SEED\n"),
        };

    public static CaseSaveResultDto UpdateProject(CaseUpdateProjectRequest request, string? repoRoot = null)
    {
        var profile = GetProfile(request.Project, repoRoot)
                      ?? throw new ArgumentException($"Unknown project: {request.Project}");

        var yaml = File.ReadAllText(profile.ConfigPath);
        var changed = new List<string>();

        if (request.Description is not null)
        {
            yaml = ReplaceYamlKey(yaml, "description", request.Description.Trim(), quote: true);
            changed.Add("description");
        }

        if (request.Host is not null)
        {
            yaml = ReplaceYamlKey(yaml, "host", request.Host.Trim(), quote: true);
            changed.Add("host");
        }

        if (request.Port is { } port)
        {
            if (port is <= 0 or >= 65536)
                throw new ArgumentException("port must be 1–65535");
            yaml = ReplaceYamlKey(yaml, "port", port.ToString(), quote: false);
            changed.Add("port");
        }

        if (request.Executable is not null)
        {
            yaml = ReplaceYamlKey(yaml, "executable", request.Executable.Trim(), quote: true);
            changed.Add("executable");
            if (request.LongLived is null)
            {
                var infer = !string.IsNullOrWhiteSpace(request.Executable);
                yaml = ReplaceYamlKey(yaml, "longLived", infer ? "true" : "false", quote: false);
                changed.Add("longLived");
            }
        }

        if (request.LongLived is { } ll)
        {
            yaml = ReplaceYamlKey(yaml, "longLived", ll ? "true" : "false", quote: false);
            if (!changed.Contains("longLived"))
                changed.Add("longLived");
        }

        if (changed.Count == 0)
            return new CaseSaveResultDto(false, "No fields to update", profile.ConfigPath, 0);

        File.WriteAllText(profile.ConfigPath, yaml);
        ProjectLoader.Load(profile.ConfigPath);
        return new CaseSaveResultDto(true,
            $"Updated {string.Join(", ", changed)} on '{request.Project}'",
            profile.ConfigPath,
            changed.Count);
    }

    private static string BuildTcpYaml(string name, string desc, string host, int port, string? exe) =>
        $$"""
        # Target profile label = name: below (Fuzz / Campaign dropdown)
        # Docs: docs/CUSTOM_TARGETS.md
        name: {{name}}
        description: {{YamlQuote(desc)}}
        kind: tcp
        target:
          executable: {{YamlQuote(exe ?? "")}}
          longLived: {{(string.IsNullOrWhiteSpace(exe) ? "false" : "true")}}
          timeoutMs: 5000
        transport:
          type: tcp
          host: {{YamlQuote(host)}}
          port: {{port}}
          receiveTimeoutMs: 2000
        fuzz:
          maxIterations: 500
          powerSchedule: true
          havocDepth: 8
          corpusDir: ../data/corpus/{{name}}
          crashesDir: ../data/crashes/{{name}}
          debuggerMode: none
        mutators:
          - bitflip
          - havoc
          - interesting
          - dictionary
          - expand
          - truncate
        seeds:
          - seeds/{{name}}_seed.bin
        dictionaryFile: dictionaries/{{name}}.txt
        dictionary:
          - "%s%s%s%s"
          - "../"
        
        """;

    private static string BuildUdpYaml(string name, string desc, string host, int port) =>
        $$"""
        # Target profile label = name: below
        name: {{name}}
        description: {{YamlQuote(desc)}}
        kind: udp
        target:
          executable: ""
          longLived: false
          timeoutMs: 3000
        transport:
          type: udp
          host: {{YamlQuote(host)}}
          port: {{port}}
          receiveTimeoutMs: 1500
        fuzz:
          maxIterations: 500
          corpusDir: ../data/corpus/{{name}}
          crashesDir: ../data/crashes/{{name}}
        mutators:
          - bitflip
          - havoc
          - dictionary
          - expand
        seeds:
          - seeds/{{name}}_seed.bin
        dictionaryFile: dictionaries/{{name}}.txt
        
        """;

    private static string BuildFileYaml(string name, string desc, string? exe, string ext) =>
        $$"""
        # Target profile label = name: below — shows in Fuzz → Campaign → Target profile
        name: {{name}}
        description: {{YamlQuote(desc)}}
        kind: file
        target:
          executable: {{YamlQuote(exe ?? "../targets/local/app.exe")}}
          args:
            - "{file}"
          timeoutMs: 8000
        transport:
          type: file
          extension: {{ext}}
        fuzz:
          maxIterations: 500
          coverageGuided: false
          corpusDir: ../data/corpus/{{name}}
          crashesDir: ../data/crashes/{{name}}
        mutators:
          - bitflip
          - havoc
          - interesting
          - dictionary
          - splice
          - duplicate
        seeds:
          - seeds/{{name}}_seed.bin
        dictionaryFile: dictionaries/{{name}}.txt
        
        """;

    private static string YamlQuote(string s)
    {
        if (string.IsNullOrEmpty(s))
            return "\"\"";
        return "\"" + s
            .Replace("\\", "\\\\", StringComparison.Ordinal)
            .Replace("\"", "\\\"", StringComparison.Ordinal)
            .Replace("\r", "\\r", StringComparison.Ordinal)
            .Replace("\n", "\\n", StringComparison.Ordinal) + "\"";
    }

    /// <summary>Replace the first YAML key line (preserves indent). Quotes string values.</summary>
    private static string ReplaceYamlKey(string yaml, string key, string value, bool quote)
    {
        var rendered = quote ? YamlQuote(value) : value;
        var pattern = new Regex($@"^([ \t]*){Regex.Escape(key)}:\s*.*$", RegexOptions.Multiline);
        if (!pattern.IsMatch(yaml))
            throw new InvalidOperationException($"YAML key '{key}:' not found — edit the file manually");
        return pattern.Replace(yaml, m => $"{m.Groups[1].Value}{key}: {rendered}", 1);
    }

    private static string SanitizeName(string name)
    {
        var s = name.Trim().ToLowerInvariant();
        s = Regex.Replace(s, @"[^a-z0-9_\-]+", "-");
        return s.Trim('-');
    }

    private static string FormatToken(byte[] t)
    {
        var ascii = Encoding.UTF8.GetString(t);
        return ascii.All(c => c is >= ' ' and <= '~') ? ascii : $"hex:{Convert.ToHexString(t)}";
    }

    private static string AsciiPreview(ReadOnlySpan<byte> bytes)
    {
        var chars = new char[bytes.Length];
        for (var i = 0; i < bytes.Length; i++)
            chars[i] = bytes[i] is >= 32 and <= 126 ? (char)bytes[i] : '.';
        return new string(chars);
    }

    private static void TryEnsureSeedInYaml(string yamlPath, string seedRel)
    {
        try
        {
            var project = ProjectLoader.Load(yamlPath);
            if (project.Seeds.Any(s =>
                    s.Equals(seedRel, StringComparison.OrdinalIgnoreCase) ||
                    Path.GetFileName(s.Replace('\\', '/'))
                        .Equals(Path.GetFileName(seedRel), StringComparison.OrdinalIgnoreCase)))
                return;

            var text = File.ReadAllText(yamlPath);
            var blockPattern = new Regex(
                @"^seeds:[ \t]*\r?\n(?:[ \t]+-[^\r\n]*\r?\n?)*",
                RegexOptions.Multiline);
            if (blockPattern.IsMatch(text))
            {
                var seeds = project.Seeds.Append(seedRel).Distinct(StringComparer.OrdinalIgnoreCase);
                var block = "seeds:\n" + string.Join("\n", seeds.Select(s => $"  - {s}")) + "\n";
                File.WriteAllText(yamlPath, blockPattern.Replace(text, block, 1));
            }
            else
            {
                File.AppendAllText(yamlPath, $"\nseeds:\n  - {seedRel}\n");
            }
        }
        catch { /* best effort */ }
    }

    private static void TryEnsureDictFileInYaml(string yamlPath, string dictRel)
    {
        try
        {
            var text = File.ReadAllText(yamlPath);
            if (Regex.IsMatch(text, @"^dictionaryFile:\s*", RegexOptions.Multiline))
            {
                File.WriteAllText(yamlPath, ReplaceYamlKey(text, "dictionaryFile", dictRel, quote: false));
                return;
            }
            File.AppendAllText(yamlPath, $"\ndictionaryFile: {dictRel}\n");
        }
        catch { /* best effort */ }
    }

    private static void TryEnsureMutatorInYaml(string yamlPath, string mutator)
    {
        try
        {
            var project = ProjectLoader.Load(yamlPath);
            if (project.Mutators.Any(m => m.Equals(mutator, StringComparison.OrdinalIgnoreCase)))
                return;
            var list = project.Mutators.Append(mutator).ToList();
            SetMutators(new CaseMutatorsRequest(
                project.Name,
                list));
        }
        catch { /* best effort */ }
    }
}
