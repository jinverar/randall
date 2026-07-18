using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using Randall.Contracts;
using Randall.Infrastructure.Mutators;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

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
        return CaseRecipeEngine.SuggestFromBytes(bytes, safe);
    }

    /// <summary>Write an uploaded sample exactly (byte-for-byte) as a project seed.</summary>
    public static CaseSaveResultDto SaveRawSeed(CaseSaveRawSeedRequest request, string? repoRoot = null)
    {
        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var profile = GetProfile(request.Project, repoRoot)
                      ?? throw new ArgumentException($"Unknown project: {request.Project}");

        var b64 = request.Base64.Trim();
        var comma = b64.IndexOf("base64,", StringComparison.OrdinalIgnoreCase);
        if (comma >= 0)
            b64 = b64[(comma + "base64,".Length)..];
        var bytes = Convert.FromBase64String(b64);
        if (bytes.Length == 0)
            return new CaseSaveResultDto(false, "Empty sample", null, 0);
        if (bytes.Length > 16_000_000)
            return new CaseSaveResultDto(false, "Sample too large (max 16 MB)", null, 0);

        var fileName = string.IsNullOrWhiteSpace(request.FileName)
            ? $"sample_{DateTime.UtcNow:yyyyMMdd_HHmmss}.bin"
            : Path.GetFileName(request.FileName);
        if (!Path.HasExtension(fileName))
            fileName += ".bin";

        var projectDir = Path.GetDirectoryName(profile.ConfigPath)!;
        var seedsDir = Path.Combine(projectDir, "seeds");
        Directory.CreateDirectory(seedsDir);
        var path = Path.Combine(seedsDir, fileName);
        File.WriteAllBytes(path, bytes);
        TryEnsureSeedInYaml(profile.ConfigPath, $"seeds/{fileName}");

        return new CaseSaveResultDto(true,
            $"Saved exact sample ({bytes.Length} bytes) as seeds/{fileName} for '{request.Project}'",
            path,
            bytes.Length);
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
            "file-wav" or "wav" =>
            [
                // Minimal PCM WAV (44 bytes): RIFF/WAVE + fmt + 4 bytes silence
                0x52, 0x49, 0x46, 0x46, 0x24, 0x00, 0x00, 0x00,
                0x57, 0x41, 0x56, 0x45, 0x66, 0x6D, 0x74, 0x20,
                0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
                0x44, 0xAC, 0x00, 0x00, 0x88, 0x58, 0x01, 0x00,
                0x02, 0x00, 0x10, 0x00, 0x64, 0x61, 0x74, 0x61,
                0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ],
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

    private static readonly JsonSerializerOptions RecipeJson = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        PropertyNameCaseInsensitive = true,
    };

    private static string RecipesDir(string configPath) =>
        Path.Combine(Path.GetDirectoryName(configPath)!, "recipes");

    public static IReadOnlyList<CaseRecipeInfoDto> ListRecipes(string projectName, string? repoRoot = null)
    {
        var profile = GetProfile(projectName, repoRoot)
                      ?? throw new ArgumentException($"Unknown project: {projectName}");
        var dir = RecipesDir(profile.ConfigPath);
        if (!Directory.Exists(dir))
            return [];

        return Directory.EnumerateFiles(dir, "*.json")
            .Select(path =>
            {
                try
                {
                    var dto = JsonSerializer.Deserialize<CaseRecipeDto>(File.ReadAllText(path), RecipeJson);
                    if (dto is null) return null;
                    var name = string.IsNullOrWhiteSpace(dto.Name)
                        ? Path.GetFileNameWithoutExtension(path)
                        : dto.Name;
                    var sessionCount = dto.SessionSteps?.Count ?? 0;
                    var blockCount = sessionCount > 0
                        ? dto.SessionSteps!.Sum(s => s.Blocks?.Count ?? 0)
                        : dto.Steps?.Count ?? 0;
                    var kind = !string.IsNullOrWhiteSpace(dto.Kind)
                        ? dto.Kind
                        : sessionCount > 0 ? "session" : "blob";
                    return new CaseRecipeInfoDto(
                        name,
                        dto.Description,
                        blockCount,
                        dto.UpdatedAt == default
                            ? File.GetLastWriteTimeUtc(path)
                            : dto.UpdatedAt,
                        $"recipes/{Path.GetFileName(path)}",
                        sessionCount,
                        kind);
                }
                catch
                {
                    return null;
                }
            })
            .Where(x => x is not null)
            .Cast<CaseRecipeInfoDto>()
            .OrderByDescending(r => r.UpdatedAt)
            .ThenBy(r => r.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    public static CaseRecipeDto LoadRecipe(string projectName, string recipeName, string? repoRoot = null)
    {
        var profile = GetProfile(projectName, repoRoot)
                      ?? throw new ArgumentException($"Unknown project: {projectName}");
        var safe = SanitizeName(Path.GetFileNameWithoutExtension(recipeName));
        var path = Path.Combine(RecipesDir(profile.ConfigPath), safe + ".json");
        if (!File.Exists(path))
            throw new FileNotFoundException($"Recipe not found: {safe}");

        var dto = JsonSerializer.Deserialize<CaseRecipeDto>(File.ReadAllText(path), RecipeJson)
                  ?? throw new InvalidOperationException("Invalid recipe JSON");
        var sessionSteps = NormalizeSessionSteps(dto.SessionSteps);
        var steps = dto.Steps ?? [];
        if (steps.Count == 0 && sessionSteps.Count > 0)
            steps = sessionSteps[0].Blocks;
        var kind = !string.IsNullOrWhiteSpace(dto.Kind)
            ? dto.Kind
            : sessionSteps.Count > 0 ? "session" : "blob";
        return dto with
        {
            Name = string.IsNullOrWhiteSpace(dto.Name) ? safe : dto.Name,
            Steps = steps,
            SessionSteps = sessionSteps.Count > 0 ? sessionSteps : null,
            MutateStep = string.IsNullOrWhiteSpace(dto.MutateStep) ? "last" : dto.MutateStep,
            Kind = kind,
        };
    }

    public static CaseSaveResultDto SaveRecipe(CaseSaveRecipeRequest request, string? repoRoot = null)
    {
        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var profile = GetProfile(request.Project, repoRoot)
                      ?? throw new ArgumentException($"Unknown project: {request.Project}");

        var sessionSteps = NormalizeSessionSteps(request.SessionSteps);
        var steps = request.Steps ?? [];
        if (sessionSteps.Count > 0 && steps.Count == 0)
            steps = sessionSteps.SelectMany(s => s.Blocks).ToList();
        if (steps.Count == 0 && sessionSteps.Count == 0)
            return new CaseSaveResultDto(false, "Recipe has no blocks", null, 0);

        var name = SanitizeName(request.Name);
        if (string.IsNullOrWhiteSpace(name))
            return new CaseSaveResultDto(false, "Recipe name required", null, 0);

        var kind = !string.IsNullOrWhiteSpace(request.Kind)
            ? request.Kind!.Trim().ToLowerInvariant()
            : sessionSteps.Count > 0 ? "session" : "blob";
        var mutate = string.IsNullOrWhiteSpace(request.MutateStep) ? "last" : request.MutateStep!.Trim();

        var dir = RecipesDir(profile.ConfigPath);
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, name + ".json");
        var dto = new CaseRecipeDto(
            name,
            request.Description,
            steps,
            DateTimeOffset.UtcNow,
            request.SuggestedSeedName,
            sessionSteps.Count > 0 ? sessionSteps : null,
            sessionSteps.Count > 0 ? mutate : null,
            kind);
        File.WriteAllText(path, JsonSerializer.Serialize(dto, RecipeJson));

        var summary = sessionSteps.Count > 0
            ? $"{sessionSteps.Count} PDU(s), {steps.Count} blocks"
            : $"{steps.Count} blocks";
        return new CaseSaveResultDto(true,
            $"Saved Scare Floor recipe '{name}' ({summary}) → recipes/{name}.json",
            path,
            steps.Count);
    }

    public static CaseSessionPreviewDto PreviewSession(IReadOnlyList<CaseSessionStepDto> sessionSteps)
    {
        var normalized = NormalizeSessionSteps(sessionSteps);
        if (normalized.Count == 0)
            throw new ArgumentException("No session steps");

        var previews = new List<CaseSessionStepPreviewDto>();
        var allHints = new List<string>();
        var notes = new List<string>();
        var total = 0;
        foreach (var step in normalized)
        {
            var preview = CaseRecipeEngine.Preview(step.Blocks);
            total += preview.Length;
            allHints.AddRange(preview.DictionaryHints);
            previews.Add(new CaseSessionStepPreviewDto(
                step.Name,
                preview.Length,
                preview.HexPreview,
                preview.AsciiPreview,
                preview.HexFull,
                preview.DictionaryHints));
            if (step.ReadBanner)
                notes.Add($"{step.Name}: readBanner");
            if (!string.IsNullOrWhiteSpace(step.ExpectResponse))
                notes.Add($"{step.Name}: expect {step.ExpectResponse}");
        }

        return new CaseSessionPreviewDto(
            previews.Count,
            total,
            previews,
            allHints.Distinct(StringComparer.Ordinal).ToList(),
            notes);
    }

    public static CaseSaveResultDto ApplySessionRecipe(CaseApplySessionRequest request, string? repoRoot = null)
    {
        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var profile = GetProfile(request.Project, repoRoot)
                      ?? throw new ArgumentException($"Unknown project: {request.Project}");
        if (!profile.Kind.Equals("tcp", StringComparison.OrdinalIgnoreCase))
            return new CaseSaveResultDto(false,
                "Apply session recipe requires a TCP Target profile (UDP multi-PDU comes later).",
                null, 0);

        var steps = NormalizeSessionSteps(request.SessionSteps);
        if (steps.Count == 0)
            return new CaseSaveResultDto(false, "No session steps to apply", null, 0);

        var flowName = SanitizeName(string.IsNullOrWhiteSpace(request.FlowName)
            ? "scare-flow"
            : request.FlowName);
        if (string.IsNullOrWhiteSpace(flowName))
            flowName = "scare-flow";

        var mutate = string.IsNullOrWhiteSpace(request.MutateStep) ? "last" : request.MutateStep.Trim();
        var projectDir = Path.GetDirectoryName(profile.ConfigPath)!;
        var seedsDir = Path.Combine(projectDir, "seeds");
        Directory.CreateDirectory(seedsDir);

        var cmdLines = new List<string> { "sessionCommands:" };
        var flowStepNames = new List<string>();
        var totalBytes = 0;
        var allHints = new List<string>();

        foreach (var step in steps)
        {
            var (bytes, hints, _) = CaseRecipeEngine.Render(step.Blocks);
            if (bytes.Length == 0)
                return new CaseSaveResultDto(false, $"Step '{step.Name}' rendered 0 bytes", null, 0);

            var seedFile = $"{flowName}_{SanitizeName(step.Name)}.bin";
            var seedPath = Path.Combine(seedsDir, seedFile);
            File.WriteAllBytes(seedPath, bytes);
            totalBytes += bytes.Length;
            allHints.AddRange(hints);
            flowStepNames.Add(step.Name);

            cmdLines.Add($"  - name: {step.Name}");
            if (request.PreferModels)
            {
                var modelName = SanitizeName($"{flowName}_{step.Name}");
                var promoted = PromoteToProtocol(new CasePromoteRequest(
                    request.Project, modelName, step.Blocks,
                    $"Scare Floor PDU {step.Name}", step.Name), repoRoot);
                if (promoted.Ok && promoted.RelativePath is not null)
                    cmdLines.Add($"    model: {promoted.RelativePath.Replace('\\', '/')}");
                else
                    cmdLines.Add($"    seed: seeds/{seedFile}");
            }
            else
            {
                cmdLines.Add($"    seed: seeds/{seedFile}");
            }
            cmdLines.Add($"    readBanner: {(step.ReadBanner ? "true" : "false")}");
            if (!string.IsNullOrWhiteSpace(step.ExpectResponse))
                cmdLines.Add($"    expectResponse: {YamlQuote(step.ExpectResponse)}");
        }

        var flowLines = new List<string>
        {
            "sessionFlows:",
            $"  - name: {flowName}",
            $"    steps: [{string.Join(", ", flowStepNames)}]",
            $"    mutateStep: {mutate}",
        };

        var yaml = File.ReadAllText(profile.ConfigPath);
        yaml = UpsertYamlTopBlock(yaml, "sessionCommands", string.Join("\n", cmdLines) + "\n");
        yaml = UpsertYamlTopBlock(yaml, "sessionFlows", string.Join("\n", flowLines) + "\n");
        File.WriteAllText(profile.ConfigPath, yaml);

        var bias = request.SessionFlowBias;
        if (bias < 0) bias = 0;
        if (bias > 1) bias = 1;
        try
        {
            yaml = File.ReadAllText(profile.ConfigPath);
            if (Regex.IsMatch(yaml, @"^\s*sessionFlowBias:", RegexOptions.Multiline))
                yaml = ReplaceYamlKey(yaml, "sessionFlowBias",
                    bias.ToString(System.Globalization.CultureInfo.InvariantCulture), quote: false);
            else if (Regex.IsMatch(yaml, @"^fuzz:\s*$", RegexOptions.Multiline))
            {
                var fuzzRx = new Regex(@"^fuzz:\s*$", RegexOptions.Multiline);
                yaml = fuzzRx.Replace(yaml,
                    $"fuzz:\n  sessionFlowBias: {bias.ToString(System.Globalization.CultureInfo.InvariantCulture)}",
                    1);
            }
            File.WriteAllText(profile.ConfigPath, yaml);
        }
        catch { /* best effort */ }

        // Keep seeds: list usable for single-blob fallback — register last PDU
        TryEnsureSeedInYaml(profile.ConfigPath, $"seeds/{flowName}_{SanitizeName(steps[^1].Name)}.bin");

        if (allHints.Count > 0)
            SaveDict(new CaseSaveDictRequest(request.Project, allHints.Distinct().ToList(), true), repoRoot);

        ProjectLoader.Load(profile.ConfigPath);
        return new CaseSaveResultDto(true,
            $"Applied flow '{flowName}' ({steps.Count} PDUs, {totalBytes} bytes) → sessionCommands + sessionFlows. Campaign will use sessionFlowBias={bias.ToString(System.Globalization.CultureInfo.InvariantCulture)}.",
            profile.ConfigPath,
            totalBytes);
    }

    private static List<CaseSessionStepDto> NormalizeSessionSteps(IReadOnlyList<CaseSessionStepDto>? steps)
    {
        if (steps is null || steps.Count == 0)
            return [];

        var used = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var list = new List<CaseSessionStepDto>();
        var i = 0;
        foreach (var s in steps)
        {
            i++;
            var blocks = (s.Blocks ?? []).ToList();
            if (blocks.Count == 0)
                continue;
            var raw = string.IsNullOrWhiteSpace(s.Name) ? $"step{i}" : s.Name.Trim();
            var name = SanitizeCommandName(raw);
            if (string.IsNullOrWhiteSpace(name))
                name = $"step{i}";
            var baseName = name;
            var n = 2;
            while (!used.Add(name))
                name = $"{baseName}{n++}";
            list.Add(new CaseSessionStepDto(name, blocks, s.ReadBanner, s.ExpectResponse));
        }
        return list;
    }

    private static string SanitizeCommandName(string name)
    {
        var s = name.Trim();
        s = Regex.Replace(s, @"[^A-Za-z0-9_\-]+", "_");
        return s.Trim('_');
    }

    /// <summary>Replace or insert a top-level YAML list block (sessionCommands / sessionFlows).</summary>
    private static string UpsertYamlTopBlock(string yaml, string key, string block)
    {
        var pattern = new Regex(
            $@"^{Regex.Escape(key)}:[ \t]*\r?\n(?:[ \t]+[^\r\n]*\r?\n?)*",
            RegexOptions.Multiline);
        var normalized = block.TrimEnd() + "\n";
        if (pattern.IsMatch(yaml))
            return pattern.Replace(yaml, normalized, 1);

        var fuzz = new Regex(@"^fuzz:\s*\r?\n", RegexOptions.Multiline);
        if (fuzz.IsMatch(yaml))
            return fuzz.Replace(yaml, normalized + "fuzz:\n", 1);

        return yaml.TrimEnd() + "\n\n" + normalized;
    }

    /// <summary>
    /// Split a pasted TCP stream / capture into session PDUs.
    /// Separators: blank line(s), or a line that is only --- / === / ###.
    /// </summary>
    public static CaseFromStreamDto FromStream(CaseFromStreamRequest request, string? repoRoot = null)
    {
        var notes = new List<string>();
        var chunks = SplitStreamChunks(request.Text ?? "");
        if (chunks.Count == 0)
            throw new ArgumentException("No message chunks found — paste text/hex separated by blank lines or ---");

        notes.Add($"Split into {chunks.Count} chunk(s)" + (request.AsHex ? " (hex mode)" : " (auto text/hex)"));
        var steps = new List<CaseSessionStepDto>();
        for (var i = 0; i < chunks.Count; i++)
        {
            var chunk = chunks[i];
            var asHex = request.AsHex || LooksLikeHexChunk(chunk);
            List<CaseStepDto> blocks;
            if (asHex)
            {
                var hex = Regex.Replace(chunk, @"[^0-9a-fA-F]", "");
                if (hex.Length < 2)
                {
                    notes.Add($"Chunk {i + 1}: skipped (no hex digits)");
                    continue;
                }
                if (hex.Length % 2 != 0)
                    hex = hex[..^1];
                var spaced = string.Join(' ', Enumerable.Range(0, hex.Length / 2)
                    .Select(j => hex.Substring(j * 2, 2)));
                blocks = [new CaseStepDto("hex", spaced, Role: "fuzzable")];
            }
            else
            {
                // Preserve line endings as CRLF blocks when present
                blocks = TextChunkToBlocks(chunk);
            }

            steps.Add(new CaseSessionStepDto(
                $"m{i + 1}",
                blocks,
                ReadBanner: i == 0));
        }

        if (steps.Count == 0)
            throw new ArgumentException("No usable chunks after parsing");

        CaseSaveResultDto? applied = null;
        if (request.Apply)
        {
            if (string.IsNullOrWhiteSpace(request.Project))
                throw new ArgumentException("--apply / Apply requires a project");
            applied = ApplySessionRecipe(new CaseApplySessionRequest(
                request.Project!,
                string.IsNullOrWhiteSpace(request.FlowName) ? "from-stream" : request.FlowName!,
                steps,
                string.IsNullOrWhiteSpace(request.MutateStep) ? "last" : request.MutateStep,
                0.5), repoRoot);
            notes.Add(applied.Message);
        }

        return new CaseFromStreamDto(steps.Count, steps, notes, applied);
    }

    private static List<string> SplitStreamChunks(string text)
    {
        var normalized = text.Replace("\r\n", "\n").Replace('\r', '\n').Trim();
        if (string.IsNullOrEmpty(normalized))
            return [];

        var parts = Regex.Split(normalized, @"\n[ \t]*(?:---+|===+|###+)[ \t]*\n|\n[ \t]*\n+");
        return parts
            .Select(p => p.Trim())
            .Where(p => p.Length > 0)
            .ToList();
    }

    private static bool LooksLikeHexChunk(string chunk)
    {
        var compact = Regex.Replace(chunk, @"\s+", "");
        if (compact.Length < 4)
            return false;
        var hex = compact.Count(c => Uri.IsHexDigit(c));
        return hex >= compact.Length * 0.85;
    }

    private static List<CaseStepDto> TextChunkToBlocks(string chunk)
    {
        var blocks = new List<CaseStepDto>();
        var lines = chunk.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n');
        foreach (var line in lines)
        {
            if (line.Length > 0)
                blocks.Add(new CaseStepDto("text", line, Role: "fuzzable"));
            // Network line protocols: always terminate with CRLF
            blocks.Add(new CaseStepDto("crlf", Role: "static"));
        }

        if (blocks.Count == 0)
            blocks.Add(new CaseStepDto("text", chunk, Role: "fuzzable"));
        return blocks;
    }

    private static readonly ISerializer ProtocolYamlSerializer = new SerializerBuilder()
        .WithNamingConvention(CamelCaseNamingConvention.Instance)
        .ConfigureDefaultValuesHandling(DefaultValuesHandling.OmitDefaults)
        .Build();

    public static CasePromoteResultDto PromoteToProtocol(CasePromoteRequest request, string? repoRoot = null)
    {
        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var profile = GetProfile(request.Project, repoRoot)
                      ?? throw new ArgumentException($"Unknown project: {request.Project}");
        var steps = request.Steps ?? [];
        if (steps.Count == 0)
            return new CasePromoteResultDto(false, "No blocks to promote", null, null);

        var name = SanitizeName(request.Name);
        if (string.IsNullOrWhiteSpace(name))
            return new CasePromoteResultDto(false, "Protocol name required", null, null);

        var def = CaseRecipeEngine.StepsToProtocol(name, request.Description, steps, out var seedFiles);
        var projectDir = Path.GetDirectoryName(profile.ConfigPath)!;
        var protoDir = Path.Combine(projectDir, "protocols");
        Directory.CreateDirectory(protoDir);
        Directory.CreateDirectory(Path.Combine(projectDir, "seeds"));

        foreach (var (rel, bytes) in seedFiles)
        {
            var seedPath = Path.Combine(projectDir, rel.Replace('/', Path.DirectorySeparatorChar));
            Directory.CreateDirectory(Path.GetDirectoryName(seedPath)!);
            File.WriteAllBytes(seedPath, bytes);
        }

        var yamlPath = Path.Combine(protoDir, name + ".yaml");
        var yaml = ProtocolYamlSerializer.Serialize(def);
        File.WriteAllText(yamlPath, yaml);

        // Validate load
        try
        {
            ProtocolLoader.Load(profile.ConfigPath, $"protocols/{name}.yaml");
        }
        catch (Exception ex)
        {
            return new CasePromoteResultDto(false,
                $"Wrote protocols/{name}.yaml but load failed: {ex.Message}",
                $"protocols/{name}.yaml", yamlPath);
        }

        var label = string.IsNullOrWhiteSpace(request.SessionStepName)
            ? name
            : $"{request.SessionStepName} → {name}";
        return new CasePromoteResultDto(true,
            $"Promoted {label} → protocols/{name}.yaml ({def.Blocks.Count} model blocks)",
            $"protocols/{name}.yaml",
            yamlPath);
    }

    public static SessionGraphReportDto SaveSessionGraph(SessionGraphSaveRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.ConfigPath))
            throw new ArgumentException("configPath required");
        var yamlPath = Path.GetFullPath(request.ConfigPath);
        if (!File.Exists(yamlPath))
            throw new FileNotFoundException("Project YAML not found", yamlPath);

        var start = (request.Start ?? "").Trim();
        if (string.IsNullOrWhiteSpace(start))
            throw new ArgumentException("start command required");

        var lines = new List<string>
        {
            "sessionGraph:",
            $"  start: {start}",
        };
        if (!string.IsNullOrWhiteSpace(request.Mutate))
            lines.Add($"  mutate: {request.Mutate.Trim()}");
        var edges = (request.Edges ?? [])
            .Where(e => !string.IsNullOrWhiteSpace(e.From) && !string.IsNullOrWhiteSpace(e.To))
            .ToList();
        if (edges.Count == 0)
        {
            lines.Add("  edges: []");
        }
        else
        {
            lines.Add("  edges:");
            foreach (var e in edges)
            {
                var when = (e.When ?? "").Replace("\"", "");
                lines.Add($"    - {{ from: {e.From.Trim()}, when: \"{when}\", to: {e.To.Trim()} }}");
            }
        }

        var yaml = File.ReadAllText(yamlPath);
        yaml = UpsertYamlTopBlock(yaml, "sessionGraph", string.Join("\n", lines) + "\n");
        File.WriteAllText(yamlPath, yaml);
        var project = ProjectLoader.Load(yamlPath);
        return SessionGraphValidator.Validate(project, yamlPath);
    }

    private static string PacksRoot(string? repoRoot = null)
    {
        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        return Path.Combine(repoRoot, "projects", "protocols", "packs");
    }

    public static IReadOnlyList<CasePackInfoDto> ListPacks(string? repoRoot = null)
    {
        var root = PacksRoot(repoRoot);
        if (!Directory.Exists(root))
            return [];

        var list = new List<CasePackInfoDto>();
        foreach (var dir in Directory.EnumerateDirectories(root))
        {
            var id = Path.GetFileName(dir);
            var packYaml = Path.Combine(dir, "pack.yaml");
            if (!File.Exists(packYaml))
                continue;
            try
            {
                var info = ReadPackInfo(id, dir, packYaml);
                list.Add(info);
            }
            catch { /* skip broken packs */ }
        }

        return list.OrderBy(p => p.Name, StringComparer.OrdinalIgnoreCase).ToList();
    }

    public static CaseRecipeDto LoadPack(string packId, string? repoRoot = null)
    {
        var root = PacksRoot(repoRoot);
        var safe = SanitizeName(packId);
        var dir = Path.Combine(root, safe);
        var recipePath = Path.Combine(dir, "recipe.json");
        if (!File.Exists(recipePath))
            throw new FileNotFoundException($"Pack recipe not found: {safe}");

        var dto = JsonSerializer.Deserialize<CaseRecipeDto>(File.ReadAllText(recipePath), RecipeJson)
                  ?? throw new InvalidOperationException("Invalid pack recipe.json");
        var session = NormalizeSessionSteps(dto.SessionSteps);
        return dto with
        {
            Name = string.IsNullOrWhiteSpace(dto.Name) ? safe : dto.Name,
            Steps = dto.Steps?.Count > 0 ? dto.Steps : session.FirstOrDefault()?.Blocks ?? [],
            SessionSteps = session.Count > 0 ? session : null,
            Kind = session.Count > 0 ? "session" : (dto.Kind ?? "blob"),
            MutateStep = string.IsNullOrWhiteSpace(dto.MutateStep) ? "last" : dto.MutateStep,
        };
    }

    private static CasePackInfoDto ReadPackInfo(string id, string dir, string packYamlPath)
    {
        var text = File.ReadAllText(packYamlPath);
        string Pick(string key, string fallback)
        {
            var m = Regex.Match(text, $@"^{key}:\s*(.+)$", RegexOptions.Multiline);
            return m.Success ? m.Groups[1].Value.Trim().Trim('"') : fallback;
        }

        var name = Pick("name", id);
        var desc = Pick("description", "");
        var kind = Pick("kind", "session");
        var protocols = new List<string>();
        var inProto = false;
        foreach (var line in text.Split('\n'))
        {
            if (Regex.IsMatch(line, @"^protocols:\s*$"))
            {
                inProto = true;
                continue;
            }
            if (inProto)
            {
                var m = Regex.Match(line, @"^\s+-\s+(.+)$");
                if (m.Success)
                    protocols.Add(m.Groups[1].Value.Trim());
                else if (line.Length > 0 && !char.IsWhiteSpace(line[0]))
                    inProto = false;
            }
        }

        var recipePath = Path.Combine(dir, "recipe.json");
        var sessionCount = 0;
        if (File.Exists(recipePath))
        {
            try
            {
                var recipe = JsonSerializer.Deserialize<CaseRecipeDto>(File.ReadAllText(recipePath), RecipeJson);
                sessionCount = recipe?.SessionSteps?.Count ?? 0;
            }
            catch { /* ignore */ }
        }

        return new CasePackInfoDto(id, name, string.IsNullOrWhiteSpace(desc) ? null : desc, kind, sessionCount, protocols);
    }

    public static CaseSaveResultDto DeleteRecipe(string projectName, string recipeName, string? repoRoot = null)
    {
        var profile = GetProfile(projectName, repoRoot)
                      ?? throw new ArgumentException($"Unknown project: {projectName}");
        var safe = SanitizeName(Path.GetFileNameWithoutExtension(recipeName));
        var path = Path.Combine(RecipesDir(profile.ConfigPath), safe + ".json");
        if (!File.Exists(path))
            return new CaseSaveResultDto(false, $"Recipe not found: {safe}", null, 0);
        File.Delete(path);
        return new CaseSaveResultDto(true, $"Deleted recipe '{safe}'", path, 0);
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
