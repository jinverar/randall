using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Optional AI seed/dictionary recipe — proposes starting inputs for a project.
/// Does not run in the fuzz hot path; write files, then <c>randall fuzz</c> as usual.
/// </summary>
public static partial class AiSeedRecipe
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNameCaseInsensitive = true,
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public sealed record SeedItem(string Name, string Encoding, string Data, string? Note);
    public sealed record RecipeResult(
        IReadOnlyList<SeedItem> Seeds,
        IReadOnlyList<string> Dictionary,
        string? Model,
        string? Notes);

    public sealed record ApplyResult(
        IReadOnlyList<string> SeedPaths,
        string? DictionaryPath,
        string RecipeJsonPath,
        int SeedCount,
        int DictionaryCount);

    public static string BuildPrompt(
        ProjectConfig project,
        string yamlPath,
        int count,
        string? userHint)
    {
        var sb = new StringBuilder();
        sb.AppendLine("You are helping an authorized fuzzing lab author starting seeds and dictionary tokens.");
        sb.AppendLine("Output ONLY valid JSON matching this schema (no markdown fences):");
        sb.AppendLine("""
            {
              "seeds": [
                {"name": "ai_seed_01.bin", "encoding": "hex|utf8|base64", "data": "...", "note": "why"}
              ],
              "dictionary": ["TOKEN", "hex:DEADBEEF"],
              "notes": "short rationale"
            }
            """);
        sb.AppendLine($"Propose about {count} diverse seeds (valid-ish + edge-case), not exploits or shellcode.");
        sb.AppendLine("Prefer protocol-shaped bytes when the target is network/file-parser shaped.");
        sb.AppendLine();
        sb.AppendLine($"Project name: {project.Name}");
        sb.AppendLine($"Kind: {project.Kind}");
        sb.AppendLine($"Description: {project.Description}");
        if (project.SessionCommands.Count > 0)
        {
            sb.AppendLine("Session commands:");
            foreach (var c in project.SessionCommands)
                sb.AppendLine($"  - {c.Name} model={c.Model}");
        }

        if (!string.IsNullOrWhiteSpace(project.Model))
            sb.AppendLine($"Model: {project.Model}");

        sb.AppendLine("Existing seeds (hex preview, truncated):");
        var shown = 0;
        foreach (var seedRel in project.Seeds.Take(5))
        {
            try
            {
                var bytes = ProjectLoader.LoadSeed(yamlPath, seedRel);
                var take = Math.Min(bytes.Length, 64);
                var hex = Convert.ToHexString(bytes.AsSpan(0, take));
                sb.AppendLine($"  - {seedRel} ({bytes.Length} bytes): {hex}{(bytes.Length > take ? "…" : "")}");
                shown++;
            }
            catch (Exception ex)
            {
                sb.AppendLine($"  - {seedRel}: (unreadable: {ex.Message})");
            }
        }

        if (shown == 0)
            sb.AppendLine("  (none)");

        if (!string.IsNullOrWhiteSpace(userHint))
        {
            sb.AppendLine();
            sb.AppendLine("Extra hint from the operator:");
            sb.AppendLine(userHint.Trim());
        }

        return sb.ToString();
    }

    public static RecipeResult ParseRecipeJson(string json)
    {
        json = StripMarkdownFence(json).Trim();
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        var seeds = new List<SeedItem>();
        if (root.TryGetProperty("seeds", out var seedsEl) && seedsEl.ValueKind == JsonValueKind.Array)
        {
            var i = 0;
            foreach (var s in seedsEl.EnumerateArray())
            {
                i++;
                var name = s.TryGetProperty("name", out var n) && n.ValueKind == JsonValueKind.String
                    ? n.GetString()!
                    : $"ai_seed_{i:D2}.bin";
                var encoding = s.TryGetProperty("encoding", out var e) && e.ValueKind == JsonValueKind.String
                    ? e.GetString()!
                    : "utf8";
                var data = s.TryGetProperty("data", out var d) && d.ValueKind == JsonValueKind.String
                    ? d.GetString() ?? ""
                    : "";
                var note = s.TryGetProperty("note", out var nt) && nt.ValueKind == JsonValueKind.String
                    ? nt.GetString()
                    : null;
                if (string.IsNullOrEmpty(data))
                    continue;
                seeds.Add(new SeedItem(SanitizeFileName(name), encoding, data, note));
            }
        }

        var dict = new List<string>();
        if (root.TryGetProperty("dictionary", out var dictEl) && dictEl.ValueKind == JsonValueKind.Array)
        {
            foreach (var t in dictEl.EnumerateArray())
            {
                if (t.ValueKind == JsonValueKind.String)
                {
                    var tok = t.GetString()?.Trim();
                    if (!string.IsNullOrEmpty(tok))
                        dict.Add(tok);
                }
            }
        }

        var notes = root.TryGetProperty("notes", out var notesEl) && notesEl.ValueKind == JsonValueKind.String
            ? notesEl.GetString()
            : null;

        return new RecipeResult(seeds, dict, Model: null, notes);
    }

    public static byte[] DecodeSeedData(string encoding, string data)
    {
        var enc = (encoding ?? "utf8").Trim().ToLowerInvariant();
        return enc switch
        {
            "hex" or "hexadecimal" => Convert.FromHexString(data.Replace(" ", "", StringComparison.Ordinal)
                .Replace("-", "", StringComparison.Ordinal)
                .Replace("0x", "", StringComparison.OrdinalIgnoreCase)),
            "base64" or "b64" => Convert.FromBase64String(data.Trim()),
            "utf8" or "text" or "ascii" or "string" => Encoding.UTF8.GetBytes(UnescapeText(data)),
            _ => Encoding.UTF8.GetBytes(data),
        };
    }

    public static ApplyResult Apply(
        ProjectConfig project,
        string yamlPath,
        RecipeResult recipe,
        string? seedsOutDir = null,
        string? dictionaryOutPath = null,
        bool updateProjectYaml = false)
    {
        var projectRoot = ProjectLoader.ResolveProjectRoot(yamlPath);
        var seedDir = seedsOutDir is null
            ? Path.Combine(projectRoot, "seeds")
            : Path.IsPathRooted(seedsOutDir)
                ? seedsOutDir
                : ProjectLoader.ResolvePath(yamlPath, seedsOutDir);
        Directory.CreateDirectory(seedDir);

        var writtenSeeds = new List<string>();
        var i = 0;
        foreach (var item in recipe.Seeds)
        {
            i++;
            byte[] bytes;
            try { bytes = DecodeSeedData(item.Encoding, item.Data); }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Warning: skip seed {item.Name}: {ex.Message}");
                continue;
            }

            if (bytes.Length == 0)
                continue;

            var fileName = string.IsNullOrWhiteSpace(item.Name)
                ? $"ai_{project.Name}_{i:D2}.bin"
                : item.Name;
            if (!Path.HasExtension(fileName))
                fileName += ".bin";
            fileName = SanitizeFileName(fileName);
            // Prefix so AI seeds are obvious in the folder.
            if (!fileName.StartsWith("ai_", StringComparison.OrdinalIgnoreCase))
                fileName = "ai_" + fileName;

            var path = Path.Combine(seedDir, fileName);
            path = UniquePath(path);
            File.WriteAllBytes(path, bytes);
            writtenSeeds.Add(path);
        }

        string? dictPath = null;
        if (recipe.Dictionary.Count > 0)
        {
            dictPath = dictionaryOutPath is null
                ? Path.Combine(projectRoot, "dictionaries", $"ai_{SanitizeFileName(project.Name)}.txt")
                : Path.IsPathRooted(dictionaryOutPath)
                    ? dictionaryOutPath
                    : ProjectLoader.ResolvePath(yamlPath, dictionaryOutPath);
            Directory.CreateDirectory(Path.GetDirectoryName(dictPath)!);
            var existing = File.Exists(dictPath)
                ? File.ReadAllLines(dictPath).Where(l => !string.IsNullOrWhiteSpace(l) && !l.TrimStart().StartsWith('#')).ToHashSet(StringComparer.Ordinal)
                : new HashSet<string>(StringComparer.Ordinal);
            foreach (var tok in recipe.Dictionary)
                existing.Add(tok);
            var body = new StringBuilder();
            body.AppendLine($"# AI seed recipe dictionary for {project.Name}");
            body.AppendLine($"# Generated {DateTimeOffset.UtcNow:u}");
            foreach (var tok in existing.OrderBy(x => x, StringComparer.Ordinal))
                body.AppendLine(tok);
            File.WriteAllText(dictPath, body.ToString());
        }

        var recipeDir = Path.Combine(
            ProjectLoader.ResolvePath(yamlPath, project.Fuzz.CorpusDir),
            "_ai_recipes");
        Directory.CreateDirectory(recipeDir);
        var recipeJsonPath = Path.Combine(recipeDir, $"{SanitizeFileName(project.Name)}_{DateTime.UtcNow:yyyyMMdd_HHmmss}.json");
        var persist = new
        {
            project = project.Name,
            generatedAt = DateTimeOffset.UtcNow,
            model = recipe.Model,
            notes = recipe.Notes,
            seeds = recipe.Seeds,
            dictionary = recipe.Dictionary,
            writtenSeeds,
            dictionaryPath = dictPath,
        };
        File.WriteAllText(recipeJsonPath, JsonSerializer.Serialize(persist, JsonOpts));

        if (updateProjectYaml && writtenSeeds.Count > 0)
            TryAppendSeedsToYaml(yamlPath, project, writtenSeeds, dictPath);

        return new ApplyResult(writtenSeeds, dictPath, recipeJsonPath, writtenSeeds.Count, recipe.Dictionary.Count);
    }

    public static async Task<RecipeResult> GenerateAsync(
        ProjectConfig project,
        string yamlPath,
        AiSeedSettings settings,
        int count,
        string? userHint,
        CancellationToken ct = default)
    {
        if (!settings.HasApiKey)
            throw new InvalidOperationException(
                $"No AI API key. Set {AiSeedSettings.EnvApiKey} or {AiSeedSettings.EnvApiKeyAlt} " +
                $"(optional — use --dry-run to preview the prompt, or --fixture <json>).");

        var prompt = BuildPrompt(project, yamlPath, count, userHint);
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(settings.TimeoutSec) };
        http.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", settings.ApiKey);
        http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

        var url = settings.BaseUrl.EndsWith("/chat/completions", StringComparison.OrdinalIgnoreCase)
            ? settings.BaseUrl
            : settings.BaseUrl.TrimEnd('/') + "/chat/completions";

        var body = new
        {
            model = settings.Model,
            temperature = 0.4,
            response_format = new { type = "json_object" },
            messages = new object[]
            {
                new { role = "system", content = "You output only JSON seed recipes for authorized fuzzing labs." },
                new { role = "user", content = prompt },
            },
        };

        using var resp = await http.PostAsJsonAsync(url, body, ct);
        var raw = await resp.Content.ReadAsStringAsync(ct);
        if (!resp.IsSuccessStatusCode)
            throw new InvalidOperationException(
                $"AI API {((int)resp.StatusCode)} from {url}: {Truncate(raw, 500)}");

        using var doc = JsonDocument.Parse(raw);
        var content = doc.RootElement
            .GetProperty("choices")[0]
            .GetProperty("message")
            .GetProperty("content")
            .GetString() ?? "{}";

        var recipe = ParseRecipeJson(content);
        return recipe with { Model = settings.Model };
    }

    public static RecipeResult LoadFixture(string path)
    {
        var json = File.ReadAllText(path);
        return ParseRecipeJson(json);
    }

    private static void TryAppendSeedsToYaml(
        string yamlPath,
        ProjectConfig project,
        IReadOnlyList<string> writtenSeeds,
        string? dictPath)
    {
        try
        {
            var yaml = File.ReadAllText(yamlPath);
            var projectRoot = ProjectLoader.ResolveProjectRoot(yamlPath);
            var relSeeds = writtenSeeds
                .Select(p => Path.GetRelativePath(projectRoot, p).Replace('\\', '/'))
                .ToList();

            if (!yaml.Contains("seeds:", StringComparison.Ordinal))
            {
                yaml = yaml.TrimEnd() + Environment.NewLine + "seeds:" + Environment.NewLine;
                foreach (var r in relSeeds)
                    yaml += $"  - {r}{Environment.NewLine}";
            }
            else
            {
                foreach (var r in relSeeds)
                {
                    if (yaml.Contains(r, StringComparison.OrdinalIgnoreCase))
                        continue;
                    // Insert after seeds: block first line — append before mutators/dictionary if present.
                    var insert = $"  - {r}{Environment.NewLine}";
                    var idx = yaml.IndexOf("seeds:", StringComparison.Ordinal);
                    var lineEnd = yaml.IndexOf('\n', idx);
                    if (lineEnd < 0) lineEnd = yaml.Length;
                    yaml = yaml.Insert(lineEnd + 1, insert);
                }
            }

            if (dictPath is not null)
            {
                var relDict = Path.GetRelativePath(projectRoot, dictPath).Replace('\\', '/');
                if (!yaml.Contains("dictionaryFile:", StringComparison.OrdinalIgnoreCase))
                    yaml = yaml.TrimEnd() + Environment.NewLine + $"dictionaryFile: {relDict}" + Environment.NewLine;
            }

            // Ensure dictionary mutator is listed when we added tokens.
            if (dictPath is not null &&
                yaml.Contains("mutators:", StringComparison.Ordinal) &&
                !yaml.Contains("dictionary", StringComparison.OrdinalIgnoreCase))
            {
                var m = yaml.IndexOf("mutators:", StringComparison.Ordinal);
                var lineEnd = yaml.IndexOf('\n', m);
                if (lineEnd >= 0)
                    yaml = yaml.Insert(lineEnd + 1, "  - dictionary" + Environment.NewLine);
            }

            File.WriteAllText(yamlPath, yaml);
            _ = project; // project name already in paths
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Warning: could not update project YAML: {ex.Message}");
        }
    }

    private static string SanitizeFileName(string name)
    {
        var n = Path.GetFileName(name.Trim());
        foreach (var c in Path.GetInvalidFileNameChars())
            n = n.Replace(c, '_');
        n = n.Replace("..", "_", StringComparison.Ordinal);
        return string.IsNullOrWhiteSpace(n) ? "ai_seed.bin" : n;
    }

    private static string UniquePath(string path)
    {
        if (!File.Exists(path))
            return path;
        var dir = Path.GetDirectoryName(path)!;
        var stem = Path.GetFileNameWithoutExtension(path);
        var ext = Path.GetExtension(path);
        for (var i = 2; i < 1000; i++)
        {
            var candidate = Path.Combine(dir, $"{stem}_{i}{ext}");
            if (!File.Exists(candidate))
                return candidate;
        }
        return Path.Combine(dir, $"{stem}_{Guid.NewGuid():N}{ext}");
    }

    private static string StripMarkdownFence(string s)
    {
        var m = FenceRegex().Match(s);
        return m.Success ? m.Groups[1].Value : s;
    }

    private static string UnescapeText(string data) =>
        data.Replace("\\r", "\r", StringComparison.Ordinal)
            .Replace("\\n", "\n", StringComparison.Ordinal)
            .Replace("\\t", "\t", StringComparison.Ordinal)
            .Replace("\\0", "\0", StringComparison.Ordinal);

    private static string Truncate(string s, int max) =>
        s.Length <= max ? s : s[..max] + "…";

    [GeneratedRegex(@"```(?:json)?\s*([\s\S]*?)```", RegexOptions.IgnoreCase)]
    private static partial Regex FenceRegex();
}
