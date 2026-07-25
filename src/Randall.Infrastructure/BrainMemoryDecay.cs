using System.Security.Cryptography;
using System.Text.Json;
using Randall.Contracts;

namespace Randall.Infrastructure;

public static class BrainMemoryDecay
{
    public const string FileName = "brain_memory.json";
    public const string MutatorChainsFileName = "mutator_chains.json";
    public const double DefaultRetentionRatio = 0.61;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    public static string StatePath(string project, string? repoRoot = null) =>
        Path.Combine(StalkCampaignStore.ProjectDir(project, repoRoot), FileName);

    public static BrainMemoryStateDto? TryLoad(string project, string? repoRoot = null)
    {
        var path = StatePath(project, repoRoot);
        if (!File.Exists(path))
            return null;
        try
        {
            return JsonSerializer.Deserialize<BrainMemoryStateDto>(File.ReadAllText(path), JsonOptions);
        }
        catch
        {
            return null;
        }
    }

    public static BrainMemoryCheckResult Ensure(ProjectConfig project, string yamlPath, string? repoRoot = null)
    {
        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        var binaryPath = ResolveTargetBinary(yamlPath, repoRoot);
        var currentHash = binaryPath is not null && File.Exists(binaryPath) ? ComputeBinaryHash(binaryPath) : null;
        var prior = TryLoad(project.Name, repoRoot);
        var confidence = prior?.MemoryConfidence ?? 1.0;
        var decayMessage = prior?.DecayMessage;
        var decayCount = prior?.DecayCount ?? 0;

        if (currentHash is null)
        {
            SaveState(project.Name, prior?.TargetBinaryHash, prior?.TargetBinaryPath, confidence, decayMessage, decayCount, repoRoot);
            RefreshTargetIntelligence(project.Name, repoRoot, prior?.TargetBinaryHash, confidence, decayMessage);
            return new BrainMemoryCheckResult(confidence, decayMessage, false, prior?.TargetBinaryHash, null);
        }

        if (prior?.TargetBinaryHash is null || string.Equals(prior.TargetBinaryHash, currentHash, StringComparison.OrdinalIgnoreCase))
        {
            SaveState(project.Name, currentHash, binaryPath, confidence, decayMessage, decayCount, repoRoot);
            RefreshTargetIntelligence(project.Name, repoRoot, currentHash, confidence, decayMessage);
            return new BrainMemoryCheckResult(confidence, decayMessage, false, currentHash, null);
        }

        if (!project.Fuzz.BrainMemoryDecay)
        {
            SaveState(project.Name, currentHash, binaryPath, 1.0, null, decayCount, repoRoot);
            RefreshTargetIntelligence(project.Name, repoRoot, currentHash, 1.0, null);
            return new BrainMemoryCheckResult(1.0, null, true, currentHash, null);
        }

        confidence = DefaultRetentionRatio;
        decayMessage = $"Target changed. Prior knowledge retained: {(int)Math.Round(DefaultRetentionRatio * 100)}%. Revalidating Scare Doors.";
        decayCount++;
        ApplyDecayArtifacts(project, yamlPath, repoRoot, DefaultRetentionRatio);
        try
        {
            TargetIntelligenceWriteBack.AppendJournal(project.Name,
                new HuntJournalEntry(DateTimeOffset.UtcNow.ToString("o"), "brain-memory", decayMessage,
                    Data: new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["priorHash"] = prior.TargetBinaryHash,
                        ["newHash"] = currentHash,
                        ["memoryConfidence"] = confidence,
                        ["decayCount"] = decayCount,
                    }), repoRoot);
        }
        catch { /* journal must not block fuzz */ }

        SaveState(project.Name, currentHash, binaryPath, confidence, decayMessage, decayCount, repoRoot);
        RefreshTargetIntelligence(project.Name, repoRoot, currentHash, confidence, decayMessage);
        return new BrainMemoryCheckResult(confidence, decayMessage, true, currentHash, decayMessage);
    }

    public static string? ResolveTargetBinary(string yamlPath, string? repoRoot)
    {
        try
        {
            var cfg = ProjectLoader.Load(yamlPath);
            if (!string.IsNullOrWhiteSpace(cfg.Target.Executable))
            {
                var declared = ProjectLoader.ResolvePath(yamlPath, cfg.Target.Executable);
                return ExecutableResolver.FindExisting(declared) ?? declared;
            }
            if (!string.IsNullOrWhiteSpace(cfg.Target.Harness))
            {
                var harness = ProjectLoader.ResolvePath(yamlPath, cfg.Target.Harness);
                return ExecutableResolver.FindExisting(harness) ?? harness;
            }
        }
        catch { /* optional fingerprint */ }
        return null;
    }

    public static string ComputeBinaryHash(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
    }

    private static void ApplyDecayArtifacts(ProjectConfig project, string yamlPath, string? repoRoot, double factor)
    {
        var corpusDir = ProjectLoader.ResolvePath(yamlPath, project.Fuzz.CorpusDir);
        MutatorCreditTracker.ApplyMemoryDecay(Path.Combine(corpusDir, "mutator_credit.txt"), factor);
        DecayMutatorChainsJson(Path.Combine(corpusDir, MutatorChainsFileName), factor);
        var frontier = FrontierEngine.TryLoad(project.Name, repoRoot);
        if (frontier?.Frontiers is { Count: > 0 } branches)
        {
            var decayed = branches.Select(b => b with
            {
                Score = Math.Max(1, (int)Math.Round(b.Score * factor)),
                ApproachCount = (int)Math.Round(b.ApproachCount * factor),
                CrossedCount = (int)Math.Round(b.CrossedCount * factor),
            }).ToList();
            FrontierEngine.Save(frontier with { Frontiers = decayed }, repoRoot);
        }
    }

    private static void DecayMutatorChainsJson(string path, double factor)
    {
        if (!File.Exists(path))
            return;
        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(path));
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
                return;
            var root = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
            foreach (var prop in doc.RootElement.EnumerateObject())
            {
                if (prop.Value.ValueKind != JsonValueKind.Array)
                {
                    root[prop.Name] = JsonSerializer.Deserialize<object>(prop.Value.GetRawText());
                    continue;
                }
                var rows = new List<Dictionary<string, object?>>();
                foreach (var item in prop.Value.EnumerateArray())
                {
                    if (item.ValueKind != JsonValueKind.Object)
                        continue;
                    var row = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
                    foreach (var field in item.EnumerateObject())
                    {
                        row[field.Name] = field.Value.ValueKind switch
                        {
                            JsonValueKind.Number when field.Value.TryGetDouble(out var n) => Math.Round(n * factor, 4),
                            JsonValueKind.Number when field.Value.TryGetInt64(out var i) => (long)Math.Round(i * factor),
                            _ => JsonSerializer.Deserialize<object>(field.Value.GetRawText()),
                        };
                    }
                    rows.Add(row);
                }
                root[prop.Name] = rows;
            }
            File.WriteAllText(path, JsonSerializer.Serialize(root, JsonOptions));
        }
        catch { /* optional artifact */ }
    }

    private static void SaveState(string project, string? hash, string? binaryPath, double confidence, string? decayMessage, int decayCount, string? repoRoot)
    {
        var path = StatePath(project, repoRoot);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, JsonSerializer.Serialize(new BrainMemoryStateDto(
            hash, binaryPath, confidence, decayMessage, DateTimeOffset.UtcNow.ToString("o"), decayCount), JsonOptions));
    }

    private static void RefreshTargetIntelligence(string project, string? repoRoot, string? targetHash, double confidence, string? decayMessage)
    {
        try
        {
            TargetIntelligenceBuilder.Build(project, repoRoot, persist: true,
                brainMemory: new BrainMemoryStateDto(targetHash, null, confidence, decayMessage,
                    DateTimeOffset.UtcNow.ToString("o"), 0));
        }
        catch { /* profile refresh is best-effort */ }
    }
}
