using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Randall ↔ Ghidra static target map: headless analyzeHeadless or Script Manager JSON import.
/// Output: <c>data/stalk/&lt;project&gt;/randall-analysis.json</c>.
/// </summary>
public static class GhidraAnalysisBridge
{
    public const string FileName = "randall-analysis.json";
    public const string ScriptName = "RandfuzzExportAnalysis.py";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
    };

    private static readonly string[] InputSourceNeedles =
    [
        "recv", "recvfrom", "read", "fread", "gets", "getenv", "argv",
        "ReadFile", "InternetReadFile", "WSARecv", "accept",
    ];

    private static readonly (string Name, int Risk)[] SinkCatalog =
    [
        ("memcpy", 90), ("memmove", 85), ("strcpy", 95), ("strncpy", 80), ("strcat", 95),
        ("sprintf", 90), ("vsprintf", 92), ("snprintf", 70), ("scanf", 85), ("sscanf", 80),
        ("gets", 100), ("malloc", 60), ("realloc", 65), ("free", 55),
        ("system", 95), ("popen", 90), ("CreateProcess", 95), ("ShellExecute", 90),
        ("LoadLibrary", 75), ("VirtualAlloc", 70), ("WriteFile", 65),
    ];

    public static string AnalysisPath(string project, string? repoRoot = null) =>
        Path.Combine(StalkCampaignStore.ProjectDir(project, repoRoot), FileName);

    public static RandallAnalysisDocument? TryLoad(string project, string? repoRoot = null)
    {
        var path = AnalysisPath(project, repoRoot);
        if (!File.Exists(path))
            return null;
        try
        {
            var json = File.ReadAllText(path);
            var doc = JsonSerializer.Deserialize<RandallAnalysisDocument>(json, JsonOptions);
            return doc is null ? null : Enrich(doc);
        }
        catch (JsonException)
        {
            return null;
        }
        catch (IOException)
        {
            return null;
        }
    }

    public static RandallAnalysisDocument LoadOrThrow(string path)
    {
        var json = File.ReadAllText(path);
        var doc = JsonSerializer.Deserialize<RandallAnalysisDocument>(json, JsonOptions)
                  ?? throw new InvalidOperationException("randall-analysis.json is empty or invalid.");
        return Enrich(doc);
    }

    public static async Task<GhidraAnalyzeResultDto> AnalyzeAsync(
        string project,
        string binaryPath,
        string? outputPath = null,
        string? repoRoot = null,
        bool skipHeadless = false,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(project))
            throw new ArgumentException("project required");
        if (string.IsNullOrWhiteSpace(binaryPath) || !File.Exists(binaryPath))
            throw new FileNotFoundException("Binary not found.", binaryPath);

        repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
        binaryPath = Path.GetFullPath(binaryPath);
        outputPath = string.IsNullOrWhiteSpace(outputPath)
            ? AnalysisPath(project, repoRoot)
            : Path.GetFullPath(outputPath);
        Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);

        var fromHeadless = false;
        if (!skipHeadless)
        {
            var discovery = GhidraTools.Discover(repoRoot);
            if (discovery.IsGhidraAvailable)
            {
                await RunHeadlessAsync(discovery, binaryPath, outputPath, repoRoot, ct);
                fromHeadless = true;
            }
            else
            {
                throw new InvalidOperationException(
                    "Ghidra not found. Install with scripts/install-ghidra.ps1 or set GHIDRA_INSTALL_DIR, " +
                    $"or export manually: Ghidra → Script Manager → {ScriptName} → save to {outputPath}");
            }
        }

        if (!File.Exists(outputPath))
            throw new InvalidOperationException($"Analysis file not produced: {outputPath}");

        var doc = LoadOrThrow(outputPath);
        doc = doc with
        {
            Binary = binaryPath,
            BinarySha256 = doc.BinarySha256 ?? ComputeSha256(binaryPath),
        };
        await File.WriteAllTextAsync(outputPath, JsonSerializer.Serialize(doc, JsonOptions), ct);

        var top = doc.Functions
            .OrderByDescending(f => f.FuzzPriority)
            .ThenByDescending(f => f.Complexity)
            .Take(12)
            .ToList();

        return new GhidraAnalyzeResultDto(
            project,
            binaryPath,
            outputPath,
            fromHeadless,
            doc.Functions.Count,
            doc.Sinks.Count,
            top,
            fromHeadless ? "Headless Ghidra export complete." : "Imported existing analysis.");
    }

    public static HeadlessCommand BuildHeadlessCommand(
        GhidraTools.Discovery discovery,
        string binaryPath,
        string outputPath,
        string repoRoot)
    {
        var ghidraHome = ResolveGhidraHome(discovery.GhidraRunPath!);
        var support = Path.Combine(ghidraHome, "support");
        var analyze = OperatingSystem.IsWindows()
            ? Path.Combine(support, "analyzeHeadless.bat")
            : Path.Combine(support, "analyzeHeadless");
        if (!File.Exists(analyze))
            throw new FileNotFoundException("analyzeHeadless not found under Ghidra install.", analyze);

        var scriptsDir = discovery.ScriptsDir ?? Path.Combine(repoRoot, "tools", "ghidra");
        var projectDir = Path.Combine(repoRoot, "data", "stalk", "_ghidra_projects");
        Directory.CreateDirectory(projectDir);
        var projectName = "randall_" + Sanitize(Path.GetFileNameWithoutExtension(binaryPath));

        var args = new List<string>
        {
            Quote(projectDir),
            Quote(projectName),
            "-import", Quote(binaryPath),
            "-postScript", ScriptName, Quote(outputPath),
            "-scriptPath", Quote(scriptsDir),
            "-deleteProject",
        };

        return new HeadlessCommand(analyze, string.Join(" ", args), ghidraHome, scriptsDir);
    }

    public sealed record HeadlessCommand(string Executable, string Arguments, string GhidraHome, string ScriptsDir);

    internal static async Task RunHeadlessAsync(
        GhidraTools.Discovery discovery,
        string binaryPath,
        string outputPath,
        string repoRoot,
        CancellationToken ct)
    {
        var cmd = BuildHeadlessCommand(discovery, binaryPath, outputPath, repoRoot);
        if (!File.Exists(Path.Combine(cmd.ScriptsDir, ScriptName)))
            throw new FileNotFoundException($"Missing Ghidra script: {ScriptName}", Path.Combine(cmd.ScriptsDir, ScriptName));

        var psi = new ProcessStartInfo
        {
            FileName = cmd.Executable,
            Arguments = cmd.Arguments,
            WorkingDirectory = cmd.GhidraHome,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };

        if (discovery.JavaHome is not null)
            psi.Environment["JAVA_HOME"] = discovery.JavaHome;

        using var proc = Process.Start(psi)
                         ?? throw new InvalidOperationException("Failed to start analyzeHeadless.");
        var stdout = await proc.StandardOutput.ReadToEndAsync(ct);
        var stderr = await proc.StandardError.ReadToEndAsync(ct);
        await proc.WaitForExitAsync(ct);

        if (proc.ExitCode != 0 || !File.Exists(outputPath))
        {
            var detail = string.IsNullOrWhiteSpace(stderr) ? stdout : stderr;
            throw new InvalidOperationException(
                $"analyzeHeadless failed (exit {proc.ExitCode}). {Trim(detail, 1200)}");
        }
    }

    public static RandallAnalysisDocument Enrich(RandallAnalysisDocument doc)
    {
        var functions = doc.Functions.Select(f =>
        {
            var priority = f.FuzzPriority > 0
                ? f.FuzzPriority
                : ComputeFuzzPriority(f.Complexity, f.BasicBlockCount, f.DangerousCalls, f.InputReachable,
                    f.CallerCount);
            return f with { FuzzPriority = priority };
        }).ToList();

        var sinks = doc.Sinks.Count > 0
            ? doc.Sinks
            : BuildSinksFromFunctions(functions, doc.Imports);

        return doc with { Functions = functions, Sinks = sinks };
    }

    public static int ComputeFuzzPriority(
        int complexity,
        int basicBlockCount,
        IReadOnlyList<string> dangerousCalls,
        bool inputReachable,
        int callerCount)
    {
        var score = 0;
        score += Math.Min(28, complexity / 2);
        score += Math.Min(22, basicBlockCount / 3);
        score += Math.Min(30, dangerousCalls.Count * 10);
        if (inputReachable)
            score += 12;
        score += Math.Min(10, callerCount);
        return Math.Clamp(score, 0, 100);
    }

    public static bool IsInputSource(string symbol) =>
        InputSourceNeedles.Any(n => symbol.Contains(n, StringComparison.OrdinalIgnoreCase));

    public static bool IsDangerousSink(string symbol) =>
        SinkCatalog.Any(s => symbol.Contains(s.Name, StringComparison.OrdinalIgnoreCase));

    public static int SinkRisk(string symbol)
    {
        foreach (var (name, risk) in SinkCatalog)
        {
            if (symbol.Contains(name, StringComparison.OrdinalIgnoreCase))
                return risk;
        }
        return 50;
    }

    private static IReadOnlyList<RandallAnalysisSinkDto> BuildSinksFromFunctions(
        IReadOnlyList<RandallAnalysisFunctionDto> functions,
        IReadOnlyList<RandallAnalysisImportDto> imports)
    {
        var sinks = new Dictionary<string, RandallAnalysisSinkDto>(StringComparer.OrdinalIgnoreCase);
        foreach (var imp in imports)
        {
            if (!IsDangerousSink(imp.Name) && !IsInputSource(imp.Name))
                continue;
            var kind = IsInputSource(imp.Name) ? "input" : "sink";
            sinks[imp.Name] = new RandallAnalysisSinkDto(
                imp.Name, imp.Address, kind, SinkRisk(imp.Name), []);
        }

        foreach (var fn in functions)
        {
            foreach (var call in fn.DangerousCalls)
            {
                if (!sinks.TryGetValue(call, out var existing))
                {
                    sinks[call] = new RandallAnalysisSinkDto(
                        call, "", "sink", SinkRisk(call), []);
                    existing = sinks[call];
                }

                var callers = existing.Callers.ToList();
                if (!callers.Contains(fn.Name, StringComparer.OrdinalIgnoreCase))
                    callers.Add(fn.Name);
                sinks[call] = existing with { Callers = callers };
            }
        }

        return sinks.Values.OrderByDescending(s => s.Risk).ThenBy(s => s.Name).ToList();
    }

    private static string ResolveGhidraHome(string ghidraRunPath)
    {
        var dir = Path.GetDirectoryName(ghidraRunPath)!;
        if (File.Exists(Path.Combine(dir, "support", OperatingSystem.IsWindows() ? "analyzeHeadless.bat" : "analyzeHeadless")))
            return dir;

        var parent = Directory.GetParent(dir)?.FullName;
        if (parent is not null &&
            File.Exists(Path.Combine(parent, "support", OperatingSystem.IsWindows() ? "analyzeHeadless.bat" : "analyzeHeadless")))
            return parent;

        return dir;
    }

    private static string ComputeSha256(string path)
    {
        using var sha = SHA256.Create();
        using var fs = File.OpenRead(path);
        return Convert.ToHexString(sha.ComputeHash(fs)).ToLowerInvariant();
    }

    private static string Sanitize(string name)
    {
        foreach (var c in Path.GetInvalidFileNameChars())
            name = name.Replace(c, '_');
        return name;
    }

    private static string Quote(string path) =>
        OperatingSystem.IsWindows() ? $"\"{path}\"" : path;

    private static string Trim(string s, int max) =>
        s.Length <= max ? s : s[..max] + "…";
}
