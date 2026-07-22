using System.Diagnostics;
using System.Globalization;
using System.Text;
using Randall.Contracts;
using Randall.Core;
using Randall.Infrastructure.Mutators;

namespace Randall.Infrastructure;

/// <summary>
/// Campaign driver for optional external coverage engines (AFL++ / honggfuzz).
/// Stages seeds, launches the engine, and syncs crashes + queue corpora back into Randfuzz.
/// Linux + file/harness targets only — see docs/ENGINE_ADAPTERS.md.
/// </summary>
public static class ExternalEngineCampaign
{
    public const string EngineRandall = "randall";
    public const string EngineAflpp = "aflpp";
    public const string EngineHonggfuzz = "honggfuzz";

    public static string Normalize(string? engine)
    {
        var e = (engine ?? EngineRandall).Trim().ToLowerInvariant();
        return e switch
        {
            "" or "default" or "own" or "randfuzz" or "randall" => EngineRandall,
            "afl" or "afl+" or "afl++" or "aflplusplus" or "aflpp" => EngineAflpp,
            "hongg" or "hfuzz" or "honggfuzz" => EngineHonggfuzz,
            _ => e,
        };
    }

    public static bool IsExternal(string? engine) =>
        Normalize(engine) is EngineAflpp or EngineHonggfuzz;

    public static async Task<FuzzRunResult> RunAsync(
        ProjectConfig project,
        string yamlPath,
        FuzzRunOptions options,
        CancellationToken cancellationToken = default)
    {
        var engineId = Normalize(project.Fuzz.Engine);
        var progress = options.Progress;
        progress?.OnStarted(project.Name, project.Kind);

        if (!OperatingSystem.IsLinux())
            throw new InvalidOperationException(
                $"{engineId} campaigns require Linux (afl-fuzz / honggfuzz). Use fuzz.engine: randall on Windows.");

        if (!project.Kind.Equals("file", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException(
                $"{engineId} campaigns require kind: file (harness reads @@ / {{file}}). " +
                "For network surfaces, write a file harness around the parse entry — see docs/ENGINE_ADAPTERS.md.");

        if (string.IsNullOrWhiteSpace(project.Target.Executable))
            throw new InvalidOperationException($"{engineId}: target.executable is required.");

        var exeDeclared = ProjectLoader.ResolvePath(yamlPath, project.Target.Executable);
        var exe = ExecutableResolver.FindExisting(exeDeclared)
            ?? throw new FileNotFoundException($"{engineId}: target not found: {exeDeclared}");

        var tool = engineId == EngineAflpp
            ? LinuxToolPaths.OptionalEngines.First(t => t.Id == "linux:afl")
            : LinuxToolPaths.OptionalEngines.First(t => t.Id == "linux:honggfuzz");
        var enginePath = LinuxToolPaths.Find(tool)
            ?? throw new InvalidOperationException(
                $"{tool.Command} not found — {tool.InstallHint} (or set {tool.EnvVar}).");

        var corpusDir = ProjectLoader.ResolvePath(yamlPath, project.Fuzz.CorpusDir);
        var crashesDir = ProjectLoader.ResolvePath(yamlPath, project.Fuzz.CrashesDir);
        var workRoot = Path.Combine(corpusDir, $"_{engineId}_work");
        var inDir = Path.Combine(workRoot, "in");
        var outDir = Path.Combine(workRoot, "out");
        Directory.CreateDirectory(inDir);
        Directory.CreateDirectory(outDir);
        Directory.CreateDirectory(corpusDir);
        Directory.CreateDirectory(crashesDir);

        var staged = StageSeeds(project, yamlPath, inDir);
        FuzzAnalystLog.Info(progress,
            $"{engineId}: staged {staged} seed(s) → {inDir}");

        var args = project.Target.Args.Count > 0
            ? project.Target.Args.ToList()
            : ["@@"];
        EnsureFilePlaceholder(args, engineId);

        var timeoutSec = project.Fuzz.EngineTimeoutSec;
        if (timeoutSec <= 0 && options.MaxIterations is > 0 and < int.MaxValue)
            timeoutSec = Math.Clamp(options.MaxIterations.Value / 20, 15, 3600);
        if (timeoutSec <= 0 && project.Fuzz.MaxIterations is > 0 and < int.MaxValue)
            timeoutSec = Math.Clamp(project.Fuzz.MaxIterations / 20, 15, 3600);

        var cmdline = BuildCommandLine(engineId, enginePath, inDir, outDir, exe, args,
            project.Fuzz.EngineExtraArgs, timeoutSec, options.DryRun);

        FuzzAnalystLog.Info(progress, $"{engineId}: {cmdline.Display}");
        if (options.DryRun)
        {
            FuzzAnalystLog.Info(progress, $"{engineId}: dry-run — not launching engine");
            progress?.OnCompleted(new FuzzRunResult(0, 0, 0, []));
            return new FuzzRunResult(0, 0, 0, []);
        }

        var crashStore = new CrashStore(crashesDir);
        crashStore.Ensure();
        var corpus = new CorpusTracker(corpusDir);
        corpus.Load();

        var workDir = string.IsNullOrWhiteSpace(project.Target.WorkingDirectory)
            ? Path.GetDirectoryName(exe) ?? ProjectLoader.ResolveProjectRoot(yamlPath)
            : ProjectLoader.ResolvePath(yamlPath, project.Target.WorkingDirectory);

        var psi = new ProcessStartInfo
        {
            FileName = cmdline.FileName,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            WorkingDirectory = workDir,
            CreateNoWindow = true,
        };
        foreach (var a in cmdline.Args)
            psi.ArgumentList.Add(a);

        // Quiet + non-interactive defaults for CI / UI campaigns.
        psi.Environment["AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES"] = "1";
        psi.Environment["AFL_SKIP_CPUFREQ"] = "1";
        psi.Environment["AFL_NO_AFFINITY"] = "1";
        psi.Environment["AFL_NO_UI"] = "1";
        if (!psi.Environment.ContainsKey("AFL_IMPORT_FIRST"))
            psi.Environment["AFL_IMPORT_FIRST"] = "1";

        using var proc = Process.Start(psi)
            ?? throw new InvalidOperationException($"Failed to start {engineId}: {cmdline.FileName}");

        progress?.OnTargetPid(proc.Id);
        FuzzAnalystLog.Info(progress, $"{engineId}: pid={proc.Id} timeout={(timeoutSec > 0 ? timeoutSec + "s" : "until stop")}");

        var engineLogPath = Path.Combine(workRoot, $"{engineId}.log");
        var engineLog = new StreamWriter(new FileStream(engineLogPath, FileMode.Create, FileAccess.Write, FileShare.Read))
        {
            AutoFlush = true,
        };
        FuzzAnalystLog.Info(progress, $"{engineId}: log → {engineLogPath}");

        var stdoutTask = DrainAsync(proc.StandardOutput, line =>
        {
            engineLog.WriteLine(line);
            if (IsEngineHighlight(line))
                FuzzAnalystLog.Info(progress, StripAnsi(line).TrimEnd());
        }, cancellationToken);
        var stderrTask = DrainAsync(proc.StandardError, line =>
        {
            engineLog.WriteLine(line);
            if (IsEngineHighlight(line))
                FuzzAnalystLog.Info(progress, StripAnsi(line).TrimEnd());
        }, cancellationToken);

        var importedCrashHashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var existing in crashStore.List(project.Name))
            importedCrashHashes.Add(existing.InputHash);

        var crashesFound = 0;
        var corpusAdded = 0;
        var syncTicks = 0;

        try
        {
            while (!proc.HasExited)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var (c, q) = SyncArtifacts(
                    project.Name, engineId, outDir, crashStore, corpus, importedCrashHashes, syncTicks);
                crashesFound += c;
                corpusAdded += q;
                syncTicks++;
                progress?.OnIteration(new FuzzIterationEvent(
                    syncTicks, engineId, 0, c > 0, q > 0, q, corpus.SeenCount, 0,
                    $"{engineId} sync crashes={crashesFound} corpus+={corpusAdded}"));
                await Task.Delay(1000, cancellationToken);
            }
        }
        catch (OperationCanceledException)
        {
            try
            {
                if (!proc.HasExited)
                    proc.Kill(entireProcessTree: true);
            }
            catch { /* ignore */ }
        }

        try { await Task.WhenAll(stdoutTask, stderrTask); }
        catch { /* ignore drain errors after kill */ }
        try { await engineLog.DisposeAsync(); } catch { /* ignore */ }

        // Final harvest after exit.
        {
            var (c, q) = SyncArtifacts(
                project.Name, engineId, outDir, crashStore, corpus, importedCrashHashes, syncTicks + 1);
            crashesFound += c;
            corpusAdded += q;
        }

        var exit = proc.HasExited ? proc.ExitCode : -1;
        FuzzAnalystLog.Info(progress,
            $"{engineId}: finished exit={exit} crashes+={crashesFound} corpus+={corpusAdded}");

        var result = new FuzzRunResult(Math.Max(syncTicks, 1), corpusAdded, crashesFound, []);
        progress?.OnCompleted(result);
        return result;
    }

    private static int StageSeeds(ProjectConfig project, string yamlPath, string inDir)
    {
        foreach (var old in Directory.EnumerateFiles(inDir))
        {
            try { File.Delete(old); } catch { /* ignore */ }
        }

        var n = 0;
        foreach (var seedRel in project.Seeds)
        {
            try
            {
                var bytes = ProjectLoader.LoadSeed(yamlPath, seedRel);
                if (bytes.Length == 0)
                    bytes = "seed"u8.ToArray();
                var name = $"seed_{n:D4}_{Path.GetFileName(seedRel)}";
                File.WriteAllBytes(Path.Combine(inDir, name), bytes);
                n++;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Warning: skip seed {seedRel}: {ex.Message}");
            }
        }

        if (n == 0)
        {
            File.WriteAllBytes(Path.Combine(inDir, "seed_0000.bin"), "seed"u8.ToArray());
            n = 1;
        }

        return n;
    }

    private static void EnsureFilePlaceholder(List<string> args, string engineId)
    {
        var has = args.Any(a =>
            a.Contains("@@", StringComparison.Ordinal) ||
            a.Contains("{file}", StringComparison.OrdinalIgnoreCase) ||
            a.Contains("___FILE___", StringComparison.Ordinal));
        if (has)
        {
            for (var i = 0; i < args.Count; i++)
            {
                args[i] = args[i]
                    .Replace("{file}", "@@", StringComparison.OrdinalIgnoreCase)
                    .Replace("___FILE___", "@@", StringComparison.Ordinal);
                if (engineId == EngineHonggfuzz)
                    args[i] = args[i].Replace("@@", "___FILE___", StringComparison.Ordinal);
            }
            return;
        }

        args.Add(engineId == EngineHonggfuzz ? "___FILE___" : "@@");
    }

    private static (string FileName, List<string> Args, string Display) BuildCommandLine(
        string engineId,
        string enginePath,
        string inDir,
        string outDir,
        string exe,
        List<string> targetArgs,
        string extraArgs,
        int timeoutSec,
        bool dryRun)
    {
        var args = new List<string>();
        if (engineId == EngineAflpp)
        {
            args.Add("-i");
            args.Add(inDir);
            args.Add("-o");
            args.Add(outDir);
            if (timeoutSec > 0)
            {
                args.Add("-V");
                args.Add(timeoutSec.ToString(CultureInfo.InvariantCulture));
            }

            foreach (var extra in SplitExtra(extraArgs))
                args.Add(extra);

            args.Add("--");
            args.Add(exe);
            args.AddRange(targetArgs);
        }
        else
        {
            // honggfuzz
            args.Add("-i");
            args.Add(inDir);
            args.Add("-o");
            args.Add(Path.Combine(outDir, "crashes"));
            Directory.CreateDirectory(Path.Combine(outDir, "crashes"));
            if (timeoutSec > 0)
            {
                args.Add("-r");
                args.Add(timeoutSec.ToString(CultureInfo.InvariantCulture));
            }

            foreach (var extra in SplitExtra(extraArgs))
                args.Add(extra);

            args.Add("--");
            args.Add(exe);
            args.AddRange(targetArgs);
        }

        var display = new StringBuilder();
        display.Append(enginePath);
        foreach (var a in args)
        {
            display.Append(' ');
            display.Append(a.Contains(' ', StringComparison.Ordinal) ? $"\"{a}\"" : a);
        }

        if (dryRun)
            display.Append("  # dry-run");

        return (enginePath, args, display.ToString());
    }

    private static IEnumerable<string> SplitExtra(string extra)
    {
        if (string.IsNullOrWhiteSpace(extra))
            yield break;
        foreach (var part in extra.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            yield return part;
    }

    private static (int Crashes, int Corpus) SyncArtifacts(
        string projectName,
        string engineId,
        string outDir,
        CrashStore crashStore,
        CorpusTracker corpus,
        HashSet<string> importedCrashHashes,
        int syncTick)
    {
        var crashes = 0;
        var corpusAdded = 0;

        foreach (var crashFile in EnumerateCrashFiles(outDir))
        {
            byte[] bytes;
            try { bytes = File.ReadAllBytes(crashFile); }
            catch { continue; }
            if (bytes.Length == 0)
                continue;

            var hash = InputHash.StackHash(bytes);
            if (!importedCrashHashes.Add(hash))
                continue;

            crashStore.Save(
                projectName,
                syncTick,
                engineId,
                bytes,
                exitCode: null,
                miniDumpPath: null,
                triageTag: $"{engineId}-crash");
            crashes++;
        }

        foreach (var queueFile in EnumerateQueueFiles(outDir))
        {
            byte[] bytes;
            try { bytes = File.ReadAllBytes(queueFile); }
            catch { continue; }
            if (bytes.Length == 0)
                continue;

            if (!corpus.IsNew(bytes))
                continue;
            var safeName = Path.GetFileName(queueFile).Replace(':', '_');
            corpus.SaveInteresting(bytes, $"{engineId}_{safeName}");
            corpusAdded++;
        }

        return (crashes, corpusAdded);
    }

    private static IEnumerable<string> EnumerateCrashFiles(string outDir)
    {
        // AFL++: out/default/crashes/id:*  (and non-default fuzzer dirs)
        // honggfuzz: out/crashes/*
        var dirs = new List<string>();
        if (Directory.Exists(outDir))
        {
            dirs.Add(Path.Combine(outDir, "crashes"));
            foreach (var sub in Directory.EnumerateDirectories(outDir))
                dirs.Add(Path.Combine(sub, "crashes"));
        }

        foreach (var dir in dirs.Where(Directory.Exists))
        {
            foreach (var file in Directory.EnumerateFiles(dir))
            {
                var name = Path.GetFileName(file);
                if (name.Equals("README.txt", StringComparison.OrdinalIgnoreCase))
                    continue;
                if (name.StartsWith(".", StringComparison.Ordinal))
                    continue;
                yield return file;
            }
        }
    }

    private static IEnumerable<string> EnumerateQueueFiles(string outDir)
    {
        if (!Directory.Exists(outDir))
            yield break;

        foreach (var sub in Directory.EnumerateDirectories(outDir))
        {
            var queue = Path.Combine(sub, "queue");
            if (!Directory.Exists(queue))
                continue;
            foreach (var file in Directory.EnumerateFiles(queue))
            {
                var name = Path.GetFileName(file);
                if (name.StartsWith(".", StringComparison.Ordinal))
                    continue;
                yield return file;
            }
        }
    }

    private static async Task DrainAsync(
        StreamReader reader,
        Action<string> onLine,
        CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                var line = await reader.ReadLineAsync(ct);
                if (line is null)
                    break;
                onLine(line);
            }
        }
        catch (OperationCanceledException) { /* stop */ }
        catch (ObjectDisposedException) { /* process gone */ }
    }

    private static bool IsEngineHighlight(string line)
    {
        if (string.IsNullOrWhiteSpace(line))
            return false;
        var s = StripAnsi(line);
        return s.Contains("crash", StringComparison.OrdinalIgnoreCase)
               || s.Contains("We're done", StringComparison.OrdinalIgnoreCase)
               || s.Contains("Statistics:", StringComparison.OrdinalIgnoreCase)
               || s.Contains("Time limit", StringComparison.OrdinalIgnoreCase)
               || s.Contains("[!] ", StringComparison.Ordinal)
               || s.Contains("ERROR", StringComparison.OrdinalIgnoreCase)
               || s.Contains("FATAL", StringComparison.OrdinalIgnoreCase);
    }

    private static string StripAnsi(string s)
    {
        if (s.IndexOf('\u001b') < 0)
            return s;
        var sb = new StringBuilder(s.Length);
        for (var i = 0; i < s.Length; i++)
        {
            if (s[i] == '\u001b' && i + 1 < s.Length && s[i + 1] == '[')
            {
                i += 2;
                while (i < s.Length && s[i] is not ('m' or 'H' or 'J' or 'K'))
                    i++;
                continue;
            }
            sb.Append(s[i]);
        }
        return sb.ToString();
    }
}
