using System.Diagnostics;
using System.Text;
using Randall.Contracts;
using Randall.Core;
using Randall.Infrastructure.Mutators;

namespace Randall.Infrastructure;

public sealed class FuzzEngine
{
    public Task<FuzzRunResult> RunAsync(
        ProjectConfig project,
        string yamlPath,
        bool dryRun = false,
        CancellationToken cancellationToken = default) =>
        RunAsync(project, yamlPath, new FuzzRunOptions(DryRun: dryRun), cancellationToken);

    public async Task<FuzzRunResult> RunAsync(
        ProjectConfig project,
        string yamlPath,
        FuzzRunOptions options,
        CancellationToken cancellationToken = default)
    {
        var dryRun = options.DryRun;
        var coverageGuided = options.CoverageGuided || project.Fuzz.CoverageGuided;
        var maxIterations = options.MaxIterations ?? project.Fuzz.MaxIterations;

        var mutators = LoadMutators(project, yamlPath);
        var seeds = LoadAllSeeds(project, yamlPath);
        if (seeds.Count == 0)
            seeds.Add(Array.Empty<byte>());

        var corpusDir = ProjectLoader.ResolvePath(yamlPath, project.Fuzz.CorpusDir);
        var traceDir = Path.Combine(corpusDir, "traces");
        Directory.CreateDirectory(corpusDir);
        Directory.CreateDirectory(traceDir);

        var corpus = new CorpusTracker(corpusDir);
        corpus.Load();

        var coveragePath = Path.Combine(corpusDir, "edges.txt");
        var coverage = new CoverageSet(coveragePath);
        coverage.Load();

        var crashStore = new CrashStore(ProjectLoader.ResolvePath(yamlPath, project.Fuzz.CrashesDir));
        crashStore.Ensure();

        var dynamo = DynamoRioRunner.Discover();
        var useCoverage = coverageGuided && dynamo.IsAvailable &&
                          project.Kind.Equals("file", StringComparison.OrdinalIgnoreCase);

        options.Progress?.OnStarted(project.Name, project.Kind);

        var crashes = new List<CrashRecord>();
        Process? longLived = null;
        if (project.Kind.Equals("tcp", StringComparison.OrdinalIgnoreCase) && project.Target.LongLived)
            longLived = TargetRunner.StartTarget(project, yamlPath, null);

        var iterations = 0;
        var crashCount = 0;
        var corpusAdded = 0;
        var rng = Random.Shared;

        var sessionCommands = SessionGraph.LoadCommands(project, yamlPath);

        try
        {
            for (var i = 0; i < maxIterations && !cancellationToken.IsCancellationRequested; i++)
            {
                iterations++;
                var mutator = mutators[rng.Next(mutators.Count)];
                TargetRunner.TcpSendOptions? tcpOptions = null;
                string commandName = "default";
                byte[] payload;

                if (sessionCommands.Count > 0)
                {
                    var cmd = sessionCommands[rng.Next(sessionCommands.Count)];
                    commandName = cmd.Name;
                    tcpOptions = new TargetRunner.TcpSendOptions(cmd.Preamble, cmd.ReadBanner);
                    if (!string.IsNullOrWhiteSpace(cmd.ModelPath))
                    {
                        var model = ProtocolLoader.Load(yamlPath, cmd.ModelPath);
                        var protoSeeds = ProtocolLoader.LoadProtocolSeeds(yamlPath, cmd.ModelPath);
                        payload = ModelFuzzer.BuildPayload(model, protoSeeds, mutator, rng);
                        var mutableFields = model.GetMutableFields();
                        if (mutableFields.Count > 0)
                            commandName = $"{cmd.Name}/{mutableFields[rng.Next(mutableFields.Count)].Name}";
                    }
                    else
                    {
                        var mutated = mutator.Mutate(cmd.Seed).ToArray();
                        payload = SessionGraph.BuildPayload(cmd, mutated);
                    }
                }
                else if (!string.IsNullOrWhiteSpace(project.Model))
                {
                    var model = ProtocolLoader.Load(yamlPath, project.Model);
                    var protoSeeds = ProtocolLoader.LoadProtocolSeeds(yamlPath, project.Model);
                    payload = ModelFuzzer.BuildPayload(model, protoSeeds, mutator, rng);
                    commandName = $"model/{model.Name}";
                }
                else
                {
                    var seed = corpus.PickSeed(seeds, rng);
                    payload = mutator.Mutate(seed).ToArray();
                    if (project.Transport.Prefix.Length > 0)
                    {
                        var prefix = Encoding.ASCII.GetBytes(project.Transport.Prefix);
                        payload = prefix.Concat(payload).ToArray();
                    }
                }

                if (dryRun)
                {
                    options.Progress?.OnIteration(new FuzzIterationEvent(
                        iterations, $"{commandName}/{mutator.Name}", payload.Length, false, false, 0, corpus.SeenCount, coverage.TotalEdges, "dry-run"));
                    Console.WriteLine($"[dry-run] #{iterations} {commandName}/{mutator.Name} len={payload.Length}");
                    continue;
                }

                var result = await TargetRunner.RunPayloadAsync(
                    project, yamlPath, payload, longLived, cancellationToken, tcpOptions);

                var newEdges = 0;
                var newCoverage = false;
                if (!result.Crashed)
                {
                    if (useCoverage)
                    {
                        var covRun = await dynamo.RunWithCoverageAsync(
                            project, yamlPath, payload, traceDir, cancellationToken);
                        newEdges = coverage.RegisterTrace(covRun.TracePath);
                        newCoverage = newEdges > 0;
                        if (newCoverage)
                        {
                            corpus.AddPriority(payload);
                            corpusAdded++;
                        }
                    }
                    else if (corpus.IsNew(payload))
                    {
                        corpus.SaveInteresting(payload, "corpus");
                        corpusAdded++;
                    }
                }

                options.Progress?.OnIteration(new FuzzIterationEvent(
                    iterations,
                    $"{commandName}/{mutator.Name}",
                    payload.Length,
                    result.Crashed,
                    newCoverage,
                    newEdges,
                    corpus.SeenCount,
                    coverage.TotalEdges,
                    result.Detail));

                if (result.Crashed)
                {
                    crashCount++;
                    var saved = crashStore.Save(
                        project.Name, iterations, $"{commandName}/{mutator.Name}", payload, result.ExitCode, result.MiniDumpPath);
                    Console.WriteLine(
                        $"CRASH #{crashCount} iter={iterations} {commandName}/{mutator.Name} " +
                        $"detail={result.Detail} saved={saved.InputPath}" +
                        (saved.MiniDumpPath is not null ? $" dump={saved.MiniDumpPath}" : ""));
                    crashes.Add(new CrashRecord(
                        saved.Id,
                        payload,
                        saved.InputHash,
                        result.ExitCode?.ToString() ?? result.Detail,
                        null,
                        saved.MiniDumpPath,
                        newEdges));

                    if (project.Kind.Equals("tcp", StringComparison.OrdinalIgnoreCase) && project.Target.LongLived)
                    {
                        longLived?.Kill(entireProcessTree: true);
                        longLived?.Dispose();
                        await Task.Delay(300, cancellationToken);
                        longLived = TargetRunner.StartTarget(project, yamlPath, null);
                    }
                }
                else if (iterations % 50 == 0)
                {
                    Console.WriteLine($"iter={iterations} ok len={payload.Length} corpus={corpus.SeenCount} edges={coverage.TotalEdges}");
                }
            }
        }
        finally
        {
            if (longLived is { HasExited: false })
            {
                longLived.Kill(entireProcessTree: true);
                longLived.Dispose();
            }
        }

        var runResult = new FuzzRunResult(iterations, corpusAdded, crashCount, crashes);
        options.Progress?.OnCompleted(runResult);
        return runResult;
    }

    private static List<IMutator> LoadMutators(ProjectConfig project, string yamlPath)
    {
        var mutators = BuiltInMutators.Create(project.Mutators).ToList();
        foreach (var pluginRef in project.Plugins)
        {
            if (!pluginRef.Hook.Equals("mutate", StringComparison.OrdinalIgnoreCase))
                continue;
            var pluginDir = ProjectLoader.ResolvePath(yamlPath, pluginRef.Path);
            var manifest = RppPluginHost.LoadManifest(Path.Combine(pluginDir, "rpp.yaml"));
            if (manifest is null)
                continue;
            mutators.Add(new RppMutator(new RppPluginHost(pluginDir), manifest));
        }
        return mutators;
    }

    private static List<byte[]> LoadAllSeeds(ProjectConfig project, string yamlPath)
    {
        var list = new List<byte[]>();
        foreach (var seed in project.Seeds)
        {
            try
            {
                list.Add(ProjectLoader.LoadSeed(yamlPath, seed));
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Warning: skip seed {seed}: {ex.Message}");
            }
        }
        return list;
    }
}
