using System.Diagnostics;
using System.Text;
using Randall.Contracts;
using Randall.Core;
using Randall.Core.Model;
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

        var seeds = LoadAllSeeds(project, yamlPath);
        if (seeds.Count == 0)
            seeds.Add(Array.Empty<byte>());

        var corpusDir = ProjectLoader.ResolvePath(yamlPath, project.Fuzz.CorpusDir);
        var traceDir = Path.Combine(corpusDir, "traces");
        Directory.CreateDirectory(corpusDir);
        Directory.CreateDirectory(traceDir);

        var corpus = new CorpusTracker(corpusDir);
        corpus.Load();

        var mutators = LoadMutators(project, yamlPath, corpus, seeds);

        var coveragePath = Path.Combine(corpusDir, "edges.txt");
        var coverage = new CoverageSet(coveragePath);
        coverage.Load();

        var crashStore = new CrashStore(ProjectLoader.ResolvePath(yamlPath, project.Fuzz.CrashesDir));
        crashStore.Ensure();

        var dynamo = DynamoRioRunner.Discover();
        var useCoverageFile = coverageGuided && dynamo.IsAvailable &&
                              project.Kind.Equals("file", StringComparison.OrdinalIgnoreCase);
        var useCoverageTcp = coverageGuided && dynamo.IsAvailable &&
                             project.Fuzz.CoverageTcpSpawn &&
                             project.Kind.Equals("tcp", StringComparison.OrdinalIgnoreCase) &&
                             !string.IsNullOrWhiteSpace(project.Target.Executable);
        var useCoverage = useCoverageFile;

        options.Progress?.OnStarted(project.Name, project.Kind);

        var crashes = new List<CrashRecord>();
        ProcessMonitor? monitor = null;
        Process? longLived = null;
        if (!useCoverageTcp && project.Target.LongLived &&
            (project.Kind.Equals("tcp", StringComparison.OrdinalIgnoreCase) ||
             project.Kind.Equals("udp", StringComparison.OrdinalIgnoreCase)))
        {
            monitor = new ProcessMonitor(project, yamlPath);
            longLived = monitor.Start();
        }

        var sessionCommands = SessionGraph.LoadCommands(project, yamlPath);
        var sessionFlows = SessionGraph.LoadFlows(project, yamlPath, sessionCommands);
        var commandsByName = sessionCommands.ToDictionary(c => c.Name, StringComparer.OrdinalIgnoreCase);
        var powerSchedule = project.Fuzz.PowerSchedule;
        var flowBias = project.Fuzz.SessionFlowBias;

        var exhaustive = FuzzCasePlanner.IsExhaustive(project);
        var plannedCases = exhaustive
            ? FuzzCasePlanner.PlanCases(project, yamlPath, mutators, sessionCommands, sessionFlows).ToList()
            : null;

        var iterations = 0;
        var crashCount = 0;
        var corpusAdded = 0;
        var rng = Random.Shared;

        try
        {
            for (var i = 0; i < maxIterations && !cancellationToken.IsCancellationRequested; i++)
            {
                iterations++;
                var mutator = mutators[rng.Next(mutators.Count)];
                TargetRunner.TcpSendOptions? tcpOptions = null;
                string commandName = "default";
                byte[] payload;
                IReadOnlyList<TargetRunner.TcpStep>? tcpSequence = null;
                var useResponseGraph = false;

                if (exhaustive && plannedCases is { Count: > 0 })
                {
                    var caseIndex = (iterations - 1) % plannedCases.Count;
                    var planned = plannedCases[caseIndex];
                    mutator = planned.Mutator;
                    commandName = planned.Label;

                    if (planned.Flow is not null && planned.Command is not null)
                    {
                        var steps = new List<TargetRunner.TcpStep>();
                        for (var si = 0; si < planned.Flow.Steps.Count; si++)
                        {
                            var cmd = planned.Flow.Steps[si];
                            var mutate = si == planned.FlowStepIndex;
                            var stepPayload = BuildCommandPayload(
                                cmd, yamlPath, mutator, rng, mutate, project, planned.TargetField);
                            steps.Add(new TargetRunner.TcpStep(
                                stepPayload,
                                new TargetRunner.TcpSendOptions(
                                cmd.Preamble, cmd.ReadBanner && si == 0, cmd.ExpectResponse)));
                        }
                        tcpSequence = steps;
                        payload = steps[planned.FlowStepIndex].Payload;
                    }
                    else if (planned.Command is not null)
                    {
                        var cmd = planned.Command;
                        tcpOptions = new TargetRunner.TcpSendOptions(
                            cmd.Preamble, cmd.ReadBanner, cmd.ExpectResponse);
                        payload = BuildCommandPayload(cmd, yamlPath, mutator, rng, true, project, planned.TargetField);
                    }
                    else if (!string.IsNullOrWhiteSpace(project.Model))
                    {
                        var model = ProtocolLoader.Load(yamlPath, project.Model);
                        var protoSeeds = ProtocolLoader.LoadProtocolSeeds(yamlPath, project.Model);
                        payload = ModelFuzzer.BuildPayload(
                            model, protoSeeds, mutator, rng,
                            project.Fuzz.SyncLengthFields, project.Fuzz.HavocDepth, planned.TargetField);
                    }
                    else
                    {
                        continue;
                    }
                }
                else if (project.SessionGraph is not null &&
                         commandsByName.Count > 0 &&
                         project.Kind.Equals("tcp", StringComparison.OrdinalIgnoreCase) &&
                         rng.NextDouble() < project.Fuzz.SessionGraphBias)
                {
                    useResponseGraph = true;
                    commandName = "graph";
                    payload = Array.Empty<byte>();
                }
                else if (sessionCommands.Count > 0 &&
                    sessionFlows.Count > 0 &&
                    rng.NextDouble() < flowBias)
                {
                    var flow = sessionFlows[rng.Next(sessionFlows.Count)];
                    var mutateSteps = MutateStepResolver.Resolve(flow.MutateStep, project.Fuzz.MutateStep, flow.Steps.Count);
                    var steps = new List<TargetRunner.TcpStep>();
                    for (var si = 0; si < flow.Steps.Count; si++)
                    {
                        var cmd = flow.Steps[si];
                        var mutate = mutateSteps.Contains(si);
                        var stepPayload = BuildCommandPayload(cmd, yamlPath, mutator, rng, mutate, project);
                        steps.Add(new TargetRunner.TcpStep(
                            stepPayload,
                            new TargetRunner.TcpSendOptions(
                                cmd.Preamble, cmd.ReadBanner && si == 0, cmd.ExpectResponse)));
                    }
                    tcpSequence = steps;
                    payload = steps[^1].Payload;
                    commandName = $"flow/{flow.Name}";
                }
                else if (sessionCommands.Count > 0)
                {
                    var cmd = sessionCommands[rng.Next(sessionCommands.Count)];
                    commandName = cmd.Name;
                    tcpOptions = new TargetRunner.TcpSendOptions(
                        cmd.Preamble, cmd.ReadBanner, cmd.ExpectResponse);
                    payload = BuildCommandPayload(cmd, yamlPath, mutator, rng, mutate: true, project);
                    if (!string.IsNullOrWhiteSpace(cmd.ModelPath))
                    {
                        var model = ProtocolLoader.Load(yamlPath, cmd.ModelPath);
                        var mutableFields = model.GetMutableFields();
                        if (mutableFields.Count > 0)
                            commandName = $"{cmd.Name}/{mutableFields[rng.Next(mutableFields.Count)].Name}";
                    }
                }
                else if (!string.IsNullOrWhiteSpace(project.Model))
                {
                    var model = ProtocolLoader.Load(yamlPath, project.Model);
                    var protoSeeds = ProtocolLoader.LoadProtocolSeeds(yamlPath, project.Model);
                    payload = ModelFuzzer.BuildPayload(
                        model, protoSeeds, mutator, rng,
                        project.Fuzz.SyncLengthFields, project.Fuzz.HavocDepth);
                    commandName = $"model/{model.Name}";
                }
                else
                {
                    var seed = corpus.PickSeed(seeds, rng, powerSchedule);
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

                if (useCoverageTcp)
                {
                    await dynamo.StopInstrumentedAsync(longLived, cancellationToken);
                    longLived = dynamo.StartInstrumentedTarget(project, yamlPath, traceDir);
                    await Task.Delay(500, cancellationToken);
                }

                TargetRunResult result;
                if (useResponseGraph && project.SessionGraph is not null)
                {
                    var graphRun = await ResponseGraphRunner.RunAsync(
                        project, yamlPath, longLived, commandsByName, project.SessionGraph,
                        mutator, rng, cancellationToken);
                    if (graphRun is null)
                        continue;
                    result = graphRun.Run;
                    payload = graphRun.LastPayload;
                    commandName = $"graph/{graphRun.PathLabel}";
                }
                else
                {
                    result = tcpSequence is not null
                        ? await TargetRunner.RunTcpSequenceAsync(
                            project, yamlPath, longLived, tcpSequence, cancellationToken)
                        : await TargetRunner.RunPayloadAsync(
                            project, yamlPath, payload, longLived, cancellationToken, tcpOptions);
                }

                var pluginAbort = await RppResponseHook.RunAsync(
                    project, yamlPath, payload, result.ResponseBytes, cancellationToken);
                if (pluginAbort is not null && !result.Crashed)
                    result = result with { Detail = $"post_receive: {pluginAbort}" };

                var newEdges = 0;
                var newCoverage = false;
                if (useCoverageTcp)
                {
                    var trace = dynamo.CollectLatestTrace(traceDir);
                    await dynamo.StopInstrumentedAsync(longLived, cancellationToken);
                    longLived = null;
                    if (trace is not null)
                    {
                        newEdges = coverage.RegisterTrace(trace);
                        newCoverage = newEdges > 0;
                        if (newCoverage && !result.Crashed)
                        {
                            corpus.AddPriority(payload);
                            corpusAdded++;
                        }
                    }
                }
                else if (!result.Crashed)
                {
                    if (useCoverageFile)
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

                    var crashTag = await RppCrashHook.RunAsync(
                        project, yamlPath, payload, result, cancellationToken);
                    if (crashTag is not null)
                        Console.WriteLine($"  triage tag: {crashTag}");

                    if (!useCoverageTcp && project.Target.LongLived &&
                        (project.Kind.Equals("tcp", StringComparison.OrdinalIgnoreCase) ||
                         project.Kind.Equals("udp", StringComparison.OrdinalIgnoreCase)))
                    {
                        monitor?.Stop();
                        await Task.Delay(300, cancellationToken);
                        longLived = monitor?.Start();
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
            if (useCoverageTcp)
                dynamo.StopInstrumentedAsync(longLived, cancellationToken).GetAwaiter().GetResult();
            monitor?.Dispose();
        }

        var runResult = new FuzzRunResult(iterations, corpusAdded, crashCount, crashes);
        options.Progress?.OnCompleted(runResult);
        return runResult;
    }

    private static List<IMutator> LoadMutators(
        ProjectConfig project,
        string yamlPath,
        CorpusTracker corpus,
        IReadOnlyList<byte[]> seeds)
    {
        var rng = Random.Shared;
        var tokens = BuiltInMutators.BuildDictionaryTokens(project, yamlPath);
        var context = new MutationContext
        {
            DictionaryTokens = tokens,
            HavocDepth = project.Fuzz.HavocDepth,
            PickAlternateSeed = () => corpus.PickAny(seeds, rng, project.Fuzz.PowerSchedule),
        };
        var mutators = BuiltInMutators.Create(project.Mutators, context: context).ToList();
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

    private static byte[] BuildCommandPayload(
        SessionGraph.PreparedCommand cmd,
        string yamlPath,
        IMutator mutator,
        Random rng,
        bool mutate,
        ProjectConfig project,
        FieldRegion? targetField = null)
    {
        if (!string.IsNullOrWhiteSpace(cmd.ModelPath))
        {
            var model = ProtocolLoader.Load(yamlPath, cmd.ModelPath);
            var protoSeeds = ProtocolLoader.LoadProtocolSeeds(yamlPath, cmd.ModelPath);
            if (mutate)
                return ModelFuzzer.BuildPayload(
                    model, protoSeeds, mutator, rng,
                    project.Fuzz.SyncLengthFields, project.Fuzz.HavocDepth, targetField);
            return model.FinalizeMessage(model.Render(protoSeeds), project.Fuzz.SyncLengthFields);
        }

        var body = mutate ? mutator.Mutate(cmd.Seed).ToArray() : cmd.Seed;
        return SessionGraph.BuildPayload(cmd, body);
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
