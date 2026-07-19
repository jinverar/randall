using System.Diagnostics;
using System.Runtime.InteropServices;
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
        var crashesDir = ProjectLoader.ResolvePath(yamlPath, project.Fuzz.CrashesDir);

        var stalkBackend = StalkTraceBackendFactory.ResolveBackendId(project);
        IStalkTraceBackend stalk = stalkBackend switch
        {
            StalkBackend.External => new ExternalDrcovStalkBackend(DynamoRioRunner.Discover()),
            StalkBackend.Native => new NativeStalkRunner(),
            _ => NullStalkTraceBackend.Instance,
        };
        var fallbackWarn = StalkTraceBackendFactory.ResolveFallbackNote(project);
        var stalkNote = fallbackWarn ?? stalk.AvailabilityNote;
        if (fallbackWarn is not null)
            Console.WriteLine($"Warning: {fallbackWarn}");
        FuzzRunJournal? journal = null;
        if (project.Fuzz.ExecutionLog)
        {
            journal = FuzzRunJournal.Start(project, yamlPath, dryRun, coverageGuided, stalkBackend, stalkNote);
            Console.WriteLine($"Run journal: {journal.RunDirectory}");
        }
        var useCoverage = coverageGuided && stalk.IsAvailable;
        var useCoverageFile = useCoverage &&
                              project.Kind.Equals("file", StringComparison.OrdinalIgnoreCase);
        var useCoverageTcp = useCoverage && project.Fuzz.CoverageTcpSpawn &&
                             project.Kind.Equals("tcp", StringComparison.OrdinalIgnoreCase) &&
                             !string.IsNullOrWhiteSpace(project.Target.Executable);

        var progress = options.Progress;
        progress?.OnStarted(project.Name, project.Kind);
        FuzzAnalystLog.Info(progress,
            $"Fuzzing '{project.Name}' ({project.Kind}) — max {maxIterations} iterations" +
            (dryRun ? " [dry-run]" : ""));

        var debuggerMode = (options.DebuggerMode ?? project.Fuzz.DebuggerMode ?? "none")
            .Trim().ToLowerInvariant();
        var debuggerKind = options.DebuggerKind ?? project.Fuzz.DebuggerKind ?? "auto";
        var debuggerOpenOnCrash = options.DebuggerOpenOnCrash ?? project.Fuzz.DebuggerOpenOnCrash;
        DebuggerWaitHandle? debuggerWait = null;

        ProcmonCapture? procmon = null;
        TcpvconCapture? tcpvcon = null;
        PktmonCapture? pktmon = null;
        ProcDumpCrashArm? procdumpArm = null;
        DebugViewCapture? debugView = null;
        SysinternalsSnapshots? sysinternalsSnap = null;
        var wantProcmon = options.ProcmonCapture ?? project.Fuzz.ProcmonCapture;
        var wantTcpvcon = options.TcpvconCapture ?? project.Fuzz.TcpvconCapture;
        var wantProcdump = options.ProcdumpOnCrash ?? project.Fuzz.ProcdumpOnCrash;
        var wantPktmon = options.PktmonCapture ?? project.Fuzz.PktmonCapture;
        var wantDebugView = options.DebugViewCapture ?? project.Fuzz.DebugViewCapture;
        var wantSysinternalsSnap = options.SysinternalsSnapshots ?? project.Fuzz.SysinternalsSnapshots;
        var wantStringsOnCrash = options.StringsOnCrash ?? project.Fuzz.StringsOnCrash;
        string? runDir = journal?.RunDirectory;
        if (!dryRun && (wantProcmon || wantTcpvcon || wantPktmon || wantDebugView || wantSysinternalsSnap))
        {
            runDir ??= Path.Combine(ProjectLoader.ResolvePath(yamlPath, project.Fuzz.RunsDir),
                $"{project.Name}_{DateTime.UtcNow:yyyyMMdd_HHmmss}");
            Directory.CreateDirectory(runDir);
        }

        string? targetExeResolved = null;
        if (!string.IsNullOrWhiteSpace(project.Target.Executable))
        {
            try
            {
                targetExeResolved = ProjectLoader.ResolvePath(yamlPath, project.Target.Executable);
            }
            catch
            {
                targetExeResolved = project.Target.Executable;
            }
        }

        if (!dryRun && wantProcmon && runDir is not null)
        {
            var pml = Path.Combine(runDir, "fuzz.pml");
            procmon = ProcmonCapture.TryStart(pml);
            if (procmon?.IsRunning == true)
                FuzzAnalystLog.Info(progress, $"Procmon capture → {procmon.PmlPath}");
            else
                FuzzAnalystLog.Warn(progress,
                    $"Procmon capture skipped: {procmon?.LastError ?? "Procmon not found (tools/ or PATH)"}");
        }

        if (!dryRun && wantTcpvcon && runDir is not null)
        {
            tcpvcon = TcpvconCapture.TryBegin(runDir);
            if (tcpvcon.Available)
                FuzzAnalystLog.Info(progress,
                    $"TCPVCon capture armed → {tcpvcon.CaptureDir}");
            else
                FuzzAnalystLog.Warn(progress,
                    $"TCPVCon capture skipped: {tcpvcon.LastError ?? "tcpvcon not found (tools/ or PATH)"}");
        }

        if (!dryRun && wantPktmon && runDir is not null)
        {
            pktmon = PktmonCapture.TryStart(runDir);
            if (pktmon?.IsRunning == true)
                FuzzAnalystLog.Info(progress, $"pktmon capture → {pktmon.EtlPath}");
            else
                FuzzAnalystLog.Warn(progress,
                    $"pktmon capture skipped: {pktmon?.LastError ?? "pktmon not available"}");
        }

        if (!dryRun && wantDebugView && runDir is not null)
        {
            debugView = DebugViewCapture.TryStart(runDir);
            if (debugView.IsRunning)
                FuzzAnalystLog.Info(progress, $"DebugView capture → {debugView.LogPath}");
            else
                FuzzAnalystLog.Warn(progress,
                    $"DebugView capture skipped: {debugView.LastError ?? "Dbgview.exe not found (tools/ or PATH)"}");
        }

        if (!dryRun && wantSysinternalsSnap && runDir is not null)
        {
            sysinternalsSnap = SysinternalsSnapshots.TryBegin(runDir);
            if (sysinternalsSnap.AnyToolFound)
                FuzzAnalystLog.Info(progress,
                    $"Sysinternals snapshots → {sysinternalsSnap.SnapshotDir} " +
                    "(handle/listdlls/pslist + sigcheck/accesschk/vmmap when present)");
            else
                FuzzAnalystLog.Warn(progress,
                    $"Sysinternals snapshots skipped: {sysinternalsSnap.LastError ?? "tools not found"}");
        }

        var crashes = new List<CrashRecord>();
        TargetRuntimeBridge? runtime = null;
        Process? longLived = null;
        InProcessSession? inProcess = null;
        PersistentTargetServer? persistentServer = null;
        var useInProcess = InProcessSession.IsInProcess(project);
        var usePersistentOop = !useInProcess && PersistentTargetServer.ShouldUse(project);
        if (useInProcess)
        {
            useCoverageTcp = false;
            useCoverageFile = false;
            FuzzAnalystLog.Step(progress, "Starting in-process harness");
            inProcess = InProcessSession.Start(project, yamlPath);
            FuzzAnalystLog.Info(progress,
                $"In-process ({inProcess.Mode}) isolation={inProcess.Isolation.Summary} — Target Runtime skipped");
            if (!inProcess.Persistent)
                FuzzAnalystLog.Info(progress,
                    "cold isolation: reload/respawn every case (reproducibility baseline; slower)");
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows) && inProcess.ForkServer)
                FuzzAnalystLog.Info(progress,
                    "forkServer on Windows = warm worker + recycle after crash (no Unix fork)");
        }
        else if (usePersistentOop)
        {
            useCoverageTcp = false;
            useCoverageFile = false;
            FuzzAnalystLog.Step(progress, "Starting persistent / fork-server target");
            persistentServer = PersistentTargetServer.Start(project, yamlPath);
            FuzzAnalystLog.Info(progress, $"Persistent target ({persistentServer.Mode})");
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows) && (project.Fuzz.ForkServer ?? false))
                FuzzAnalystLog.Info(progress,
                    "forkServer on Windows = warm stdio process (AFL FORKSRV_FD is Linux-only)");
        }
        else if (!useCoverageTcp && project.Target.LongLived &&
            (project.Kind.Equals("tcp", StringComparison.OrdinalIgnoreCase) ||
             project.Kind.Equals("udp", StringComparison.OrdinalIgnoreCase)))
        {
            FuzzAnalystLog.Step(progress, "Starting target (Target Runtime)");
            runtime = new TargetRuntimeBridge(project, yamlPath);
            var (proc, st) = await runtime.StartAsync(cancellationToken);
            if (!st.Ok && !st.Running)
                throw new InvalidOperationException($"Target Runtime start failed: {st.Message}");
            longLived = proc;
            FuzzAnalystLog.Info(progress, runtime.IsRemote
                ? $"Target Runtime (agent {runtime.AgentUrl}): {st.Message}"
                : $"Target Runtime (local): {st.Message}");
            if (runtime.IsRemote)
                FuzzAnalystLog.Info(progress, "Debugger attach skipped on remote agent (dumps stay on agent host)");
            else
                await ArmDebuggerAsync(longLived);
        }

        async Task ArmDebuggerAsync(Process? proc)
        {
            debuggerWait?.Dispose();
            debuggerWait = null;
            if (proc is null || proc.HasExited || dryRun)
                return;

            options.Progress?.OnTargetPid(proc.Id);
            Console.WriteLine($"Target PID: {proc.Id}");

            if (sysinternalsSnap is { AnyToolFound: true })
            {
                try
                {
                    sysinternalsSnap.CaptureArm(proc.Id, targetExeResolved);
                    FuzzAnalystLog.Info(progress, $"Sysinternals arm snapshots (pid={proc.Id})");
                }
                catch (Exception ex)
                {
                    FuzzAnalystLog.Warn(progress, $"Sysinternals arm snapshots: {ex.Message}");
                }
            }

            if (tcpvcon is { Available: true })
            {
                try
                {
                    tcpvcon.CaptureArm(proc.Id);
                    FuzzAnalystLog.Info(progress, $"TCPVCon arm snapshot (pid={proc.Id})");
                }
                catch (Exception ex)
                {
                    FuzzAnalystLog.Warn(progress, $"TCPVCon arm snapshot: {ex.Message}");
                }
            }

            // Only one debugger can attach. "both" = scream wait + open GUI after crash (not live dual-attach).
            if (debuggerMode is "attach")
            {
                var attach = DebuggerSession.Attach(proc.Id, debuggerKind, go: true);
                Console.WriteLine(attach.Ok
                    ? $"  debugger attach: {attach.Message}"
                    : $"  debugger attach skipped: {attach.Message}");
            }

            if (debuggerMode is "wait" or "both")
            {
                var dumpsDir = Path.Combine(crashesDir, "dumps");
                debuggerWait = DebuggerSession.StartWaitWatcher(proc.Id, dumpsDir, preferred: "scream");
                if (debuggerWait?.Scream is { } scream)
                {
                    var attached = await scream.WaitUntilAttachedAsync(TimeSpan.FromSeconds(5), cancellationToken);
                    Console.WriteLine(attached
                        ? $"  scream ready ({(scream.IsWow64 ? "wow64" : "x64")}) → {scream.DumpPath}"
                        : $"  scream attach/ready failed: {scream.LastError ?? scream.Phase}");
                    if (!attached)
                    {
                        debuggerWait.Dispose();
                        debuggerWait = null;
                    }
                }
                else
                {
                    Console.WriteLine("  scream wait skipped");
                }
            }

            // ProcDump -e also debug-attaches — only arm when Scream/attach is not holding the process.
            procdumpArm?.Dispose();
            procdumpArm = null;
            if (wantProcdump)
            {
                if (debuggerWait?.Scream is not null || debuggerMode is "attach")
                {
                    FuzzAnalystLog.Warn(progress,
                        "procdumpOnCrash skipped: Scream/debugger already attached (only one debugger)");
                }
                else
                {
                    var dumpsDir = Path.Combine(crashesDir, "dumps");
                    procdumpArm = ProcDumpCrashArm.TryArm(proc.Id, dumpsDir);
                    if (procdumpArm?.IsRunning == true)
                        FuzzAnalystLog.Info(progress, $"ProcDump armed (-e -ma) → {procdumpArm.DumpPath}");
                    else
                        FuzzAnalystLog.Warn(progress,
                            $"procdumpOnCrash skipped: {procdumpArm?.LastError ?? "ProcDump not found (tools/ or PATH)"}");
                }
            }
        }

        async Task<string?> TakeWaitDumpAsync(string? existingDump)
        {
            if (debuggerWait is null)
                return existingDump;
            try
            {
                var dump = await DebuggerSession.WaitForDumpAsync(
                    debuggerWait, Math.Max(project.Target.TimeoutMs, 5000), cancellationToken);
                if (dump is not null)
                {
                    Console.WriteLine($"  debugger dump: {dump}");
                    return dump;
                }
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                Console.WriteLine($"  debugger wait: {ex.Message}");
            }
            return existingDump;
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
                string? parentInputHash = null;
                string seedSource = "unknown";
                var seedFiles = new List<string>();
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
                            var built = BuildCommandPayload(
                                cmd, yamlPath, mutator, rng, mutate, project, planned.TargetField);
                            var stepPayload = built.Payload;
                            if (mutate)
                            {
                                parentInputHash = built.ParentHash;
                                seedSource = built.SeedSource;
                                seedFiles = built.SeedFiles;
                            }
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
                        var built = BuildCommandPayload(cmd, yamlPath, mutator, rng, true, project, planned.TargetField);
                        payload = built.Payload;
                        parentInputHash = built.ParentHash;
                        seedSource = built.SeedSource;
                        seedFiles = built.SeedFiles;
                    }
                    else if (!string.IsNullOrWhiteSpace(project.Model))
                    {
                        var model = ProtocolLoader.Load(yamlPath, project.Model);
                        var protoSeeds = ProtocolLoader.LoadProtocolSeeds(yamlPath, project.Model);
                        payload = ModelFuzzer.BuildPayload(
                            model, protoSeeds, mutator, rng,
                            project.Fuzz.SyncLengthFields, project.Fuzz.HavocDepth, planned.TargetField);
                        var baseline = model.Render(protoSeeds);
                        parentInputHash = InputHash.StackHash(baseline);
                        seedSource = "model";
                        seedFiles = protoSeeds.Keys.ToList();
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
                    seedSource = "sessionGraph";
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
                        var built = BuildCommandPayload(cmd, yamlPath, mutator, rng, mutate, project);
                        var stepPayload = built.Payload;
                        if (mutate)
                        {
                            parentInputHash = built.ParentHash;
                            seedSource = built.SeedSource;
                            seedFiles = built.SeedFiles;
                        }
                        steps.Add(new TargetRunner.TcpStep(
                            stepPayload,
                            new TargetRunner.TcpSendOptions(
                                cmd.Preamble, cmd.ReadBanner && si == 0, cmd.ExpectResponse)));
                    }
                    tcpSequence = steps;
                    payload = steps[^1].Payload;
                    commandName = $"flow/{flow.Name}";
                    seedSource = "sessionFlow";
                }
                else if (sessionCommands.Count > 0)
                {
                    var cmd = sessionCommands[rng.Next(sessionCommands.Count)];
                    commandName = cmd.Name;
                    tcpOptions = new TargetRunner.TcpSendOptions(
                        cmd.Preamble, cmd.ReadBanner, cmd.ExpectResponse);
                    var built = BuildCommandPayload(cmd, yamlPath, mutator, rng, mutate: true, project);
                    payload = built.Payload;
                    parentInputHash = built.ParentHash;
                    seedSource = built.SeedSource;
                    seedFiles = built.SeedFiles;
                    if (!string.IsNullOrWhiteSpace(cmd.ModelPath))
                    {
                        var model = ProtocolLoader.Load(yamlPath, cmd.ModelPath);
                        var protoSeeds = ProtocolLoader.LoadProtocolSeeds(yamlPath, cmd.ModelPath);
                        var mutableFields = model.GetMutableFields(protoSeeds);
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
                    parentInputHash = InputHash.StackHash(model.Render(protoSeeds));
                    seedSource = "model";
                    seedFiles = protoSeeds.Keys.ToList();
                }
                else
                {
                    var seed = corpus.PickSeed(seeds, rng, powerSchedule);
                    parentInputHash = InputHash.StackHash(seed);
                    seedSource = "corpus";
                    payload = mutator.Mutate(seed).ToArray();
                    if (project.Transport.Prefix.Length > 0)
                    {
                        var prefix = Encoding.ASCII.GetBytes(project.Transport.Prefix);
                        payload = prefix.Concat(payload).ToArray();
                    }
                }

                var mutatorChain = new List<string> { mutator.Name };
                var sw = Stopwatch.StartNew();
                string? iterTracePath = null;

                if (dryRun)
                {
                    var dryLabel = $"{commandName}/{mutator.Name}";
                    FuzzAnalystLog.Case(progress, iterations, dryLabel);
                    FuzzAnalystLog.Step(progress, $"Fuzzing node '{commandName}'", iterations);
                    FuzzAnalystLog.Tx(progress, payload, iterations);
                    sw.Stop();
                    journal?.LogIteration(new IterationLogEntry(
                        iterations, DateTimeOffset.UtcNow, commandName, mutator.Name, mutatorChain,
                        parentInputHash, seedSource, payload.Length, InputHash.StackHash(payload),
                        false, 0, coverage.TotalEdges, sw.ElapsedMilliseconds, "dry-run", null,
                        stalkBackend, null, journal?.RunId ?? "", true));
                    progress?.OnIteration(new FuzzIterationEvent(
                        iterations, dryLabel, payload.Length, false, false, 0, corpus.SeenCount, coverage.TotalEdges, "dry-run"));
                    FuzzAnalystLog.Ok(progress, "Check OK: dry-run (not sent).", iterations);
                    continue;
                }

                if (useCoverageTcp)
                {
                    await stalk.StopLongLivedAsync(longLived, cancellationToken);
                    longLived = stalk.StartLongLivedTarget(project, yamlPath, traceDir);
                    await Task.Delay(500, cancellationToken);
                }

                var caseLabel = $"{commandName}/{mutator.Name}";
                FuzzAnalystLog.Case(progress, iterations, caseLabel);
                if (project.Kind is "tcp" or "udp")
                {
                    FuzzAnalystLog.Info(progress,
                        $"Opening target connection to {project.Transport.Host}:{project.Transport.Port}…",
                        iterations);
                }

                FuzzAnalystLog.Step(progress, $"Fuzzing node '{commandName}'", iterations);
                FuzzAnalystLog.Tx(progress, payload, iterations);

                TargetRunResult result;
                if (inProcess is not null)
                {
                    commandName = "harness";
                    caseLabel = $"harness/{mutator.Name}";
                    result = await inProcess.RunAsync(payload, cancellationToken);
                    if (iterations > 0 && iterations % 50 == 0)
                        FuzzAnalystLog.Info(progress,
                            $"Harness perf: {inProcess.Stats.Format()}", iterations);
                }
                else if (persistentServer is not null)
                {
                    commandName = "persistent";
                    caseLabel = $"persistent/{mutator.Name}";
                    result = await persistentServer.RunAsync(payload, cancellationToken);
                }
                else if (useResponseGraph && project.SessionGraph is not null)
                {
                    var graphRun = await ResponseGraphRunner.RunAsync(
                        project, yamlPath, longLived, commandsByName, project.SessionGraph,
                        mutator, rng, cancellationToken);
                    if (graphRun is null)
                        continue;
                    result = graphRun.Run;
                    payload = graphRun.LastPayload;
                    commandName = $"graph/{graphRun.PathLabel}";
                    caseLabel = $"{commandName}/{mutator.Name}";
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

                // Remote agent: no local Process handle — poll Target Runtime for death.
                if (runtime is { IsRemote: true } && !result.Crashed &&
                    await runtime.HasExitedAsync(longLived, cancellationToken))
                {
                    var st = await runtime.StatusAsync(cancellationToken);
                    result = result with
                    {
                        Crashed = true,
                        ExitCode = st.LastExitCode,
                        Detail = "remote target exited (Target Runtime)",
                    };
                }

                // Scream holds the process at second-chance before Kill — detect dump even if
                // TargetRunner still saw HasExited == false for a moment.
                if (debuggerWait is not null &&
                    (debuggerWait.Completion?.IsCompleted == true ||
                     debuggerWait.TryExistingDump() is not null ||
                     longLived is { HasExited: true }))
                {
                    var screamDump = await TakeWaitDumpAsync(result.MiniDumpPath);
                    if (screamDump is not null || debuggerWait.Scream?.ExceptionInfo is not null)
                    {
                        var hint = debuggerWait.Scream?.ExceptionInfo?.ExceptionHint ?? "scream exception";
                        result = result with
                        {
                            Crashed = true,
                            MiniDumpPath = screamDump ?? result.MiniDumpPath,
                            Detail = result.Crashed ? result.Detail : $"scream: {hint}",
                            ExitCode = result.ExitCode ??
                                       (int?)debuggerWait.Scream?.ExceptionInfo?.ExceptionCode,
                        };
                    }
                }

                if (procdumpArm is not null &&
                    (procdumpArm.TryExistingDump() is not null || longLived is { HasExited: true }))
                {
                    var pd = procdumpArm.TryExistingDump();
                    if (pd is not null)
                    {
                        result = result with
                        {
                            Crashed = true,
                            MiniDumpPath = result.MiniDumpPath ?? pd,
                            Detail = result.Crashed ? result.Detail : "procdump exception dump",
                        };
                    }
                }

                var newEdges = 0;
                var newCoverage = false;
                if (useCoverageTcp)
                {
                    await stalk.StopLongLivedAsync(longLived, cancellationToken);
                    longLived = null;
                    await Task.Delay(250, cancellationToken);
                    var trace = stalk.CollectLatestTrace(traceDir);
                    iterTracePath = trace;
                    if (trace is not null && File.Exists(trace))
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
                else if (useCoverageFile)
                {
                    var covRun = await stalk.RunFileTargetAsync(
                        project, yamlPath, payload, traceDir, cancellationToken);
                    iterTracePath = covRun.TracePath;
                    newEdges = coverage.RegisterTrace(covRun.TracePath);
                    newCoverage = newEdges > 0;
                    if (newCoverage && !result.Crashed)
                    {
                        corpus.AddPriority(payload);
                        corpusAdded++;
                    }
                }
                else if (!result.Crashed && corpus.IsNew(payload))
                {
                    corpus.SaveInteresting(payload, "corpus");
                    corpusAdded++;
                }

                sw.Stop();
                journal?.LogIteration(new IterationLogEntry(
                    iterations, DateTimeOffset.UtcNow, commandName, mutator.Name, mutatorChain,
                    parentInputHash, seedSource, payload.Length, InputHash.StackHash(payload),
                    result.Crashed, newEdges, coverage.TotalEdges, sw.ElapsedMilliseconds,
                    result.Detail, result.ExitCode, stalkBackend, iterTracePath,
                    journal?.RunId ?? "", false));

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

                FuzzAnalystLog.Step(progress, "Monitor / checkAlive", iterations);

                if (result.Crashed)
                {
                    FuzzAnalystLog.Crash(progress, iterations, $"{caseLabel} — {result.Detail}");
                    crashCount++;
                    if (sysinternalsSnap is { AnyToolFound: true } || tcpvcon is { Available: true })
                    {
                        int? crashPid = null;
                        try
                        {
                            if (longLived is { HasExited: false })
                                crashPid = longLived.Id;
                        }
                        catch
                        {
                            /* process may be gone */
                        }

                        if (sysinternalsSnap is { AnyToolFound: true })
                        {
                            try
                            {
                                sysinternalsSnap.CaptureCrash(crashPid);
                            }
                            catch (Exception ex)
                            {
                                FuzzAnalystLog.Warn(progress, $"Sysinternals crash snapshots: {ex.Message}", iterations);
                            }
                        }

                        if (tcpvcon is { Available: true })
                        {
                            try
                            {
                                tcpvcon.CaptureCrash(crashPid);
                            }
                            catch (Exception ex)
                            {
                                FuzzAnalystLog.Warn(progress, $"TCPVCon crash snapshot: {ex.Message}", iterations);
                            }
                        }
                    }

                    var crashDump = await TakeWaitDumpAsync(result.MiniDumpPath);
                    var crashTag = await RppCrashHook.RunAsync(
                        project, yamlPath, payload, result, cancellationToken);

                    var mutatorLabel = $"{commandName}/{mutator.Name}";
                    var payloadHash = InputHash.StackHash(payload);
                    var expectedInputPath = Path.Combine(crashesDir, $"{project.Name}_{iterations}_{payloadHash}.bin");

                    var saved = crashStore.Save(
                        project.Name,
                        iterations,
                        mutatorLabel,
                        payload,
                        result.ExitCode,
                        crashDump,
                        crashTag,
                        journal?.RunId,
                        buildSidecar: id =>
                        {
                            var traceCopy = CrashSidecarWriter.CopyTrace(crashesDir, id, iterTracePath);
                            return new CrashSidecarDto(
                                id,
                                journal?.RunId ?? "",
                                iterations,
                                project.Name,
                                commandName,
                                mutator.Name,
                                mutatorChain,
                                parentInputHash,
                                seedSource,
                                seedFiles,
                                payloadHash,
                                expectedInputPath,
                                payload.Length,
                                result.ExitCode,
                                WindowsExceptionHints.Describe(result.ExitCode),
                                result.Detail,
                                crashTag,
                                newEdges,
                                coverage.TotalEdges,
                                stalkBackend,
                                iterTracePath,
                                traceCopy,
                                crashDump,
                                CrashSidecarWriter.HexPreview(result.ResponseBytes),
                                new TransportSnapshotDto(
                                    project.Kind, project.Transport.Host, project.Transport.Port, project.Transport.Tls),
                                new FuzzSnapshotDto(coverageGuided, dryRun, Path.GetFullPath(yamlPath)),
                                DateTimeOffset.UtcNow);
                        });

                    Console.WriteLine(
                        $"CRASH #{crashCount} iter={iterations} {mutatorLabel} " +
                        $"detail={result.Detail} saved={saved.InputPath}" +
                        (saved.MiniDumpPath is not null ? $" dump={saved.MiniDumpPath}" : "") +
                        (saved.SidecarPath is not null ? $" sidecar={saved.SidecarPath}" : "") +
                        (crashTag is not null ? $" tag={crashTag}" : ""));

                    if (wantStringsOnCrash && !string.IsNullOrWhiteSpace(saved.InputPath))
                    {
                        try
                        {
                            var stringsOut = StringsOnCrash.TryCapture(saved.InputPath!);
                            if (stringsOut is not null)
                                FuzzAnalystLog.Info(progress, $"Strings on crash → {stringsOut}", iterations);
                            else
                                FuzzAnalystLog.Warn(progress,
                                    "stringsOnCrash skipped: strings64.exe not found or capture failed",
                                    iterations);
                        }
                        catch (Exception ex)
                        {
                            FuzzAnalystLog.Warn(progress, $"stringsOnCrash: {ex.Message}", iterations);
                        }
                    }

                    if (project.Fuzz.AutoAnalyzeCrash && saved.MiniDumpPath is not null)
                    {
                        var analysis = CrashAnalysisWriter.AnalyzeDump(saved.MiniDumpPath);
                        if (!analysis.Ok && debuggerWait?.Scream?.ExceptionInfo is { } screamEx)
                        {
                            analysis = new CrashAnalysisDto(
                                true,
                                saved.MiniDumpPath,
                                $"0x{screamEx.ExceptionCode:X8}",
                                screamEx.ExceptionHint,
                                screamEx.FaultAddress,
                                null,
                                screamEx.Registers,
                                [],
                                null);
                        }

                        var analysisPath = CrashAnalysisWriter.Write(crashesDir, saved.Id, analysis);
                        if (analysis.Ok)
                        {
                            Console.WriteLine(
                                $"  analysis: {analysis.ExceptionHint} @ {analysis.FaultAddress}" +
                                (analysis.FaultModule is not null ? $" ({analysis.FaultModule})" : "") +
                                $" → {analysisPath}");
                        }
                        else
                        {
                            Console.WriteLine($"  analysis skipped: {analysis.Error}");
                        }

                        try
                        {
                            var lens = MemoryLensAnalyzer.AnalyzeDump(
                                saved.MiniDumpPath, analysis, longLived?.Id);
                            var (lensJson, _) = MemoryLensWriter.Write(crashesDir, saved.Id, lens);
                            foreach (var line in lens.SummaryLines.Take(4))
                                FuzzAnalystLog.Info(progress, $"[memory] {line}", iterations);
                            Console.WriteLine($"  memory lens → {lensJson}");
                        }
                        catch (Exception lensEx)
                        {
                            Console.WriteLine($"  memory lens skipped: {lensEx.Message}");
                        }
                    }

                    if ((debuggerOpenOnCrash || debuggerMode is "both") && saved.MiniDumpPath is not null)
                    {
                        var opened = DebuggerSession.OpenDump(saved.MiniDumpPath, debuggerKind);
                        Console.WriteLine(opened.Ok
                            ? $"  debugger open: {opened.Message}"
                            : $"  debugger open skipped: {opened.Message}");
                    }

                    // Auto-record a stalk "crash" layer when coverage edges/trace exist.
                    try
                    {
                        var stalkLayer = StalkCampaignStore.AddLayer(new StalkLayerCreateRequest(
                            project.Name,
                            "crash",
                            $"crash {saved.Id.ToString("N")[..8]} iter={iterations}",
                            null,
                            null,
                            null,
                            saved.Id.ToString(),
                            crashTag ?? result.Detail));
                        Console.WriteLine(
                            $"  stalk layer: {stalkLayer.Tag} blocks={stalkLayer.BlockCount} id={stalkLayer.Id}");
                    }
                    catch (Exception stalkEx)
                    {
                        Console.WriteLine($"  stalk layer skipped: {stalkEx.Message}");
                    }

                    crashes.Add(new CrashRecord(
                        saved.Id,
                        payload,
                        saved.InputHash,
                        result.ExitCode?.ToString() ?? result.Detail,
                        null,
                        saved.MiniDumpPath,
                        newEdges));

                    if (runtime is not null)
                    {
                        FuzzAnalystLog.Warn(progress,
                            "Cannot reach target or process died; restarting via Target Runtime…",
                            iterations);
                        FuzzAnalystLog.Step(progress, "Restarting target", iterations);
                        await Task.Delay(300, cancellationToken);
                        var (proc, rst) = await runtime.RestartAsync(cancellationToken);
                        longLived = proc;
                        FuzzAnalystLog.Info(progress, $"Target Runtime restart: {rst.Message}", iterations);
                        if (!runtime.IsRemote)
                            await ArmDebuggerAsync(longLived);
                    }
                }
                else
                {
                    FuzzAnalystLog.Ok(progress, iteration: iterations);
                    if (result.Detail is not null and not "ok" and not "")
                        FuzzAnalystLog.Info(progress, $"Info: {result.Detail}", iterations);
                }
            }
        }
        finally
        {
            debuggerWait?.Dispose();
            procdumpArm?.Dispose();
            if (useCoverageTcp)
                stalk.StopLongLivedAsync(longLived, cancellationToken).GetAwaiter().GetResult();
            if (sysinternalsSnap is { AnyToolFound: true } || tcpvcon is { Available: true })
            {
                int? endPid = null;
                try
                {
                    if (longLived is { HasExited: false })
                        endPid = longLived.Id;
                }
                catch
                {
                    /* ignore */
                }

                if (sysinternalsSnap is { AnyToolFound: true })
                {
                    try
                    {
                        sysinternalsSnap.CaptureDisarm(endPid);
                        Console.WriteLine($"Sysinternals snapshots: {sysinternalsSnap.SnapshotDir}");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Sysinternals snapshots: {ex.Message}");
                    }
                    finally
                    {
                        sysinternalsSnap.Dispose();
                    }
                }
                else
                {
                    sysinternalsSnap?.Dispose();
                }

                if (tcpvcon is { Available: true })
                {
                    try
                    {
                        tcpvcon.CaptureDisarm(endPid);
                        Console.WriteLine($"TCPVCon snapshots: {tcpvcon.CaptureDir}");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"TCPVCon: {ex.Message}");
                    }
                    finally
                    {
                        tcpvcon.Dispose();
                    }
                }
                else
                {
                    tcpvcon?.Dispose();
                }
            }
            else
            {
                sysinternalsSnap?.Dispose();
                tcpvcon?.Dispose();
            }

            if (debugView is not null)
            {
                debugView.Stop();
                if (File.Exists(debugView.LogPath) && new FileInfo(debugView.LogPath).Length > 0)
                    Console.WriteLine($"DebugView log: {debugView.LogPath}");
                else if (debugView.LastError is not null)
                    Console.WriteLine($"DebugView: {debugView.LastError}");
                debugView.Dispose();
            }

            if (procmon is not null)
            {
                procmon.Stop();
                if (File.Exists(procmon.PmlPath))
                    Console.WriteLine($"Procmon saved: {procmon.PmlPath}");
                procmon.Dispose();
            }
            if (pktmon is not null)
            {
                pktmon.Stop();
                if (File.Exists(pktmon.EtlPath))
                    Console.WriteLine($"pktmon saved: {pktmon.EtlPath}");
                else if (pktmon.LastError is not null)
                    Console.WriteLine($"pktmon: {pktmon.LastError}");
                pktmon.Dispose();
            }
            runtime?.Dispose();
            if (inProcess is not null)
            {
                FuzzAnalystLog.Info(progress, $"Harness final: {inProcess.Stats.Format()}");
                inProcess.DisposeAsync().AsTask().GetAwaiter().GetResult();
            }
            if (persistentServer is not null)
                persistentServer.DisposeAsync().AsTask().GetAwaiter().GetResult();
            options.Progress?.OnTargetPid(null);
            journal?.Complete(iterations, crashCount, coverage.GetTopHotEdges());
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

    private sealed record CommandPayloadBuild(
        byte[] Payload,
        string? ParentHash,
        string SeedSource,
        List<string> SeedFiles);

    private static CommandPayloadBuild BuildCommandPayload(
        SessionGraph.PreparedCommand cmd,
        string yamlPath,
        IMutator mutator,
        Random rng,
        bool mutate,
        ProjectConfig project,
        FieldRegion? targetField = null)
    {
        var seedFiles = new List<string>();
        var seedSource = "sessionCommand";
        string? parentInputHash = null;

        if (!string.IsNullOrWhiteSpace(cmd.ModelPath))
        {
            var model = ProtocolLoader.Load(yamlPath, cmd.ModelPath);
            var protoSeeds = ProtocolLoader.LoadProtocolSeeds(yamlPath, cmd.ModelPath);
            seedFiles = protoSeeds.Keys.ToList();
            seedSource = "model";
            var baseline = model.Render(protoSeeds);
            parentInputHash = InputHash.StackHash(baseline);
            if (mutate)
            {
                return new CommandPayloadBuild(
                    ModelFuzzer.BuildPayload(
                        model, protoSeeds, mutator, rng,
                        project.Fuzz.SyncLengthFields, project.Fuzz.HavocDepth, targetField),
                    parentInputHash, seedSource, seedFiles);
            }
            return new CommandPayloadBuild(
                model.FinalizeMessage(baseline, project.Fuzz.SyncLengthFields),
                parentInputHash, seedSource, seedFiles);
        }

        parentInputHash = InputHash.StackHash(cmd.Seed);
        var body = mutate ? mutator.Mutate(cmd.Seed).ToArray() : cmd.Seed;
        return new CommandPayloadBuild(
            SessionGraph.BuildPayload(cmd, body),
            parentInputHash, seedSource, seedFiles);
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
