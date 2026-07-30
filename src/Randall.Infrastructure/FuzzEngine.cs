using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using Randall.Contracts;
using Randall.Core;
using Randall.Core.Model;
using Randall.Infrastructure.BugHunt;
using Randall.Infrastructure.Magician;
using Randall.Infrastructure.Mutators;
using Randall.Infrastructure.Oracles;

namespace Randall.Infrastructure;

public sealed class FuzzEngine
{
    public ObservationBus ObservationBus { get; private set; } = new();

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
        if (ExternalEngineCampaign.IsExternal(project.Fuzz.Engine))
            return await ExternalEngineCampaign.RunAsync(project, yamlPath, options, cancellationToken);

        var dryRun = options.DryRun;
        var coverageGuided = options.CoverageGuided || project.Fuzz.CoverageGuided;
        var maxIterations = options.MaxIterations ?? project.Fuzz.MaxIterations;
        var verbose = options.Verbose || project.Fuzz.Verbose;

        // Bug Hunter engine: analyze AI/human sources + suggest oracle/dict arming.
        // Oracle engine (below) remains judgment/reporting only.
        // Magician (after) casts spells / summons when Oracle needs intervention.
        _ = BugHunterEngine.PrepareForFuzz(project, yamlPath, options.Progress);
        _ = MagicianEngine.PrepareForFuzz(project, yamlPath, options.Progress);

        if (project.Fuzz.SyncCookies || ProjectKinds.IsHttp(project))
            HttpCookieSession.Begin();

        FuzzRunConsoleLog? consoleLog = null;
        try
        {
        ObservationBus = new ObservationBus();
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

        var repoRoot = CrashCatalog.FindRepoRoot();
        var brainMemory = BrainMemoryDecay.Ensure(project, yamlPath, repoRoot);
        if (brainMemory.LogLine is not null)
            Console.WriteLine(brainMemory.LogLine);

        var mutatorCredit = new MutatorCreditTracker(
            Path.Combine(corpusDir, "mutator_credit.txt"),
            project.Fuzz.MutatorCredit);
        var mutatorChainTracker = new MutatorChainTracker(
            Path.Combine(corpusDir, "mutator_chains.json"),
            project.Fuzz.MutatorCredit);
        var lineageByHash = new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase);
        string? lastPrimaryMutator = null;

        BrainDecisionStore.Clear();
        HuntPolicyStore.Clear();
        var brain = new RandallBrain();
        var brainSignals = brain.LoadSignals(project.Name, repoRoot);
        var brainActive = RandallBrain.ShouldActivate(project, brainSignals);
        NextHuntDecision? huntDecision = null;

        var coveragePath = Path.Combine(corpusDir, "edges.txt");
        var coverage = new CoverageSet(coveragePath);
        coverage.Load();

        var pathCoverage = new PathCoverageSet(Path.Combine(corpusDir, "paths.txt"));
        pathCoverage.Load();
        if (pathCoverage.Total > 0)
            FuzzAnalystLog.Info(options.Progress, $"Path stalk loaded — {pathCoverage.Total} known stages");

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
        string? runDir = null;
        if (project.Fuzz.ExecutionLog)
        {
            journal = FuzzRunJournal.Start(project, yamlPath, dryRun, coverageGuided, stalkBackend, stalkNote);
            runDir = journal.RunDirectory;
            Console.WriteLine($"Run journal: {journal.RunDirectory}");
        }
        else
        {
            // Still allocate a run folder so the primary console tee has a stable home.
            runDir = FuzzRunJournal.AllocateRunDirectory(project, yamlPath);
            Console.WriteLine($"Run folder: {runDir}");
        }
        consoleLog = FuzzRunConsoleLog.Attach(runDir);
        var runId = journal?.RunId ?? Path.GetFileName(runDir) ?? Guid.NewGuid().ToString("N");
        var useCoverage = coverageGuided && stalk.IsAvailable;
        var useCoverageFile = useCoverage &&
                              project.Kind.Equals("file", StringComparison.OrdinalIgnoreCase);
        var useCoverageTcp = useCoverage && project.Fuzz.CoverageTcpSpawn &&
                             ProjectKinds.IsTcpLike(project) &&
                             !string.IsNullOrWhiteSpace(project.Target.Executable);

        // Labs UI (or a prior Target Runtime) often already owns the listen port. Fighting that
        // with per-iteration drrun respawn + WaitUntilFree looks "stuck" (5s/iter silence) until
        // Ctrl+C cancels the wait — then the next Start appears to "kick start" fuzzing.
        var fuzzExistingListener = false;
        if (useCoverageTcp && project.Transport.Port > 0)
        {
            var listenHost = string.IsNullOrWhiteSpace(project.Transport.Host)
                ? "127.0.0.1"
                : project.Transport.Host;
            if (PortReadiness.Probe(listenHost, project.Transport.Port, project.Kind))
            {
                useCoverageTcp = false;
                fuzzExistingListener = true;
                FuzzAnalystLog.Warn(options.Progress,
                    $"Coverage-TCP respawn disabled — {listenHost}:{project.Transport.Port} already accepting " +
                    "(lab/target running). Fuzzing the existing listener. Uncheck Coverage-guided or stop the lab " +
                    "to spawn DynamoRIO-instrumented copies per case.");
            }
        }

        var progress = options.Progress;
        progress?.OnStarted(project.Name, project.Kind);
        if (brainActive)
        {
            FuzzAnalystLog.Info(progress, $"Brain on — {brainSignals.SummaryLine}");
        }
        else if (project.Fuzz.Brain)
        {
            FuzzAnalystLog.Info(progress,
                "Brain armed — waiting for frontier/static/oracle/scream signals (soft no-op until data exists)");
        }
        FuzzAnalystLog.Info(progress,
            $"Fuzzing '{project.Name}' ({project.Kind}) — max {maxIterations} iterations" +
            (dryRun ? " [dry-run]" : "") +
            (verbose ? " [verbose]" : ""));
        FuzzAnalystLog.Info(progress, $"Fuzz console log → {consoleLog.Path}");
        if (verbose)
            LogVerboseEngineBanner(project, progress, coverageGuided, useCoverage);

        var debuggerMode = (options.DebuggerMode ?? project.Fuzz.DebuggerMode ?? "none")
            .Trim().ToLowerInvariant();
        var debuggerKind = options.DebuggerKind ?? project.Fuzz.DebuggerKind ?? "auto";
        var debuggerOpenOnCrash = options.DebuggerOpenOnCrash ?? project.Fuzz.DebuggerOpenOnCrash;
        DebuggerWaitHandle? debuggerWait = null;

        ProcmonCapture? procmon = null;
        TcpvconCapture? tcpvcon = null;
        PktmonCapture? pktmon = null;
        TsharkCapture? tshark = null;
        EtwCapture? etw = null;
        ProcDumpCrashArm? procdumpArm = null;
        DebugViewCapture? debugView = null;
        SysinternalsSnapshots? sysinternalsSnap = null;
        var wantProcmon = options.ProcmonCapture ?? project.Fuzz.ProcmonCapture;
        var wantTcpvcon = options.TcpvconCapture ?? project.Fuzz.TcpvconCapture;
        var wantProcdump = options.ProcdumpOnCrash ?? project.Fuzz.ProcdumpOnCrash;
        var wantPktmon = options.PktmonCapture ?? project.Fuzz.PktmonCapture;
        var wantTshark = options.TsharkCapture ?? project.Fuzz.TsharkCapture;
        var wantEtw = options.EtwCapture ?? project.Fuzz.EtwCapture;
        var wantDebugView = options.DebugViewCapture ?? project.Fuzz.DebugViewCapture;
        var wantSysinternalsSnap = options.SysinternalsSnapshots ?? project.Fuzz.SysinternalsSnapshots;
        var wantStringsOnCrash = options.StringsOnCrash ?? project.Fuzz.StringsOnCrash;
        var wantCdbAnalyze = options.CdbAnalyzeCrash ?? project.Fuzz.CdbAnalyzeCrash;
        if (!dryRun && (wantProcmon || wantTcpvcon || wantPktmon || wantTshark || wantEtw || wantDebugView || wantSysinternalsSnap))
            Directory.CreateDirectory(runDir!);

        string? targetExeResolved = null;
        if (!string.IsNullOrWhiteSpace(project.Target.Executable))
        {
            try
            {
                var declared = ProjectLoader.ResolvePath(yamlPath, project.Target.Executable);
                targetExeResolved = ExecutableResolver.FindExisting(declared) ?? declared;
            }
            catch
            {
                targetExeResolved = project.Target.Executable;
            }
        }

        var preflightError = FuzzPreflight.ValidateTargetExecutable(project, yamlPath, dryRun);
        if (preflightError is not null)
        {
            FuzzAnalystLog.Warn(progress, preflightError);
            throw new InvalidOperationException(preflightError);
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

        if (!dryRun && wantTshark && runDir is not null)
        {
            string? filterHost = null;
            var filterPort = 0;
            if (ProjectKinds.IsTcpLike(project) || ProjectKinds.IsUdp(project) ||
                project.Transport.Type is "tcp" or "udp" or "http" or "https")
            {
                filterHost = project.Transport.Host;
                filterPort = project.Transport.Port;
            }

            tshark = TsharkCapture.TryStart(runDir, filterHost, filterPort);
            if (tshark.IsRunning)
                FuzzAnalystLog.Info(progress,
                    $"tshark capture → {tshark.PcapPath}" +
                    (tshark.CaptureFilter is not null ? $" (filter: {tshark.CaptureFilter})" : ""));
            else
                FuzzAnalystLog.Warn(progress,
                    $"tshark capture skipped: {tshark.LastError ?? "tshark not available"}");
        }

        if (!dryRun && wantEtw && runDir is not null)
        {
            etw = EtwCapture.TryStart(runDir);
            if (etw?.IsRunning == true)
                FuzzAnalystLog.Info(progress, $"ETW/WPR capture → {etw.EtlPath}");
            else
                FuzzAnalystLog.Warn(progress,
                    $"ETW/WPR capture skipped: {etw?.LastError ?? "wpr not available"}");
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
        TargetGenerationDto? currentGeneration = null;
        DateTimeOffset? lastSendStartedUtc = null;
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
            else if (OperatingSystem.IsLinux() && (project.Fuzz.ForkServer ?? false)
                     && persistentServer.Mode.Contains("forksrv", StringComparison.OrdinalIgnoreCase))
                FuzzAnalystLog.Info(progress,
                    "forkServer on Linux = AFL classic FORKSRV_FD (198/199)");
        }
        else if (!useCoverageTcp && project.Target.LongLived &&
            (ProjectKinds.IsTcpLike(project) || ProjectKinds.IsUdp(project)))
        {
            runtime = new TargetRuntimeBridge(project, yamlPath);
            Process? proc = null;
            TargetRuntimeStatusDto? st = null;
            if (fuzzExistingListener)
            {
                proc = TryAdoptPortListener(project, targetExeResolved);
                if (proc is not null)
                {
                    FuzzAnalystLog.Info(progress,
                        $"Adopted lab listener PID {proc.Id} on {project.Transport.Host}:{project.Transport.Port} " +
                        "(Scream will attach — stop orphan labs to avoid wrong PID)");
                }
            }

            if (proc is null)
            {
                FuzzAnalystLog.Step(progress, "Starting target (Target Runtime)");
                (proc, st) = await runtime.StartAsync(cancellationToken);
                if (!st.Ok && !st.Running)
                {
                    proc = TryAdoptPortListener(project, targetExeResolved);
                    if (proc is null)
                        throw new InvalidOperationException($"Target Runtime start failed: {st.Message}");
                    FuzzAnalystLog.Warn(progress,
                        $"Target Runtime start failed ({st.Message}); adopted listener PID {proc.Id}");
                }
                else
                {
                    FuzzAnalystLog.Info(progress, runtime.IsRemote
                        ? $"Target Runtime (agent {runtime.AgentUrl}): {st!.Message}"
                        : $"Target Runtime (local): {st!.Message}");
                }
            }

            longLived = proc;
            if (runtime.IsRemote)
                FuzzAnalystLog.Info(progress, "Debugger attach skipped on remote agent (dumps stay on agent host)");
            else
                await ArmDebuggerAsync(longLived);
        }

        async Task<Process?> RestartLongLivedAsync(int iteration)
        {
            if (runtime is null)
                return longLived;

            FuzzAnalystLog.Warn(progress,
                "Cannot reach target or process died; restarting via Target Runtime…",
                iteration);
            FuzzAnalystLog.Step(progress, "Restarting target", iteration);
            Process? proc = null;
            TargetRuntimeStatusDto? rst = null;
            for (var attempt = 0; attempt < 3; attempt++)
            {
                await Task.Delay(300 + attempt * 400, cancellationToken);
                (proc, rst) = await runtime.RestartAsync(cancellationToken);
                if (rst is { Ok: false } && rst.Message.Contains("No runtime slot", StringComparison.OrdinalIgnoreCase))
                    (proc, rst) = await runtime.StartAsync(cancellationToken);
                if (rst.Ok && (runtime.IsRemote || proc is { HasExited: false }))
                    break;
                FuzzAnalystLog.Warn(progress,
                    $"Target Runtime restart attempt {attempt + 1}/3: {rst.Message}",
                    iteration);
            }

            FuzzAnalystLog.Info(progress,
                $"Target Runtime restart: {rst?.Message ?? "(no status)"}", iteration);
            if (rst is { Ok: false } || (!runtime.IsRemote && proc is null or { HasExited: true }))
            {
                FuzzAnalystLog.Warn(progress,
                    "Target did not come back — stop labs/orphans on the project port, then retry",
                    iteration);
                return proc;
            }

            if (!runtime.IsRemote)
                await ArmDebuggerAsync(proc);
            return proc;
        }

        async Task ArmDebuggerAsync(Process? proc)
        {
            debuggerWait?.Dispose();
            debuggerWait = null;
            if (proc is null || proc.HasExited || dryRun)
                return;

            // New target generation on every successful start/restart (prevents PID-reuse dump joins).
            try
            {
                if (currentGeneration?.DumpReservationId is Guid oldRid)
                    CrashArtifactIdentityService.ExpireIfUnclaimed(crashesDir, oldRid);

                currentGeneration = CrashArtifactIdentityService.BeginGeneration(
                    project.Name,
                    journal?.RunId ?? runId,
                    proc,
                    targetExeResolved,
                    crashesDir);
                FuzzAnalystLog.Info(progress,
                    $"Target generation {currentGeneration.TargetGenerationId:N} pid={proc.Id}");
            }
            catch (Exception genEx)
            {
                currentGeneration = null;
                FuzzAnalystLog.Warn(progress, $"Target generation stamp failed: {genEx.Message}");
            }

            FuzzProgressGuard.Try(options.Progress, p => p.OnTargetPid(proc.Id));
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

            // Only one debugger can attach. "both" = same Scream wait as "wait"; GUI open is debuggerOpenOnCrash only.
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
                    if (currentGeneration?.DumpReservationId is Guid rid)
                    {
                        CrashArtifactIdentityService.MarkTriggered(crashesDir, rid);
                        if (!string.IsNullOrWhiteSpace(scream.DumpPath))
                            CrashArtifactIdentityService.UpdateArmedDumpPath(crashesDir, rid, scream.DumpPath);
                    }

                    var attached = await scream.WaitUntilAttachedAsync(TimeSpan.FromSeconds(5), cancellationToken);
                    Console.WriteLine(attached
                        ? $"  scream ready ({(scream.IsWow64 ? "wow64" : "x64")}) → {scream.DumpPath}"
                        : $"  scream attach/ready failed: {scream.LastError ?? scream.Phase}");
                    if (!attached)
                    {
                        FuzzAnalystLog.Warn(progress,
                            $"Scream attach/ready failed: {scream.LastError ?? scream.Phase} — " +
                            "dumps will be empty; close other debuggers or run elevated");
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

        static Process? TryAdoptPortListener(ProjectConfig project, string? targetExe)
        {
            if (!OperatingSystem.IsWindows() || project.Transport.Port <= 0)
                return null;

            var wantName = string.IsNullOrWhiteSpace(targetExe)
                ? null
                : Path.GetFileNameWithoutExtension(targetExe);
            foreach (var pid in ProcessTreeKill.FindListeningPids(project.Transport.Port, project.Kind))
            {
                try
                {
                    var proc = Process.GetProcessById(pid);
                    if (proc.HasExited)
                        continue;
                    if (wantName is not null &&
                        !proc.ProcessName.Equals(wantName, StringComparison.OrdinalIgnoreCase))
                        continue;
                    return proc;
                }
                catch
                {
                    /* try next pid */
                }
            }

            foreach (var pid in ProcessTreeKill.FindListeningPids(project.Transport.Port, project.Kind))
            {
                try
                {
                    var proc = Process.GetProcessById(pid);
                    if (!proc.HasExited)
                        return proc;
                }
                catch
                {
                    /* ignore */
                }
            }

            return null;
        }

        async Task<string?> TakeWaitDumpAsync(string? existingDump)
        {
            existingDump = CrashDumpPaths.Sanitize(existingDump);
            if (debuggerWait is null)
                return existingDump;
            try
            {
                var dump = CrashDumpPaths.Sanitize(await DebuggerSession.WaitForDumpAsync(
                    debuggerWait, Math.Max(project.Target.TimeoutMs, 5000), cancellationToken));
                if (dump is not null)
                {
                    if (currentGeneration?.DumpReservationId is Guid rid)
                        CrashArtifactIdentityService.MarkDumpMaterialized(crashesDir, rid, dump);
                    Console.WriteLine($"  debugger dump: {dump}");
                    return dump;
                }
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) when (BenignRecorderPipeException.IsBenign(ex))
            {
                Console.WriteLine($"  debugger wait (hub/recorder noise): {ex.Message}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  debugger wait: {ex.Message}");
            }

            if (debuggerWait.Scream?.ExceptionInfo is not null && existingDump is null)
                FuzzAnalystLog.Warn(progress,
                    "Scream saw a crash but minidump write failed — check SeDebug / close other debuggers");

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
        OracleSessionTracker? oracleSession = null;
        if (OracleEngine.IsEnabled(project) && project.Oracles is { } ocfg)
        {
            oracleSession = new OracleSessionTracker();
            oracleSession.ConfigureAuthMarkers(ocfg);
            FuzzAnalystLog.Info(progress,
                $"Oracles on — auth={ocfg.Auth.Count} state={ocfg.State.Count} " +
                $"integer={ocfg.Integer.Count} structure={ocfg.Structure.Count} resource={ocfg.Resource.Count}");
        }

        JokerCardDeck? jokerDeck = null;
        if (JokerEngine.IsEnabled(project) || project.Joker?.DeckEnabled == true)
        {
            var mageDir = Path.Combine(crashesDir, "_magician");
            Directory.CreateDirectory(mageDir);
            jokerDeck = new JokerCardDeck(JokerCardDeck.DefaultPath(mageDir));
        }

        var stopGoals = IntelligenceStopGoalEvaluator.Resolve(project.Fuzz);
        var stopGoalReached = false;
        string? stopReason = null;
        var lastObservedNewEdges = 0;
        var lastObservedUniqueCrashes = 0;

        try
        {
            for (var i = 0; i < maxIterations && !cancellationToken.IsCancellationRequested && !stopGoalReached; i++)
            {
                try
                {
                iterations++;
                JokerTrick? jokerTrick = null;
                var iterFlowBias = flowBias;
                var iterGraphBias = project.Fuzz.SessionGraphBias;
                var uniqueCrashThisIter = false;
                HypothesisExperimentPlan? hypothesisPlan = null;
                IMutator mutator;
                if (brainActive)
                {
                    var coverageFraction = brainSignals.StaticHints?.CoverageSummary?.CoverageFraction ?? 0;
                    if (coverageFraction <= 0 && coverage.TotalEdges > 0)
                        coverageFraction = Math.Min(1.0, coverage.TotalEdges / 5000.0);

                    huntDecision = brain.Decide(
                        project.Name,
                        brainSignals,
                        mutatorCredit.SnapshotRows(),
                        mutators,
                        iterations,
                        repoRoot,
                        chainRows: mutatorChainTracker.SnapshotRows(),
                        memoryConfidence: brainMemory.MemoryConfidence,
                        coverageFraction: coverageFraction,
                        baseJokerChance: JokerEngine.EffectiveChance(project));
                    brain.PersistLast(huntDecision, repoRoot);
                    if (verbose)
                    {
                        FuzzAnalystLog.Info(progress, RandallBrain.FormatVerbose(huntDecision), iterations);
                        if (huntDecision.HuntPolicy is not null)
                            FuzzAnalystLog.Info(progress, HuntPolicyEngine.FormatVerbose(huntDecision.HuntPolicy), iterations);
                    }

                    if (huntDecision.HuntPolicy is { NeedsExperiment: true })
                    {
                        MagicianEngine.OnHuntPolicyNeedsExperiment(
                            project, yamlPath, huntDecision.HuntPolicy, iterations, progress);
                    }

                    if (huntDecision.HuntPolicy is { NeedsExperiment: true }
                        or { TopHypothesisConfidence: >= HypothesisEngine.MinExperimentConfidence })
                    {
                        hypothesisPlan = HypothesisEngine.TryDequeuePlan(project.Name, repoRoot);
                    }
                }

                if (HuntPolicyEngine.ShouldInvokeJoker(huntDecision?.HuntPolicy, project, rng) && mutators.Count > 0)
                {
                    jokerTrick = JokerEngine.StartTrick(project, mutators, rng, jokerDeck);
                    mutator = jokerTrick.PrimaryMutator;
                    if (jokerTrick.FlowBiasOverride is double fb)
                        iterFlowBias = fb;
                    if (jokerTrick.GraphBiasOverride is double gb)
                        iterGraphBias = gb;
                    if (verbose)
                    {
                        FuzzAnalystLog.Info(progress,
                            $"Joker plays [{jokerTrick.TrickName}] id={jokerTrick.Id} " +
                            $"primary={jokerTrick.PrimaryMutator.Name} chaos={jokerTrick.ChaosLevel} " +
                            $"wild={jokerTrick.WildBytes} " +
                            $"flowBias={(jokerTrick.FlowBiasOverride is double f ? f.ToString("0.00") : "-")} " +
                            $"graphBias={(jokerTrick.GraphBiasOverride is double g ? g.ToString("0.00") : "-")}",
                            iterations);
                    }
                }
                else if (brainActive && huntDecision is { Active: true })
                {
                    mutator = brain.PickMutator(huntDecision, mutators, mutatorCredit, rng,
                        mutatorChainTracker, lastPrimaryMutator);
                }
                else
                {
                    mutator = mutatorChainTracker.BlendPick(mutators, mutatorCredit, lastPrimaryMutator, rng);
                }
                TargetRunner.TcpSendOptions? tcpOptions = null;
                string commandName = "default";
                byte[] payload;
                string? parentInputHash = null;
                string seedSource = "unknown";
                var seedFiles = new List<string>();
                IReadOnlyList<TargetRunner.TcpStep>? tcpSequence = null;
                List<string>? oracleFlowPriorCommands = null;
                List<string?>? oracleFlowPriorExpects = null;
                var useResponseGraph = false;

                if (exhaustive && plannedCases is { Count: > 0 })
                {
                    var caseIndex = (iterations - 1) % plannedCases.Count;
                    var planned = plannedCases[caseIndex];
                    mutator = planned.Mutator;
                    commandName = planned.Label;

                    if (planned.Flow is not null && planned.Command is not null)
                    {
                        if (planned.Flow.Steps.Count == 0
                            || planned.FlowStepIndex < 0
                            || planned.FlowStepIndex >= planned.Flow.Steps.Count)
                        {
                            throw new ArgumentOutOfRangeException(
                                nameof(planned.FlowStepIndex),
                                planned.FlowStepIndex,
                                $"Invalid flow step index for '{planned.Label}' " +
                                $"(steps={planned.Flow.Steps.Count}) — skipping case");
                        }

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
                        if (planned.FlowStepIndex > 0)
                        {
                            oracleFlowPriorCommands = planned.Flow.Steps
                                .Take(planned.FlowStepIndex)
                                .Select(c => c.Name)
                                .ToList();
                            oracleFlowPriorExpects = planned.Flow.Steps
                                .Take(planned.FlowStepIndex)
                                .Select(c => c.ExpectResponse)
                                .ToList()!;
                        }
                        commandName = planned.Command.Name;
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
                            model, protoSeeds, mutator, rng, project.Fuzz, planned.TargetField);
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
                else if (hypothesisPlan?.CrashInputPath is { } hypInput && File.Exists(hypInput))
                {
                    var basePayload = File.ReadAllBytes(hypInput);
                    payload = HypothesisEngine.ApplyExperiment(
                               basePayload, hypothesisPlan.Experiment, hypothesisPlan.SweepIndex, rng, mutators)
                           ?? basePayload;
                    parentInputHash = InputHash.StackHash(basePayload);
                    seedSource = $"hypothesis/{hypothesisPlan.HypothesisId}";
                    if (!string.IsNullOrWhiteSpace(hypothesisPlan.Experiment.Mutator))
                    {
                        var hypMut = mutators.FirstOrDefault(m =>
                            m.Name.Equals(hypothesisPlan.Experiment.Mutator, StringComparison.OrdinalIgnoreCase));
                        if (hypMut is not null)
                            mutator = hypMut;
                    }
                    if (verbose)
                    {
                        FuzzAnalystLog.Info(progress,
                            $"[hypothesis] {hypothesisPlan.HypothesisId} " +
                            $"{hypothesisPlan.Experiment.Kind} conf={hypothesisPlan.ConfidencePercent}% " +
                            $"sweep={hypothesisPlan.SweepIndex}",
                            iterations);
                    }
                }
                else if (project.SessionGraph is not null &&
                         commandsByName.Count > 0 &&
                         ProjectKinds.IsTcpLike(project) &&
                         rng.NextDouble() < iterGraphBias)
                {
                    useResponseGraph = true;
                    commandName = "graph";
                    payload = Array.Empty<byte>();
                    seedSource = "sessionGraph";
                }
                else if (sessionCommands.Count > 0 &&
                    sessionFlows.Count > 0 &&
                    rng.NextDouble() < iterFlowBias)
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
                    commandName = $"flow/{flow.Name}/{flow.Steps[^1].Name}";
                    seedSource = "sessionFlow";
                    if (flow.Steps.Count > 1)
                    {
                        var priors = flow.Steps.Take(flow.Steps.Count - 1).ToList();
                        oracleFlowPriorCommands = priors.Select(c => c.Name).ToList();
                        oracleFlowPriorExpects = priors.Select(c => c.ExpectResponse).ToList();
                    }
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
                        model, protoSeeds, mutator, rng, project.Fuzz);
                    commandName = $"model/{model.Name}";
                    parentInputHash = InputHash.StackHash(model.Render(protoSeeds));
                    seedSource = "model";
                    seedFiles = protoSeeds.Keys.ToList();
                }
                else
                {
                    var corpusBias = huntDecision?.CorpusPriorityBias ?? 0.65;
                    var seed = corpus.PickSeed(seeds, rng, powerSchedule, corpusBias);
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
                if (jokerTrick is not null && payload.Length > 0)
                {
                    payload = JokerEngine.FinishTrick(
                        jokerTrick, payload, mutators, rng, JokerEngine.GetConfig(project));
                    mutatorChain = jokerTrick.MutatorChain.ToList();
                    seedSource = seedSource.StartsWith("joker", StringComparison.Ordinal)
                        ? seedSource
                        : $"joker/{seedSource}";
                    if (verbose)
                    {
                        FuzzAnalystLog.Info(progress,
                            $"Joker finished [{jokerTrick.TrickName}] chain={string.Join('→', mutatorChain)} " +
                            $"payload={payload.Length}B detail={jokerTrick.Detail}",
                            iterations);
                    }
                }
                var payloadHash = InputHash.StackHash(payload);
                var fullLineageChain = LineageChainBuilder.BuildFromParent(
                    parentInputHash, lineageByHash, mutatorChain);
                lineageByHash[payloadHash] = fullLineageChain;
                var sw = Stopwatch.StartNew();
                string? iterTracePath = null;

                if (dryRun)
                {
                    var dryLabel = jokerTrick is null
                        ? $"{commandName}/{mutator.Name}"
                        : $"{commandName}/joker:{jokerTrick.TrickName}";
                    FuzzAnalystLog.Case(progress, iterations, dryLabel);
                    FuzzAnalystLog.Step(progress, $"Fuzzing node '{commandName}'", iterations);
                    FuzzAnalystLog.Tx(progress, payload, iterations, verbose ? 64 : 24);
                    sw.Stop();
                    journal?.LogIteration(new IterationLogEntry(
                        iterations, DateTimeOffset.UtcNow, commandName, mutator.Name, mutatorChain,
                        parentInputHash, seedSource, payload.Length, InputHash.StackHash(payload),
                        false, 0, coverage.TotalEdges, sw.ElapsedMilliseconds, "dry-run", null,
                        stalkBackend, null, journal?.RunId ?? "", true));
                    FuzzProgressGuard.Try(progress, p => p.OnIteration(new FuzzIterationEvent(
                        iterations, dryLabel, payload.Length, false, false, 0, corpus.SeenCount, coverage.TotalEdges, "dry-run",
                        CoverageBlocks: coverage.TotalEdges,
                        SemanticStageHits: pathCoverage.Total,
                        CoverageKind: DescribeCoverageKind(coverage.TotalEdges, pathCoverage.Total, coverageGuided))));
                    FuzzAnalystLog.Ok(progress, "Check OK: dry-run (not sent).", iterations);
                    mutatorCredit.Record(mutator.Name, 0, uniqueCrash: false);
                    mutatorChainTracker.RecordLineage(fullLineageChain, newEdges: 0, uniqueCrash: false);
                    lastPrimaryMutator = mutator.Name;
                    RecordScareDoorProgress(project.Name, repoRoot ?? "", iterations, mutator.Name, parentInputHash, 0, false, coverage.TotalEdges);
                    continue;
                }

                if (useCoverageTcp)
                {
                    await stalk.StopLongLivedAsync(longLived, cancellationToken);
                    longLived = null;
                    var covHost = string.IsNullOrWhiteSpace(project.Transport.Host)
                        ? "127.0.0.1"
                        : project.Transport.Host;
                    var covPort = project.Transport.Port;

                    // Lab / prior listener already accepting — do NOT WaitUntilFree (looks stuck for 5–10s).
                    if (covPort > 0 && PortReadiness.Probe(covHost, covPort, project.Kind))
                    {
                        useCoverageTcp = false;
                        FuzzAnalystLog.Warn(progress,
                            $"Coverage-TCP: {covHost}:{covPort} already accepting — fuzzing existing listener " +
                            "(no per-case DynamoRIO spawn). Stop Labs or uncheck Coverage-guided for BB edges.",
                            iterations);
                        if (runtime is null && project.Target.LongLived)
                        {
                            try
                            {
                                runtime = new TargetRuntimeBridge(project, yamlPath);
                                var adopted = TryAdoptPortListener(project, targetExeResolved);
                                if (adopted is not null)
                                {
                                    longLived = adopted;
                                    FuzzAnalystLog.Info(progress,
                                        $"Adopted lab listener PID {adopted.Id}", iterations);
                                }
                                else
                                {
                                    var (proc, st) = await runtime.StartAsync(cancellationToken);
                                    if (st.Ok || st.Running)
                                    {
                                        longLived = proc;
                                        FuzzAnalystLog.Info(progress,
                                            $"Adopted Target Runtime: {st.Message}", iterations);
                                    }
                                }

                                if (longLived is not null && !runtime.IsRemote)
                                    await ArmDebuggerAsync(longLived);
                            }
                            catch (Exception ex)
                            {
                                FuzzAnalystLog.Warn(progress,
                                    $"Could not adopt Target Runtime: {ex.Message}", iterations);
                            }
                        }
                    }
                    else if (covPort > 0)
                    {
                        // DynamoRIO teardown can leave the listen port busy briefly — wait before respawn.
                        if (iterations <= 1 || iterations % 10 == 0)
                        {
                            FuzzAnalystLog.Info(progress,
                                $"Coverage-TCP: waiting for {covHost}:{covPort} to free before drrun spawn…",
                                iterations);
                        }

                        var freed = await PortReadiness.WaitUntilFreeAsync(
                            covHost, covPort, project.Kind, TimeSpan.FromSeconds(5), cancellationToken);
                        if (!freed && PortReadiness.Probe(covHost, covPort, project.Kind))
                        {
                            useCoverageTcp = false;
                            FuzzAnalystLog.Warn(progress,
                                $"Coverage-TCP: {covHost}:{covPort} still accepting — switching to existing listener " +
                                "(no more per-case drrun respawn; BB graph will stay empty until DynamoRIO spawn works)",
                                iterations);
                        }
                    }

                    if (useCoverageTcp)
                    {
                        longLived = stalk.StartLongLivedTarget(project, yamlPath, traceDir);
                        if (longLived is null)
                        {
                            FuzzAnalystLog.Warn(progress,
                                "Coverage TCP spawn failed — drrun did not start the target. " +
                                "Check `randall doctor` DynamoRIO; graph falls back to corpus-novelty / session path.",
                                iterations);
                            useCoverageTcp = false;
                            continue;
                        }

                        // Cold drrun+drcov often needs >500ms before accept(); poll instead of sleeping.
                        // If something else is already accepting, WaitAsync returns immediately.
                        var ready = covPort <= 0 || await PortReadiness.WaitAsync(
                            covHost, covPort, project.Kind, TimeSpan.FromSeconds(10), cancellationToken);
                        if (!ready)
                        {
                            FuzzAnalystLog.Warn(progress,
                                $"Coverage TCP spawn: {covHost}:{covPort} not accepting within 10s — " +
                                "DynamoRIO spawn failed (port busy or target crashed). Disabling per-case coverage spawn.",
                                iterations);
                            await stalk.StopLongLivedAsync(longLived, cancellationToken);
                            longLived = null;
                            useCoverageTcp = false;
                            continue;
                        }

                        if (longLived is not null && (runtime is null || !runtime.IsRemote))
                            await ArmDebuggerAsync(longLived);
                    }
                }

                var caseLabel = jokerTrick is null
                    ? $"{commandName}/{mutator.Name}"
                    : $"{commandName}/joker:{jokerTrick.TrickName}";
                FuzzAnalystLog.Case(progress, iterations, caseLabel);
                if (ProjectKinds.IsTcpLike(project) || ProjectKinds.IsUdp(project))
                {
                    FuzzAnalystLog.Info(progress,
                        $"Opening target connection to {project.Transport.Host}:{project.Transport.Port}…",
                        iterations);
                }

                FuzzAnalystLog.Step(progress, $"Fuzzing node '{commandName}'", iterations);
                FuzzAnalystLog.Tx(progress, payload, iterations, verbose ? 64 : 24);
                lastSendStartedUtc = DateTimeOffset.UtcNow;

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
                var pluginAbortDetail = pluginAbort;
                if (pluginAbort is not null && !result.Crashed)
                    result = result with { Detail = $"post_receive: {pluginAbort}" };

                // Remote agent: no local Process handle — poll Target Runtime for death.
                // Local longLived: also promote death when TargetRunner returned a soft mismatch.
                if (!result.Crashed && runtime is not null &&
                    await runtime.HasExitedAsync(longLived, cancellationToken))
                {
                    var st = await runtime.StatusAsync(cancellationToken);
                    result = result with
                    {
                        Crashed = true,
                        ExitCode = st.LastExitCode ?? (longLived is { HasExited: true } ? longLived.ExitCode : null),
                        Detail = runtime.IsRemote
                            ? "remote target exited (Target Runtime)"
                            : (result.Detail is { Length: > 0 }
                                ? $"server exited; {result.Detail}"
                                : "server exited"),
                    };
                }
                else if (!result.Crashed && longLived is { HasExited: true } &&
                         !TargetRunner.IsInfrastructureExitCode(longLived.ExitCode))
                {
                    result = result with
                    {
                        Crashed = true,
                        ExitCode = longLived.ExitCode,
                        Detail = result.Detail is { Length: > 0 }
                            ? $"server exited; {result.Detail}"
                            : "server exited",
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
                        if (newEdges == 0 && CoverageBackendResolver.ShouldIngestSancov(project))
                            newEdges = SanitizerCoverageBackend.TryIngestTraceDirectory(coverage, traceDir);
                        newCoverage = newEdges > 0;
                        if (newCoverage && !result.Crashed)
                        {
                            corpus.AddPriority(payload);
                            corpusAdded++;
                            ApplyGhidraStaticBias(project, corpus, payload, newEdges, verbose, progress, iterations);
                            ApplyBrainEnergyBoost(huntDecision, corpus, payload, verbose, progress, iterations);
                        }
                    }
                }
                else if (useCoverageFile)
                {
                    var covRun = await stalk.RunFileTargetAsync(
                        project, yamlPath, payload, traceDir, cancellationToken);
                    iterTracePath = covRun.TracePath;
                    newEdges = coverage.RegisterTrace(covRun.TracePath);
                    if (newEdges == 0 && CoverageBackendResolver.ShouldIngestSancov(project))
                        newEdges = SanitizerCoverageBackend.TryIngestTraceDirectory(coverage, traceDir);
                    newCoverage = newEdges > 0;
                    if (newCoverage && !result.Crashed)
                    {
                        corpus.AddPriority(payload);
                        corpusAdded++;
                        ApplyGhidraStaticBias(project, corpus, payload, newEdges, verbose, progress, iterations);
                        ApplyBrainEnergyBoost(huntDecision, corpus, payload, verbose, progress, iterations);
                    }

                    // Dragon Dance sidecar: binary drcov (no -dump_text) on novel / crash
                    if (project.Fuzz.CaptureBinaryDrcov && (newCoverage || result.Crashed) &&
                        stalk.BackendId == StalkBackend.External)
                    {
                        try
                        {
                            var bin = await BinaryDrcovCapture.CaptureFileAsync(
                                project, yamlPath, payload, cancellationToken: cancellationToken);
                            if (bin.Success)
                                FuzzAnalystLog.Info(progress,
                                    $"binary drcov (Dragon Dance) → {Path.GetFileName(bin.TracePath)}",
                                    iterations);
                        }
                        catch (Exception ex)
                        {
                            FuzzAnalystLog.Info(progress,
                                $"binary drcov sidecar skipped: {ex.Message}", iterations);
                        }
                    }
                }
                else if (!result.Crashed && corpus.IsNew(payload))
                {
                    corpus.SaveInteresting(payload, "corpus");
                    corpusAdded++;
                }

                payloadHash = InputHash.StackHash(payload);
                if (result.PathHits is { Count: > 0 } hits)
                {
                    var novelPaths = pathCoverage.Add(hits);
                    if (novelPaths > 0)
                    {
                        newCoverage = true;
                        newEdges += novelPaths;
                        if (!result.Crashed)
                        {
                            if (corpus.IsNew(payload))
                            {
                                corpus.SaveInteresting(payload, "paths");
                                corpusAdded++;
                            }
                            corpus.BoostEnergy(payload, Math.Min(10, 2 + novelPaths));
                            FuzzAnalystLog.Info(progress,
                                $"+{novelPaths} path(s) → total {pathCoverage.Total} " +
                                $"[{string.Join(',', hits.Take(10))}{(hits.Count > 10 ? ",…" : "")}]",
                                iterations);
                        }

                        ObservationBus.Publish(ObservationEvents.Path(
                            runId, iterations, payloadHash, novelPaths, pathCoverage.Total, project.Name));
                    }
                }

                if (newEdges > 0)
                {
                    ObservationBus.Publish(ObservationEvents.Coverage(
                        runId, iterations, payloadHash, newEdges, coverage.TotalEdges, project.Name));
                }

                await RppObserveHook.RunAsync(
                    project,
                    yamlPath,
                    ObservationBus,
                    runId,
                    iterations,
                    payloadHash,
                    payload,
                    newEdges,
                    coverage.TotalEdges,
                    result.Detail,
                    cancellationToken);

                // Hybrid semantic oracle stack — supplements coverage (docs/ORACLES.md).
                OracleEvalResult? oracleEval = null;
                if (OracleEngine.IsEnabled(project))
                {
                    var expectPattern = tcpOptions?.ExpectResponse
                        ?? tcpSequence?.LastOrDefault()?.Options.ExpectResponse;
                    // Credit prior PDUs on this connection before evaluating the mutated step.
                    if (oracleSession is not null && oracleFlowPriorCommands is not null)
                    {
                        for (var pi = 0; pi < oracleFlowPriorCommands.Count; pi++)
                        {
                            var exp = oracleFlowPriorExpects is { Count: > 0 } && pi < oracleFlowPriorExpects.Count
                                ? oracleFlowPriorExpects[pi]
                                : null;
                            oracleSession.NotePriorStep(oracleFlowPriorCommands[pi], exp);
                        }
                    }
                    var oracleObs = new OracleObservation(
                        project, yamlPath, payload, result, commandName, mutator.Name,
                        iterations, newEdges, coverage.TotalEdges, pluginAbortDetail, expectPattern,
                        oracleSession);
                    oracleEval = await OracleEngine.EvaluateAsync(oracleObs, cancellationToken);
                    ObservationBus.Publish(ObservationEvents.OracleEval(
                        runId, iterations, payloadHash, oracleEval.Score,
                        oracleEval.MaxSeverity.ToString().ToLowerInvariant(),
                        oracleEval.Findings.Count, oracleEval.Summary, project.Name));
                    // Advance session facts after evaluation (so pre-auth checks see prior iters only).
                    oracleSession?.Observe(commandName, result);
                    OracleEngine.PersistFindings(project, yamlPath, oracleEval);
                    if (MagicianEngine.IsEnabled(project))
                    {
                        var cast = MagicianEngine.OnOracleEval(
                            project, yamlPath, oracleEval, corpus, payload, mutators, progress);
                        if (cast is { CoverageGuidedEnabled: true })
                            coverageGuided = true;
                        if (verbose && cast is { Spells.Count: > 0 })
                        {
                            foreach (var spell in cast.Spells)
                            {
                                FuzzAnalystLog.Info(progress,
                                    $"  Magician spell {spell.Spell}" +
                                    (spell.Summon is null ? "" : $"→{spell.Summon}") +
                                    $": {spell.Detail} ({spell.Reason})",
                                    iterations);
                            }
                            if (cast.MutatorsEnsured.Count > 0)
                                FuzzAnalystLog.Info(progress,
                                    $"  Magician mutators ensured: {string.Join(',', cast.MutatorsEnsured)}",
                                    iterations);
                            if (cast.DictionaryTokensAdded.Count > 0)
                                FuzzAnalystLog.Info(progress,
                                    $"  Magician dict tokens +{cast.DictionaryTokensAdded.Count}: " +
                                    string.Join(',', cast.DictionaryTokensAdded.Take(8)) +
                                    (cast.DictionaryTokensAdded.Count > 8 ? ",…" : ""),
                                    iterations);
                            if (cast.ExtraEnergyBoost > 0)
                                FuzzAnalystLog.Info(progress,
                                    $"  Magician energy boost +{cast.ExtraEnergyBoost}", iterations);
                            if (cast.CoverageGuidedEnabled)
                                FuzzAnalystLog.Info(progress, "  Magician enabled coverageGuided (knight)", iterations);
                            if (cast.HunterRearmed)
                                FuzzAnalystLog.Info(progress, "  Magician re-armed Bug Hunter", iterations);
                        }
                    }
                    if (oracleEval.RetainInCorpus && !result.Crashed && oracleEval.Findings.Count > 0)
                    {
                        if (corpus.IsNew(payload))
                        {
                            corpus.SaveInteresting(payload, "oracle");
                            corpusAdded++;
                        }
                        if (oracleEval.EnergyBoost > 0)
                            corpus.BoostEnergy(payload, oracleEval.EnergyBoost);
                        ApplyBrainEnergyBoost(huntDecision, corpus, payload, verbose, progress, iterations);
                    }

                    if (verbose)
                    {
                        if (oracleEval.Findings.Count == 0)
                        {
                            FuzzAnalystLog.Info(progress,
                                "Oracle: clean (no findings)", iterations);
                        }
                        else
                        {
                            foreach (var f in oracleEval.Findings)
                            {
                                var line =
                                    $"Oracle finding {f.RuleClass}/{f.RuleId}:{f.Severity} " +
                                    $"conf={f.Confidence:0.00} cmd={f.Command ?? "-"} " +
                                    $"expect={f.ExpectedRelation} actual={f.ActualRelation}";
                                if (f.Severity is "violation" or "runtime")
                                    FuzzAnalystLog.Warn(progress, line, iterations);
                                else
                                    FuzzAnalystLog.Info(progress, line, iterations);
                            }
                            if (oracleEval.Needs.Count > 0)
                            {
                                FuzzAnalystLog.Info(progress,
                                    $"Oracle needs Magician: {string.Join("; ", oracleEval.Needs.Select(n => $"{n.Request}({n.Severity})"))}",
                                    iterations);
                            }
                            FuzzAnalystLog.Info(progress,
                                $"Oracle score={oracleEval.Score.Total} retain={oracleEval.RetainInCorpus} " +
                                $"energy+={oracleEval.EnergyBoost} summary={oracleEval.Summary}",
                                iterations);
                        }
                    }
                    else if (!string.IsNullOrEmpty(oracleEval.Summary))
                    {
                        if (oracleEval.MaxSeverity >= OracleSeverity.Violation)
                            FuzzAnalystLog.Warn(progress,
                                $"Oracle [{oracleEval.Score.Total}]: {oracleEval.Summary}", iterations);
                        else
                            FuzzAnalystLog.Info(progress,
                                $"Oracle near-miss [{oracleEval.Score.Total}]: {oracleEval.Summary}",
                                iterations);
                    }
                }

                if (!result.Crashed && oracleEval is not null)
                {
                    var iterMutatorLabel = jokerTrick is null
                        ? $"{commandName}/{mutator.Name}"
                        : $"{commandName}/joker:{jokerTrick.TrickName}";
                    var silent = SilentScreamBuilder.Promote(
                        project, yamlPath, crashStore, crashesDir, iterations, iterMutatorLabel,
                        commandName, mutator.Name, payload, payloadHash, result, oracleEval,
                        mutatorChain, parentInputHash, seedSource, seedFiles,
                        newEdges, coverage.TotalEdges, coverageGuided, dryRun,
                        stalkBackend, iterTracePath, journal?.RunId, progress);
                    if (silent is { IsNew: true })
                        uniqueCrashThisIter = true;
                }

                if (jokerTrick is not null && !result.Crashed)
                {
                    MagicianEngine.WatchJoker(
                        project, yamlPath, jokerTrick, iterations,
                        crashed: false, capitalized: false, progress);
                }

                sw.Stop();
                var iterDetail = result.Detail;
                if (oracleEval is { Findings.Count: > 0 } && !string.IsNullOrEmpty(oracleEval.Summary))
                    iterDetail = string.IsNullOrEmpty(iterDetail)
                        ? $"oracle: {oracleEval.Summary}"
                        : $"{iterDetail}; oracle: {oracleEval.Summary}";
                if (jokerTrick is not null)
                    iterDetail = string.IsNullOrEmpty(iterDetail)
                        ? $"joker:{jokerTrick.TrickName}"
                        : $"{iterDetail}; joker:{jokerTrick.TrickName}";

                // Crash-cascade guard BEFORE journal / progress — never record a rejected
                // TCP-dead cascade as a crash (UI/API journal must match engine truth).
                if (ShouldRejectCascadeCrash(
                        result.Crashed,
                        ProjectKinds.IsTcpLike(project),
                        result.Connected,
                        result.MiniDumpPath,
                        debuggerWait?.Scream?.ExceptionInfo is not null))
                {
                    FuzzAnalystLog.Warn(progress,
                        $"Rejected crash (no TCP connect — target already dead or unreachable): {result.Detail}",
                        iterations);
                    result = result with
                    {
                        Crashed = false,
                        Detail = $"not a crash (connection never established): {result.Detail}",
                    };
                    iterDetail = result.Detail;
                }

                journal?.LogIteration(new IterationLogEntry(
                    iterations, DateTimeOffset.UtcNow, commandName,
                    jokerTrick is null ? mutator.Name : $"joker:{jokerTrick.TrickName}",
                    mutatorChain,
                    parentInputHash, seedSource, payload.Length, InputHash.StackHash(payload),
                    result.Crashed, newEdges, coverage.TotalEdges, sw.ElapsedMilliseconds,
                    iterDetail, result.ExitCode, stalkBackend, iterTracePath,
                    journal?.RunId ?? "", false));

                FuzzProgressGuard.Try(options.Progress, p => p.OnIteration(new FuzzIterationEvent(
                    iterations,
                    caseLabel,
                    payload.Length,
                    result.Crashed,
                    newCoverage,
                    newEdges,
                    corpus.SeenCount,
                    coverage.TotalEdges,
                    iterDetail,
                    CoverageBlocks: coverage.TotalEdges,
                    SemanticStageHits: pathCoverage.Total,
                    CoverageKind: DescribeCoverageKind(coverage.TotalEdges, pathCoverage.Total, coverageGuided))));

                if (verbose)
                {
                    FuzzAnalystLog.Info(progress,
                        $"Coverage edges new={newEdges} total={coverage.TotalEdges} " +
                        $"novel={newCoverage} corpus={corpus.SeenCount} " +
                        $"payload={payload.Length}B mutator={mutator.Name}" +
                        (jokerTrick is null ? "" : $" joker={jokerTrick.TrickName}"),
                        iterations);
                }

                FuzzAnalystLog.Step(progress, "Monitor / checkAlive", iterations);

                if (result.Crashed)
                {
                    FuzzAnalystLog.Crash(progress, iterations, $"{caseLabel} — {result.Detail}");
                    crashCount++;
                    oracleSession?.Reset(); // long-lived target will recycle — drop auth/state
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

                    var mutatorLabel = jokerTrick is null
                        ? $"{commandName}/{mutator.Name}"
                        : $"{commandName}/joker:{jokerTrick.TrickName}";
                    var expectedInputPath = Path.Combine(crashesDir, $"{project.Name}_{iterations}_{payloadHash}.bin");
                    var randallScore = OracleScorer.PreferCrash(
                        oracleEval?.Score,
                        result.Detail,
                        newEdges,
                        crashed: true);
                    ObservationBus.Publish(ObservationEvents.Crash(
                        runId, iterations, payloadHash, result.ExitCode, result.Detail, newEdges, project.Name));
                    var crashFaultPreview = CrashTriage.Classify(
                        analysis: null,
                        sidecar: null,
                        summary: new CrashSummaryDto(
                            Guid.Empty, project.Name, iterations, mutatorLabel, payloadHash, expectedInputPath,
                            crashDump, result.ExitCode?.ToString(), crashTag, null, journal?.RunId,
                            DateTimeOffset.UtcNow),
                        payload: payload);
                    FaultSignalMapper.PublishFaults(
                        ObservationBus,
                        runId,
                        iterations,
                        payloadHash,
                        project.Name,
                        FaultSignalMapper.FromCrash(
                            crashFaultPreview,
                            analysis: null,
                            cdb: null,
                            sidecar: null,
                            pageHeapEnabled: project.Target.PageHeap,
                            rppTag: crashTag,
                            targetDetail: result.Detail,
                            exitCode: result.ExitCode));

                    var savedResult = crashStore.SaveEx(
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
                            var triagePreview = CrashTriage.Classify(
                                analysis: null,
                                sidecar: null,
                                summary: new CrashSummaryDto(
                                    id, project.Name, iterations, mutatorLabel, payloadHash, expectedInputPath,
                                    crashDump, result.ExitCode?.ToString(), crashTag, null, journal?.RunId,
                                    DateTimeOffset.UtcNow),
                                payload: payload);
                            var intel = CrashIntelAdvisor.Build(
                                project, yamlPath, commandName, mutator.Name, payload, result,
                                targetExeResolved, triagePreview, id,
                                newEdgesAtCrash: newEdges,
                                totalEdgesAtCrash: coverage.TotalEdges,
                                coverageGuided: coverageGuided);
                            try
                            {
                                CrashIntelAdvisor.WriteIntelFiles(
                                    crashesDir, id, project.Name, iterations, payloadHash, intel);
                            }
                            catch (Exception intelEx)
                            {
                                FuzzAnalystLog.Warn(progress, $"intel write: {intelEx.Message}", iterations);
                            }

                            CrashArtifactIdentity? artifactIdentity = null;
                            var integrity = ArtifactIntegrityStatus.Unverified;
                            if (currentGeneration is not null)
                            {
                                DumpReservationDto? claimed = null;
                                if (currentGeneration.DumpReservationId is Guid rid)
                                {
                                    if (!string.IsNullOrWhiteSpace(crashDump))
                                        CrashArtifactIdentityService.MarkDumpMaterialized(crashesDir, rid, crashDump!);
                                    var (res, claimErr) = CrashArtifactIdentityService.TryClaimOnce(
                                        crashesDir, rid, id, iterations);
                                    claimed = res;
                                    if (claimErr is not null)
                                    {
                                        FuzzAnalystLog.Warn(progress,
                                            $"dump claim failed: {claimErr}", iterations);
                                    }
                                }

                                var inputSha = CrashArtifactIdentityService.BytesSha256(payload);
                                var failureAt = DateTimeOffset.UtcNow;
                                artifactIdentity = CrashArtifactIdentityService.BuildIdentity(
                                    id,
                                    journal?.RunId ?? runId,
                                    currentGeneration,
                                    iterations,
                                    project.Name,
                                    inputSha,
                                    expectedInputPath,
                                    crashDump,
                                    lastSendStartedUtc,
                                    failureAt,
                                    failureAt,
                                    claimed);
                                var validation = CrashArtifactIdentityService.ValidateIdentity(
                                    artifactIdentity, claimed, inputSha);
                                artifactIdentity = validation.Identity;
                                integrity = validation.Status;
                                CrashArtifactIdentityService.PersistIdentity(crashesDir, artifactIdentity);
                                if (integrity == ArtifactIntegrityStatus.Rejected)
                                {
                                    FuzzAnalystLog.Warn(progress,
                                        $"[artifact-identity] Rejected — {validation.Summary}", iterations);
                                }
                                else if (integrity == ArtifactIntegrityStatus.VerifiedWithWarnings)
                                {
                                    FuzzAnalystLog.Info(progress,
                                        $"[artifact-identity] {validation.Summary}", iterations);
                                }
                            }

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
                                DateTimeOffset.UtcNow,
                                intel,
                                randallScore,
                                ArtifactIdentity: artifactIdentity,
                                IntegrityStatus: integrity);
                        });
                    var saved = savedResult.Crash;
                    uniqueCrashThisIter = savedResult.IsNew;

                    Console.WriteLine(
                        $"CRASH #{crashCount} iter={iterations} {mutatorLabel} " +
                        $"detail={result.Detail} saved={saved.InputPath}" +
                        (savedResult.IsNew ? "" : " (dedup)") +
                        (saved.MiniDumpPath is not null ? $" dump={saved.MiniDumpPath}" : "") +
                        (saved.SidecarPath is not null ? $" sidecar={saved.SidecarPath}" : "") +
                        (crashTag is not null ? $" tag={crashTag}" : ""));

                    if (savedResult.IsNew && saved.SidecarPath is not null)
                    {
                        var sc = CrashSidecarWriter.TryRead(saved.SidecarPath);
                        if (sc?.Intel is { } intel)
                            Console.WriteLine(CrashIntelAdvisor.FormatConsole(intel));
                    }
                    else if (verbose && !savedResult.IsNew)
                    {
                        // Dedup path skipped sidecar rebuild — rebuild INTEL for the console only.
                        var triagePreview = CrashTriage.Classify(
                            analysis: null,
                            sidecar: null,
                            summary: new CrashSummaryDto(
                                saved.Id, project.Name, iterations, mutatorLabel, payloadHash, saved.InputPath,
                                saved.MiniDumpPath ?? crashDump, result.ExitCode?.ToString(), crashTag,
                                saved.SidecarPath, journal?.RunId,
                                DateTimeOffset.UtcNow),
                            payload: payload);
                        var intel = CrashIntelAdvisor.Build(
                            project, yamlPath, commandName, mutator.Name, payload, result,
                            targetExeResolved, triagePreview, saved.Id,
                            newEdgesAtCrash: newEdges,
                            totalEdgesAtCrash: coverage.TotalEdges,
                            coverageGuided: coverageGuided);
                        Console.WriteLine(CrashIntelAdvisor.FormatConsole(intel));
                    }

                    if (savedResult.IsNew && project.Notifications is { Enabled: true, OnUniqueCrash: true })
                    {
                        try
                        {
                            var alert = NotificationDispatcher.BuildCrashAlert(
                                project.Notifications,
                                saved,
                                WindowsExceptionHints.Describe(result.ExitCode),
                                result.Detail);
                            var notifyResults = await NotificationDispatcher.NotifyCrashAsync(
                                project.Notifications, alert, cancellationToken);
                            foreach (var nr in notifyResults)
                            {
                                if (nr.Ok)
                                    FuzzAnalystLog.Info(progress, $"notify/{nr.Channel}: {nr.Message}", iterations);
                                else
                                    FuzzAnalystLog.Warn(progress, $"notify/{nr.Channel} failed: {nr.Message}", iterations);
                            }
                        }
                        catch (Exception notifyEx)
                        {
                            FuzzAnalystLog.Warn(progress, $"notify: {notifyEx.Message}", iterations);
                        }
                    }

                    if (jokerTrick is not null)
                    {
                        _ = MagicianEngine.CapitalizeOnJokerCrash(
                            project, yamlPath, jokerTrick, payload, corpus, mutators, iterations, progress);
                    }

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
                        if (LinuxCrashAnalysisWriter.LooksLikeLinuxCore(saved.MiniDumpPath))
                        {
                            try
                            {
                                byte[]? crashInput = null;
                                try
                                {
                                    if (File.Exists(saved.InputPath))
                                        crashInput = await File.ReadAllBytesAsync(saved.InputPath, cancellationToken);
                                }
                                catch { /* ignore */ }

                                var linux = LinuxCrashAnalysisWriter.Analyze(
                                    crashesDir,
                                    saved.Id,
                                    saved.MiniDumpPath,
                                    targetExeResolved,
                                    exitCode: result.ExitCode,
                                    patternLen: null,
                                    projectName: project.Name,
                                    crashInput: crashInput);
                                Console.WriteLine(
                                    $"  linux triage: {linux.SummaryLine} → {linux.AnalysisPath}");
                                if (linux.HeapTriagePath is not null)
                                    Console.WriteLine($"  heap triage → {linux.HeapTriagePath}");
                                if (linux.ExploitGuidePath is not null)
                                    Console.WriteLine($"  exploit guide → {linux.ExploitGuidePath}");
                                FuzzAnalystLog.Info(progress,
                                    $"[linux-triage] {linux.SummaryLine}", iterations);
                            }
                            catch (Exception linuxEx)
                            {
                                Console.WriteLine($"  linux triage skipped: {linuxEx.Message}");
                            }
                        }
                        else
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

                            if (wantCdbAnalyze && OperatingSystem.IsWindows())
                            {
                                try
                                {
                                    var crashSidecar = CrashSidecarWriter.TryRead(saved.SidecarPath);
                                    var cdb = WindowsCdbCrashAnalysisWriter.Analyze(
                                        crashesDir, saved.Id, saved.MiniDumpPath,
                                        crashSidecar: crashSidecar);
                                    Console.WriteLine($"  cdb triage: {cdb.SummaryLine}");
                                    if (cdb.Sidecar.AnalyzeTextPath is not null)
                                        Console.WriteLine($"  !analyze → {cdb.Sidecar.AnalyzeTextPath}");
                                    if (cdb.Sidecar.ExploitableTextPath is not null)
                                        Console.WriteLine($"  !exploitable → {cdb.Sidecar.ExploitableTextPath}");
                                    FuzzAnalystLog.Info(progress, $"[cdb] {cdb.SummaryLine}", iterations);

                                    var inv = ScreamInvestigator.TryRead(
                                        ScreamInvestigator.ObservationPathFor(crashesDir, saved.Id));
                                    if (inv is { Ok: true })
                                    {
                                        Console.WriteLine($"  scream investigator: {inv.Diagnosis}");
                                        FuzzAnalystLog.Info(progress,
                                            $"[scream-investigator] {inv.Diagnosis}", iterations);
                                        ObservationBus.Publish(ObservationEvents.Debugger(
                                            runId, iterations, payloadHash, inv, project.Name));
                                    }
                                    else if (inv?.Error is not null)
                                    {
                                        Console.WriteLine($"  scream investigator: {inv.Error}");
                                    }

                                    var corruption = CorruptionChainBuilder.TryRead(
                                        CorruptionChainBuilder.PathFor(crashesDir, saved.Id));
                                    if (corruption is { Ok: true })
                                    {
                                        Console.WriteLine($"  corruption chain [{corruption.Confidence}]: {corruption.Summary}");
                                        FuzzAnalystLog.Info(progress,
                                            $"[corruption-chain] {corruption.Summary}", iterations);
                                    }
                                }
                                catch (Exception cdbEx)
                                {
                                    Console.WriteLine($"  cdb triage skipped: {cdbEx.Message}");
                                }
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
                    }

                    if (savedResult.IsNew)
                    {
                        try
                        {
                            PublishEnrichedCrashFaults(
                                project,
                                saved,
                                crashesDir,
                                crashTag,
                                result.Detail,
                                runId,
                                iterations,
                                payloadHash);
                        }
                        catch (Exception faultEx)
                        {
                            FuzzAnalystLog.Warn(progress, $"fault republish: {faultEx.Message}", iterations);
                        }

                        TryPersistScreamEvolution(
                            project, yamlPath, crashesDir, saved, mutatorChain,
                            corpus, mutators, mutatorCredit, iterations, progress);

                        TryPersistHypotheses(
                            project, yamlPath, crashesDir, saved,
                            sidecar: CrashSidecarWriter.TryRead(saved.SidecarPath),
                            iterations, progress);

                        await TryPersistDeepScream(
                            project, yamlPath, crashesDir, saved, iterations, progress, cancellationToken);

                        if (stopGoals.IsEnabled && savedResult.IsNew && repoRoot is not null)
                        {
                            var projectCrashes = CrashCatalog.ListAll(repoRoot, project.Name);
                            var evolutions = stopGoals.UniqueScreamsWithMomentum is { Count: > 0, MinMomentum: > 0 }
                                ? IntelligenceStopGoalEvaluator.LoadEvolutions(repoRoot, project.Name, projectCrashes)
                                : null;
                            var goalEval = IntelligenceStopGoalEvaluator.Evaluate(stopGoals, projectCrashes, evolutions);
                            FuzzProgressGuard.Try(options.Progress, p => p.OnGoalProgress(goalEval));
                            if (goalEval.Met)
                            {
                                stopReason = goalEval.Reason;
                                FuzzAnalystLog.Info(progress, $"{stopReason} — stopping", iterations);
                                stopGoalReached = true;
                                if (stopGoals.QueueTopClustersOnGoal)
                                {
                                    var queued = IntelligenceStopGoalEvaluator.TryQueueTopClusters(
                                        project.Name, projectCrashes, repoRoot, iterations);
                                    if (queued > 0)
                                        FuzzAnalystLog.Info(progress, $"Queued {queued} top cluster(s) for replay/minimize", iterations);
                                }
                            }
                        }
                    }

                    if (DebuggerSession.ShouldOpenDumpOnCrash(debuggerOpenOnCrash) && saved.MiniDumpPath is not null)
                    {
                        try
                        {
                            var opened = DebuggerSession.OpenDump(saved.MiniDumpPath, debuggerKind, saved.Id);
                            Console.WriteLine(opened.Ok
                                ? $"  debugger open: {opened.Message}"
                                : $"  debugger open skipped: {opened.Message}");
                        }
                        catch (Exception openEx)
                        {
                            Console.WriteLine($"  debugger open skipped: {openEx.Message}");
                        }
                    }

                    // Auto-record a stalk "crash" layer when coverage edges/trace exist.
                    try
                    {
                        var stalkLayer = StalkCampaignStore.AddLayer(new StalkLayerCreateRequest(
                            project.Name,
                            "crash",
                            $"crash {saved.Id.ToString("N")[..8]} iter={iterations}",
                            null,
                            iterTracePath,
                            null,
                            saved.Id.ToString(),
                            crashTag ?? result.Detail));
                        Console.WriteLine(
                            $"  stalk layer: {stalkLayer.Tag} blocks={stalkLayer.BlockCount} id={stalkLayer.Id}");
                        if (repoRoot is not null)
                        {
                            try
                            {
                                TargetGravityEngine.RefreshForStalkMap(project.Name, repoRoot, limit: 40);
                            }
                            catch
                            {
                                /* gravity refresh must not block crash path */
                            }
                        }
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
                        longLived = await RestartLongLivedAsync(iterations);
                }
                else
                {
                    FuzzAnalystLog.Ok(progress, iteration: iterations);
                    if (result.Detail is not null and not "ok" and not "")
                        FuzzAnalystLog.Info(progress, $"Info: {result.Detail}", iterations);

                    // Bind/start failures are not fuzz crashes, but the server is still dead — bring it back.
                    var needsInfraRestart = runtime is not null &&
                        (result.Detail?.Contains("bind/start failure", StringComparison.OrdinalIgnoreCase) == true ||
                         longLived is { HasExited: true });
                    if (needsInfraRestart)
                        longLived = await RestartLongLivedAsync(iterations);
                }

                mutatorCredit.RecordWithChain(mutator.Name, mutatorChain, newEdges, uniqueCrashThisIter);
                mutatorChainTracker.RecordLineage(fullLineageChain, newEdges, uniqueCrashThisIter);

                if (hypothesisPlan is not null)
                {
                    HypothesisEngine.RecordOutcome(
                        project.Name,
                        hypothesisPlan,
                        iterations,
                        result.Crashed,
                        result.Detail,
                        result.ExitCode?.ToString(),
                        repoRoot);
                    if (verbose)
                    {
                        FuzzAnalystLog.Info(progress,
                            $"[hypothesis] recorded outcome for {hypothesisPlan.HypothesisId} " +
                            $"crash={result.Crashed}",
                            iterations);
                    }
                }
                lastPrimaryMutator = mutator.Name;
                if (jokerTrick is not null && jokerDeck is not null)
                {
                    var oracleDelta = oracleEval is { Findings.Count: > 0 } ? oracleEval.Score.Total : 0;
                    jokerDeck.RecordOutcome(project, jokerTrick,
                        new JokerTrickOutcome(newEdges, uniqueCrashThisIter, newCoverage, oracleDelta, result.Crashed),
                        jokerTrick.PlayMode ?? "chaos");
                }
                RecordScareDoorProgress(
                    project.Name, repoRoot ?? "", iterations, mutator.Name, parentInputHash,
                    newEdges, newCoverage, coverage.TotalEdges);
                lastObservedNewEdges = newEdges;
                lastObservedUniqueCrashes = uniqueCrashThisIter ? 1 : 0;
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception ex) when (BenignRecorderPipeException.IsBenign(ex))
                {
                    FuzzAnalystLog.Warn(progress,
                        $"Recorder/hub noise — continuing fuzz: {ex.Message}", iterations);
                }
                catch (Exception ex)
                {
                    var isBounds = ex is IndexOutOfRangeException or ArgumentOutOfRangeException;
                    FuzzAnalystLog.Warn(progress,
                        isBounds
                            ? $"Iteration bounds error (config/flow index) — recorded as failed, continuing: {ex.Message}"
                            : $"Iteration error — continuing fuzz: {ex.Message}",
                        iterations);
                    // Keep journal/timeline accounting honest: iteration was counted but produced no case.
                    try
                    {
                        journal?.LogIteration(BuildFailedIterationEntry(
                            iterations, isBounds, ex.Message, coverage.TotalEdges,
                            stalkBackend, journal?.RunId ?? ""));
                        FuzzProgressGuard.Try(options.Progress, p => p.OnIteration(new FuzzIterationEvent(
                            iterations, "error", 0, false, false, 0,
                            corpus.SeenCount, coverage.TotalEdges,
                            isBounds ? $"failed (bounds): {ex.Message}" : $"failed: {ex.Message}")));
                    }
                    catch
                    {
                        /* journal best-effort */
                    }

                    if (runtime is not null)
                    {
                        try
                        {
                            if (longLived is null or { HasExited: true })
                                longLived = await RestartLongLivedAsync(iterations);
                        }
                        catch (Exception restartEx)
                        {
                            FuzzAnalystLog.Warn(progress,
                                $"Target restart after iteration error: {restartEx.Message}", iterations);
                        }
                    }
                }
            }
        }
        finally
        {
            // Capture end PID before stalk/runtime tear down kills the process.
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

            try { debuggerWait?.Dispose(); }
            catch { /* ignore */ }

            try
            {
                if (useCoverageTcp)
                    stalk.StopLongLivedAsync(longLived, CancellationToken.None).GetAwaiter().GetResult();
            }
            catch
            {
                /* ignore — never skip recorder teardown */
            }

            // Single path: every armed recorder stopped/disposed even if one step faults.
            RecordingTeardown.DisposeArmed(
                progress,
                endPid,
                procdumpArm,
                sysinternalsSnap,
                tcpvcon,
                debugView,
                procmon,
                pktmon,
                tshark,
                etw);
            procdumpArm = null;
            sysinternalsSnap = null;
            tcpvcon = null;
            debugView = null;
            procmon = null;
            pktmon = null;
            tshark = null;
            etw = null;

            try { runtime?.Dispose(); }
            catch { /* ignore */ }

            try
            {
                if (inProcess is not null)
                {
                    FuzzAnalystLog.Info(progress, $"Harness final: {inProcess.Stats.Format()}");
                    inProcess.DisposeAsync().AsTask().GetAwaiter().GetResult();
                }
            }
            catch
            {
                /* ignore */
            }

            try
            {
                if (persistentServer is not null)
                    persistentServer.DisposeAsync().AsTask().GetAwaiter().GetResult();
            }
            catch
            {
                /* ignore */
            }

            try { FuzzProgressGuard.Try(options.Progress, p => p.OnTargetPid(null)); }
            catch { /* ignore */ }

            try
            {
                mutatorCredit.Save();
                mutatorChainTracker.Save();
                var statsDir = journal?.RunDirectory ?? runDir;
                if (statsDir is not null)
                {
                    mutatorCredit.WriteRunJson(statsDir);
                    mutatorChainTracker.WriteRunJson(statsDir);
                }
                var creditBoard = mutatorCredit.FormatLeaderboard();
                var chainBoard = mutatorChainTracker.FormatLeaderboard();
                Console.WriteLine(creditBoard);
                Console.WriteLine(chainBoard);
                consoleLog?.AppendPlain(creditBoard);
                consoleLog?.AppendPlain(chainBoard);
            }
            catch { /* ignore */ }

            try { journal?.Complete(iterations, crashCount, coverage.GetTopHotEdges()); }
            catch { /* ignore */ }

            try
            {
                if (!dryRun)
                {
                    TargetIntelligenceWriteBack.OnFuzzComplete(
                        project.Name,
                        runId,
                        iterations,
                        crashCount,
                        corpusAdded,
                        ObservationBus.Snapshot);
                }
            }
            catch { /* intel write-back must not break teardown */ }

            try { consoleLog?.Dispose(); }
            catch { /* ignore */ }
            consoleLog = null;
        }

        var runResult = new FuzzRunResult(iterations, corpusAdded, crashCount, crashes, stopGoalReached, stopReason);
        TryNotifyCompleted(options.Progress, runResult);
        return runResult;
        }
        finally
        {
            try { consoleLog?.Dispose(); }
            catch { /* ignore */ }
            HttpCookieSession.End();
        }
    }

    private static void TryNotifyCompleted(IFuzzProgressSink? progress, FuzzRunResult result)
    {
        try
        {
            progress?.OnCompleted(result);
        }
        catch (Exception ex) when (BenignRecorderPipeException.IsBenign(ex))
        {
            FuzzAnalystLog.Warn(progress, $"Recording teardown notify skipped: {ex.Message}");
        }
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
                        model, protoSeeds, mutator, rng, project.Fuzz, targetField),
                    parentInputHash, seedSource, seedFiles);
            }
            var (lenPol, crcPol, lenDelta, crcDelta) = FuzzDependencyPolicies.Resolve(project.Fuzz);
            var baselineMsg = model.FinalizeMessage(baseline, lenPol, crcPol, lenDelta, crcDelta);
            if (project.Fuzz.SyncNbssLength)
                baselineMsg = NbssFraming.TrySyncLength(baselineMsg);
            return new CommandPayloadBuild(
                baselineMsg,
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

    private static void LogVerboseEngineBanner(
        ProjectConfig project,
        IFuzzProgressSink? progress,
        bool coverageGuided,
        bool useCoverage)
    {
        var o = project.Oracles;
        var m = project.Magician;
        var j = project.Joker;
        var bh = project.BugHunter;
        FuzzAnalystLog.Info(progress,
            $"Engines — oracle={(o is { Enabled: true } ? "ON" : "off")} " +
            $"magician={(m is { Enabled: true } ? "ON" : "off")} " +
            $"joker={(j is { Enabled: true } || (j?.EncoreIterations > 0) ? "ON" : "off")} " +
            $"bugHunter={(bh is { Enabled: true } ? "ON" : "off")} " +
            $"coverageGuided={(coverageGuided ? "ON" : "off")} " +
            $"stalk={(useCoverage ? "armed" : "off")}");
        if (o is { Enabled: true })
        {
            FuzzAnalystLog.Info(progress,
                $"  Oracle rules: auth={o.Auth.Count} state={o.State.Count} integer={o.Integer.Count} " +
                $"structure={o.Structure.Count} resource={o.Resource.Count} " +
                $"invariants={o.Invariants.Count} differential={o.Differential.Count} metamorphic={o.Metamorphic.Count}");
            if (DifferentialOracleHook.IsArmed(project))
                FuzzAnalystLog.Info(progress, $"  {DifferentialOracleHook.Describe(project)}");
        }
        var academy = project.Academy;
        if (academy is not null)
        {
            FuzzAnalystLog.Info(progress,
                $"  Academy: mode={academy.PresentationMode} instructor={academy.InstructorMode} " +
                $"level={academy.InstructorLevel} silentScreams={academy.SilentScreams}");
        }
        else if (SilentScreamBuilder.IsEnabled(project))
        {
            FuzzAnalystLog.Info(progress, "  Academy: silentScreams=on (default)");
        }
        if (m is { Enabled: true })
        {
            FuzzAnalystLog.Info(progress,
                $"  Magician: blessOnStart={m.BlessOnStart} autoCast={m.AutoCastOnOracle} " +
                $"summonJoker={m.AllowSummonJoker} watchJoker={m.WatchJoker} " +
                $"capitalizeJoker={m.CapitalizeJokerCrashes}");
        }
        if (j is { Enabled: true } || (j?.EncoreIterations > 0))
        {
            FuzzAnalystLog.Info(progress,
                $"  Joker: chance={JokerEngine.EffectiveChance(project):0.00} " +
                $"maxStack={j?.MaxStack ?? 0} wildBytes={j?.WildBytes == true} " +
                $"flipSessionBias={j?.FlipSessionBias == true} encoreLeft={j?.EncoreIterations ?? 0}");
        }
    }

    private static void ApplyGhidraStaticBias(
        ProjectConfig project,
        CorpusTracker corpus,
        byte[] payload,
        int newEdges,
        bool verbose,
        IFuzzProgressSink? progress,
        int iterations)
    {
        var boost = GhidraStaticMapBias.NovelCoverageEnergyBoost(
            project.Name,
            newEdges,
            project.Fuzz.GhidraStaticBias,
            CrashCatalog.FindRepoRoot());
        if (boost <= 0)
            return;

        corpus.BoostEnergy(payload, boost);
        if (verbose)
        {
            FuzzAnalystLog.Info(progress,
                $"  Ghidra static bias energy +{boost} (uncovered targets in randall-analysis.json)",
                iterations);
        }
    }

    private static void ApplyBrainEnergyBoost(
        NextHuntDecision? decision,
        CorpusTracker corpus,
        byte[] payload,
        bool verbose,
        IFuzzProgressSink? progress,
        int iterations)
    {
        if (decision is not { Active: true } or { RecommendedEnergyBoost: <= 0 })
            return;

        corpus.BoostEnergy(payload, decision.RecommendedEnergyBoost);
        if (verbose)
        {
            FuzzAnalystLog.Info(progress,
                $"  Brain energy +{decision.RecommendedEnergyBoost} ({decision.FocusKind} focus)",
                iterations);
        }
    }

    private static void RecordScareDoorProgress(
        string project,
        string repoRoot,
        int iteration,
        string mutator,
        string? seedId,
        int newEdges,
        bool newCoverage,
        int coverageEdgeTotal)
    {
        try
        {
            var focus = RandallBrain.TryLoadFocus(project, repoRoot);
            if (focus is null || !focus.FocusKind.Equals("frontier", StringComparison.OrdinalIgnoreCase))
                return;

            var frontier = FrontierEngine.TryLoad(project, repoRoot);
            ScareDoorProgressStore.RecordPinnedIteration(
                project, focus, frontier, iteration, mutator, seedId,
                newEdges, newCoverage, coverageEdgeTotal, repoRoot);
        }
        catch { /* hunt pressure must not break fuzz loop */ }
    }

    private void TryPersistScreamEvolution(
        ProjectConfig project,
        string yamlPath,
        string crashesDir,
        SavedCrash saved,
        IReadOnlyList<string> mutatorChain,
        CorpusTracker corpus,
        List<IMutator>? mutators,
        MutatorCreditTracker mutatorCredit,
        int iterations,
        IFuzzProgressSink? progress)
    {
        try
        {
            var sidecar = CrashSidecarWriter.TryRead(saved.SidecarPath);
            var debugger = ScreamInvestigator.TryRead(
                ScreamInvestigator.ObservationPathFor(crashesDir, saved.Id));
            var corruption = CorruptionChainBuilder.TryRead(
                CorruptionChainBuilder.PathFor(crashesDir, saved.Id));

            byte[]? payload = null;
            if (File.Exists(saved.InputPath))
            {
                try { payload = File.ReadAllBytes(saved.InputPath); }
                catch { /* ignore */ }
            }

            var summary = new CrashSummaryDto(
                saved.Id, project.Name, iterations, sidecar?.Mutator ?? "?",
                saved.InputHash, saved.InputPath, saved.MiniDumpPath,
                sidecar?.ExitCode?.ToString(), sidecar?.TriageTag, saved.SidecarPath,
                sidecar?.RunId, DateTimeOffset.UtcNow);

            var triage = CrashTriage.Classify(null, sidecar, summary, payload, debugger: debugger);
            var contexts = ScreamEvolutionBuilder.LoadProjectContexts(crashesDir, project.Name);
            var repoRoot = CrashCatalog.FindRepoRoot();
            var evolution = ScreamEvolutionBuilder.PersistForCrash(
                crashesDir, saved.Id, project.Name, sidecar, triage, debugger, corruption, contexts, repoRoot);

            if (evolution is not { Ok: true })
                return;

            var lineageQueued = TryQueueEvolutionLineageBreeding(
                evolution, sidecar, crashesDir, project.Name, corpus);

            var seedRoot = sidecar?.InputHash;
            var (index, telemetry, decayApplied) = ScreamFamilyIndex.Update(
                project.Name, evolution, sidecar, seedRoot, repoRoot, lineageQueued);

            evolution = ScreamEvolutionBuilder.ApplyFamilyIndex(evolution, sidecar, seedRoot, repoRoot);
            var indexEntry = index.Families.FirstOrDefault(f =>
                f.FamilyId.Equals(evolution.FamilyId, StringComparison.OrdinalIgnoreCase));
            if (indexEntry is not null)
            {
                evolution = evolution with
                {
                    MomentumScore = indexEntry.EffectiveMomentumScore,
                    MomentumLabel = indexEntry.MomentumLabel,
                };
            }
            ScreamEvolutionBuilder.Write(crashesDir, evolution);

            if (decayApplied > 0)
            {
                FuzzAnalystLog.Info(progress,
                    $"[scream-evolution] momentum decay −{decayApplied} on stagnant family {evolution.FamilyId}",
                    iterations);
            }

            Console.WriteLine($"  scream evolution: {evolution.Summary}");
            if (evolution.MomentumScore >= ScreamFamilyIndex.MomentumWarmThreshold
                || telemetry.FamilyCount > 0)
            {
                FuzzAnalystLog.Info(progress,
                    $"[scream-evolution] {evolution.MomentumLabel} momentum={evolution.MomentumScore} · " +
                    $"families={telemetry.FamilyCount} warm={telemetry.WarmingFamilies} hot={telemetry.HotFamilies} " +
                    $"stagnant={telemetry.StagnantFamilies} lineage+={lineageQueued} · {evolution.Summary}",
                    iterations);
            }

            mutatorCredit.RecordEvolutionWarmth(mutatorChain, evolution.MomentumScore, evolution.ProgressionDelta);

            if (evolution.MomentumScore >= 40 && File.Exists(saved.InputPath))
            {
                try
                {
                    var crashPayload = payload ?? File.ReadAllBytes(saved.InputPath);
                    if (corpus.IsNew(crashPayload) || evolution.MomentumLabel is "warming" or "hot")
                        corpus.BoostEnergy(crashPayload, Math.Min(15, evolution.MomentumScore / 5 + 3));
                }
                catch { /* ignore */ }
            }

            _ = MagicianEngine.OnScreamEvolutionWarm(
                project, yamlPath, evolution, sidecar, corpus,
                mutators, iterations, progress);
        }
        catch (Exception ex)
        {
            FuzzAnalystLog.Warn(progress, $"scream evolution: {ex.Message}", iterations);
        }
    }

    private static int TryQueueEvolutionLineageBreeding(
        ScreamEvolutionDto evolution,
        CrashSidecarDto? sidecar,
        string crashesDir,
        string project,
        CorpusTracker corpus)
    {
        if (evolution.MomentumScore < ScreamFamilyIndex.MomentumWarmThreshold)
            return 0;

        var queued = 0;
        var store = new CrashStore(crashesDir);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void QueueHash(string? hash)
        {
            if (string.IsNullOrWhiteSpace(hash) || !seen.Add(hash))
                return;
            if (TryQueueCrashInput(store, project, hash, corpus))
                queued++;
        }

        QueueHash(sidecar?.ParentInputHash);
        QueueHash(evolution.AncestorInputHash);

        if (evolution.AncestorCrashId is { } ancId)
        {
            var anc = store.List(project).FirstOrDefault(c => c.Id == ancId);
            if (anc is not null && TryQueueCrashInputPath(anc.InputPath, corpus))
                queued++;
        }

        if (sidecar?.MutatorChain is { Count: >= 2 })
            QueueHash(sidecar.InputHash);

        return queued;
    }

    private static bool TryQueueCrashInput(CrashStore store, string project, string? hash, CorpusTracker corpus)
    {
        if (string.IsNullOrWhiteSpace(hash))
            return false;
        var crash = store.FindByHash(hash, project);
        return crash is not null && TryQueueCrashInputPath(crash.InputPath, corpus);
    }

    private static bool TryQueueCrashInputPath(string? inputPath, CorpusTracker corpus)
    {
        if (string.IsNullOrWhiteSpace(inputPath) || !File.Exists(inputPath))
            return false;
        try
        {
            corpus.AddPriority(File.ReadAllBytes(inputPath));
            return true;
        }
        catch
        {
            return false;
        }
    }

    private void TryPersistHypotheses(
        ProjectConfig project,
        string yamlPath,
        string crashesDir,
        SavedCrash saved,
        CrashSidecarDto? sidecar,
        int iterations,
        IFuzzProgressSink? progress)
    {
        try
        {
            var debugger = ScreamInvestigator.TryRead(
                ScreamInvestigator.ObservationPathFor(crashesDir, saved.Id));
            var corruption = CorruptionChainBuilder.TryRead(
                CorruptionChainBuilder.PathFor(crashesDir, saved.Id));
            var evolution = ScreamEvolutionBuilder.TryRead(
                ScreamEvolutionBuilder.PathFor(crashesDir, saved.Id));

            byte[]? payload = null;
            if (File.Exists(saved.InputPath))
            {
                try { payload = File.ReadAllBytes(saved.InputPath); }
                catch { /* ignore */ }
            }

            var summary = new CrashSummaryDto(
                saved.Id, project.Name, iterations, sidecar?.Mutator ?? "?",
                saved.InputHash, saved.InputPath, saved.MiniDumpPath,
                sidecar?.ExitCode?.ToString(), sidecar?.TriageTag, saved.SidecarPath,
                sidecar?.RunId, DateTimeOffset.UtcNow);
            var triage = CrashTriage.Classify(null, sidecar, summary, payload, debugger: debugger);
            var oracleScore = sidecar?.RandallScore;

            var backwardTrace = BackwardTraceBuilder.TryRead(BackwardTraceBuilder.PathFor(crashesDir, saved.Id));

            var set = HypothesisEngine.PersistForCrash(
                crashesDir, saved.Id, project.Name, sidecar, triage,
                debugger, corruption, evolution, oracleScore, backwardTrace);

            TryPersistRootCause(crashesDir, saved.Id, project.Name, sidecar, triage,
                debugger, corruption, backwardTrace, oracleScore);

            TryPersistInfluenceMap(crashesDir, saved.Id, project.Name, sidecar, triage,
                debugger, corruption, backwardTrace, set, oracleScore, payload);

            EvidenceFactBuilder.PersistForCrash(
                crashesDir,
                saved.Id,
                project.Name,
                sidecar,
                triage,
                debugger,
                corruption,
                backwardTrace,
                evolution,
                oracleScore,
                set,
                validation: ResolveArtifactValidation(crashesDir, saved.Id, sidecar, debugger));

            TryPersistResearchStack(
                project, yamlPath, crashesDir, saved.Id, project.Name, sidecar, triage,
                debugger, corruption, set, progress, iterations);

            if (set is not { Ok: true, Hypotheses.Count: > 0 })
                return;

            var top = HypothesisEngine.TopPending(set);
            if (top is not null)
            {
                Console.WriteLine($"  hypotheses: {set.Hypotheses.Count} ranked · top {top.Id} ({top.ConfidencePercent}%)");
                FuzzAnalystLog.Info(progress,
                    $"[hypothesis] top {top.Id} ({top.ConfidencePercent}%) — {top.Statement}",
                    iterations);
            }
        }
        catch (Exception ex)
        {
            FuzzAnalystLog.Warn(progress, $"hypotheses: {ex.Message}", iterations);
        }
    }

    private void TryPersistRootCause(
        string crashesDir,
        Guid crashId,
        string project,
        CrashSidecarDto? sidecar,
        CrashTriageDto? triage,
        DebuggerObservation? debugger,
        CrashCorruptionChainDto? corruption,
        CrashBackwardTraceDto? backwardTrace,
        OracleScore? oracleScore,
        IFuzzProgressSink? progress = null,
        int iterations = 0)
    {
        try
        {
            var validation = ResolveArtifactValidation(crashesDir, crashId, sidecar, debugger);
            if (!CrashArtifactIdentityService.AllowsStrongPromotion(validation, out var blockReason))
            {
                FuzzAnalystLog.Warn(progress,
                    $"[root-cause] blocked — {blockReason}", iterations);
                return;
            }

            var analysis = RootCauseEngine.PersistForCrash(
                crashesDir, crashId, project, sidecar, triage, debugger, corruption, backwardTrace, oracleScore);
            if (analysis is { Ok: true })
            {
                var cat = analysis.Candidate.Category.ToString();
                FuzzAnalystLog.Info(progress,
                    $"[root-cause] {cat} ({analysis.Candidate.Confidence}) — {Truncate(analysis.EducationalSummary, 120)}",
                    iterations);
            }
        }
        catch (Exception ex)
        {
            FuzzAnalystLog.Warn(progress, $"root-cause: {ex.Message}", iterations);
        }
    }

    private static ArtifactValidationResult? ResolveArtifactValidation(
        string crashesDir,
        Guid crashId,
        CrashSidecarDto? sidecar,
        DebuggerObservation? debugger) =>
        CrashArtifactIdentityService.ResolveForCrash(crashesDir, crashId, sidecar, debugger);

    private void TryPersistInfluenceMap(
        string crashesDir,
        Guid crashId,
        string project,
        CrashSidecarDto? sidecar,
        CrashTriageDto? triage,
        DebuggerObservation? debugger,
        CrashCorruptionChainDto? corruption,
        CrashBackwardTraceDto? backwardTrace,
        HypothesisSetDto? hypotheses,
        OracleScore? oracleScore,
        byte[]? payload,
        IFuzzProgressSink? progress = null,
        int iterations = 0)
    {
        try
        {
            var validation = ResolveArtifactValidation(crashesDir, crashId, sidecar, debugger);
            if (!CrashArtifactIdentityService.AllowsStrongPromotion(validation, out var blockReason))
            {
                FuzzAnalystLog.Warn(progress, $"[influence] blocked — {blockReason}", iterations);
                return;
            }

            var facts = EvidenceFactBuilder.CollectFacts(
                crashId,
                project,
                sidecar,
                triage,
                debugger,
                corruption,
                backwardTrace,
                oracleScore: oracleScore,
                hypotheses: hypotheses,
                validation: validation);
            var map = InfluenceEngine.PersistForCrash(
                crashesDir, crashId, project, sidecar, triage, debugger, corruption,
                backwardTrace, hypotheses, facts, payload);
            if (map is { Ok: true, Links.Count: > 0 })
            {
                FuzzAnalystLog.Info(progress,
                    $"[influence] {map.Links.Count} link(s) [{map.Confidence}] — {Truncate(map.Summary, 100)}",
                    iterations);
            }
        }
        catch (Exception ex)
        {
            FuzzAnalystLog.Warn(progress, $"influence: {ex.Message}", iterations);
        }
    }

    private void TryPersistResearchStack(
        ProjectConfig projectConfig,
        string yamlPath,
        string crashesDir,
        Guid crashId,
        string project,
        CrashSidecarDto? sidecar,
        CrashTriageDto? triage,
        DebuggerObservation? debugger,
        CrashCorruptionChainDto? corruption,
        HypothesisSetDto? hypotheses,
        IFuzzProgressSink? progress = null,
        int iterations = 0)
    {
        try
        {
            var validation = ResolveArtifactValidation(crashesDir, crashId, sidecar, debugger);
            if (!CrashArtifactIdentityService.AllowsStrongPromotion(validation, out var blockReason))
            {
                FuzzAnalystLog.Warn(progress,
                    $"[research-stack] blocked — {blockReason}", iterations);
                return;
            }

            var rootCause = RootCauseEngine.TryRead(RootCauseEngine.PathFor(crashesDir, crashId));
            var influence = InfluenceEngine.TryRead(InfluenceEngine.PathFor(crashesDir, crashId));
            var facts = EvidenceFactBuilder.TryReadForCrash(crashesDir, crashId)?.Facts;
            var primitives = PrimitiveEngine.PersistForCrash(
                crashesDir, crashId, project, influence, rootCause, debugger, corruption, triage, facts, hypotheses);
            var plan = ResearchPlannerEngine.PersistForCrash(
                crashesDir, crashId, project, rootCause, influence, primitives, hypotheses);
            var skeptic = SkepticEngine.PersistForCrash(
                crashesDir, crashId, project, plan, rootCause, influence, primitives);
            var advisor = ExploitabilityAdvisor.PersistForCrash(
                crashesDir, crashId, project, rootCause, influence, primitives, debugger, triage, skeptic);

            var backwardTrace = BackwardTraceBuilder.TryRead(BackwardTraceBuilder.PathFor(crashesDir, crashId));
            var deepScream = DeepScreamBuilder.TryRead(DeepScreamBuilder.PathFor(crashesDir, crashId));
            var patchHyp = PatchHypothesisEngine.PersistForCrash(
                crashesDir, crashId, project, rootCause, influence, primitives, triage, debugger);
            var temporal = TemporalBugEngine.PersistForCrash(
                crashesDir, crashId, project, backwardTrace, corruption, rootCause, deepScream);

            // Bounded live counterfactual loop (execute→observe→persist). Plan-only fallback
            // when replay oracle cannot be built. Caps probes so post-crash path stays cheap.
            Func<byte[], bool>? stillCrashes = null;
            try
            {
                stillCrashes = CounterfactualLiveLoop.CreateReplayOracle(projectConfig, yamlPath);
            }
            catch
            {
                stillCrashes = null;
            }

            var live = CounterfactualLiveLoop.PersistOrRunLive(
                crashesDir, crashId, project, TryLoadCrashBytes(crashesDir, crashId),
                stillCrashes,
                maxProbes: CounterfactualLiveLoop.DefaultMaxProbes,
                settleSkeptic: true,
                force: false,
                suspectedOffset: corruption?.PatternDepthBytes,
                influence: influence,
                rootCause: rootCause,
                corruption: corruption,
                hypotheses: hypotheses);
            var counterfactual = live.Report;
            if (live.Hypotheses is not null)
                hypotheses = live.Hypotheses;
            if (live.Skeptic is not null)
                skeptic = live.Skeptic;
            if (live.Influence is not null)
                influence = live.Influence;

            // Recompute maturity with Skeptic gate after live settle (R5+ needs Survived).
            primitives = PrimitiveEngine.PersistForCrash(
                crashesDir, crashId, project, influence, rootCause, debugger, corruption, triage,
                facts, hypotheses, skeptic);

            try
            {
                ExploitResearchPanelBuilder.PersistForCrash(
                    crashesDir, crashId, project, debugger, influence, primitives, counterfactual,
                    plan, skeptic, corruption, TryLoadCrashBytes(crashesDir, crashId),
                    mutatorHint: corruption?.SuspectedMutator
                                 ?? corruption?.MutatorLineage?.FirstOrDefault());
            }
            catch (Exception ex)
            {
                FuzzAnalystLog.Warn(progress, $"exploit-research panel: {ex.Message}", iterations);
            }

            var twins = VulnerabilityTwinEngine.PersistForCrash(
                crashesDir, crashId, project, rootCause, triage, debugger, queueHuntHints: true);

            try
            {
                var genealogy = BugGenealogyEngine.PersistForProject(project);
                if (genealogy is { Ok: true })
                {
                    FuzzAnalystLog.Info(progress,
                        $"[genealogy] {genealogy.ProbableVulnCount} probable vuln(s) / {genealogy.FailureCount} failure(s)",
                        iterations);
                }
            }
            catch (Exception ex)
            {
                FuzzAnalystLog.Warn(progress, $"genealogy: {ex.Message}", iterations);
            }

            if (primitives is { Ok: true })
            {
                FuzzAnalystLog.Info(progress,
                    $"[primitive] {primitives.Maturity} · {primitives.MaturityLabel} — {Truncate(primitives.Summary, 100)}",
                    iterations);
            }
            if (plan is { Ok: true, Steps.Count: > 0 })
            {
                FuzzAnalystLog.Info(progress,
                    $"[research-plan] {plan.Steps.Count} step(s) [{plan.Confidence}] — {Truncate(plan.Objective, 100)}",
                    iterations);
            }
            if (skeptic is { Ok: true, Challenges.Count: > 0 })
            {
                FuzzAnalystLog.Info(progress,
                    $"[skeptic] {skeptic.Challenges.Count} falsification challenge(s)",
                    iterations);
            }
            if (advisor is { Ok: true })
            {
                FuzzAnalystLog.Info(progress,
                    $"[advisor] {advisor.OverallLabel} [{advisor.Confidence}] — {Truncate(advisor.Summary, 100)}",
                    iterations);
            }
            if (patchHyp is { Ok: true })
            {
                FuzzAnalystLog.Info(progress,
                    $"[patch-hypothesis] [{patchHyp.Confidence}] — {Truncate(patchHyp.RemediationText, 100)}",
                    iterations);
            }
            if (temporal is { Ok: true })
            {
                FuzzAnalystLog.Info(progress,
                    $"[temporal] {temporal.Timeline.Count} phase(s) [{temporal.Confidence}] — {Truncate(temporal.Summary, 100)}",
                    iterations);
            }
            if (counterfactual is { Ok: true })
            {
                var liveTag = counterfactual.LiveExecuted
                    ? $"live {counterfactual.ExperimentsExecuted}"
                    : "plan";
                FuzzAnalystLog.Info(progress,
                    $"[counterfactual:{liveTag}] {counterfactual.Probes.Count} probe(s) @ offset {counterfactual.SuspectedOffset?.ToString() ?? "?"} — {Truncate(counterfactual.Summary, 100)}",
                    iterations);
            }
            if (twins is { Ok: true })
            {
                FuzzAnalystLog.Info(progress,
                    $"[vuln-twins] {twins.Twins.Count} twin(s) seed={twins.SeedFunction ?? "?"} ghidra={(twins.StaticMapPresent ? "yes" : "stub")}",
                    iterations);
            }

            var researchPkg = ResearchPackageReportBuilder.PersistForCrash(
                crashesDir, crashId, project, advisor, plan, patchHyp,
                barriers: null,
                sidecar: sidecar,
                triage: triage,
                debugger: debugger,
                rootCause: rootCause,
                influence: influence,
                primitives: primitives,
                hypotheses: hypotheses,
                skeptic: skeptic,
                counterfactual: counterfactual,
                corruption: corruption,
                payload: TryLoadCrashBytes(crashesDir, crashId));
            if (researchPkg is { Ok: true })
            {
                FuzzAnalystLog.Info(progress,
                    $"[research-package] {researchPkg.ReportId} · {researchPkg.Packages.Count} checklist item(s) [{researchPkg.Confidence}]",
                    iterations);
            }
        }
        catch (Exception ex)
        {
            FuzzAnalystLog.Warn(progress, $"research-stack: {ex.Message}", iterations);
        }
    }

    private static string Truncate(string? text, int max) =>
        string.IsNullOrEmpty(text) ? "" : text.Length <= max ? text : text[..max] + "…";

    private static byte[]? TryLoadCrashBytes(string crashesDir, Guid crashId)
    {
        try
        {
            var store = new CrashStore(crashesDir);
            var hit = store.List().FirstOrDefault(c => c.Id == crashId);
            if (hit is not null && File.Exists(hit.InputPath))
                return File.ReadAllBytes(hit.InputPath);
        }
        catch
        {
            /* ignore */
        }

        return null;
    }

    private async Task TryPersistDeepScream(
        ProjectConfig project, string yamlPath, string crashesDir, SavedCrash saved,
        int iterations, IFuzzProgressSink? progress, CancellationToken cancellationToken)
    {
        try
        {
            var sidecar = CrashSidecarWriter.TryRead(saved.SidecarPath);
            var debugger = ScreamInvestigator.TryRead(ScreamInvestigator.ObservationPathFor(crashesDir, saved.Id));
            var corruption = CorruptionChainBuilder.TryRead(CorruptionChainBuilder.PathFor(crashesDir, saved.Id));
            var evolution = ScreamEvolutionBuilder.TryRead(ScreamEvolutionBuilder.PathFor(crashesDir, saved.Id));
            var hypotheses = HypothesisEngine.TryReadForCrash(crashesDir, saved.Id);
            byte[]? payload = null;
            if (File.Exists(saved.InputPath)) { try { payload = File.ReadAllBytes(saved.InputPath); } catch { } }
            var summary = new CrashSummaryDto(saved.Id, project.Name, iterations, sidecar?.Mutator ?? "?",
                saved.InputHash, saved.InputPath, saved.MiniDumpPath, sidecar?.ExitCode?.ToString(),
                sidecar?.TriageTag, saved.SidecarPath, sidecar?.RunId, DateTimeOffset.UtcNow);
            var triage = CrashTriage.Classify(null, sidecar, summary, payload, debugger: debugger);
            var intelligence = CrashIntelligenceBuilder.Build(summary, triage, sidecar, payload?.Length ?? 0,
                CrashCatalog.ListAll(projectFilter: project.Name), null, null, false, summary.TriageTag, debugger,
                corruption, evolution, hypotheses);
            var deepScream = await DeepScreamBuilder.ProcessAndPersistAsync(crashesDir, saved.Id, project.Name,
                intelligence.ScreamScore, intelligence.SeenCount, intelligence.Reproducible, intelligence.Minimized,
                saved.MiniDumpPath, triage.SemanticFingerprint, evolution, project.Fuzz.DeepScreamAutoMinimize,
                project, yamlPath, payload, cancellationToken);
            if (deepScream.IsMarked)
            {
                Console.WriteLine($"  deep scream: {DeepScreamBuilder.FormatSummary(deepScream)}");
                FuzzAnalystLog.Info(progress, $"[deep-scream] marked scream={deepScream.ScreamScore} family={deepScream.FamilyId ?? "—"}", iterations);
                if (project.Fuzz.RewindScream)
                    _ = MagicianEngine.DeepScreamOnCrash(project, yamlPath, saved.Id, saved.MiniDumpPath, saved.InputPath, deepScream, progress);
            }
            else if (deepScream.FamilySuppressed)
                FuzzAnalystLog.Info(progress, $"[deep-scream] family dedup — prior `{deepScream.PriorFamilyCrashId:N}`", iterations);
        }
        catch (Exception ex) { FuzzAnalystLog.Warn(progress, $"deep scream: {ex.Message}", iterations); }
    }

    private void PublishEnrichedCrashFaults(
        ProjectConfig project,
        SavedCrash saved,
        string crashesDir,
        string? crashTag,
        string? targetDetail,
        string runId,
        int iterations,
        string payloadHash)
    {
        var summary = new CrashSummaryDto(
            saved.Id, saved.Project, saved.Iteration, saved.Mutator, saved.InputHash, saved.InputPath,
            saved.MiniDumpPath, saved.TargetExitCode, saved.TriageTag, saved.SidecarPath, saved.RunId, saved.At);
        var sidecar = CrashSidecarWriter.TryRead(saved.SidecarPath);
        var analysisPath = CrashAnalysisWriter.AnalysisPathFor(crashesDir, saved.Id);
        var analysis = CrashAnalysisWriter.TryRead(analysisPath)
            ?? (saved.MiniDumpPath is not null ? CrashAnalysisWriter.AnalyzeDump(saved.MiniDumpPath) : null);
        var cdbSidecar = WindowsCdbCrashAnalysisWriter.TryRead(
            WindowsCdbCrashAnalysisWriter.TriagePathFor(crashesDir, saved.Id));
        var triage = CrashTriage.Classify(
            analysis,
            sidecar,
            summary,
            null,
            cdbSidecar?.ExploitableClassification);
        var faults = FaultSignalMapper.FromCrash(
            triage,
            analysis,
            CrashCatalog.MapCdbTriage(cdbSidecar),
            sidecar,
            project.Target.PageHeap,
            crashTag ?? saved.TriageTag,
            targetDetail ?? sidecar?.TargetDetail,
            sidecar?.ExitCode ?? (int.TryParse(saved.TargetExitCode, out var ec) ? ec : null));
        FaultSignalMapper.PublishFaults(
            ObservationBus, runId, iterations, payloadHash, project.Name, faults);
    }

    /// <summary>Honest coverage mode label for live UI (bb-edges | path-novelty | unavailable).</summary>
    /// <summary>
    /// TCP-dead cascade: connection never established and no dump/Scream exception —
    /// not an input-triggered crash. Must run before journal / SignalR / crashCount++.
    /// </summary>
    internal static bool ShouldRejectCascadeCrash(
        bool crashed,
        bool tcpLike,
        bool connected,
        string? miniDumpPath,
        bool hasScreamException) =>
        crashed
        && tcpLike
        && !connected
        && string.IsNullOrWhiteSpace(miniDumpPath)
        && !hasScreamException;

    /// <summary>Journal/progress payload for an iteration that threw before producing a case.</summary>
    internal static IterationLogEntry BuildFailedIterationEntry(
        int iteration,
        bool isBounds,
        string message,
        int coverageEdges,
        string? stalkBackend,
        string runId) =>
        new(
            iteration, DateTimeOffset.UtcNow, "?",
            isBounds ? "error:bounds" : "error:exception",
            ["error"],
            null, "error", 0, "0",
            false, 0, coverageEdges, 0,
            isBounds ? $"failed (bounds): {message}" : $"failed: {message}",
            null, stalkBackend ?? "", null,
            runId ?? "", false);

    private static string DescribeCoverageKind(int edges, int semanticStages, bool coverageGuided) =>
        edges > 0 ? "bb-edges"
        : semanticStages > 0 ? "path-novelty"
        : coverageGuided ? "unavailable"
        : "unavailable";
}
