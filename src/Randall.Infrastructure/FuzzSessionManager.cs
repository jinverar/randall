using Randall.Contracts;
using Randall.Core;

namespace Randall.Infrastructure;

public sealed class FuzzSessionManager(FuzzLiveLogBuffer liveLog)
{
    private readonly object _gate = new();
    private CancellationTokenSource? _cts;
    private Task? _task;
    private FuzzSessionStatusDto _status = new(false, "idle", null, 0, 0, 0, 0, null, null, null, null, null);

    public FuzzSessionStatusDto Status
    {
        get { lock (_gate) return _status; }
    }

    /// <summary>True when a run task is still alive (including stuck stopping).</summary>
    public bool HasActiveTask
    {
        get { lock (_gate) return _task is { IsCompleted: false }; }
    }

    public bool Start(FuzzStartRequest request, IFuzzProgressSink? sink = null)
    {
        lock (_gate)
        {
            if (_task is { IsCompleted: false })
            {
                // Orphaned: status says idle/done but task never finished — auto-recover.
                if (!_status.Running &&
                    _status.Phase is not ("starting" or "running" or "stopping"))
                {
                    AbandonLocked("Orphaned fuzz task cleared — status was idle while a worker lingered");
                }
                else
                {
                    return false;
                }
            }

            return StartLocked(request, sink);
        }
    }

    /// <summary>
    /// Cancel any in-flight run, wait briefly, then force status back to idle so Start can proceed.
    /// </summary>
    public async Task<FuzzSessionStatusDto> ForceClearAsync(TimeSpan? wait = null)
    {
        CancellationTokenSource? cts;
        Task? task;
        lock (_gate)
        {
            cts = _cts;
            task = _task;
            if (task is null || task.IsCompleted)
            {
                AbandonLocked("No active fuzz session");
                return _status;
            }

            try { cts?.Cancel(); }
            catch { /* ignore */ }
            _status = _status with { Running = true, Phase = "stopping", LastMessage = "Force-clearing stuck session…" };
        }

        if (task is not null)
        {
            var timeout = wait ?? TimeSpan.FromSeconds(4);
            try { await Task.WhenAny(task, Task.Delay(timeout)); }
            catch { /* ignore */ }
        }

        lock (_gate)
        {
            if (_task is { IsCompleted: false })
                AbandonLocked("Force-cleared orphaned fuzz session (worker did not finish in time)");
            else if (_status.Running || _status.Phase is "starting" or "running" or "stopping")
                AbandonLocked("Force-cleared fuzz session");
            return _status;
        }
    }

    public bool Stop()
    {
        lock (_gate)
        {
            if (_task is not { IsCompleted: false })
                return false;

            _cts?.Cancel();
            _status = _status with { Running = true, Phase = "stopping", LastMessage = "Stopping…" };
            return true;
        }
    }

    private bool StartLocked(FuzzStartRequest request, IFuzzProgressSink? sink)
    {
        liveLog.Clear();
        _cts = new CancellationTokenSource();
        var token = _cts.Token;
        var dbgMode = request.DebuggerMode;
        _status = new FuzzSessionStatusDto(
            true, "starting", request.ConfigPath, 0, 0, 0, 0, request.CoverageGuided, null,
            null, dbgMode, null);

        _task = Task.Run(async () =>
        {
            try
            {
                var yamlPath = Path.GetFullPath(request.ConfigPath);
                var project = ProjectLoader.Load(yamlPath);
                lock (_gate)
                {
                    _status = _status with { Project = project.Name };
                }
                if (request.MaxIterations is > 0)
                    project.Fuzz.MaxIterations = request.MaxIterations.Value;
                ApplySemanticStackOverrides(project, request);

                var progress = new MultiplexFuzzProgressSink(
                    sink, UpdateFromEvent, UpdatePid, UpdateGoalProgress, UpdateFromLog);
                progress.OnStarted(project.Name, project.Kind);
                UpdateFromLog(new FuzzLogEvent("info", $"Starting {project.Name}…", DateTimeOffset.UtcNow));

                var engine = new FuzzEngine();
                var result = await engine.RunAsync(
                    project,
                    yamlPath,
                    new FuzzRunOptions(
                        request.DryRun,
                        request.CoverageGuided,
                        request.MaxIterations,
                        progress,
                        request.DebuggerMode,
                        request.DebuggerKind,
                        request.DebuggerOpenOnCrash,
                        request.ProcmonCapture,
                        request.TcpvconCapture,
                        request.ProcdumpOnCrash,
                        request.PktmonCapture,
                        request.TsharkCapture,
                        request.EtwCapture,
                        request.DebugViewCapture,
                        request.SysinternalsSnapshots,
                        request.StringsOnCrash,
                        request.CdbAnalyzeCrash),
                    token);

                lock (_gate)
                {
                    // Keep Project / counters so the stalker dashboard retains session summary after end-of-run.
                    _status = _status with
                    {
                        Running = false,
                        Phase = "completed",
                        Project = project.Name,
                        Iterations = result.Iterations,
                        Crashes = result.CrashesFound,
                        CorpusAdded = result.CorpusAdded,
                        LastMessage = result.StopGoalMet
                            ? $"Stop goal met — {result.StopReason}"
                            : $"Done — {result.Iterations} iterations, {result.CrashesFound} crashes",
                        StopGoalMet = result.StopGoalMet,
                        StopReason = result.StopReason,
                        GoalProgress = _status.GoalProgress,
                    };
                }
            }
            catch (OperationCanceledException)
            {
                sink?.OnStopped("cancelled");
                lock (_gate)
                {
                    _status = _status with
                    {
                        Running = false,
                        Phase = "stopped",
                        LastMessage = "Stopped by user",
                    };
                }
            }
            catch (Exception ex) when (BenignRecorderPipeException.IsBenign(ex))
            {
                FuzzRunResult partial;
                var expectedIters = request.MaxIterations is > 0 ? request.MaxIterations.Value : (int?)null;
                lock (_gate)
                {
                    partial = new FuzzRunResult(
                        _status.Iterations,
                        _status.CorpusAdded,
                        _status.Crashes,
                        []);
                    var early = expectedIters is > 0 && partial.Iterations < expectedIters.Value;
                    _status = _status with
                    {
                        Running = false,
                        Phase = partial.Iterations > 0 ? "completed" : "error",
                        LastMessage = partial.Iterations > 0
                            ? early
                                ? $"Done — {partial.Iterations} iterations (stopped early — hub/recorder noise: {ex.Message})"
                                : $"Done — {partial.Iterations} iterations (recorder teardown noise: {ex.Message})"
                            : ex.Message,
                    };
                }

                if (partial.Iterations > 0)
                {
                    try { sink?.OnCompleted(partial); }
                    catch (Exception notifyEx) when (BenignRecorderPipeException.IsBenign(notifyEx))
                    {
                        /* hub/client pipe already closed */
                    }
                }
                else
                {
                    sink?.OnError(ex.Message);
                }
            }
            catch (Exception ex)
            {
                sink?.OnError(ex.Message);
                lock (_gate)
                {
                    _status = _status with
                    {
                        Running = false,
                        Phase = "error",
                        LastMessage = ex.Message,
                    };
                }
            }
        }, token);

        return true;
    }

    private void AbandonLocked(string message)
    {
        try { _cts?.Cancel(); }
        catch { /* ignore */ }
        try { _cts?.Dispose(); }
        catch { /* ignore */ }
        _cts = null;
        _task = null;
        _status = new FuzzSessionStatusDto(
            false,
            "idle",
            _status.ConfigPath,
            _status.Iterations,
            _status.Crashes,
            _status.CorpusAdded,
            _status.CoverageEdges,
            _status.CoverageGuided,
            message,
            null,
            _status.DebuggerMode,
            _status.Project,
            _status.StopGoalMet,
            _status.StopReason,
            _status.GoalProgress);
        liveLog.Clear();
    }

    private static void ApplySemanticStackOverrides(ProjectConfig project, FuzzStartRequest request)
    {
        if (request.OraclesEnabled is bool oracles)
        {
            project.Oracles ??= new OracleConfig();
            project.Oracles.Enabled = oracles;
        }

        if (request.MagicianEnabled is bool magician)
        {
            project.Magician ??= new MagicianConfig();
            project.Magician.Enabled = magician;
            if (magician)
                project.Magician.AutoCastOnOracle = true;
        }

        if (request.JokerEnabled is bool joker)
        {
            project.Joker ??= new JokerConfig();
            project.Joker.Enabled = joker;
        }
    }

    private void UpdateFromEvent(FuzzIterationEvent ev)
    {
        lock (_gate)
        {
            _status = _status with
            {
                Running = true,
                Phase = "running",
                Iterations = ev.Iteration,
                Crashes = _status.Crashes + (ev.Crashed ? 1 : 0),
                CorpusAdded = ev.CorpusSize,
                CoverageEdges = ev.CoverageEdgeTotal,
                CoverageBlocks = ev.CoverageBlocks,
                SemanticStageHits = ev.SemanticStageHits,
                CoverageKind = ev.CoverageKind ?? _status.CoverageKind,
                LastMessage = ev.Crashed
                    ? $"CRASH iter={ev.Iteration} {ev.Mutator}"
                    : ev.NewCoverage
                        ? $"New coverage +{ev.NewEdgeCount} edges"
                        : $"iter={ev.Iteration} {ev.Mutator} len={ev.PayloadLength}",
            };
        }
    }

    private void UpdateGoalProgress(IntelligenceStopGoalProgressDto progress)
    {
        lock (_gate)
        {
            _status = _status with { GoalProgress = progress };
        }
    }

    private void UpdatePid(int? pid)
    {
        lock (_gate)
        {
            _status = _status with { TargetPid = pid };
        }
    }

    private void UpdateFromLog(FuzzLogEvent entry)
    {
        if (string.IsNullOrWhiteSpace(entry.Message))
            return;
        lock (_gate)
        {
            if (_status.Phase is not ("starting" or "running" or "stopping"))
                return;
            // Keep STATUS honest during long starts (port wait / drrun) — logs already flow to Live log.
            _status = _status with { LastMessage = TruncateMsg(entry.Message, 160) };
        }
    }

    private static string TruncateMsg(string msg, int max) =>
        msg.Length <= max ? msg : msg[..(max - 1)] + "…";
}

internal sealed class MultiplexFuzzProgressSink(
    IFuzzProgressSink? outer,
    Action<FuzzIterationEvent>? local,
    Action<int?>? onPid = null,
    Action<IntelligenceStopGoalProgressDto>? onGoalProgress = null,
    Action<FuzzLogEvent>? onLog = null) : IFuzzProgressSink
{
    public void OnStarted(string project, string kind) => outer?.OnStarted(project, kind);

    public void OnTargetPid(int? pid)
    {
        onPid?.Invoke(pid);
        outer?.OnTargetPid(pid);
    }

    public void OnIteration(FuzzIterationEvent iteration)
    {
        local?.Invoke(iteration);
        outer?.OnIteration(iteration);
    }

    public void OnLog(FuzzLogEvent entry)
    {
        onLog?.Invoke(entry);
        outer?.OnLog(entry);
    }

    public void OnGoalProgress(IntelligenceStopGoalProgressDto progress)
    {
        onGoalProgress?.Invoke(progress);
        outer?.OnGoalProgress(progress);
    }

    public void OnCompleted(FuzzRunResult result) => outer?.OnCompleted(result);
    public void OnStopped(string reason) => outer?.OnStopped(reason);
    public void OnError(string message) => outer?.OnError(message);
}
