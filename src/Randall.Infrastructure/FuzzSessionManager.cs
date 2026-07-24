using Randall.Contracts;
using Randall.Core;

namespace Randall.Infrastructure;

public sealed class FuzzSessionManager(FuzzLiveLogBuffer liveLog)
{
    private readonly object _gate = new();
    private CancellationTokenSource? _cts;
    private Task? _task;
    private FuzzSessionStatusDto _status = new(false, "idle", null, 0, 0, 0, 0, null, null);

    public FuzzSessionStatusDto Status
    {
        get { lock (_gate) return _status; }
    }

    public bool Start(FuzzStartRequest request, IFuzzProgressSink? sink = null)
    {
        lock (_gate)
        {
            if (_task is { IsCompleted: false })
                return false;

            liveLog.Clear();
            _cts = new CancellationTokenSource();
            var token = _cts.Token;
            var dbgMode = request.DebuggerMode;
            _status = new FuzzSessionStatusDto(
                true, "starting", request.ConfigPath, 0, 0, 0, 0, request.CoverageGuided, null,
                null, dbgMode);

            _task = Task.Run(async () =>
            {
                try
                {
                    var yamlPath = Path.GetFullPath(request.ConfigPath);
                    var project = ProjectLoader.Load(yamlPath);
                    if (request.MaxIterations is > 0)
                        project.Fuzz.MaxIterations = request.MaxIterations.Value;

                    var progress = new MultiplexFuzzProgressSink(sink, UpdateFromEvent, UpdatePid);
                    progress.OnStarted(project.Name, project.Kind);

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
                            request.StringsOnCrash),
                        token);

                    lock (_gate)
                    {
                        _status = _status with
                        {
                            Running = false,
                            Phase = "completed",
                            Iterations = result.Iterations,
                            Crashes = result.CrashesFound,
                            CorpusAdded = result.CorpusAdded,
                            LastMessage = $"Done — {result.Iterations} iterations, {result.CrashesFound} crashes",
                        };
                    }
                }
                catch (OperationCanceledException)
                {
                    sink?.OnStopped("cancelled");
                    lock (_gate)
                    {
                        _status = _status with { Running = false, Phase = "stopped", LastMessage = "Stopped by user" };
                    }
                }
                catch (Exception ex) when (BenignRecorderPipeException.IsBenign(ex))
                {
                    FuzzRunResult partial;
                    lock (_gate)
                    {
                        partial = new FuzzRunResult(
                            _status.Iterations,
                            _status.CorpusAdded,
                            _status.Crashes,
                            []);
                        _status = _status with
                        {
                            Running = false,
                            Phase = partial.Iterations > 0 ? "completed" : "error",
                            LastMessage = partial.Iterations > 0
                                ? $"Done — {partial.Iterations} iterations (recorder teardown noise: {ex.Message})"
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
                LastMessage = ev.Crashed
                    ? $"CRASH iter={ev.Iteration} {ev.Mutator}"
                    : ev.NewCoverage
                        ? $"New coverage +{ev.NewEdgeCount} edges"
                        : $"iter={ev.Iteration} {ev.Mutator} len={ev.PayloadLength}",
            };
        }
    }

    private void UpdatePid(int? pid)
    {
        lock (_gate)
        {
            _status = _status with { TargetPid = pid };
        }
    }
}

internal sealed class MultiplexFuzzProgressSink(
    IFuzzProgressSink? outer,
    Action<FuzzIterationEvent>? local,
    Action<int?>? onPid = null) : IFuzzProgressSink
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

    public void OnLog(FuzzLogEvent entry) => outer?.OnLog(entry);

    public void OnCompleted(FuzzRunResult result) => outer?.OnCompleted(result);
    public void OnStopped(string reason) => outer?.OnStopped(reason);
    public void OnError(string message) => outer?.OnError(message);
}
