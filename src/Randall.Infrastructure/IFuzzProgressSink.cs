using Randall.Core;

namespace Randall.Infrastructure;

public interface IFuzzProgressSink
{
    void OnStarted(string project, string kind);
    void OnTargetPid(int? pid) { }
    void OnIteration(FuzzIterationEvent iteration);
    void OnCompleted(FuzzRunResult result);
    void OnStopped(string reason);
    void OnError(string message);
}

public sealed record FuzzIterationEvent(
    int Iteration,
    string Mutator,
    int PayloadLength,
    bool Crashed,
    bool NewCoverage,
    int NewEdgeCount,
    int CorpusSize,
    int CoverageEdgeTotal,
    string Detail);

public sealed record FuzzRunOptions(
    bool DryRun = false,
    bool CoverageGuided = false,
    int? MaxIterations = null,
    IFuzzProgressSink? Progress = null,
    string? DebuggerMode = null,
    string? DebuggerKind = null,
    bool? DebuggerOpenOnCrash = null,
    bool? ProcmonCapture = null);
