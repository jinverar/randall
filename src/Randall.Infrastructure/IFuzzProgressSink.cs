using Randall.Core;

namespace Randall.Infrastructure;

public interface IFuzzProgressSink
{
    void OnStarted(string project, string kind);
    void OnTargetPid(int? pid) { }
    void OnIteration(FuzzIterationEvent iteration);
    /// <summary>Boofuzz-style analyst log line (timestamp + color kind).</summary>
    void OnLog(FuzzLogEvent entry) { }
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

/// <summary>
/// Rich live-log event. <see cref="Kind"/> drives UI/console colors:
/// info, case, step, tx, ok, crash, warn.
/// </summary>
public sealed record FuzzLogEvent(
    string Kind,
    string Message,
    DateTimeOffset At,
    int? Iteration = null,
    int? ByteLength = null,
    string? HexPreview = null);

public sealed record FuzzRunOptions(
    bool DryRun = false,
    bool CoverageGuided = false,
    int? MaxIterations = null,
    IFuzzProgressSink? Progress = null,
    string? DebuggerMode = null,
    string? DebuggerKind = null,
    bool? DebuggerOpenOnCrash = null,
    bool? ProcmonCapture = null,
    bool? TcpvconCapture = null,
    bool? ProcdumpOnCrash = null,
    bool? PktmonCapture = null,
    bool? TsharkCapture = null,
    bool? EtwCapture = null,
    bool? DebugViewCapture = null,
    bool? SysinternalsSnapshots = null,
    bool? StringsOnCrash = null,
    /// <summary>Extra Oracle / Magician / Joker / coverage / INTEL console detail.</summary>
    bool Verbose = false);
