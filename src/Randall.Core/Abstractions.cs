namespace Randall.Core;

/// <summary>
/// Leg 1 — Model: block-based protocol definition (Sulley/Boofuzz-style).
/// </summary>
public interface IProtocolModel
{
    string Name { get; }
    byte[] Render();
}

/// <summary>
/// Leg 2 — Mutate: transform inputs before send.
/// </summary>
public interface IMutator
{
    string Name { get; }
    ReadOnlyMemory<byte> Mutate(ReadOnlyMemory<byte> input);
}

/// <summary>
/// Leg 3 — Send: deliver bytes to the target.
/// </summary>
public interface ITransport
{
    Task SendAsync(ReadOnlyMemory<byte> payload, CancellationToken cancellationToken = default);
    Task<ReadOnlyMemory<byte>?> ReceiveAsync(CancellationToken cancellationToken = default);
}

/// <summary>
/// Leg 4 — Stalk: coverage feedback from DynamoRIO or other backends.
/// </summary>
public interface ICoverageBackend
{
    Task<CoverageResult> RunAsync(ReadOnlyMemory<byte> input, CancellationToken cancellationToken = default);
}

public sealed record CoverageResult(
    bool IsNewPath,
    int NewEdgeCount,
    ReadOnlyMemory<byte> Bitmap,
    string? TracePath);

/// <summary>
/// Leg 5 — Scream: crash detection and capture.
/// </summary>
public interface ICrashMonitor
{
    Task<CrashRecord?> ObserveAsync(CancellationToken cancellationToken = default);
}

public sealed record CrashRecord(
    Guid Id,
    ReadOnlyMemory<byte> Input,
    string StackHash,
    string ExceptionCode,
    ulong? FaultAddress,
    string? MiniDumpPath,
    int NewEdgesBeforeCrash);

/// <summary>
/// Top-level fuzz session orchestrator.
/// </summary>
public interface IFuzzEngine
{
    Task<FuzzRunResult> RunSessionAsync(FuzzSessionRequest request, CancellationToken cancellationToken = default);
}

public sealed record FuzzSessionRequest(
    string ProjectName,
    IProtocolModel Model,
    ITransport Transport,
    ICoverageBackend? Coverage,
    ICrashMonitor Monitor,
    IReadOnlyList<IMutator> Mutators);

public sealed record FuzzRunResult(
    int Iterations,
    int CorpusAdded,
    int CrashesFound,
    IReadOnlyList<CrashRecord> Crashes);
