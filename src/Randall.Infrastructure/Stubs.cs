using Randall.Core;

namespace Randall.Infrastructure;

/// <summary>
/// Leg 4 — Stalk: DynamoRIO drcov wrapper (stub — implementation planned).
/// </summary>
public sealed class DynamoRioCoverageBackend : ICoverageBackend
{
    public Task<CoverageResult> RunAsync(ReadOnlyMemory<byte> input, CancellationToken cancellationToken = default)
    {
        _ = input;
        return Task.FromResult(new CoverageResult(
            IsNewPath: false,
            NewEdgeCount: 0,
            Bitmap: ReadOnlyMemory<byte>.Empty,
            TracePath: null));
    }
}

/// <summary>
/// Leg 5 — Scream: process monitor stub.
/// </summary>
public sealed class ProcessCrashMonitor : ICrashMonitor
{
    public Task<CrashRecord?> ObserveAsync(CancellationToken cancellationToken = default)
    {
        _ = cancellationToken;
        return Task.FromResult<CrashRecord?>(null);
    }
}
