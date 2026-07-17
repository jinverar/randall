using System.Diagnostics;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Phase 16 — Randall-native basic-block stalk (in development).
/// Goal: emit drcov-compatible traces without third-party instrumentation runtimes.
/// </summary>
public sealed class NativeStalkRunner : IStalkTraceBackend
{
    public string BackendId => StalkBackend.Native;
    public bool IsAvailable => false;
    public string AvailabilityNote =>
        "Native stalk engine is under construction — use stalkMode: auto|external for now.";

    public Task<StalkTraceResult> RunFileTargetAsync(
        ProjectConfig project,
        string yamlPath,
        byte[] input,
        string traceDir,
        CancellationToken cancellationToken = default)
    {
        if (!IsAvailable)
        {
            return Task.FromResult(new StalkTraceResult(
                false, null, null,
                "Native stalk not yet available — set fuzz.stalkMode to auto or external."));
        }

        return Task.FromResult(new StalkTraceResult(false, null, null, "unimplemented"));
    }

    public Process? StartLongLivedTarget(ProjectConfig project, string yamlPath, string traceDir) => null;

    public string? CollectLatestTrace(string traceDir) => null;

    public Task StopLongLivedAsync(Process? process, CancellationToken cancellationToken = default)
    {
        process?.Dispose();
        return Task.CompletedTask;
    }
}
