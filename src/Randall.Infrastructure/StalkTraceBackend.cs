using System.Diagnostics;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Pluggable coverage trace backend. External (DynamoRIO) is optional;
/// <see cref="NativeStalkRunner"/> will become the default Randall-owned implementation.
/// </summary>
public interface IStalkTraceBackend
{
    string BackendId { get; }
    bool IsAvailable { get; }
    string AvailabilityNote { get; }

    Task<StalkTraceResult> RunFileTargetAsync(
        ProjectConfig project,
        string yamlPath,
        byte[] input,
        string traceDir,
        CancellationToken cancellationToken = default);

    Process? StartLongLivedTarget(ProjectConfig project, string yamlPath, string traceDir);

    string? CollectLatestTrace(string traceDir);

    Task StopLongLivedAsync(Process? process, CancellationToken cancellationToken = default);
}

public sealed record StalkTraceResult(
    bool Success,
    string? TracePath,
    int? ExitCode,
    string Detail);

public static class StalkTraceBackendFactory
{
    public static IStalkTraceBackend Create(ProjectConfig project)
    {
        var mode = (project.Fuzz.StalkMode ?? "auto").Trim().ToLowerInvariant();
        var native = new NativeStalkRunner();
        var external = new ExternalDrcovStalkBackend(DynamoRioRunner.Discover());

        // Prefer DynamoRIO (full BB) over native PC sampling when both exist.
        return mode switch
        {
            "native" when native.IsAvailable => native,
            "native" => native,
            "external" => external,
            "none" => NullStalkTraceBackend.Instance,
            "auto" when external.IsAvailable => external,
            "auto" when native.IsAvailable => native,
            _ => NullStalkTraceBackend.Instance,
        };
    }

    public static string ResolveBackendId(ProjectConfig project)
    {
        var backend = Create(project);
        if (backend.IsAvailable)
            return backend.BackendId;

        var mode = (project.Fuzz.StalkMode ?? "auto").Trim().ToLowerInvariant();
        if (mode is "native" or "auto")
        {
            var external = new ExternalDrcovStalkBackend(DynamoRioRunner.Discover());
            if (external.IsAvailable)
                return StalkBackend.External;
            var native = new NativeStalkRunner();
            if (native.IsAvailable)
                return StalkBackend.Native;
            return StalkBackend.None;
        }

        return backend.BackendId;
    }

    /// <summary>Human-readable note when requested mode cannot be honored.</summary>
    public static string? ResolveFallbackNote(ProjectConfig project)
    {
        var mode = (project.Fuzz.StalkMode ?? "auto").Trim().ToLowerInvariant();
        if (mode == "native" && !new NativeStalkRunner().IsAvailable)
        {
            var external = new ExternalDrcovStalkBackend(DynamoRioRunner.Discover());
            return external.IsAvailable
                ? "stalkMode: native unavailable — using DynamoRIO (external)"
                : "stalkMode: native unavailable — coverage disabled";
        }
        if (mode == "auto" && !DynamoRioRunner.Discover().IsAvailable && new NativeStalkRunner().IsAvailable)
            return "stalkMode: auto — using native PC stalk (install DynamoRIO for full BB coverage)";
        return null;
    }
}

public sealed class NullStalkTraceBackend : IStalkTraceBackend
{
    public static readonly NullStalkTraceBackend Instance = new();
    public string BackendId => StalkBackend.None;
    public bool IsAvailable => true;
    public string AvailabilityNote => "No coverage instrumentation.";

    public Task<StalkTraceResult> RunFileTargetAsync(
        ProjectConfig project, string yamlPath, byte[] input, string traceDir,
        CancellationToken cancellationToken = default) =>
        Task.FromResult(new StalkTraceResult(false, null, null, "stalk disabled"));

    public Process? StartLongLivedTarget(ProjectConfig project, string yamlPath, string traceDir) => null;

    public string? CollectLatestTrace(string traceDir) => null;

    public Task StopLongLivedAsync(Process? process, CancellationToken cancellationToken = default)
    {
        process?.Dispose();
        return Task.CompletedTask;
    }
}

public sealed class ExternalDrcovStalkBackend(DynamoRioRunner dynamo) : IStalkTraceBackend
{
    public string BackendId => StalkBackend.External;
    public bool IsAvailable => dynamo.IsAvailable;
    public string AvailabilityNote => dynamo.IsAvailable
        ? $"DynamoRIO drrun: {dynamo.DrrunPath}"
        : "Set DYNAMORIO_HOME or install DynamoRIO (optional adapter).";

    public async Task<StalkTraceResult> RunFileTargetAsync(
        ProjectConfig project, string yamlPath, byte[] input, string traceDir,
        CancellationToken cancellationToken = default)
    {
        var r = await dynamo.RunWithCoverageAsync(
            project, yamlPath, input, traceDir, dumpText: true, cancellationToken);
        return new StalkTraceResult(r.Success, r.TracePath, r.ExitCode, r.Detail);
    }

    public Process? StartLongLivedTarget(ProjectConfig project, string yamlPath, string traceDir) =>
        dynamo.StartInstrumentedTarget(project, yamlPath, traceDir);

    public string? CollectLatestTrace(string traceDir) => dynamo.CollectLatestTrace(traceDir);

    public Task StopLongLivedAsync(Process? process, CancellationToken cancellationToken = default) =>
        dynamo.StopInstrumentedAsync(process, cancellationToken);
}
