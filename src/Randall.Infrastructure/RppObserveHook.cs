using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Runs RPP <c>observe</c> plugins after each iteration and publishes custom observations / fault hints.
/// </summary>
public static class RppObserveHook
{
    public static async Task<IReadOnlyList<RppObserveResult>> RunAsync(
        ProjectConfig project,
        string yamlPath,
        ObservationBus bus,
        string runId,
        int iteration,
        string inputHash,
        byte[] payload,
        int newEdges,
        int totalEdges,
        string? detail,
        CancellationToken cancellationToken = default)
    {
        var results = new List<RppObserveResult>();
        foreach (var pluginRef in project.Plugins)
        {
            if (!pluginRef.Hook.Equals("observe", StringComparison.OrdinalIgnoreCase))
                continue;

            var dir = ProjectLoader.ResolvePath(yamlPath, pluginRef.Path);
            var manifest = RppPluginHost.LoadManifest(Path.Combine(dir, "rpp.yaml"));
            if (manifest is null)
                continue;

            var host = new RppPluginHost(dir);
            var result = await host.ObserveAsync(
                manifest,
                iteration,
                payload,
                newEdges,
                totalEdges,
                detail,
                cancellationToken);
            if (result is null)
                continue;

            results.Add(result);

            if (result.Observation is not null)
                bus.Publish(result.Observation with
                {
                    RunId = runId,
                    Iteration = iteration,
                    InputHash = inputHash,
                    Project = project.Name,
                });

            if (result.Fault is not null)
                bus.Publish(ObservationEvents.Fault(
                    runId, iteration, inputHash, result.Fault, project.Name));
        }

        return results;
    }
}

public sealed record RppObserveResult(
    string PluginName,
    Observation? Observation,
    FaultSignal? Fault,
    string? Note);
