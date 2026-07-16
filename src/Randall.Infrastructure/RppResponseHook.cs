using Randall.Contracts;

namespace Randall.Infrastructure;

public static class RppResponseHook
{
    public static async Task<string?> RunAsync(
        ProjectConfig project,
        string yamlPath,
        byte[] sent,
        byte[]? response,
        CancellationToken cancellationToken = default)
    {
        foreach (var pluginRef in project.Plugins)
        {
            if (!pluginRef.Hook.Equals("post_receive", StringComparison.OrdinalIgnoreCase))
                continue;

            var dir = ProjectLoader.ResolvePath(yamlPath, pluginRef.Path);
            var manifest = RppPluginHost.LoadManifest(Path.Combine(dir, "rpp.yaml"));
            if (manifest is null)
                continue;

            var host = new RppPluginHost(dir);
            var result = await host.PostReceiveAsync(manifest, sent, response, cancellationToken);
            if (result is null)
                continue;
            if (result.Action.Equals("abort", StringComparison.OrdinalIgnoreCase))
                return result.Note ?? "plugin abort";
        }
        return null;
    }
}
