using Randall.Contracts;

namespace Randall.Infrastructure;

public static class RppCrashHook
{
    public static async Task<string?> RunAsync(
        ProjectConfig project,
        string yamlPath,
        byte[] crashInput,
        TargetRunResult result,
        CancellationToken cancellationToken = default)
    {
        foreach (var pluginRef in project.Plugins)
        {
            if (!pluginRef.Hook.Equals("post_crash", StringComparison.OrdinalIgnoreCase))
                continue;

            var dir = ProjectLoader.ResolvePath(yamlPath, pluginRef.Path);
            var manifest = RppPluginHost.LoadManifest(Path.Combine(dir, "rpp.yaml"));
            if (manifest is null)
                continue;

            var host = new RppPluginHost(dir);
            var tag = await host.PostCrashAsync(
                manifest,
                crashInput,
                result.ExitCode,
                result.Detail,
                result.MiniDumpPath,
                cancellationToken);
            if (!string.IsNullOrWhiteSpace(tag))
                return tag;
        }
        return null;
    }
}
