using System.Diagnostics;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Fuzz-engine façade over <see cref="TargetRuntimeService"/> (local) or
/// <see cref="TargetRuntimeClient"/> (remote agent).
/// </summary>
public sealed class TargetRuntimeBridge : IDisposable
{
    private readonly string _slotId;
    private readonly string _yamlPath;
    private readonly string? _agentUrl;
    private bool _started;

    public TargetRuntimeBridge(ProjectConfig project, string yamlPath)
    {
        _yamlPath = Path.GetFullPath(yamlPath);
        _slotId = string.IsNullOrWhiteSpace(project.Name)
            ? Path.GetFileNameWithoutExtension(yamlPath)
            : project.Name.Trim();
        _agentUrl = string.IsNullOrWhiteSpace(project.Target.AgentUrl)
            ? null
            : project.Target.AgentUrl.Trim();
    }

    public string SlotId => _slotId;
    public bool IsRemote => _agentUrl is not null;
    public string? AgentUrl => _agentUrl;

    public async Task<(Process? Process, TargetRuntimeStatusDto Status)> StartAsync(
        CancellationToken cancellationToken = default)
    {
        TargetRuntimeStatusDto st;
        if (_agentUrl is null)
            st = TargetRuntimeService.StartFromProject(_yamlPath, _slotId);
        else
            st = await TargetRuntimeClient.StartFromProjectAsync(
                _agentUrl, YamlPathForAgent(), _slotId, cancellationToken);

        _started = st.Ok || st.Running;
        var proc = _agentUrl is null ? TargetRuntimeService.TryGetProcess(_slotId) : null;
        return (proc, st);
    }

    /// <summary>Repo-relative YAML path so the agent resolves against its own checkout.</summary>
    private string YamlPathForAgent()
    {
        var root = CrashCatalog.FindRepoRoot();
        if (root is not null)
        {
            var rel = Path.GetRelativePath(root, _yamlPath);
            if (!rel.StartsWith("..", StringComparison.Ordinal))
                return rel.Replace('\\', '/');
        }

        return _yamlPath.Replace('\\', '/');
    }

    public async Task<(Process? Process, TargetRuntimeStatusDto Status)> RestartAsync(
        CancellationToken cancellationToken = default)
    {
        TargetRuntimeStatusDto st;
        if (_agentUrl is null)
            st = TargetRuntimeService.Restart(_slotId);
        else
            st = await TargetRuntimeClient.RestartAsync(_agentUrl, _slotId, cancellationToken);

        var proc = _agentUrl is null ? TargetRuntimeService.TryGetProcess(_slotId) : null;
        return (proc, st);
    }

    public async Task<TargetRuntimeStatusDto> StatusAsync(CancellationToken cancellationToken = default)
    {
        if (_agentUrl is null)
            return TargetRuntimeService.Status(_slotId);
        return await TargetRuntimeClient.StatusAsync(_agentUrl, _slotId, cancellationToken);
    }

    /// <summary>True when the managed target has died (local process or remote slot).</summary>
    public async Task<bool> HasExitedAsync(Process? localProcess, CancellationToken cancellationToken = default)
    {
        if (localProcess is not null)
        {
            try { return localProcess.HasExited; }
            catch { return true; }
        }

        if (!_started)
            return false;

        var st = await StatusAsync(cancellationToken);
        return !st.Running;
    }

    public async Task StopAsync(CancellationToken cancellationToken = default)
    {
        if (!_started && _agentUrl is null && !TargetRuntimeService.IsManagedRunning(_slotId))
            return;

        if (_agentUrl is null)
            TargetRuntimeService.Stop(_slotId);
        else
            await TargetRuntimeClient.StopAsync(_agentUrl, _slotId, cancellationToken);

        _started = false;
    }

    public void Dispose()
    {
        try
        {
            StopAsync().GetAwaiter().GetResult();
        }
        catch
        {
            /* ignore dispose errors */
        }
    }
}
