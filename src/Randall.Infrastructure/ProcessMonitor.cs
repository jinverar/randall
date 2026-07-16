using System.Diagnostics;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>Boofuzz-style process monitor — start, detect death, restart long-lived targets.</summary>
public sealed class ProcessMonitor : IDisposable
{
    private Process? _process;
    private readonly ProjectConfig _project;
    private readonly string _yamlPath;

    public ProcessMonitor(ProjectConfig project, string yamlPath)
    {
        _project = project;
        _yamlPath = yamlPath;
    }

    public Process? Process => _process;
    public bool IsRunning => _process is { HasExited: false };

    public Process Start()
    {
        Stop();
        _process = TargetRunner.StartTarget(_project, _yamlPath, null);
        return _process ?? throw new InvalidOperationException("Failed to start target process");
    }

    public async Task RestartIfCrashedAsync(CancellationToken cancellationToken = default)
    {
        if (_process is null || !_process.HasExited)
            return;
        Stop();
        await Task.Delay(300, cancellationToken);
        Start();
    }

    public void Stop()
    {
        if (_process is { HasExited: false })
        {
            _process.Kill(entireProcessTree: true);
            _process.Dispose();
        }
        _process = null;
    }

    public void Dispose() => Stop();
}
