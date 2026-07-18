namespace Randall.Infrastructure;

/// <summary>
/// In-process remote stalk helpers for <c>randall agent</c> —
/// Procmon start/stop shared across HTTP requests on the lab box.
/// </summary>
public static class RemoteStalkAgent
{
    private static readonly object Gate = new();
    private static ProcmonCapture? _procmon;

    public static ProcmonStatusDto Status(string? repoRoot = null)
    {
        lock (Gate)
        {
            var exe = ProcmonCapture.DiscoverExecutable(repoRoot);
            return new ProcmonStatusDto(
                exe is not null,
                exe,
                _procmon?.IsRunning == true,
                _procmon?.PmlPath,
                exe is null
                    ? "Install Procmon into tools/ or PATH"
                    : "POST /api/remote/procmon/start { backingFile? }");
        }
    }

    public static ProcmonStatusDto Start(string? backingFile = null, string? repoRoot = null)
    {
        lock (Gate)
        {
            _procmon?.Dispose();
            _procmon = null;
            repoRoot ??= CrashCatalog.FindRepoRoot() ?? Directory.GetCurrentDirectory();
            var path = string.IsNullOrWhiteSpace(backingFile)
                ? Path.Combine(repoRoot, "data", "procmon", $"remote_{DateTime.UtcNow:yyyyMMdd_HHmmss}.pml")
                : Path.GetFullPath(backingFile);
            _procmon = ProcmonCapture.TryStart(path, repoRoot);
            return Status(repoRoot) with
            {
                Hint = _procmon?.IsRunning == true
                    ? $"Capturing → {_procmon.PmlPath}"
                    : _procmon?.LastError ?? "failed to start",
            };
        }
    }

    public static ProcmonStatusDto Stop(string? repoRoot = null)
    {
        lock (Gate)
        {
            var pml = _procmon?.PmlPath;
            _procmon?.Stop();
            _procmon?.Dispose();
            _procmon = null;
            var st = Status(repoRoot);
            return st with
            {
                PmlPath = pml,
                Hint = pml is not null && File.Exists(pml) ? $"Saved {pml}" : "Stopped",
            };
        }
    }
}
