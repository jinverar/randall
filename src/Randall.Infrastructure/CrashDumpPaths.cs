namespace Randall.Infrastructure;

/// <summary>Validate crash dump paths before persisting or opening in a debugger.</summary>
public static class CrashDumpPaths
{
    /// <summary>True when the dump file exists and has non-zero length.</summary>
    public static bool IsUsableDump(string? path) => Sanitize(path) is not null;

    /// <summary>Return <paramref name="path"/> only when the file exists and is non-empty; otherwise null.</summary>
    public static string? Sanitize(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return null;
        try
        {
            if (!File.Exists(path))
                return null;
            return new FileInfo(path).Length > 0 ? path : null;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>Best-effort delete of a 0-byte dump placeholder left after a failed write.</summary>
    public static void TryDeleteEmpty(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return;
        try
        {
            if (File.Exists(path) && new FileInfo(path).Length == 0)
                File.Delete(path);
        }
        catch
        {
            /* ignore */
        }
    }
}
