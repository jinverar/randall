using System.Diagnostics;

namespace Randall.Infrastructure;

/// <summary>
/// Platform dump capture: Windows minidumps via <see cref="MiniDumpWriter"/>, Linux cores via
/// <see cref="LinuxCoreCapture"/>. Soft-fails when the OS/tooling cannot produce an artifact.
/// </summary>
public static class CrashDumpWriter
{
    public static string? TryWrite(
        Process process,
        string dumpsDir,
        string baseName,
        bool allowExited = false)
    {
        if (OperatingSystem.IsWindows())
            return MiniDumpWriter.TryWriteDump(process, dumpsDir, baseName, allowExited);

        if (OperatingSystem.IsLinux())
            return LinuxCoreCapture.TryCapture(process, dumpsDir, baseName);

        return null;
    }
}
