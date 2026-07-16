using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Randall.Infrastructure;

/// <summary>Leg 5 — Scream: capture minidump before killing hung targets.</summary>
public static class MiniDumpWriter
{
    private const int MiniDumpWithDataSegs = 0x00000002;

    public static string? TryWriteDump(Process process, string dumpsDir, string baseName, bool allowExited = false)
    {
        if (process.HasExited && !allowExited)
            return null;

        try
        {
            Directory.CreateDirectory(dumpsDir);
            var path = Path.Combine(dumpsDir, $"{baseName}.dmp");
            using var file = File.Open(path, FileMode.Create, FileAccess.Write, FileShare.None);
            var ok = MiniDumpWriteDump(
                process.Handle,
                (uint)process.Id,
                file.SafeFileHandle,
                MiniDumpWithDataSegs,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero);
            return ok ? path : null;
        }
        catch
        {
            return null;
        }
    }

    [DllImport("dbghelp.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool MiniDumpWriteDump(
        IntPtr hProcess,
        uint processId,
        SafeFileHandle hFile,
        int dumpType,
        IntPtr exceptionParam,
        IntPtr userStreamParam,
        IntPtr callbackParam);
}
