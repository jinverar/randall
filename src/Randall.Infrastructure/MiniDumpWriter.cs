using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Randall.Infrastructure;

/// <summary>Leg 5 — Scream: capture minidump before killing hung targets.</summary>
public static class MiniDumpWriter
{
    private const int MiniDumpType =
        0x00000002 | // WithDataSegs
        0x00000004 | // WithHandleData
        0x00000008 | // WithThreadInfo
        0x00000020;  // WithUnloadedModules

    private const int ProcessQueryLimitedInformation = 0x1000;
    private const int ProcessVmRead = 0x0010;
    private const uint TokenAdjustPrivileges = 0x0020;
    private const uint TokenQuery = 0x0008;
    private const uint SeDebugPrivilege = 0x0014;

    public static string? TryWriteDump(Process process, string dumpsDir, string baseName, bool allowExited = false)
    {
        if (process.HasExited && !allowExited)
            return null;

        try
        {
            TryEnableDebugPrivilege();
            Directory.CreateDirectory(dumpsDir);
            var path = Path.Combine(dumpsDir, $"{baseName}.dmp");
            using var file = File.Open(path, FileMode.Create, FileAccess.Write, FileShare.None);

            var pid = process.Id;
            var handle = process.HasExited
                ? OpenProcess(ProcessQueryLimitedInformation | ProcessVmRead, false, pid)
                : process.Handle;

            if (handle == IntPtr.Zero)
                return null;

            var owned = process.HasExited;
            try
            {
                var ok = MiniDumpWriteDump(
                    handle,
                    (uint)pid,
                    file.SafeFileHandle,
                    MiniDumpType,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    IntPtr.Zero);
                if (!ok || file.Length == 0)
                {
                    try { File.Delete(path); } catch { /* ignore */ }
                    return null;
                }
                return path;
            }
            finally
            {
                if (owned)
                    CloseHandle(handle);
            }
        }
        catch
        {
            return null;
        }
    }

    private static void TryEnableDebugPrivilege()
    {
        try
        {
            if (!OpenProcessToken(GetCurrentProcess(), TokenAdjustPrivileges | TokenQuery, out var token))
                return;
            using (token)
            {
                if (!LookupPrivilegeValue(null, "SeDebugPrivilege", out var luid))
                    return;
                var tp = new TOKEN_PRIVILEGES
                {
                    PrivilegeCount = 1,
                    Privileges = new LUID_AND_ATTRIBUTES { Luid = luid, Attributes = 0x00000002 },
                };
                AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
            }
        }
        catch { /* best effort */ }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LUID_AND_ATTRIBUTES
    {
        public LUID Luid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        public LUID_AND_ATTRIBUTES Privileges;
    }

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out SafeFileHandle tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool LookupPrivilegeValue(string? lpSystemName, string lpName, out LUID lpLuid);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AdjustTokenPrivileges(
        SafeFileHandle tokenHandle,
        bool disableAllPrivileges,
        ref TOKEN_PRIVILEGES newState,
        uint bufferLength,
        IntPtr previousState,
        IntPtr returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(int desiredAccess, bool inheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

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
