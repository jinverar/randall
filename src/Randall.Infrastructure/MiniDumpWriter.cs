using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Randall.Infrastructure;

/// <summary>Leg 5 — Scream: capture minidump before killing hung targets.</summary>
public static class MiniDumpWriter
{
    private const int MiniDumpType =
        0x00000002 | // WithFullMemory (legacy comment was wrong)
        0x00000004 | // WithHandleData
        0x00001000 | // WithThreadInfo
        0x00000020;  // WithUnloadedModules

    /// <summary>Smaller dump when full memory write fails (disk/ACL).</summary>
    public const int MiniDumpTypeLight =
        0x00000001 | // WithDataSegs
        0x00000004 | // WithHandleData
        0x00001000 | // WithThreadInfo
        0x00000020 | // WithUnloadedModules
        0x00000040;  // WithIndirectlyReferencedMemory

    private const int MiniDumpTypeCrash =
        0x00000002 | // WithFullMemory
        0x00000004 | // WithHandleData
        0x00000020 | // WithUnloadedModules
        0x00001000;  // WithThreadInfo

    private const int ProcessQueryLimitedInformation = 0x1000;
    private const int ProcessQueryInformation = 0x0400;
    private const int ProcessVmRead = 0x0010;
    private const int ProcessVmOperation = 0x0008;
    private const int ProcessDupHandle = 0x0040;
    private const uint TokenAdjustPrivileges = 0x0020;
    private const uint TokenQuery = 0x0008;

    public static string? TryWriteDump(
        Process process,
        string dumpsDir,
        string baseName,
        bool allowExited = false,
        int? dumpType = null)
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
                ? OpenProcess(ProcessQueryInformation | ProcessVmRead, false, pid)
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
                    dumpType ?? MiniDumpType,
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

    public static string? TryWriteDumpForPid(
        int pid,
        string dumpsDir,
        string baseName,
        bool allowExited = false,
        int? dumpType = null)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            return TryWriteDump(p, dumpsDir, baseName, allowExited, dumpType);
        }
        catch
        {
            if (!allowExited)
                return null;
            try
            {
                TryEnableDebugPrivilege();
                Directory.CreateDirectory(dumpsDir);
                var path = Path.Combine(dumpsDir, $"{baseName}.dmp");
                var handle = OpenProcess(ProcessQueryInformation | ProcessVmRead, false, pid);
                if (handle == IntPtr.Zero)
                    return null;
                try
                {
                    using var file = File.Open(path, FileMode.Create, FileAccess.Write, FileShare.None);
                    var ok = MiniDumpWriteDump(
                        handle, (uint)pid, file.SafeFileHandle,
                        dumpType ?? MiniDumpTypeLight, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
                    if (!ok || file.Length == 0)
                    {
                        try { File.Delete(path); } catch { /* ignore */ }
                        return null;
                    }
                    return path;
                }
                finally
                {
                    CloseHandle(handle);
                }
            }
            catch
            {
                return null;
            }
        }
    }

    /// <summary>Exposed for <see cref="ScreamWatcher"/> attach.</summary>
    public static void TryEnableDebugPrivilegePublic() => TryEnableDebugPrivilege();

    /// <summary>
    /// Write a dump frozen at an exception (debug event). Includes exception stream for analyze.
    /// Tries full memory, then a lighter dump type.
    /// </summary>
    public static string? TryWriteDumpAtException(
        int pid,
        int threadId,
        in ExceptionRecord exceptionRecord,
        string dumpsDir,
        string baseName,
        bool wow64 = false)
    {
        var full = WriteExceptionDump(pid, threadId, in exceptionRecord, dumpsDir, baseName, MiniDumpTypeCrash, wow64);
        if (full is not null)
            return full;
        return WriteExceptionDump(pid, threadId, in exceptionRecord, dumpsDir, baseName + "_light", MiniDumpTypeLight, wow64);
    }

    private static string? WriteExceptionDump(
        int pid,
        int threadId,
        in ExceptionRecord exceptionRecord,
        string dumpsDir,
        string baseName,
        int dumpType,
        bool wow64)
    {
        try
        {
            TryEnableDebugPrivilege();
            Directory.CreateDirectory(dumpsDir);
            var path = Path.Combine(dumpsDir, $"{baseName}.dmp");

            var access = ProcessQueryInformation | ProcessQueryLimitedInformation | ProcessVmRead |
                         ProcessVmOperation | ProcessDupHandle;
            var hProcess = OpenProcess(access, false, pid);
            if (hProcess == IntPtr.Zero)
                hProcess = OpenProcess(ProcessQueryInformation | ProcessVmRead, false, pid);
            if (hProcess == IntPtr.Zero)
                return null;

            IntPtr ctxMem = IntPtr.Zero;
            IntPtr recordMem = IntPtr.Zero;
            IntPtr pointersMem = IntPtr.Zero;
            try
            {
                var ctxSize = wow64 ? 716 : 1232;
                ctxMem = Marshal.AllocHGlobal(ctxSize);
                for (var i = 0; i < ctxSize; i++)
                    Marshal.WriteByte(ctxMem, i, 0);

                if (wow64)
                    Marshal.WriteInt32(ctxMem, 0, unchecked((int)0x00010007)); // WOW64 CONTEXT_FULL
                else
                    Marshal.WriteInt32(ctxMem, 0x30, unchecked((int)0x00100007)); // AMD64 CONTEXT_FULL

                var hThread = OpenThread(0x0008 | 0x0040 | 0x0002, false, (uint)threadId);
                if (hThread != IntPtr.Zero)
                {
                    if (wow64)
                        Wow64GetThreadContext(hThread, ctxMem);
                    else
                        GetThreadContext(hThread, ctxMem);
                    CloseHandle(hThread);
                }

                recordMem = Marshal.AllocHGlobal(Marshal.SizeOf<ExceptionRecord>());
                Marshal.StructureToPtr(exceptionRecord, recordMem, false);

                pointersMem = Marshal.AllocHGlobal(IntPtr.Size * 2);
                Marshal.WriteIntPtr(pointersMem, 0, recordMem);
                Marshal.WriteIntPtr(pointersMem, IntPtr.Size, ctxMem);

                var mei = new MINIDUMP_EXCEPTION_INFORMATION
                {
                    ThreadId = (uint)threadId,
                    ExceptionPointers = pointersMem,
                    ClientPointers = false,
                };

                using var file = File.Open(path, FileMode.Create, FileAccess.Write, FileShare.None);
                var ok = MiniDumpWriteDump(
                    hProcess,
                    (uint)pid,
                    file.SafeFileHandle,
                    dumpType,
                    ref mei,
                    IntPtr.Zero,
                    IntPtr.Zero);

                if (!ok || file.Length == 0)
                {
                    // Retry without exception stream — still useful for WinDbg.
                    file.SetLength(0);
                    ok = MiniDumpWriteDump(
                        hProcess, (uint)pid, file.SafeFileHandle, dumpType,
                        IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
                }

                if (!ok || file.Length == 0)
                {
                    try { File.Delete(path); } catch { /* ignore */ }
                    return null;
                }

                return path;
            }
            finally
            {
                if (pointersMem != IntPtr.Zero) Marshal.FreeHGlobal(pointersMem);
                if (recordMem != IntPtr.Zero) Marshal.FreeHGlobal(recordMem);
                if (ctxMem != IntPtr.Zero) Marshal.FreeHGlobal(ctxMem);
                CloseHandle(hProcess);
            }
        }
        catch
        {
            return null;
        }
    }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    private struct MINIDUMP_EXCEPTION_INFORMATION
    {
        public uint ThreadId;
        public IntPtr ExceptionPointers;
        [MarshalAs(UnmanagedType.Bool)]
        public bool ClientPointers;
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
    private static extern IntPtr OpenThread(int dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetThreadContext(IntPtr hThread, IntPtr lpContext);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool Wow64GetThreadContext(IntPtr hThread, IntPtr lpContext);

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

    [DllImport("dbghelp.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool MiniDumpWriteDump(
        IntPtr hProcess,
        uint processId,
        SafeFileHandle hFile,
        int dumpType,
        ref MINIDUMP_EXCEPTION_INFORMATION exceptionParam,
        IntPtr userStreamParam,
        IntPtr callbackParam);
}
