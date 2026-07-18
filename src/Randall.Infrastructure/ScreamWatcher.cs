using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// First-party exception watcher (Leg 5 — Scream): debug-attach, wait for a
/// second-chance exception, write a full minidump via <see cref="MiniDumpWriter"/>,
/// then terminate the target so the fuzz loop can restart.
/// </summary>
public sealed class ScreamWatcher : IDisposable
{
    private readonly int _pid;
    private readonly string _dumpPath;
    private readonly CancellationTokenSource _cts = new();
    private readonly TaskCompletionSource<string?> _done =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource<bool> _attached =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource<bool> _ready =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly Thread _thread;
    private bool _disposed;
    private bool _wow64;
    private bool _sawInitialBreakpoint;
    private readonly List<string> _eventLog = [];

    private ScreamWatcher(int pid, string dumpPath)
    {
        _pid = pid;
        _dumpPath = dumpPath;
        _thread = new Thread(DebugLoop)
        {
            IsBackground = true,
            Name = $"randfuzz-scream-{pid}",
        };
        _thread.Start();
    }

    public string DumpPath => _dumpPath;
    public string Backend => "scream";
    public Task<string?> Completion => _done.Task;
    public Task<bool> Attached => _attached.Task;
    /// <summary>True after attach and the loader breakpoint has been continued (target can run).</summary>
    public Task<bool> Ready => _ready.Task;
    public string? LastError { get; private set; }
    public string Phase { get; private set; } = "starting";
    public bool IsWow64 => _wow64;
    public IReadOnlyList<string> EventLog => _eventLog;

    /// <summary>Exception metadata captured at second-chance (for analysis without dump stream).</summary>
    public ScreamExceptionInfo? ExceptionInfo { get; private set; }

    public static ScreamWatcher Start(int pid, string dumpsDir)
    {
        Directory.CreateDirectory(dumpsDir);
        var stamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmssfff");
        var dumpPath = Path.Combine(dumpsDir, $"scream_{pid}_{stamp}.dmp");
        return new ScreamWatcher(pid, dumpPath);
    }

    public async Task<bool> WaitUntilAttachedAsync(TimeSpan timeout, CancellationToken cancellationToken = default)
    {
        // Wait until the target is past the loader breakpoint and can accept I/O.
        var finished = await Task.WhenAny(_ready.Task, Task.Delay(timeout, cancellationToken));
        if (finished != _ready.Task)
            return false;
        return await _ready.Task;
    }

    private void DebugLoop()
    {
        try
        {
            Phase = "enabling-privilege";
            MiniDumpWriter.TryEnableDebugPrivilegePublic();

            try
            {
                using var probe = Process.GetProcessById(_pid);
                if (probe.HasExited)
                {
                    FailAttach("target already exited");
                    return;
                }

                _wow64 = IsWow64Process(probe.Handle, out var wow) && wow;
            }
            catch (ArgumentException)
            {
                FailAttach($"no process with PID {_pid}");
                return;
            }

            Phase = "attaching";
            if (!DebugActiveProcess((uint)_pid))
            {
                var err = Marshal.GetLastWin32Error();
                FailAttach($"DebugActiveProcess failed: {Win32Message(err)} ({err})");
                return;
            }

            // We terminate explicitly after dump; don't kill merely on detach.
            DebugSetProcessKillOnExit(false);
            Phase = "attached";
            _attached.TrySetResult(true);

            // Opaque buffer avoids brittle DEBUG_EVENT union size/packing across Windows SKUs.
            var eventMem = Marshal.AllocHGlobal(1024);
            try
            {
                while (!_cts.IsCancellationRequested)
                {
                    Zero(eventMem, 1024);
                    if (!WaitForDebugEvent(eventMem, 200))
                    {
                        var err = Marshal.GetLastWin32Error();
                        // 258 = WAIT_TIMEOUT, 121 = ERROR_SEM_TIMEOUT (seen on some hosts)
                        if (err is 0 or 121 or 258)
                            continue;
                        LastError = $"WaitForDebugEvent: {Win32Message(err)} ({err})";
                        break;
                    }

                    var eventBuf = new byte[256];
                    Marshal.Copy(eventMem, eventBuf, 0, eventBuf.Length);
                    var code = BitConverter.ToUInt32(eventBuf, 0);
                    var processId = BitConverter.ToUInt32(eventBuf, 4);
                    var threadId = BitConverter.ToUInt32(eventBuf, 8);
                    var continueStatus = Native.DbgContinue;

                    var markReady = false;
                    switch (code)
                    {
                        case Native.ExceptionDebugEvent:
                            (continueStatus, markReady) = HandleException(eventBuf, threadId);
                            if (_done.Task.IsCompleted)
                            {
                                ContinueDebugEvent(processId, threadId, continueStatus);
                                return;
                            }
                            break;

                        case Native.CreateProcessDebugEvent:
                            CloseEventFileHandle(eventBuf, offsetInUnion: 0);
                            break;

                        case Native.LoadDllDebugEvent:
                            CloseEventFileHandle(eventBuf, offsetInUnion: 0);
                            break;

                        case Native.ExitProcessDebugEvent:
                            ContinueDebugEvent(processId, threadId, Native.DbgContinue);
                            Phase = "target-exited";
                            // If we never saw an exception, still finish (selftest will FAIL clearly).
                            _ready.TrySetResult(_sawInitialBreakpoint);
                            _done.TrySetResult(ExistingDumpOrNull());
                            return;

                        case Native.OutputDebugStringEvent:
                        case Native.CreateThreadDebugEvent:
                        case Native.ExitThreadDebugEvent:
                        case Native.UnloadDllDebugEvent:
                        case Native.RipEvent:
                            break;
                    }

                    if (!ContinueDebugEvent(processId, threadId, continueStatus))
                    {
                        LastError = $"ContinueDebugEvent: {Win32Message(Marshal.GetLastWin32Error())}";
                        break;
                    }

                    // Only mark ready after the loader BP has been continued.
                    if (markReady)
                    {
                        Phase = "ready";
                        _ready.TrySetResult(true);
                    }
                }

                _done.TrySetResult(ExistingDumpOrNull());
            }
            finally
            {
                Marshal.FreeHGlobal(eventMem);
            }
        }
        catch (Exception ex)
        {
            LastError = ex.Message;
            Phase = "error";
            _attached.TrySetResult(false);
            _ready.TrySetResult(false);
            _done.TrySetResult(ExistingDumpOrNull());
        }
        finally
        {
            try { DebugActiveProcessStop((uint)_pid); } catch { /* ignore */ }
            _ready.TrySetResult(_sawInitialBreakpoint);
            if (Phase is "attached" or "ready" or "dumping")
                Phase = "detached";
        }
    }

    private void FailAttach(string message)
    {
        LastError = message;
        Phase = "attach-failed";
        _attached.TrySetResult(false);
        _ready.TrySetResult(false);
        _done.TrySetResult(null);
    }

    private (uint ContinueStatus, bool MarkReady) HandleException(byte[] eventBuf, uint threadId)
    {
        // DEBUG_EVENT: code@0 pid@4 tid@8; union `u` is pointer-aligned → @16 on x64, @12 on x86.
        // EXCEPTION_DEBUG_INFO = EXCEPTION_RECORD + dwFirstChance.
        var union = IntPtr.Size == 8 ? 16 : 12;
        var exceptionCode = BitConverter.ToUInt32(eventBuf, union + 0);
        var exceptionAddress = IntPtr.Size == 8
            ? (IntPtr)BitConverter.ToInt64(eventBuf, union + 16)
            : (IntPtr)BitConverter.ToInt32(eventBuf, union + 12);

        // EXCEPTION_RECORD is 152 bytes on x64 / 80 on x86; dwFirstChance follows.
        var recordSize = IntPtr.Size == 8 ? 152 : 80;
        var firstChance = BitConverter.ToUInt32(eventBuf, union + recordSize) != 0;
        _eventLog.Add(
            $"{(firstChance ? "1st" : "2nd")} 0x{exceptionCode:X8} @ 0x{(ulong)exceptionAddress.ToInt64():X}");

        // Loader / attach breakpoint — continue so the target can run (accept TCP, etc.).
        if (exceptionCode is Native.ExceptionBreakpoint or Native.ExceptionSingleStep)
        {
            var markReady = false;
            if (!_sawInitialBreakpoint)
            {
                _sawInitialBreakpoint = true;
                markReady = true;
            }
            return (Native.DbgContinue, markReady);
        }

        // .NET / CRT often ExitProcess after first-chance AV without a second-chance.
        // Dump immediately on fatal codes; let non-fatal first-chance EH continue.
        if (firstChance && !IsFatalException(exceptionCode))
            return (Native.DbgExceptionNotHandled, false);

        CaptureAndKill(eventBuf, union, threadId, exceptionCode, exceptionAddress,
            firstChance ? "first-chance-fatal" : "second-chance");
        return (Native.DbgContinue, false);
    }

    private void CaptureAndKill(
        byte[] eventBuf,
        int union,
        uint threadId,
        uint exceptionCode,
        IntPtr exceptionAddress,
        string reason)
    {
        Phase = "dumping";
        var record = ExceptionRecord.FromDebugEventUnion(eventBuf, union);
        RegisterSnapshotDto? regs = null;
        try { regs = TryReadRegisters(threadId); }
        catch { /* best effort */ }

        ExceptionInfo = new ScreamExceptionInfo(
            exceptionCode,
            WindowsExceptionHints.DescribeCode(exceptionCode) ?? $"exception 0x{exceptionCode:X8}",
            $"0x{(ulong)exceptionAddress.ToInt64():X}",
            (int)threadId,
            regs,
            _wow64,
            reason);

        var dumpsDir = Path.GetDirectoryName(_dumpPath)!;
        var baseName = Path.GetFileNameWithoutExtension(_dumpPath);
        var path = MiniDumpWriter.TryWriteDumpAtException(
            _pid, (int)threadId, in record, dumpsDir, baseName, _wow64);

        path ??= TryFallbackDump(dumpsDir, baseName);

        if (path is not null &&
            !string.Equals(path, _dumpPath, StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                File.Move(path, _dumpPath, overwrite: true);
                path = _dumpPath;
            }
            catch
            {
                /* keep path */
            }
        }

        TerminateTarget(exceptionCode);

        var finalPath = path is not null && File.Exists(path) && new FileInfo(path).Length > 0
            ? path
            : ExistingDumpOrNull();
        Phase = finalPath is null ? "dump-failed" : "dumped";
        if (finalPath is null)
            LastError ??= $"{reason} seen but minidump write failed";
        _done.TrySetResult(finalPath);
    }

    private static bool IsFatalException(uint code) => code is
        0xC0000005 or // ACCESS_VIOLATION
        0xC0000008 or // INVALID_HANDLE
        0xC000001D or // ILLEGAL_INSTRUCTION
        0xC0000094 or // INTEGER_DIVIDE_BY_ZERO
        0xC0000096 or // PRIVILEGED_INSTRUCTION
        0xC00000FD or // STACK_OVERFLOW
        0xC0000374 or // HEAP_CORRUPTION
        0xC0000409 or // STACK_BUFFER_OVERRUN
        0xC0000417 or // INVALID_CRUNTIME_PARAMETER
        0xC0000420;   // ASSERTION_FAILURE

    private string? TryFallbackDump(string dumpsDir, string baseName)
    {
        try
        {
            using var p = Process.GetProcessById(_pid);
            return MiniDumpWriter.TryWriteDump(p, dumpsDir, baseName + "_fallback", allowExited: false)
                   ?? MiniDumpWriter.TryWriteDump(p, dumpsDir, baseName + "_light", allowExited: false,
                       dumpType: MiniDumpWriter.MiniDumpTypeLight);
        }
        catch
        {
            return MiniDumpWriter.TryWriteDumpForPid(_pid, dumpsDir, baseName + "_pid", allowExited: true);
        }
    }

    private void TerminateTarget(uint exceptionCode)
    {
        try
        {
            using var p = Process.GetProcessById(_pid);
            if (!p.HasExited)
                p.Kill(entireProcessTree: true);
            return;
        }
        catch
        {
            /* fall through */
        }

        var h = OpenProcess(Native.ProcessTerminate, false, _pid);
        if (h != IntPtr.Zero)
        {
            TerminateProcess(h, exceptionCode);
            CloseHandle(h);
        }
    }

    private RegisterSnapshotDto? TryReadRegisters(uint threadId)
    {
        var access = Native.ThreadGetContext | Native.ThreadQueryInformation | Native.ThreadSuspendResume;
        var hThread = OpenThread(access, false, threadId);
        if (hThread == IntPtr.Zero)
            return null;

        try
        {
            if (_wow64)
                return TryReadWow64Registers(hThread);
            return TryReadAmd64Registers(hThread);
        }
        finally
        {
            CloseHandle(hThread);
        }
    }

    private static RegisterSnapshotDto? TryReadAmd64Registers(IntPtr hThread)
    {
        const int ctxSize = 1232;
        var mem = Marshal.AllocHGlobal(ctxSize);
        try
        {
            Zero(mem, ctxSize);
            Marshal.WriteInt32(mem, 0x30, unchecked((int)Native.ContextFullAmd64));
            if (!GetThreadContext(hThread, mem))
                return null;

            return new RegisterSnapshotDto(
                Hex(Marshal.ReadInt64(mem, 0xF8)), // Rip
                Hex(Marshal.ReadInt64(mem, 0x98)), // Rsp
                Hex(Marshal.ReadInt64(mem, 0xA0)), // Rbp
                Hex(Marshal.ReadInt64(mem, 0x78)), // Rax
                Hex(Marshal.ReadInt64(mem, 0x90)), // Rbx
                Hex(Marshal.ReadInt64(mem, 0x80)), // Rcx
                Hex(Marshal.ReadInt64(mem, 0x88))); // Rdx
        }
        finally
        {
            Marshal.FreeHGlobal(mem);
        }
    }

    private static RegisterSnapshotDto? TryReadWow64Registers(IntPtr hThread)
    {
        // WOW64_CONTEXT — ContextFlags at 0, Eip@0xB8, Esp@0xC4, Ebp@0xB4, Eax@0xB0, …
        const int ctxSize = 716;
        var mem = Marshal.AllocHGlobal(ctxSize);
        try
        {
            Zero(mem, ctxSize);
            Marshal.WriteInt32(mem, 0, unchecked((int)Native.ContextFullX86));
            if (!Wow64GetThreadContext(hThread, mem))
                return null;

            uint Eip() => unchecked((uint)Marshal.ReadInt32(mem, 0xB8));
            uint Esp() => unchecked((uint)Marshal.ReadInt32(mem, 0xC4));
            uint Ebp() => unchecked((uint)Marshal.ReadInt32(mem, 0xB4));
            uint Eax() => unchecked((uint)Marshal.ReadInt32(mem, 0xB0));
            uint Ebx() => unchecked((uint)Marshal.ReadInt32(mem, 0xA4));
            uint Ecx() => unchecked((uint)Marshal.ReadInt32(mem, 0xAC));
            uint Edx() => unchecked((uint)Marshal.ReadInt32(mem, 0xA8));

            return new RegisterSnapshotDto(
                $"0x{Eip():X}", $"0x{Esp():X}", $"0x{Ebp():X}",
                $"0x{Eax():X}", $"0x{Ebx():X}", $"0x{Ecx():X}", $"0x{Edx():X}");
        }
        finally
        {
            Marshal.FreeHGlobal(mem);
        }
    }

    public string? TryExistingDumpPath() => ExistingDumpOrNull();

    private string? ExistingDumpOrNull() =>
        File.Exists(_dumpPath) && new FileInfo(_dumpPath).Length > 0 ? _dumpPath : null;

    public void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;
        _cts.Cancel();
        try
        {
            if (!_thread.Join(3000))
            {
                try { DebugActiveProcessStop((uint)_pid); } catch { /* ignore */ }
            }
        }
        catch
        {
            /* ignore */
        }

        _cts.Dispose();
        _attached.TrySetResult(false);
        _ready.TrySetResult(false);
        _done.TrySetResult(ExistingDumpOrNull());
    }

    private static void CloseEventFileHandle(byte[] eventBuf, int offsetInUnion)
    {
        var union = IntPtr.Size == 8 ? 16 : 12;
        var hFile = ReadIntPtr(eventBuf, union + offsetInUnion);
        if (hFile != IntPtr.Zero)
            CloseHandle(hFile);
    }

    private static IntPtr ReadIntPtr(byte[] buf, int offset) =>
        IntPtr.Size == 8
            ? (IntPtr)BitConverter.ToInt64(buf, offset)
            : (IntPtr)BitConverter.ToInt32(buf, offset);

    private static void Zero(IntPtr mem, int size)
    {
        for (var i = 0; i < size; i++)
            Marshal.WriteByte(mem, i, 0);
    }

    private static string Hex(long value) => $"0x{(ulong)value:X}";

    private static string Win32Message(int err)
    {
        try { return new Win32Exception(err).Message; }
        catch { return "unknown"; }
    }

    #region Native

    private static class Native
    {
        public const uint ExceptionDebugEvent = 1;
        public const uint CreateThreadDebugEvent = 2;
        public const uint CreateProcessDebugEvent = 3;
        public const uint ExitThreadDebugEvent = 4;
        public const uint ExitProcessDebugEvent = 5;
        public const uint LoadDllDebugEvent = 6;
        public const uint UnloadDllDebugEvent = 7;
        public const uint OutputDebugStringEvent = 8;
        public const uint RipEvent = 9;

        public const uint ExceptionBreakpoint = 0x80000003;
        public const uint ExceptionSingleStep = 0x80000004;

        public const uint DbgContinue = 0x00010002;
        public const uint DbgExceptionNotHandled = 0x80010001;

        public const int ProcessTerminate = 0x0001;
        public const int ThreadGetContext = 0x0008;
        public const int ThreadQueryInformation = 0x0040;
        public const int ThreadSuspendResume = 0x0002;

        public const uint ContextAmd64 = 0x00100000;
        public const uint ContextFullAmd64 = ContextAmd64 | 0x1 | 0x2 | 0x4;
        public const uint ContextFullX86 = 0x00010007;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DebugActiveProcess(uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DebugActiveProcessStop(uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DebugSetProcessKillOnExit(bool KillOnExit);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool WaitForDebugEvent(IntPtr lpDebugEvent, uint dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ContinueDebugEvent(uint dwProcessId, uint dwThreadId, uint dwContinueStatus);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenThread(int dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetThreadContext(IntPtr hThread, IntPtr lpContext);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool Wow64GetThreadContext(IntPtr hThread, IntPtr lpContext);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWow64Process(IntPtr hProcess, out bool wow64Process);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    #endregion
}

/// <summary>Native EXCEPTION_RECORD with correct x64 padding before ExceptionInformation.</summary>
[StructLayout(LayoutKind.Sequential)]
public struct ExceptionRecord
{
    public uint ExceptionCode;
    public uint ExceptionFlags;
    public IntPtr ExceptionRecordPtr;
    public IntPtr ExceptionAddress;
    public uint NumberParameters;
    public uint Padding; // x64 alignment before ULONG_PTR[15]
    public ulong I0, I1, I2, I3, I4, I5, I6, I7, I8, I9, I10, I11, I12, I13, I14;

    public static ExceptionRecord FromDebugEventUnion(byte[] buf, int unionOffset)
    {
        var r = new ExceptionRecord
        {
            ExceptionCode = BitConverter.ToUInt32(buf, unionOffset + 0),
            ExceptionFlags = BitConverter.ToUInt32(buf, unionOffset + 4),
        };

        if (IntPtr.Size == 8)
        {
            r.ExceptionRecordPtr = (IntPtr)BitConverter.ToInt64(buf, unionOffset + 8);
            r.ExceptionAddress = (IntPtr)BitConverter.ToInt64(buf, unionOffset + 16);
            r.NumberParameters = BitConverter.ToUInt32(buf, unionOffset + 24);
            r.Padding = BitConverter.ToUInt32(buf, unionOffset + 28);
            var info = unionOffset + 32;
            r.I0 = BitConverter.ToUInt64(buf, info + 0);
            r.I1 = BitConverter.ToUInt64(buf, info + 8);
            r.I2 = BitConverter.ToUInt64(buf, info + 16);
            r.I3 = BitConverter.ToUInt64(buf, info + 24);
            r.I4 = BitConverter.ToUInt64(buf, info + 32);
        }
        else
        {
            r.ExceptionRecordPtr = (IntPtr)BitConverter.ToInt32(buf, unionOffset + 8);
            r.ExceptionAddress = (IntPtr)BitConverter.ToInt32(buf, unionOffset + 12);
            r.NumberParameters = BitConverter.ToUInt32(buf, unionOffset + 16);
            var info = unionOffset + 20;
            r.I0 = BitConverter.ToUInt32(buf, info + 0);
            r.I1 = BitConverter.ToUInt32(buf, info + 4);
            r.I2 = BitConverter.ToUInt32(buf, info + 8);
            r.I3 = BitConverter.ToUInt32(buf, info + 12);
            r.I4 = BitConverter.ToUInt32(buf, info + 16);
        }

        return r;
    }
}

public sealed record ScreamExceptionInfo(
    uint ExceptionCode,
    string ExceptionHint,
    string FaultAddress,
    int ThreadId,
    RegisterSnapshotDto? Registers,
    bool Wow64 = false,
    string Chance = "second-chance");
