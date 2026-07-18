using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Phase 16 — coarse native PC stalk via the Windows debug API (no DynamoRIO).
/// Records unique exception / breakpoint RVAs into a drcov-compatible BB table.
/// Not full basic-block coverage — prefer stalkMode: external when DynamoRIO is installed.
/// </summary>
public sealed class NativeStalkRunner : IStalkTraceBackend
{
    public string BackendId => StalkBackend.Native;

    public bool IsAvailable => OperatingSystem.IsWindows();

    public string AvailabilityNote =>
        "Native PC stalk (debug-event samples → drcov). Coarser than DynamoRIO; use external when available.";

    public async Task<StalkTraceResult> RunFileTargetAsync(
        ProjectConfig project,
        string yamlPath,
        byte[] input,
        string traceDir,
        CancellationToken cancellationToken = default)
    {
        if (!IsAvailable)
            return new StalkTraceResult(false, null, null, "Native stalk requires Windows");

        Directory.CreateDirectory(traceDir);
        var targetExe = ProjectLoader.ResolvePath(yamlPath, project.Target.Executable);
        if (!File.Exists(targetExe))
            return new StalkTraceResult(false, null, null, $"Target not found: {targetExe}");

        var inputFile = Path.Combine(traceDir, $"input_{Guid.NewGuid():N}.bin");
        await File.WriteAllBytesAsync(inputFile, input, cancellationToken);

        var args = project.Target.Args
            .Select(a => a.Replace("{file}", inputFile, StringComparison.OrdinalIgnoreCase))
            .ToArray();
        var workDir = string.IsNullOrWhiteSpace(project.Target.WorkingDirectory)
            ? Path.GetDirectoryName(targetExe)!
            : ProjectLoader.ResolvePath(yamlPath, project.Target.WorkingDirectory);

        var timeoutMs = Math.Clamp(project.Target.TimeoutMs, 500, 120_000);
        var result = await Task.Run(
            () => DebugRunCollect(targetExe, args, workDir, traceDir, timeoutMs),
            cancellationToken);

        try { File.Delete(inputFile); } catch { /* ignore */ }
        return result;
    }

    public Process? StartLongLivedTarget(ProjectConfig project, string yamlPath, string traceDir)
    {
        if (!IsAvailable) return null;
        var exe = ProjectLoader.ResolvePath(yamlPath, project.Target.Executable);
        if (!File.Exists(exe)) return null;
        Directory.CreateDirectory(traceDir);
        var psi = new ProcessStartInfo
        {
            FileName = exe,
            WorkingDirectory = string.IsNullOrWhiteSpace(project.Target.WorkingDirectory)
                ? Path.GetDirectoryName(exe)!
                : ProjectLoader.ResolvePath(yamlPath, project.Target.WorkingDirectory),
            UseShellExecute = false,
        };
        foreach (var a in project.Target.Args)
            psi.ArgumentList.Add(a);
        return Process.Start(psi);
    }

    public string? CollectLatestTrace(string traceDir)
    {
        if (!Directory.Exists(traceDir)) return null;
        return Directory.EnumerateFiles(traceDir, "native_*.log")
            .OrderByDescending(File.GetLastWriteTimeUtc)
            .FirstOrDefault();
    }

    public Task StopLongLivedAsync(Process? process, CancellationToken cancellationToken = default)
    {
        try
        {
            if (process is { HasExited: false })
            {
                process.Kill(entireProcessTree: true);
                process.WaitForExit(3000);
            }
        }
        catch { /* ignore */ }
        process?.Dispose();
        return Task.CompletedTask;
    }

    private static StalkTraceResult DebugRunCollect(
        string exe,
        string[] args,
        string workDir,
        string traceDir,
        int timeoutMs)
    {
        MiniDumpWriter.TryEnableDebugPrivilegePublic();

        var cmdLine = "\"" + exe + "\"";
        if (args.Length > 0)
            cmdLine += " " + string.Join(' ', args.Select(a => a.Contains(' ') ? $"\"{a}\"" : a));

        var si = new STARTUPINFO { cb = Marshal.SizeOf<STARTUPINFO>() };
        if (!CreateProcess(
                null,
                new StringBuilder(cmdLine),
                IntPtr.Zero,
                IntPtr.Zero,
                false,
                DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,
                IntPtr.Zero,
                workDir,
                ref si,
                out var pi))
        {
            return new StalkTraceResult(false, null, null,
                $"CreateProcess(DEBUG) failed: {Marshal.GetLastWin32Error()}");
        }

        var modules = new List<(int Id, ulong Start, ulong End, string Path)>();
        var pcs = new HashSet<(int Mod, uint Rva)>();
        var exitCode = 0;
        var deadline = Environment.TickCount64 + timeoutMs;
        var sawExit = false;
        var union = IntPtr.Size == 8 ? 16 : 12;
        var eventMem = Marshal.AllocHGlobal(1024);

        try
        {
            while (!sawExit && Environment.TickCount64 < deadline)
            {
                if (!WaitForDebugEvent(eventMem, 200))
                {
                    var err = Marshal.GetLastWin32Error();
                    if (err is 0 or 121 or 258)
                        continue;
                    break;
                }

                var buf = new byte[256];
                Marshal.Copy(eventMem, buf, 0, buf.Length);
                var code = BitConverter.ToUInt32(buf, 0);
                var pid = BitConverter.ToUInt32(buf, 4);
                var tid = BitConverter.ToUInt32(buf, 8);
                var continueStatus = DBG_CONTINUE;

                switch (code)
                {
                    case CREATE_PROCESS_DEBUG_EVENT:
                    {
                        // lpBaseOfImage at union+24 on x64 (hFile, hProcess, hThread, lpBaseOfImage)
                        var baseOff = union + (IntPtr.Size * 3);
                        var baseAddr = IntPtr.Size == 8
                            ? (ulong)BitConverter.ToInt64(buf, baseOff)
                            : BitConverter.ToUInt32(buf, baseOff);
                        modules.Add((0, baseAddr, baseAddr + 0x1000_0000UL, exe));
                        // Close hFile at union+0
                        var hFile = IntPtr.Size == 8
                            ? (IntPtr)BitConverter.ToInt64(buf, union)
                            : (IntPtr)BitConverter.ToInt32(buf, union);
                        if (hFile != IntPtr.Zero)
                            CloseHandle(hFile);
                        break;
                    }
                    case LOAD_DLL_DEBUG_EVENT:
                    {
                        var baseOff = union + IntPtr.Size; // after hFile
                        var baseAddr = IntPtr.Size == 8
                            ? (ulong)BitConverter.ToInt64(buf, baseOff)
                            : BitConverter.ToUInt32(buf, baseOff);
                        var id = modules.Count;
                        modules.Add((id, baseAddr, baseAddr + 0x40_0000UL, $"module_{id}"));
                        var hFile = IntPtr.Size == 8
                            ? (IntPtr)BitConverter.ToInt64(buf, union)
                            : (IntPtr)BitConverter.ToInt32(buf, union);
                        if (hFile != IntPtr.Zero)
                            CloseHandle(hFile);
                        break;
                    }
                    case EXCEPTION_DEBUG_EVENT:
                    {
                        // ExceptionAddress @ union + 16 (x64 EXCEPTION_RECORD)
                        var addrOff = union + 16;
                        var addr = IntPtr.Size == 8
                            ? (ulong)BitConverter.ToInt64(buf, addrOff)
                            : BitConverter.ToUInt32(buf, addrOff);
                        RecordPc(modules, pcs, addr);
                        var excCode = BitConverter.ToUInt32(buf, union);
                        if (excCode is not (EXCEPTION_BREAKPOINT or EXCEPTION_SINGLE_STEP))
                        {
                            var firstChance = BitConverter.ToUInt32(buf, union + (IntPtr.Size == 8 ? 152 : 80));
                            // Rough: prefer continue for first-chance; still sample PC
                            if (firstChance == 0)
                                continueStatus = DBG_EXCEPTION_NOT_HANDLED;
                        }
                        break;
                    }
                    case EXIT_PROCESS_DEBUG_EVENT:
                        exitCode = (int)BitConverter.ToUInt32(buf, union);
                        sawExit = true;
                        break;
                }

                ContinueDebugEvent(pid, tid, continueStatus);
            }

            if (!sawExit)
            {
                try { TerminateProcess(pi.hProcess, 0xFFFF_FFFF); } catch { /* ignore */ }
                for (var i = 0; i < 20 && WaitForDebugEvent(eventMem, 100); i++)
                {
                    var buf = new byte[16];
                    Marshal.Copy(eventMem, buf, 0, 16);
                    ContinueDebugEvent(BitConverter.ToUInt32(buf, 4), BitConverter.ToUInt32(buf, 8), DBG_CONTINUE);
                }
            }
        }
        finally
        {
            Marshal.FreeHGlobal(eventMem);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        }

        var stamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmssfff", CultureInfo.InvariantCulture);
        var tracePath = Path.Combine(traceDir, $"native_{stamp}.log");
        WriteDrcov(tracePath, modules, pcs);
        return new StalkTraceResult(
            true,
            tracePath,
            exitCode,
            $"native PC samples: {pcs.Count} unique · modules: {modules.Count}");
    }

    private static void RecordPc(
        List<(int Id, ulong Start, ulong End, string Path)> modules,
        HashSet<(int Mod, uint Rva)> pcs,
        ulong addr)
    {
        foreach (var m in modules)
        {
            if (addr >= m.Start && addr < m.End)
            {
                pcs.Add((m.Id, (uint)(addr - m.Start)));
                return;
            }
        }

        if (modules.Count > 0)
            pcs.Add((0, (uint)(addr & 0xFFFF_FFFF)));
    }

    private static void WriteDrcov(
        string path,
        List<(int Id, ulong Start, ulong End, string Path)> modules,
        HashSet<(int Mod, uint Rva)> pcs)
    {
        var sb = new StringBuilder();
        sb.AppendLine("DRCOV VERSION: 2");
        sb.AppendLine("DRCOV FLAVOR: randfuzz-native-pc");
        sb.AppendLine($"Module Table: version 2, count {Math.Max(modules.Count, 1)}");
        sb.AppendLine("Columns: id, containing_id, start, end, entry, checksum, timestamp, path");
        if (modules.Count == 0)
            sb.AppendLine("0, 0, 0x0, 0x1000000, 0x0, 0x0, 0x0, unknown");
        else
        {
            foreach (var m in modules)
            {
                sb.AppendLine(
                    $"{m.Id}, 0, 0x{m.Start:x}, 0x{m.End:x}, 0x{m.Start:x}, 0x0, 0x0, {m.Path}");
            }
        }

        sb.AppendLine($"BB Table: {pcs.Count} bbs");
        sb.AppendLine("module id, start, size:");
        foreach (var (mod, rva) in pcs.OrderBy(p => p.Mod).ThenBy(p => p.Rva))
            sb.AppendLine($"  {mod}, 0x{rva:x}, 1");

        File.WriteAllText(path, sb.ToString());
    }

    private const uint DEBUG_PROCESS = 0x00000001;
    private const uint DEBUG_ONLY_THIS_PROCESS = 0x00000002;
    private const uint CREATE_NEW_CONSOLE = 0x00000010;
    private const uint DBG_CONTINUE = 0x00010002;
    private const uint DBG_EXCEPTION_NOT_HANDLED = 0x80010001;
    private const uint EXCEPTION_BREAKPOINT = 0x80000003;
    private const uint EXCEPTION_SINGLE_STEP = 0x80000004;
    private const uint EXCEPTION_DEBUG_EVENT = 1;
    private const uint CREATE_PROCESS_DEBUG_EVENT = 3;
    private const uint EXIT_PROCESS_DEBUG_EVENT = 5;
    private const uint LOAD_DLL_DEBUG_EVENT = 6;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO
    {
        public int cb;
        public IntPtr lpReserved, lpDesktop, lpTitle;
        public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short wShowWindow, cbReserved2;
        public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public IntPtr hProcess, hThread;
        public uint dwProcessId, dwThreadId;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateProcess(
        string? lpApplicationName,
        StringBuilder lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string? lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool WaitForDebugEvent(IntPtr lpDebugEvent, uint dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ContinueDebugEvent(uint dwProcessId, uint dwThreadId, uint dwContinueStatus);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);
}
