using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Loader;
using System.Text;
using Randall.Contracts;

namespace Randall.Infrastructure;

/// <summary>
/// Resolved isolation mode for an in-process session.
/// See docs/HARNESS_DESIGN.md.
/// </summary>
public sealed record HarnessIsolation(
    bool Persistent,
    bool ForkServer,
    bool Strict,
    string Summary);

/// <summary>Perf / health counters — question results if recycle rate or latency spikes.</summary>
public sealed class HarnessRunStats
{
    public long Cases;
    public long Crashes;
    public long Resets;
    public long ColdStarts;
    public long Recycles;
    public double TotalFuzzOneMs;
    public double MaxFuzzOneMs;
    public double TotalResetMs;

    public double AvgFuzzOneMs => Cases == 0 ? 0 : TotalFuzzOneMs / Cases;
    public double CrashRate => Cases == 0 ? 0 : (double)Crashes / Cases;
    public double RecycleRate => Cases == 0 ? 0 : (double)Recycles / Cases;

    public string Format() =>
        $"cases={Cases} crashes={Crashes} ({CrashRate:P1}) " +
        $"resets={Resets} coldStarts={ColdStarts} recycles={Recycles} ({RecycleRate:P1}) " +
        $"avgFuzzOne={AvgFuzzOneMs:F3}ms max={MaxFuzzOneMs:F3}ms avgReset={(Resets == 0 ? 0 : TotalResetMs / Resets):F3}ms";
}

/// <summary>
/// In-process fuzz delivery with explicit persistent / cold and forkServer / non-forkServer modes.
/// </summary>
public sealed class InProcessSession : IAsyncDisposable
{
    private readonly ProjectConfig _project;
    private readonly string _harnessPath;
    private readonly string _mode; // managed | native
    private readonly HarnessIsolation _isolation;
    private ManagedHarnessHost? _managed;
    private NativeHarnessWorker? _native;
    private int _iterationsOnWorker;
    private readonly HarnessRunStats _stats = new();

    private InProcessSession(
        ProjectConfig project, string harnessPath, string mode, HarnessIsolation isolation)
    {
        _project = project;
        _harnessPath = harnessPath;
        _mode = mode;
        _isolation = isolation;
    }

    public string Mode => _mode;
    public bool Persistent => _isolation.Persistent;
    public bool ForkServer => _isolation.ForkServer;
    public HarnessIsolation Isolation => _isolation;
    public HarnessRunStats Stats => _stats;
    public int IterationsOnWorker => _iterationsOnWorker;

    public static bool IsInProcess(ProjectConfig project)
    {
        var exec = (project.Fuzz.ExecutionMode ?? "out-of-process").Trim();
        if (exec.Equals("in-process", StringComparison.OrdinalIgnoreCase) ||
            exec.Equals("inprocess", StringComparison.OrdinalIgnoreCase))
            return true;
        return project.Kind.Equals("harness", StringComparison.OrdinalIgnoreCase);
    }

    public static HarnessIsolation ResolveIsolation(ProjectConfig project)
    {
        // Defaults: in-process → persistent on, forkServer follows persistent.
        var persistent = project.Fuzz.Persistent ?? true;
        var forkServer = project.Fuzz.ForkServer ?? persistent;
        var strict = project.Fuzz.HarnessStrict;
        var summary = (persistent ? "persistent" : "cold") +
                      "+" + (forkServer ? "forkServer" : "no-forkServer") +
                      (strict ? "+strict" : "");
        return new HarnessIsolation(persistent, forkServer, strict, summary);
    }

    public static InProcessSession Start(ProjectConfig project, string yamlPath)
    {
        var harnessPath = ResolveHarnessPath(project, yamlPath);
        if (harnessPath is null)
            throw new InvalidOperationException(
                "In-process mode requires target.harness (or target.executable) pointing at a harness DLL.");

        var type = ResolveHarnessType(project, harnessPath);
        var isolation = ResolveIsolation(project);
        var session = new InProcessSession(project, harnessPath, type, isolation);

        if (type == "managed")
        {
            session._managed = ManagedHarnessHost.Load(harnessPath);
            session.ValidateResetContract(session._managed);
        }
        else
        {
            session._native = NativeHarnessWorker.Start(harnessPath, project.Target.HarnessExport);
            session._stats.ColdStarts++;
        }

        Console.WriteLine($"Harness isolation: {isolation.Summary} ({type})");
        Console.WriteLine(
            "Harness contract: target rejects invalid input — do not filter in the harness. " +
            "Question high crash rates and ignore warm-cache illusions. See docs/HARNESS_DESIGN.md");
        return session;
    }

    private void ValidateResetContract(ManagedHarnessHost host)
    {
        if (_isolation.Persistent && !host.SupportsReset)
        {
            var msg =
                "Harness has no IInProcessHarnessReset while persistent=true. " +
                "Iteration state may leak (unintended persistent state). docs/HARNESS_DESIGN.md";
            if (_isolation.Strict)
                throw new InvalidOperationException(msg + " (fuzz.harnessStrict: true)");
            Console.WriteLine("Warning: " + msg);
        }
    }

    public async Task<TargetRunResult> RunAsync(byte[] payload, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        TargetRunResult result;

        if (_mode == "managed")
        {
            result = await RunManagedAsync(payload);
        }
        else
        {
            result = await RunNativeAsync(payload, ct);
        }

        sw.Stop();
        var fuzzMs = sw.Elapsed.TotalMilliseconds;
        _stats.Cases++;
        _stats.TotalFuzzOneMs += fuzzMs;
        if (fuzzMs > _stats.MaxFuzzOneMs)
            _stats.MaxFuzzOneMs = fuzzMs;
        if (result.Crashed)
            _stats.Crashes++;

        var n = ++_iterationsOnWorker;
        var detail = result.Detail +
                     $" [{_isolation.Summary} n={n} fuzzOne={fuzzMs:F3}ms]";

        // Performance signal: warn if a single case is extremely slow vs average
        if (_stats.Cases >= 20 && fuzzMs > Math.Max(50, _stats.AvgFuzzOneMs * 20))
        {
            Console.WriteLine(
                $"Warning: slow harness case {fuzzMs:F1}ms " +
                $"(avg {_stats.AvgFuzzOneMs:F3}ms) — question timeout/deadlock vs real work");
        }

        return result with { Detail = detail };
    }

    private Task<TargetRunResult> RunManagedAsync(byte[] payload)
    {
        if (!_isolation.Persistent)
        {
            // Cold: full reload each case — max isolation, honest reproducibility baseline.
            _managed?.Dispose();
            _managed = ManagedHarnessHost.Load(_harnessPath);
            _stats.ColdStarts++;
            ValidateResetContract(_managed);
        }
        else
        {
            _managed ??= ManagedHarnessHost.Load(_harnessPath);
            var rst = Stopwatch.StartNew();
            _managed.Reset();
            rst.Stop();
            _stats.Resets++;
            _stats.TotalResetMs += rst.Elapsed.TotalMilliseconds;
        }

        var result = _managed.Run(payload);
        if (result.Crashed && _isolation.ForkServer)
        {
            // Managed forkServer: re-Initialize via reload for a clean generation after crash.
            _managed.Dispose();
            _managed = ManagedHarnessHost.Load(_harnessPath);
            _stats.Recycles++;
            _iterationsOnWorker = 0;
        }

        return Task.FromResult(result);
    }

    private async Task<TargetRunResult> RunNativeAsync(byte[] payload, CancellationToken ct)
    {
        if (!_isolation.Persistent)
        {
            if (_native is not null)
                await _native.DisposeAsync();
            _native = NativeHarnessWorker.Start(_harnessPath, _project.Target.HarnessExport);
            _stats.ColdStarts++;
            _iterationsOnWorker = 0;
        }
        else
        {
            _native ??= NativeHarnessWorker.Start(_harnessPath, _project.Target.HarnessExport);
        }

        var result = await _native.RunAsync(payload, _project.Target.TimeoutMs, ct);
        if (result.Crashed)
        {
            // Native crash kills worker — always need a new one to continue.
            // forkServer=true: explicit generation recycle; forkServer=false: still must respawn.
            await _native.DisposeAsync();
            _native = null;
            _stats.Recycles++;
            _iterationsOnWorker = 0;
            if (_isolation.Persistent || _isolation.ForkServer)
                _native = NativeHarnessWorker.Start(_harnessPath, _project.Target.HarnessExport);
        }

        return result;
    }

    public async ValueTask DisposeAsync()
    {
        Console.WriteLine($"Harness stats: {_stats.Format()}");
        if (_stats.CrashRate > 0.25)
            Console.WriteLine(
                "Warning: crash rate >25% — question over-broad bug oracle, harness throw on reject, " +
                "or dictionary dominating. Prefer target reject → return 0.");
        if (_isolation.Persistent && _stats.Resets == 0 && _mode == "managed" && _stats.Cases > 0)
            Console.WriteLine(
                "Warning: zero Reset() calls — unintended persistent state likely.");

        _managed?.Dispose();
        _managed = null;
        if (_native is not null)
        {
            await _native.DisposeAsync();
            _native = null;
        }
    }

    private static string? ResolveHarnessPath(ProjectConfig project, string yamlPath)
    {
        var raw = project.Target.Harness;
        if (string.IsNullOrWhiteSpace(raw))
            raw = project.Target.Executable;
        if (string.IsNullOrWhiteSpace(raw))
            return null;
        var path = ProjectLoader.ResolvePath(yamlPath, raw);
        return File.Exists(path) ? path : null;
    }

    private static string ResolveHarnessType(ProjectConfig project, string harnessPath)
    {
        var configured = (project.Target.HarnessType ?? "auto").Trim().ToLowerInvariant();
        if (configured is "managed" or "native")
            return configured;

        try
        {
            AssemblyName.GetAssemblyName(harnessPath);
            return "managed";
        }
        catch
        {
            return "native";
        }
    }
}

internal sealed class ManagedHarnessHost : IDisposable
{
    private readonly AssemblyLoadContext _alc;
    private readonly IInProcessHarness _harness;
    private readonly IInProcessHarnessLifecycle? _life;
    private readonly IInProcessHarnessReset? _reset;

    private ManagedHarnessHost(AssemblyLoadContext alc, IInProcessHarness harness)
    {
        _alc = alc;
        _harness = harness;
        _life = harness as IInProcessHarnessLifecycle;
        _reset = harness as IInProcessHarnessReset;
        _life?.Initialize();
    }

    public void Reset() => _reset?.Reset();

    public bool SupportsReset => _reset is not null;

    public static ManagedHarnessHost Load(string assemblyPath)
    {
        var alc = new AssemblyLoadContext($"randall-harness-{Guid.NewGuid():N}", isCollectible: true);
        var asm = alc.LoadFromAssemblyPath(Path.GetFullPath(assemblyPath));
        Type[] types;
        try { types = asm.GetTypes(); }
        catch (ReflectionTypeLoadException ex) { types = ex.Types.Where(t => t is not null).Cast<Type>().ToArray(); }

        var type = types.FirstOrDefault(t =>
                       t is { IsAbstract: false, IsInterface: false } &&
                       typeof(IInProcessHarness).IsAssignableFrom(t))
                   ?? throw new InvalidOperationException(
                       $"No IInProcessHarness implementation found in {assemblyPath}");
        var instance = (IInProcessHarness)(Activator.CreateInstance(type)
            ?? throw new InvalidOperationException($"Could not construct {type.FullName}"));
        return new ManagedHarnessHost(alc, instance);
    }

    public TargetRunResult Run(byte[] payload)
    {
        try
        {
            var code = _harness.FuzzOne(payload);
            if (code != 0)
            {
                return new TargetRunResult(
                    true, code, null, $"harness returned {code} (treated as crash/signal)");
            }

            return new TargetRunResult(false, 0, null, "in-process ok");
        }
        catch (Exception ex)
        {
            // Crash transparency: never swallow.
            return new TargetRunResult(
                true, null, null, $"in-process exception: {ex.GetType().Name}: {ex.Message}");
        }
    }

    public void Dispose()
    {
        try { _life?.Shutdown(); } catch { /* ignore */ }
        _alc.Unload();
    }
}

/// <summary>
/// Persistent worker hosting a native fuzz export.
/// Protocol: u32le length + bytes → line "OK" | "CRASH exit=N" | "ERR …"
/// </summary>
internal sealed class NativeHarnessWorker : IAsyncDisposable
{
    private readonly string _dllPath;
    private readonly string _export;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private Process? _proc;

    private NativeHarnessWorker(string dllPath, string export, Process proc)
    {
        _dllPath = dllPath;
        _export = export;
        _proc = proc;
    }

    public static NativeHarnessWorker Start(string dllPath, string export)
    {
        var proc = StartProcess(dllPath, export);
        return new NativeHarnessWorker(dllPath, export, proc);
    }

    public async Task<TargetRunResult> RunAsync(byte[] payload, int timeoutMs, CancellationToken ct)
    {
        await _gate.WaitAsync(ct);
        try
        {
            EnsureAlive();
            return await SendOneAsync(payload, timeoutMs, ct);
        }
        finally
        {
            _gate.Release();
        }
    }

    private void EnsureAlive()
    {
        if (_proc is { HasExited: false })
            return;
        try { _proc?.Dispose(); } catch { /* ignore */ }
        _proc = StartProcess(_dllPath, _export);
    }

    private async Task<TargetRunResult> SendOneAsync(byte[] payload, int timeoutMs, CancellationToken ct)
    {
        var proc = _proc ?? throw new InvalidOperationException("worker missing");
        try
        {
            var stdin = proc.StandardInput.BaseStream;
            await stdin.WriteAsync(BitConverter.GetBytes(payload.Length), ct);
            if (payload.Length > 0)
                await stdin.WriteAsync(payload, ct);
            await stdin.FlushAsync(ct);

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(Math.Max(250, timeoutMs));
            var lineTask = proc.StandardOutput.ReadLineAsync(cts.Token);
            var line = await lineTask;

            if (line is null)
            {
                try { await proc.WaitForExitAsync(CancellationToken.None); } catch { /* ignore */ }
                var code = proc.HasExited ? proc.ExitCode : (int?)null;
                try { proc.Dispose(); } catch { /* ignore */ }
                _proc = null;
                return new TargetRunResult(
                    true, code, null, "native harness worker died (likely AV/crash)");
            }

            if (line.StartsWith("OK", StringComparison.OrdinalIgnoreCase))
                return new TargetRunResult(false, 0, null, "in-process native ok");

            if (line.StartsWith("CRASH", StringComparison.OrdinalIgnoreCase))
            {
                int? code = null;
                var idx = line.IndexOf("exit=", StringComparison.OrdinalIgnoreCase);
                if (idx >= 0)
                {
                    var rest = line[(idx + 5)..].Trim();
                    var space = rest.IndexOf(' ');
                    if (space > 0) rest = rest[..space];
                    if (int.TryParse(rest, out var c))
                        code = c;
                }

                return new TargetRunResult(true, code, null, $"native harness: {line}");
            }

            return new TargetRunResult(false, null, null, line);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            try { if (!proc.HasExited) proc.Kill(entireProcessTree: true); } catch { /* ignore */ }
            try { proc.Dispose(); } catch { /* ignore */ }
            _proc = null;
            return new TargetRunResult(true, null, null, "native harness timeout");
        }
        catch (Exception ex)
        {
            if (proc.HasExited)
            {
                var code = proc.ExitCode;
                try { proc.Dispose(); } catch { /* ignore */ }
                _proc = null;
                return new TargetRunResult(true, code, null, $"native harness worker exited: {ex.Message}");
            }

            throw;
        }
    }

    public async ValueTask DisposeAsync()
    {
        await _gate.WaitAsync();
        try
        {
            if (_proc is not null)
            {
                try
                {
                    if (!_proc.HasExited)
                    {
                        try { _proc.StandardInput.Close(); } catch { /* ignore */ }
                        if (!_proc.WaitForExit(1500))
                            _proc.Kill(entireProcessTree: true);
                    }
                }
                catch { /* ignore */ }
                _proc.Dispose();
                _proc = null;
            }
        }
        finally
        {
            _gate.Release();
            _gate.Dispose();
        }
    }

    private static Process StartProcess(string dllPath, string export)
    {
        var cli = FindCliDll()
                  ?? throw new InvalidOperationException(
                      "Could not locate Randall.Cli.dll to host the native harness worker.");

        var psi = new ProcessStartInfo
        {
            FileName = "dotnet",
            Arguments = $"\"{cli}\" harness-worker --dll \"{dllPath}\" --export \"{export}\"",
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        return Process.Start(psi)
               ?? throw new InvalidOperationException("Failed to start native harness worker");
    }

    private static string? FindCliDll()
    {
        var starts = new[]
        {
            AppContext.BaseDirectory,
            Directory.GetCurrentDirectory(),
            CrashCatalog.FindRepoRoot() ?? "",
        };
        foreach (var start in starts)
        {
            if (string.IsNullOrWhiteSpace(start)) continue;
            foreach (var c in new[]
                     {
                         Path.Combine(start, "Randall.Cli.dll"),
                         Path.Combine(start, "src", "Randall.Cli", "bin", "Debug", "net8.0", "Randall.Cli.dll"),
                         Path.Combine(start, "src", "Randall.Cli", "bin", "Release", "net8.0", "Randall.Cli.dll"),
                     })
            {
                if (File.Exists(c)) return Path.GetFullPath(c);
            }

            var dir = new DirectoryInfo(Path.GetFullPath(start));
            while (dir is not null)
            {
                var dbg = Path.Combine(dir.FullName, "src", "Randall.Cli", "bin", "Debug", "net8.0", "Randall.Cli.dll");
                var rel = Path.Combine(dir.FullName, "src", "Randall.Cli", "bin", "Release", "net8.0", "Randall.Cli.dll");
                if (File.Exists(dbg)) return dbg;
                if (File.Exists(rel)) return rel;
                dir = dir.Parent;
            }
        }

        return null;
    }
}

/// <summary>Entry used by <c>randall harness-worker</c>.</summary>
public static class NativeHarnessWorkerHost
{
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int FuzzExport(IntPtr data, nuint size);

    public static int Run(string dllPath, string exportName)
    {
        if (!File.Exists(dllPath))
        {
            Console.Error.WriteLine($"DLL not found: {dllPath}");
            return 2;
        }

        var lib = NativeLibrary.Load(Path.GetFullPath(dllPath));
        if (!NativeLibrary.TryGetExport(lib, exportName, out var fn))
        {
            Console.Error.WriteLine($"Export not found: {exportName}");
            return 3;
        }

        var fuzz = Marshal.GetDelegateForFunctionPointer<FuzzExport>(fn);
        var stdin = Console.OpenStandardInput();
        var stdout = Console.OpenStandardOutput();
        var lenBuf = new byte[4];

        while (true)
        {
            if (!ReadExact(stdin, lenBuf))
                break;
            var len = BitConverter.ToInt32(lenBuf, 0);
            if (len < 0 || len > 64 * 1024 * 1024)
            {
                WriteLine(stdout, "ERR bad length");
                continue;
            }

            var data = len == 0 ? Array.Empty<byte>() : new byte[len];
            if (len > 0 && !ReadExact(stdin, data))
                break;

            try
            {
                var handle = GCHandle.Alloc(data.Length == 0 ? new byte[1] : data, GCHandleType.Pinned);
                try
                {
                    var ptr = handle.AddrOfPinnedObject();
                    var code = fuzz(ptr, (nuint)data.Length);
                    WriteLine(stdout, code != 0 ? $"CRASH exit={code}" : "OK");
                }
                finally
                {
                    handle.Free();
                }
            }
            catch (Exception ex)
            {
                WriteLine(stdout, $"CRASH exit=exception {ex.GetType().Name}");
            }
        }

        return 0;
    }

    private static bool ReadExact(Stream s, byte[] buf)
    {
        var off = 0;
        while (off < buf.Length)
        {
            var n = s.Read(buf, off, buf.Length - off);
            if (n <= 0) return false;
            off += n;
        }

        return true;
    }

    private static void WriteLine(Stream s, string line)
    {
        var bytes = Encoding.UTF8.GetBytes(line + "\n");
        s.Write(bytes);
        s.Flush();
    }
}
